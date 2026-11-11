"""Local TLS mock for §14.2 integration tests. Never shipped."""
import json
import os
import socket
import ssl
import subprocess
import threading


def _run(cmd):
    subprocess.run(cmd, shell=True, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def generate_certs(d):
    os.makedirs(d, exist_ok=True)
    ca, key = os.path.join(d, "ca.pem"), os.path.join(d, "ca.key")
    _run("openssl req -x509 -newkey rsa:2048 -nodes -keyout %s -out %s "
         "-days 3650 -subj '/CN=miniddns Test CA'" % (key, ca))
    hosts = "DNS:api.cloudflare.com,DNS:api.ipify.org,DNS:ipv4.icanhazip.com,DNS:ipv4.ident.me"
    san = os.path.join(d, "san.cnf")
    with open(san, "w") as f:
        f.write("subjectAltName=%s\nbasicConstraints=CA:FALSE\n"
                "keyUsage=digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n" % hosts)
    _run("openssl req -new -newkey rsa:2048 -nodes -keyout %s/server.key -out %s/server.csr "
         "-subj '/CN=api.cloudflare.com'" % (d, d))
    _run("openssl x509 -req -in %s/server.csr -CA %s -CAkey %s -CAcreateserial "
         "-out %s/server.pem -days 3650 -extfile %s" % (d, ca, key, d, san))
    # deliberately wrong hostname
    san2 = os.path.join(d, "wrong.cnf")
    with open(san2, "w") as f:
        f.write("subjectAltName=DNS:wrong.example.com\nbasicConstraints=CA:FALSE\n"
                "extendedKeyUsage=serverAuth\n")
    _run("openssl req -new -newkey rsa:2048 -nodes -keyout %s/wrong.key -out %s/wrong.csr "
         "-subj '/CN=wrong.example.com'" % (d, d))
    _run("openssl x509 -req -in %s/wrong.csr -CA %s -CAkey %s -CAcreateserial "
         "-out %s/wrong.pem -days 3650 -extfile %s" % (d, ca, key, d, san2))
    # an unrelated CA (for the untrusted-CA test)
    _run("openssl req -x509 -newkey rsa:2048 -nodes -keyout %s/other.key -out %s/other.pem "
         "-days 3650 -subj '/CN=Unrelated CA'" % (d, d))
    return ca


class MockServer:
    def __init__(self, certdir, statefile, logfile, cert="server.pem", key="server.key"):
        self.statefile = statefile
        self.logfile = logfile
        self.stop = False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(os.path.join(certdir, cert), os.path.join(certdir, key))
        self.ctx = ctx
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.5)
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        open(logfile, "w").close()

    def start(self):
        self.thread.start()

    def close(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def state(self):
        try:
            with open(self.statefile) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def log(self, line):
        with open(self.logfile, "a") as f:
            f.write(line + "\n")

    def _accept_loop(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            s = self.ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            conn.close()
            return
        s.settimeout(6.0)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
        except (socket.timeout, ssl.SSLError, OSError):
            pass
        appbytes = len(data)
        if data:
            head, _, rest = data.partition(b"\r\n\r\n")
            lines = head.decode("latin1").split("\r\n")
            request_line = lines[0] if lines else ""
            parts = request_line.split(" ")
            method = parts[0] if parts else "?"
            path = parts[1] if len(parts) > 1 else "?"
            clen = 0
            for line in lines[1:]:
                if line.lower().startswith("content-length:"):
                    try:
                        clen = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        clen = 0
            body = rest
            while len(body) < clen:
                try:
                    more = s.recv(4096)
                except (socket.timeout, ssl.SSLError, OSError):
                    break
                if not more:
                    break
                body += more
            self.log("APPBYTES %d" % appbytes)
            self.log("%s %s %s" % (method, path, body[:512].decode("latin1", "replace")))
            self._respond(s, method, path, body.decode("latin1", "replace"))
        else:
            self.log("APPBYTES 0")
        try:
            s.close()
        except OSError:
            pass

    def _respond(self, s, method, path, body):
        st = self.state()
        status = int(st.get("status", 200))
        reason = {200: "OK", 403: "Forbidden", 429: "Too Many Requests",
                  500: "Internal Server Error"}.get(status, "OK")
        headers = ["HTTP/1.1 %d %s" % (status, reason)]
        ctype = "application/json"
        payload_obj = None
        if "/client/v4/zones/" not in path:
            # IPv4 echo endpoint
            ctype = "text/plain"
            payload = st.get("echo_ip", "1.1.1.1") + "\n"
        else:
            if st.get("fail_name") and st["fail_name"] in path:
                status, reason = 500, "Internal Server Error"
                headers[0] = "HTTP/1.1 500 %s" % reason
                payload_obj = {"success": False, "result": [],
                               "errors": [{"code": 1000, "message": "injected"}]}
            elif method in ("PATCH", "POST"):
                payload_obj = {"success": True, "result": {"id": "rec123",
                               "content": "1.1.1.1"}, "errors": []}
            elif st.get("success", True) is False:
                payload_obj = {"success": False, "result": [],
                               "errors": st.get("errors", [{"code": 9109,
                                                          "message": "Invalid access token"}])}
            else:
                payload_obj = {"success": True, "result": st.get("discover",
                               [{"id": "rec123", "content": "1.1.1.1"}]), "errors": []}
            payload = json.dumps(payload_obj, separators=(",", ":"))
        if isinstance(payload_obj, dict):
            payload = json.dumps(payload_obj, separators=(",", ":"))
        raw = payload.encode()
        headers.append("Content-Type: %s" % ctype)
        headers.append("Connection: close")
        if st.get("retry_after"):
            headers.append("Retry-After: %s" % st["retry_after"])
        if st.get("chunked"):
            headers.append("Transfer-Encoding: chunked")
            chunks = b""
            for i in range(0, len(raw), max(1, len(raw) // 2 or 1)):
                part = raw[i:i + max(1, len(raw) // 2 or 1)]
                chunks += ("%x\r\n" % len(part)).encode() + part + b"\r\n"
            chunks += b"0\r\n\r\n"
            out = ("\r\n".join(headers) + "\r\n\r\n").encode() + chunks
        else:
            headers.append("Content-Length: %d" % len(raw))
            out = ("\r\n".join(headers) + "\r\n\r\n").encode() + raw
        try:
            s.sendall(out)
        except (ssl.SSLError, OSError):
            pass
