#!/usr/bin/env python3
"""Short/24h soak and dual-track resource gate for miniddns (design §14.4/§14.5).

Uses production-like inputs (token_file + full CA bundle) so memory regressions
and optimizations (RssAnon, VmRSS, VmPeak, smaps [stack] Rss) are exercised.

Defaults are CI-friendly (60 s, 2 s fallback). For the acceptance soak run:

    python3 scripts/soak.py --seconds 86400 --interval 60
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from mock_server import MockServer, generate_certs  # noqa: E402

LIMITS = {
    "glibc": {
        "rss": 2458,          # 2.4 MiB VmRSS
        "anon": 320,          # 320 KiB RssAnon
        "stack": 32,          # 32 KiB smaps [stack] Rss
        "peak": 2867,         # 2.8 MiB VmHWM
        "vmpeak": 3891,       # 3.8 MiB VmPeak
        "growth": 32,         # 32 KiB steady-state RssAnon growth
        "cpu": 1.5,           # 1.5 s target (hard spec ceiling 2.0 s)
    },
    "musl": {
        "rss": 768,
        "anon": 256,
        "stack": 32,
        "peak": 1024,
        "vmpeak": 1536,
        "growth": 32,
        "cpu": 1.5,
    },
}


def proc_status_kib(pid):
    out = {}
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                for key in ("VmRSS", "RssAnon", "RssFile", "VmHWM", "VmPeak"):
                    if line.startswith(key + ":"):
                        out[key] = int(line.split()[1])
    except OSError:
        pass
    return out


def proc_stack_rss_kib(pid):
    in_stack = False
    total = 0
    try:
        with open("/proc/%d/smaps" % pid) as f:
            for line in f:
                sp = line.strip().split(None, 5)
                if sp and "-" in sp[0] and len(sp) >= 5:
                    in_stack = len(sp) > 5 and sp[5].strip() == "[stack]"
                elif in_stack and line.startswith("Rss:"):
                    total += int(line.split()[1])
    except OSError:
        return -1
    return total


def proc_cpu_seconds(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            parts = f.read().split()
        ticks = int(parts[13]) + int(parts[14])
        return ticks / float(os.sysconf("SC_CLK_TCK"))
    except (OSError, IndexError, ValueError):
        return 0.0


def detect_libc(binary):
    try:
        out = subprocess.check_output([binary, "--version"], text=True, timeout=10)
        if "libc=musl" in out:
            return "musl"
        if "libc=glibc" in out:
            return "glibc"
    except (OSError, subprocess.SubprocessError):
        pass
    return "glibc"


def build_ca_bundle(test_ca_path, dst_path):
    """Combine full CA bundle (repo snapshot or system bundle) with local mock CA."""
    candidates = [
        os.path.join(ROOT, "ca", "ca-certificates.crt"),
        "/etc/ssl/certs/ca-certificates.crt",
    ]
    full_ca = next((p for p in candidates if os.path.isfile(p) and os.path.getsize(p) > 4096), None)
    with open(dst_path, "wb") as out:
        if full_ca:
            with open(full_ca, "rb") as f:
                out.write(f.read())
            out.write(b"\n")
        with open(test_ca_path, "rb") as f:
            out.write(f.read())
    os.chmod(dst_path, 0o644)


def run_in_netns(args):
    """Re-exec this script inside an isolated user+mount+net namespace for static musl."""
    hosts = tempfile.NamedTemporaryFile("w", prefix="mn-hosts-", delete=False)
    try:
        hosts.write("127.0.0.1 localhost api.cloudflare.com api.ipify.org "
                    "ipv4.icanhazip.com ipv4.ident.me\n")
        hosts.close()
        os.chmod(hosts.name, 0o644)
        inner = [
            sys.executable, os.path.abspath(__file__),
            "--seconds", str(args.seconds),
            "--interval", str(args.interval),
            "--sample", str(args.sample),
            "--binary", os.path.abspath(args.binary),
            "--mock-mode", "hosts",
        ]
        if args.libc:
            inner += ["--libc", args.libc]
        cmd = [
            "unshare", "-rmn", "--", "sh", "-c",
            "ip link set lo up 2>/dev/null || true; "
            "mount --bind \"$1\" /etc/hosts && shift && exec \"$@\"",
            "_", hosts.name,
        ] + inner
        return subprocess.call(cmd)
    finally:
        try:
            os.unlink(hosts.name)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description="miniddns soak/resource gate")
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--interval", type=int, default=2)
    ap.add_argument("--sample", type=float, default=1.0)
    ap.add_argument("--binary", default=os.path.join(ROOT, "build", "miniddns"))
    ap.add_argument("--libc", choices=["musl", "glibc"], default=None)
    ap.add_argument("--mock-mode", choices=["preload", "netns", "hosts"], default="preload")
    args = ap.parse_args()
    if args.seconds < 2 or args.interval < 1:
        print("ERROR: seconds and interval too small", file=sys.stderr)
        return 2

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        print("ERROR: binary missing: %s" % binary, file=sys.stderr)
        return 2

    if args.mock_mode == "netns":
        return run_in_netns(args)

    libc = args.libc or detect_libc(binary)
    lim = LIMITS[libc]
    preload = os.path.join(ROOT, "tests", "build", "redirect.so")
    if args.mock_mode == "preload" and not os.path.isfile(preload):
        print("ERROR: tests/build/redirect.so missing; run make -C tests build/redirect.so",
              file=sys.stderr)
        return 2

    tmp = tempfile.mkdtemp(prefix="miniddns-soak-")
    ca_artifact = os.path.join(ROOT, "ca", "soak-ca-%d.pem" % os.getpid())
    problems = []
    try:
        certdir = os.path.join(tmp, "certs")
        ca = generate_certs(certdir)
        os.chmod(ca, 0o644)
        os.makedirs(os.path.dirname(ca_artifact), exist_ok=True)
        build_ca_bundle(ca, ca_artifact)

        tokfile = os.path.join(tmp, "cloudflare.token")
        with open(tokfile, "w") as f:
            f.write("SOAKTOKEN_PRODUCTION_LIKE\n")
        os.chmod(tokfile, 0o600)

        state = os.path.join(tmp, "state.json")
        reqlog = os.path.join(tmp, "requests.log")
        with open(state, "w") as f:
            json.dump({"discover": [{"id": "rec123", "content": "1.1.1.1"}],
                       "echo_ip": "1.1.1.1"}, f)
        bind_port = 443 if args.mock_mode == "hosts" else 0
        srv = MockServer(certdir, state, reqlog, bind_port=bind_port)
        srv.start()

        conf = os.path.join(tmp, "soak.conf")
        with open(conf, "w") as f:
            f.write(
                "[core]\n"
                "instance = soak\n"
                "interval_fallback = %d\n"
                "debounce_ms = 100\n"
                "write_memo_ms = 0\n"
                "ca_bundle = %s\n"
                "log_level = info\n"
                "lock_file = %s\n\n"
                "[detect]\n"
                "ipv4_mode = external\n"
                "ipv6_mode = off\n"
                "ipv4_echo_url = https://api.ipify.org\n\n"
                "[provider]\n"
                "id = cf\n"
                "kind = cloudflare\n"
                "zone_id = 023e105f4ecef8ad9ca31a8372d0c353\n"
                "token_file = %s\n\n"
                "[record]\n"
                "provider = cf\n"
                "name = home.example.com\n"
                "type = A\n" % (args.interval, ca_artifact,
                                os.path.join(tmp, "soak.lock"), tokfile))
        os.chmod(conf, 0o644)

        env = os.environ.copy()
        if args.mock_mode == "preload":
            env.update({
                "LD_PRELOAD": preload,
                "MOCK_PORT": str(srv.port),
                "MOCK_HOSTS": "api.cloudflare.com,api.ipify.org",
            })
        logpath = os.path.join(tmp, "daemon.log")
        logf = open(logpath, "w")
        p = subprocess.Popen([binary, "--allow-non-root-owner", "-f", "-c", conf],
                             env=env, stdout=logf, stderr=subprocess.STDOUT)

        first_anon = last_anon = 0
        last_rss = last_file = peak_rss = vm_peak = max_stack = 0
        deadline = time.time() + args.seconds
        next_sample = time.time() + min(2.0, max(0.5, args.seconds / 4.0))
        while time.time() < deadline:
            if p.poll() is not None:
                problems.append("daemon exited early rc=%s" % p.returncode)
                break
            if time.time() >= next_sample:
                st = proc_status_kib(p.pid)
                sr = proc_stack_rss_kib(p.pid)
                rss = st.get("VmRSS", 0)
                anon = st.get("RssAnon", 0)
                rfile = st.get("RssFile", 0)
                hwm = st.get("VmHWM", 0)
                vp = st.get("VmPeak", 0)
                if rss:
                    last_rss = rss
                    last_file = rfile
                    peak_rss = max(peak_rss, hwm or rss)
                if anon:
                    if first_anon == 0:
                        first_anon = anon
                    last_anon = anon
                if vp:
                    vm_peak = max(vm_peak, vp)
                if sr >= 0:
                    max_stack = max(max_stack, sr)
                next_sample += args.sample
            time.sleep(0.1)

        cpu = proc_cpu_seconds(p.pid)
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
        try:
            rc = p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            rc = p.wait()
        logf.close()
        srv.close()
        if rc != 0:
            problems.append("daemon did not exit 0 on SIGTERM (rc=%s)" % rc)

        text = ""
        try:
            with open(logpath, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            pass
        cycles = text.count("cycle start")
        expected = args.seconds // args.interval + 1
        if cycles < max(1, expected - 2):
            problems.append("too few cycles: got %d expected about %d" % (cycles, expected))
        if any("detect family=" in l and "level=info" in l for l in text.splitlines()):
            problems.append("detect success line must be debug, not info")

        requests = ""
        try:
            with open(reqlog, encoding="utf-8", errors="replace") as f:
                requests = f.read()
        except OSError:
            pass
        if any(l.startswith(("PATCH ", "POST ", "PUT ")) for l in requests.splitlines()):
            problems.append("mock observed write requests")

        if first_anon and last_anon - first_anon > lim["growth"]:
            problems.append("RssAnon grew by %d KiB (limit %d KiB)"
                            % (last_anon - first_anon, lim["growth"]))
        if last_rss > lim["rss"]:
            problems.append("VmRSS %d KiB exceeds %d KiB (%s)" % (last_rss, lim["rss"], libc))
        if last_anon > lim["anon"]:
            problems.append("RssAnon %d KiB exceeds %d KiB (%s)" % (last_anon, lim["anon"], libc))
        if max_stack > lim["stack"]:
            problems.append("stack Rss %d KiB exceeds %d KiB (%s)" % (max_stack, lim["stack"], libc))
        if peak_rss > lim["peak"]:
            problems.append("VmHWM %d KiB exceeds %d KiB (%s)" % (peak_rss, lim["peak"], libc))
        if vm_peak > lim["vmpeak"]:
            problems.append("VmPeak %d KiB exceeds %d KiB (%s)" % (vm_peak, lim["vmpeak"], libc))
        if cpu > lim["cpu"]:
            problems.append("CPU %.3fs exceeds %.1fs" % (cpu, lim["cpu"]))

        print("soak: libc=%s mode=%s seconds=%d interval=%d cycles=%d "
              "rss=%dKiB anon=%dKiB file=%dKiB stack=%dKiB peak=%dKiB vmpeak=%dKiB cpu=%.3fs"
              % (libc, args.mock_mode, args.seconds, args.interval, cycles,
                 last_rss, last_anon, last_file, max_stack, peak_rss, vm_peak, cpu))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        try:
            os.unlink(ca_artifact)
        except OSError:
            pass

    if problems:
        for pr in problems:
            print("soak: ERROR: %s" % pr, file=sys.stderr)
        return 1
    print("soak: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
