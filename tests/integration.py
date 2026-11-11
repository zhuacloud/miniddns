#!/usr/bin/env python3
"""§14.2 integration tests against a local self-signed TLS mock (LD_PRELOAD redirect)."""
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BIN = os.path.join(ROOT, "build", "miniddns")
PRELOAD = os.path.join(HERE, "build", "redirect.so")
TMP = os.path.join(HERE, "tmp", "itest")
sys.path.insert(0, HERE)
from mock_server import MockServer, generate_certs  # noqa: E402

failures = []
checks = 0


def check(name, cond, detail=""):
    global checks
    checks += 1
    if cond:
        print("  ok  %s" % name)
    else:
        failures.append("%s %s" % (name, detail))
        print(" FAIL %s %s" % (name, detail))


def write_state(d):
    with open(os.path.join(TMP, "state.json"), "w") as f:
        json.dump(d, f)


def log_text(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def clear_log(path):
    open(path, "w").close()


def conf(ca, extra="", lock=None, records=None):
    if records is None:
        records = "[record]\nprovider = cf\nname = home.example.com\ntype = A\n"
    return ("[core]\ninstance = itest\ninterval_fallback = 0\ndebounce_ms = 100\n"
            "write_memo_ms = 0\nca_bundle = %s\nlog_level = debug\n"
            "lock_file = %s\n\n[detect]\nipv4_mode = external\nipv6_mode = off\n"
            "ipv4_echo_url = https://api.ipify.org\n\n"
            "[provider]\nid = cf\nkind = cloudflare\n"
            "zone_id = 023e105f4ecef8ad9ca31a8372d0c353\ntoken = TESTTOKEN123456\n\n"
            "%s%s" % (ca, lock or os.path.join(TMP, "itest.lock"), records, extra))


def write_conf(name, text):
    p = os.path.join(TMP, name)
    with open(p, "w") as f:
        f.write(text)
    os.chmod(p, 0o644)  # §03 rejects group/world writable config files
    return p


def run(args, port, timeout=40, extra_env=None):
    env = os.environ.copy()
    env["LD_PRELOAD"] = PRELOAD
    env["MOCK_PORT"] = str(port)
    env["MOCK_HOSTS"] = "api.cloudflare.com,api.ipify.org"
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    if extra_env:
        env.update(extra_env)
    try:
        return subprocess.run([BIN] + args, env=env, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        class R:
            returncode = 124
            stdout = (e.stdout or b"").decode("latin1", "replace")
            stderr = (e.stderr or b"").decode("latin1", "replace")
        return R()


def out(r):
    return (r.stdout or "") + (r.stderr or "")


def main():
    os.makedirs(TMP, exist_ok=True)
    certdir = os.path.join(TMP, "certs")
    ca = generate_certs(certdir)
    # whitelisted CA paths: artifact root is the repo root when ca/ exists
    repo_ca = os.path.join(ROOT, "ca")
    os.makedirs(repo_ca, exist_ok=True)
    system_ca = "/etc/ssl/certs/ca-certificates.crt"
    if not os.path.exists(os.path.join(repo_ca, "ca-certificates.crt")) and os.path.exists(system_ca):
        shutil.copy(system_ca, os.path.join(repo_ca, "ca-certificates.crt"))
        os.chmod(os.path.join(repo_ca, "ca-certificates.crt"), 0o644)
    for n in ("test-ca.pem", "test-ca-untrusted.pem", "test-ca-wrong.pem"):
        src = {"test-ca.pem": "ca.pem", "test-ca-untrusted.pem": "other.pem",
               "test-ca-wrong.pem": "ca.pem"}[n]
        dst = os.path.join(repo_ca, n)
        shutil.copy(os.path.join(certdir, src), dst)
        os.chmod(dst, 0o644)  # §03 rejects group/world writable CA bundles
    ca_good = os.path.join(repo_ca, "test-ca.pem")
    ca_bad = os.path.join(repo_ca, "test-ca-untrusted.pem")

    statefile = os.path.join(TMP, "state.json")
    logfile = os.path.join(TMP, "requests.log")
    write_state({})
    srv = MockServer(certdir, statefile, logfile)
    srv.start()
    wronglog = os.path.join(TMP, "wrong.log")
    wrong = MockServer(certdir, statefile, wronglog, cert="wrong.pem", key="wrong.key")
    wrong.start()
    print("mock ports: main=%d wrong=%d" % (srv.port, wrong.port))

    base = ["--allow-non-root-owner"]
    cfg = write_conf("base.conf", conf(ca_good))

    # 1. --check-ca trusted, and ZERO application bytes
    clear_log(logfile)
    r = run(base + ["--check-ca", "-c", cfg], srv.port)
    txt = log_text(logfile)
    check("check-ca OK", r.returncode == 0 and "check-ca: OK" in out(r), out(r)[-400:])
    check("check-ca sends no request bytes", "APPBYTES 0" in txt and "APPBYTES " in txt
          and all("APPBYTES 0" in l for l in txt.splitlines() if l.startswith("APPBYTES")),
          txt[:300])

    # 2. untrusted CA must fail closed with E_TLS_CERT and no request bytes
    cfg_untrusted = write_conf("untrusted.conf", conf(ca_bad))
    clear_log(logfile)
    r = run(base + ["--check-ca", "-c", cfg_untrusted], srv.port)
    txt = log_text(logfile)
    check("untrusted CA fails with E_TLS_CERT", r.returncode == 1 and "E_TLS_CERT" in out(r),
          out(r)[-400:])
    check("untrusted CA sends zero bytes",
          all("APPBYTES 0" in l for l in txt.splitlines() if l.startswith("APPBYTES")), txt[:300])

    # 3. hostname mismatch => E_TLS_CERT
    clear_log(wronglog)
    r = run(base + ["--check-ca", "-c", cfg], wrong.port)
    check("hostname mismatch fails", r.returncode == 1 and "E_TLS_CERT" in out(r), out(r)[-400:])

    # 4. --check-config masks inline token
    r = run(base + ["--check-config", "-c", cfg], srv.port)
    check("check-config passes", r.returncode == 0, out(r)[-300:])
    check("check-config masks token", "TESTTOKEN123456" not in out(r), out(r)[-300:])

    # 5. --print-ip uses external echo
    write_state({})
    r = run(base + ["--print-ip", "-c", cfg], srv.port)
    check("print-ip external", r.returncode == 0 and "ipv4=1.1.1.1" in out(r), out(r)[-300:])

    # 6. zero writes when IP unchanged (core invariant), 3 cycles
    write_state({"discover": [{"id": "rec123", "content": "1.1.1.1"}]})
    clear_log(logfile)
    for _ in range(3):
        r = run(base + ["--once", "-c", cfg], srv.port)
    txt = log_text(logfile)
    writes = [l for l in txt.splitlines() if l.startswith("PATCH ") or l.startswith("POST ")
              or l.startswith("PUT ")]
    check("zero writes when IP unchanged", r.returncode == 0 and len(writes) == 0,
          "writes=%s log=%s" % (writes, txt[:300]))
    check("one discover GET per cycle",
          len([l for l in txt.splitlines() if l.startswith("GET /client/v4/zones/")]) == 3,
          txt[:400])

    # 7. PATCH contains ONLY content, never PUT
    write_state({"discover": [{"id": "rec123", "content": "9.9.9.9"}]})
    clear_log(logfile)
    r = run(base + ["--once", "-c", cfg], srv.port)
    txt = log_text(logfile)
    patches = [l for l in txt.splitlines() if l.startswith("PATCH ")]
    ok = (r.returncode == 0 and len(patches) == 1
          and '{"content":"1.1.1.1"}' in patches[0]
          and "PUT " not in txt and '"ttl"' not in patches[0] and '"proxied"' not in patches[0])
    check("PATCH body has only content", ok, "patches=%s log=%s" % (patches, txt[:400]))

    # 8. create path
    write_state({"discover": []})
    clear_log(logfile)
    r = run(base + ["--once", "-c", cfg], srv.port)
    txt = log_text(logfile)
    posts = [l for l in txt.splitlines() if l.startswith("POST ")]
    ok = (r.returncode == 0 and len(posts) == 1
          and all(k in posts[0] for k in ('"type":"A"', '"name":"home.example.com"',
                                          '"content":"1.1.1.1"', '"ttl":60', '"proxied":false')))
    check("create POST body", ok, "posts=%s" % posts)

    # 9. --dry-run implies --once, no writes
    write_state({"discover": [{"id": "rec123", "content": "9.9.9.9"}]})
    clear_log(logfile)
    r = run(base + ["--dry-run", "-c", cfg], srv.port)
    txt = log_text(logfile)
    check("dry-run would-update", r.returncode == 0 and "would-update" in out(r), out(r)[-400:])
    check("dry-run performs no writes",
          not any(l.startswith(("PATCH ", "POST ", "PUT ")) for l in txt.splitlines()), txt[:300])

    # 10. success=false + api_code
    write_state({"discover": [], "success": False,
                 "errors": [{"code": 9109, "message": "Invalid access token"}]})
    r = run(base + ["--once", "-c", cfg], srv.port)
    check("api_code logged on success=false",
          r.returncode == 1 and "api_code=9109" in out(r), out(r)[-500:])

    # 11. 429 + Retry-After
    write_state({"status": 429, "retry_after": "30"})
    r = run(base + ["--once", "-c", cfg], srv.port)
    check("429 retry_after", r.returncode == 1
          and ("retry_after=30" in out(r) or "E_RATELIMIT" in out(r) or "http_status=429" in out(r)),
          out(r)[-500:])

    # 12. chunked response must parse (not E_PARSE)
    write_state({"chunked": True, "discover": [{"id": "rec123", "content": "1.1.1.1"}]})
    r = run(base + ["--once", "-c", cfg], srv.port)
    check("chunked response parses", r.returncode == 0 and "E_PARSE" not in out(r), out(r)[-500:])

    # 13. multi-record partial failure
    two = ("[record]\nprovider = cf\nname = home.example.com\ntype = A\n\n"
           "[record]\nprovider = cf\nname = bad.example.com\ntype = A\n")
    cfg2 = write_conf("two.conf", conf(ca_good, records=two))
    write_state({"discover": [{"id": "rec123", "content": "9.9.9.9"}],
                 "fail_name": "bad.example.com"})
    clear_log(logfile)
    r = run(base + ["--once", "-c", cfg2], srv.port)
    txt = log_text(logfile)
    check("partial failure ok=1 fail=1", "ok=1 fail=1" in out(r), out(r)[-600:])
    check("healthy record still updated",
          any(l.startswith("PATCH ") for l in txt.splitlines()), txt[:400])

    # 14. private IPv4 never reaches provider
    write_state({"echo_ip": "192.168.1.1"})
    clear_log(logfile)
    r = run(base + ["--once", "-c", cfg], srv.port)
    txt = log_text(logfile)
    check("private IPv4 not published", r.returncode == 0
          and not any("GET /client/v4/zones/" in l for l in txt.splitlines()),
          "out=%s log=%s" % (out(r)[-300:], txt[:300]))

    # 15. flock contention => exit 0 + lock held
    write_state({})
    lockpath = os.path.join(TMP, "held.lock")
    cfg_lock = write_conf("lock.conf", conf(ca_good, lock=lockpath))
    holder = subprocess.Popen(["flock", "-n", lockpath, "-c", "sleep 6"])
    time.sleep(0.3)
    r = run(base + ["--once", "-c", cfg_lock], srv.port)
    check("flock contention exits 0", r.returncode == 0 and "lock held" in out(r), out(r)[-300:])
    holder.terminate()
    try:
        holder.wait(timeout=2)
    except subprocess.TimeoutExpired:
        holder.kill()

    # 16. token symlink rejected (§03)
    sym_target = os.path.join(TMP, "token-real")
    with open(sym_target, "w") as f:
        f.write("abc\n")
    sym = os.path.join(TMP, "token-link")
    try:
        os.unlink(sym)
    except OSError:
        pass
    os.symlink(sym_target, sym)
    cfg_sym = write_conf("sym.conf", conf(ca_good).replace("token = TESTTOKEN123456",
                                                         "token_file = %s" % sym))
    r = run(base + ["--once", "-c", cfg_sym], srv.port)
    check("token symlink rejected", r.returncode != 0
          and ("E_CFG" in out(r) or "symlink" in out(r) or "token" in out(r)), out(r)[-400:])

    # 17. clock guard (§05.6): no requests at all while the clock is unsynced
    cfg_clock = write_conf("clock.conf",
                           conf(ca_good).replace("[core]\n",
                                                 "[core]\nclock_guard_epoch = 2000000000\n"))
    write_state({"discover": [{"id": "rec123", "content": "9.9.9.9"}]})
    clear_log(logfile)
    r = run(base + ["--once", "-c", cfg_clock], srv.port)
    txt = log_text(logfile)
    check("clock guard blocks all writes", r.returncode == 0
          and "clock_unsynced" in out(r)
          and not any(l.startswith(("GET ", "PATCH ", "POST "))
                      for l in txt.splitlines()), "out=%s log=%s" % (out(r)[-300:], txt[:300]))

    srv.close()
    wrong.close()
    for n in ("test-ca.pem", "test-ca-untrusted.pem", "test-ca-wrong.pem"):
        try:
            os.unlink(os.path.join(repo_ca, n))
        except OSError:
            pass
    print("\nintegration: %d checks, %d failures" % (checks, len(failures)))
    for f in failures:
        print("  FAIL:", f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
