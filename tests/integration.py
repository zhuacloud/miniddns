#!/usr/bin/env python3
"""§14.2 integration tests against a local self-signed TLS mock (LD_PRELOAD redirect)."""
import json
import os
import shutil
import signal
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
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:verify_asan_link_order=0"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
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


def daemon_env(port):
    env = os.environ.copy()
    env["LD_PRELOAD"] = PRELOAD
    env["MOCK_PORT"] = str(port)
    env["MOCK_HOSTS"] = "api.cloudflare.com,api.ipify.org"
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:verify_asan_link_order=0"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return env


def start_daemon(cfg, port, logpath):
    f = open(logpath, "w")
    p = subprocess.Popen([BIN, "--allow-non-root-owner", "-f", "-c", cfg],
                         env=daemon_env(port), stdout=f,
                         stderr=subprocess.STDOUT)
    return p, f


def stop_daemon(p, f, sig=signal.SIGTERM, timeout=5):
    if p.poll() is None:
        p.send_signal(sig)
    try:
        rc = p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        rc = p.wait()
    f.close()
    return rc


def wait_text(path, needle, timeout):
    end = time.time() + timeout
    while time.time() < end:
        txt = log_text(path)
        if needle in txt:
            return txt
        time.sleep(0.05)
    return log_text(path)


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
    check("check-ca reports earliest_notAfter and tls=1.2",
          "earliest_notAfter=" in out(r) and "tls=1.2" in out(r), out(r)[-400:])
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

    # 18. daemon: boot failure must schedule the first backoff step (5 s)
    cfg_daemon = write_conf("daemon-retry.conf",
                            conf(ca_good, lock=os.path.join(TMP, "daemon-retry.lock")))
    write_state({"status": 500})
    dlog = os.path.join(TMP, "daemon-retry.log")
    p, f = start_daemon(cfg_daemon, srv.port, dlog)
    txt = wait_text(dlog, "retry scheduled delay_ms=5000", 2.0)
    check("daemon boot failure schedules 5s retry", "delay_ms=5000" in txt, txt[-500:])
    txt = wait_text(dlog, "cycle start reason=retry", 7.0)
    check("daemon performs the scheduled retry", "cycle start reason=retry" in txt, txt[-500:])
    rc = stop_daemon(p, f)
    txt = log_text(dlog)
    check("daemon SIGTERM exits 0", rc == 0 and "stop signal=15" in txt, txt[-300:])

    # 19. daemon: clock guard must schedule a fixed 30 s retry after boot
    cfg_clockd = write_conf("daemon-clock.conf",
                            conf(ca_good, lock=os.path.join(TMP, "daemon-clock.lock"))
                            .replace("[core]\n", "[core]\nclock_guard_epoch = 2000000000\n"))
    dlog = os.path.join(TMP, "daemon-clock.log")
    p, f = start_daemon(cfg_clockd, srv.port, dlog)
    txt = wait_text(dlog, "retry scheduled delay_ms=30000 reason=clock", 2.0)
    check("daemon clock guard schedules 30s retry", "delay_ms=30000" in txt, txt[-500:])
    rc = stop_daemon(p, f)
    check("clock-guard daemon exits 0 on SIGTERM", rc == 0, txt[-300:])

    # 20. SIGHUP is logged and ignored; SIGTERM still exits 0
    write_state({})
    cfg_hup = write_conf("daemon-hup.conf",
                         conf(ca_good, lock=os.path.join(TMP, "daemon-hup.lock")))
    dlog = os.path.join(TMP, "daemon-hup.log")
    p, f = start_daemon(cfg_hup, srv.port, dlog)
    wait_text(dlog, "cycle end", 3.0)
    p.send_signal(signal.SIGHUP)
    time.sleep(0.4)
    alive = p.poll() is None
    txt = log_text(dlog)
    check("SIGHUP ignored and logged", alive and "sighup_ignored" in txt, txt[-400:])
    rc = stop_daemon(p, f)
    check("SIGTERM after SIGHUP exits 0", rc == 0, txt[-300:])

    # 21. 429 Retry-After: 1 must drive the next attempt, not the long backoff
    cfg_429d = write_conf("daemon-429.conf",
                          conf(ca_good, lock=os.path.join(TMP, "daemon-429.lock")))
    write_state({"status": 429, "retry_after": "1"})
    dlog = os.path.join(TMP, "daemon-429.log")
    p, f = start_daemon(cfg_429d, srv.port, dlog)
    txt = wait_text(dlog, "retry scheduled delay_ms=1000", 2.0)
    check("daemon honors Retry-After=1", "delay_ms=1000" in txt, txt[-500:])
    txt = wait_text(dlog, "cycle start reason=retry", 2.5)
    check("daemon retries after Retry-After", "cycle start reason=retry" in txt, txt[-500:])
    stop_daemon(p, f)

    # 22. Content-Length + keep-alive: stop at the framed end, not at timeout
    write_state({"keep_alive": True, "echo_ip": "1.1.1.1"})
    cfg_http = write_conf("http-keepalive.conf",
                          conf(ca_good, lock=os.path.join(TMP, "http.lock"))
                          .replace("[core]\n",
                                   "[core]\nhttp_timeout_ms = 3000\nconnect_timeout_ms = 1000\n"))
    t0 = time.time()
    r = run(base + ["--print-ip", "-c", cfg_http], srv.port, timeout=10)
    elapsed = time.time() - t0
    check("keep-alive Content-Length response completes early",
          r.returncode == 0 and "ipv4=1.1.1.1" in out(r) and elapsed < 2.0,
          "rc=%d elapsed=%.2fs out=%r" % (r.returncode, elapsed, out(r)[-800:]))

    # 23. Truncated close-delimited body must be rejected (no close_notify)
    write_state({"truncate_body": True, "echo_ip": "1.1.1.77"})
    r = run(base + ["--print-ip", "-c", cfg_http], srv.port, timeout=10)
    check("truncated close-delimited body rejected",
          r.returncode == 1 and "tls_truncated" in out(r) and "ipv4=1.1.1.7 " not in out(r),
          "rc=%d out=%r" % (r.returncode, out(r)[-800:]))

    # 24. connect_timeout_ms covers the TLS handshake, not just TCP connect
    cfg_stall = write_conf("stall.conf",
                           conf(ca_good, lock=os.path.join(TMP, "stall.lock"))
                           .replace("[core]\n",
                                    "[core]\nhttp_timeout_ms = 3000\nconnect_timeout_ms = 500\n"))
    stall = MockServer(certdir, statefile, os.path.join(TMP, "stall.log"), stall=True)
    stall.start()
    t0 = time.time()
    r = run(base + ["--print-ip", "-c", cfg_stall], stall.port, timeout=10)
    elapsed = time.time() - t0
    stall.close()
    check("TLS handshake respects connect_timeout",
          r.returncode == 1 and elapsed < 2.5, "elapsed=%.2fs out=%s" % (elapsed, out(r)[-300:]))

    # 25. empty CA bundle => E_CA_LOAD, not a fake TLS verification success
    empty_ca = os.path.join(repo_ca, "empty.pem")
    open(empty_ca, "wb").close()
    os.chmod(empty_ca, 0o644)
    cfg_empty = write_conf("empty-ca.conf", conf(empty_ca))
    r = run(base + ["--check-ca", "-c", cfg_empty], srv.port)
    check("empty CA returns E_CA_LOAD",
          r.returncode == 1 and "E_CA_LOAD" in out(r), out(r)[-400:])

    srv.close()
    wrong.close()
    for n in ("test-ca.pem", "test-ca-untrusted.pem", "test-ca-wrong.pem", "empty.pem"):
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
