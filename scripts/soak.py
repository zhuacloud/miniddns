#!/usr/bin/env python3
"""Short/24h soak and resource gate for miniddns (§14.4/§14.5).

Defaults are CI-friendly (60 s, 2 s fallback).  For the acceptance soak run:

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

RSS_LIMIT_KIB = 2560
PEAK_LIMIT_KIB = 6144
GROWTH_LIMIT_KIB = 64
CPU_LIMIT_SECONDS = 2.0


def proc_kib(pid, key):
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith(key + ":"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def proc_cpu_seconds(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            parts = f.read().split()
        ticks = int(parts[13]) + int(parts[14])
        return ticks / float(os.sysconf("SC_CLK_TCK"))
    except (OSError, IndexError, ValueError):
        return 0.0


def main():
    ap = argparse.ArgumentParser(description="miniddns soak/resource gate")
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--interval", type=int, default=2)
    ap.add_argument("--sample", type=float, default=1.0)
    args = ap.parse_args()
    if args.seconds < 2 or args.interval < 1:
        print("ERROR: seconds and interval too small", file=sys.stderr)
        return 2

    binary = os.path.join(ROOT, "build", "miniddns")
    if not os.path.isfile(binary):
        print("ERROR: build/miniddns missing; run make first", file=sys.stderr)
        return 2
    preload = os.path.join(ROOT, "tests", "build", "redirect.so")
    if not os.path.isfile(preload):
        print("ERROR: tests/build/redirect.so missing; run make -C tests build/redirect.so",
              file=sys.stderr)
        return 2

    tmp = tempfile.mkdtemp(prefix="miniddns-soak-")
    problems = []
    try:
        certdir = os.path.join(tmp, "certs")
        ca = generate_certs(certdir)
        os.chmod(ca, 0o644)
        # CA whitelist (§03): the bundle must live under /etc, /usr/share or
        # the artifact root, so stage it next to the repository's ca/ directory.
        ca_dir = os.path.join(ROOT, "ca")
        os.makedirs(ca_dir, exist_ok=True)
        ca_artifact = os.path.join(ca_dir, "soak-ca.pem")
        shutil.copyfile(ca, ca_artifact)
        os.chmod(ca_artifact, 0o644)
        state = os.path.join(tmp, "state.json")
        reqlog = os.path.join(tmp, "requests.log")
        with open(state, "w") as f:
            json.dump({"discover": [{"id": "rec123", "content": "1.1.1.1"}],
                       "echo_ip": "1.1.1.1"}, f)
        srv = MockServer(certdir, state, reqlog)
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
                "token = SOAKTOKEN\n\n"
                "[record]\n"
                "provider = cf\n"
                "name = home.example.com\n"
                "type = A\n" % (args.interval, ca_artifact, os.path.join(tmp, "soak.lock")))
        os.chmod(conf, 0o644)
        env = os.environ.copy()
        env.update({
            "LD_PRELOAD": preload,
            "MOCK_PORT": str(srv.port),
            "MOCK_HOSTS": "api.cloudflare.com,api.ipify.org",
        })
        logpath = os.path.join(tmp, "daemon.log")
        logf = open(logpath, "w")
        p = subprocess.Popen([binary, "--allow-non-root-owner", "-f", "-c", conf],
                             env=env, stdout=logf, stderr=subprocess.STDOUT)
        first_rss = last_rss = 0
        peak_rss = 0
        deadline = time.time() + args.seconds
        next_sample = time.time() + min(2.0, max(0.5, args.seconds / 4.0))
        while time.time() < deadline:
            if p.poll() is not None:
                problems.append("daemon exited early rc=%s" % p.returncode)
                break
            if time.time() >= next_sample:
                rss = proc_kib(p.pid, "VmRSS")
                peak = proc_kib(p.pid, "VmHWM")
                if rss:
                    if first_rss == 0:
                        first_rss = rss
                    last_rss = rss
                    peak_rss = max(peak_rss, peak or rss)
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
        writes = [l for l in text.splitlines()
                  if l.startswith(("PATCH ", "POST ", "PUT "))]
        if writes:
            problems.append("unexpected writes in steady state: %d" % len(writes))
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

        if first_rss and last_rss - first_rss > GROWTH_LIMIT_KIB:
            problems.append("RSS grew by %d KiB" % (last_rss - first_rss))
        if last_rss > RSS_LIMIT_KIB:
            problems.append("RSS %d KiB exceeds %d KiB" % (last_rss, RSS_LIMIT_KIB))
        if peak_rss > PEAK_LIMIT_KIB:
            problems.append("peak RSS %d KiB exceeds %d KiB" % (peak_rss, PEAK_LIMIT_KIB))
        if cpu > CPU_LIMIT_SECONDS:
            problems.append("CPU %.3fs exceeds %.1fs" % (cpu, CPU_LIMIT_SECONDS))
        print("soak: seconds=%d interval=%d cycles=%d rss=%dKiB peak=%dKiB cpu=%.3fs"
              % (args.seconds, args.interval, cycles, last_rss, peak_rss, cpu))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        try:
            os.unlink(os.path.join(ROOT, "ca", "soak-ca.pem"))
        except OSError:
            pass

    if problems:
        for p in problems:
            print("soak: ERROR: %s" % p, file=sys.stderr)
        return 1
    print("soak: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
