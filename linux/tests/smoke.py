#!/usr/bin/env python3
"""
Integration smoke test: starts the real NetShield daemon against a fake upstream
DNS server (no internet needed) and exercises it over UDP, TCP and the control
socket.

    python3 linux/tests/smoke.py [--jar linux/build/netshield-dns.jar]
"""
import argparse
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_JAR = HERE.parent / "build" / "netshield-dns.jar"

failures = 0
checks = 0


def check(cond, what):
    global failures, checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + what, flush=True)
    if not cond:
        failures += 1


# ---- DNS helpers --------------------------------------------------------------------------

def build_query(name, qtype=1, qid=0x1234, edns=0):
    hdr = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1 if edns else 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    q += struct.pack(">HH", qtype, 1)
    if edns:
        q += b"\x00" + struct.pack(">HHIH", 41, edns, 0, 0)
    return hdr + q


def skip_name(d, off):
    while True:
        n = d[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        off += 1 + n


def parse_response(d):
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", d[:12])
    off = 12
    for _ in range(qd):
        off = skip_name(d, off) + 4
    answers = []
    for _ in range(an):
        off = skip_name(d, off)
        t, c, ttl, rdlen = struct.unpack(">HHIH", d[off:off + 10])
        off += 10
        answers.append((t, d[off:off + rdlen]))
        off += rdlen
    return {"id": qid, "rcode": flags & 0xF, "tc": bool(flags & 0x200), "qr": bool(flags & 0x8000),
            "answers": answers, "len": len(d)}


def udp_query(port, pkt, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, ("127.0.0.1", port))
        data, _ = s.recvfrom(65535)
        return parse_response(data)
    finally:
        s.close()


def tcp_query(port, pkt, timeout=6):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(struct.pack(">H", len(pkt)) + pkt)
        n = struct.unpack(">H", recv_exact(s, 2))[0]
        return parse_response(recv_exact(s, n))
    finally:
        s.close()


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def ip4(ans):
    return ".".join(str(b) for b in ans[1]) if ans[0] == 1 else None


# ---- fake upstream ------------------------------------------------------------------------

class FakeUpstream(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.counts = {}
        self.lock = threading.Lock()

    def count(self, name):
        with self.lock:
            return self.counts.get(name, 0)

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            qid = struct.unpack(">H", data[:2])[0]
            off = 12
            labels = []
            while data[off]:
                labels.append(data[off + 1:off + 1 + data[off]].decode())
                off += 1 + data[off]
            name = ".".join(labels)
            qtype = struct.unpack(">H", data[off + 1:off + 3])[0]
            qend = off + 5
            with self.lock:
                self.counts[name] = self.counts.get(name, 0) + 1
            if name == "drop.test":
                continue  # simulate a dead upstream
            question = data[12:qend]
            answers = b""
            n = 0
            if qtype == 1:
                n = 40 if name == "big.test" else 1
                for i in range(n):
                    answers += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34 + i % 200])
            hdr = struct.pack(">HHHHHH", qid, 0x8180, 1, n, 0, 0)
            self.sock.sendto(hdr + question + answers, addr)


# ---- harness ------------------------------------------------------------------------------

def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Harness:
    def __init__(self, jar):
        self.jar = str(jar)
        self.tmp = Path(tempfile.mkdtemp(prefix="netshield-smoke-"))
        self.conf = self.tmp / "netshield.conf"
        self.sock = self.tmp / "ctl.sock"
        self.port = free_port()
        self.upstream = FakeUpstream()
        self.upstream.start()
        self.proc = None
        self.log = None

    def write_conf(self, extra=""):
        self.conf.write_text(
            "listen_address=127.0.0.1\n"
            f"port={self.port}\n"
            "upstream_mode=UDP\n"
            f"upstream_primary=127.0.0.1:{self.upstream.port}\n"
            "upstream_secondary=\n"
            "fallback_udp=false\n"
            "sync_interval_hours=0\n"
            f"state_dir={self.tmp / 'state'}\n"
            f"log_dir={self.tmp / 'log'}\n"
            f"control_socket={self.sock}\n" + extra)

    def start(self):
        self.log = open(self.tmp / "daemon.out", "ab")
        self.proc = subprocess.Popen(
            ["java", "-Xmx128m", "-cp", self.jar, "com.psbdx.netshield.Daemon", "--config", str(self.conf)],
            stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("daemon exited early:\n" + (self.tmp / "daemon.out").read_text())
            if self.sock.exists():
                try:
                    if self.ctl("status")[0] == 0:
                        return
                except Exception:
                    pass
            time.sleep(0.2)
        raise RuntimeError("daemon did not come up:\n" + (self.tmp / "daemon.out").read_text())

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.log:
            self.log.close()
        return self.proc.returncode if self.proc else None

    def ctl(self, *args):
        r = subprocess.run(["java", "-cp", self.jar, "com.psbdx.netshield.Cli", "--socket", str(self.sock), *args],
                           capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout + r.stderr

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


def wait_for(fn, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.3)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jar", default=str(DEFAULT_JAR))
    ap.add_argument("--keep", action="store_true", help="keep the temp dir for inspection")
    args = ap.parse_args()
    if not Path(args.jar).exists():
        sys.exit(f"jar not found: {args.jar} (run linux/packaging/build-deb.sh first)")

    h = Harness(args.jar)
    try:
        run(h)
    except Exception as e:  # noqa: BLE001
        check(False, f"unexpected exception: {e!r}")
    finally:
        h.stop()
        if not args.keep:
            h.cleanup()
        else:
            print("kept", h.tmp)
    print(f"\n{checks} checks, {failures} failures")
    sys.exit(1 if failures else 0)


def run(h):
    hosts = h.tmp / "hosts.txt"
    hosts.write_text("# test list\n0.0.0.0 fromlist.test\n0.0.0.0 cdn.tracker.test\n")
    (h.tmp / "rules.conf").write_text(
        "block blocked.test\nallow ok.blocked.test\nmap nas.home 10.0.0.5\nmap v6.home fd00::5\n")
    (h.tmp / "sources.list").write_text(hosts.as_uri() + " Test list\n")
    (h.tmp / "trusted.list").write_text("trusted.blocked.test # trusted beats block\n")
    h.write_conf()

    print("start daemon")
    h.start()
    p = h.port

    print("blocking")
    r = udp_query(p, build_query("ads.blocked.test", 1))
    check(r["rcode"] == 0 and len(r["answers"]) == 1 and ip4(r["answers"][0]) == "0.0.0.0", "A for blocked domain -> 0.0.0.0")
    r = udp_query(p, build_query("ads.blocked.test", 28))
    check(len(r["answers"]) == 1 and r["answers"][0][1] == b"\x00" * 16, "AAAA for blocked domain -> ::")
    r = udp_query(p, build_query("ads.blocked.test", 16))
    check(r["rcode"] == 0 and r["answers"] == [], "TXT for blocked domain -> NODATA")
    check(h.upstream.count("ads.blocked.test") == 0, "blocked queries never reach upstream")

    print("allow / trusted / mapping")
    r = udp_query(p, build_query("ok.blocked.test", 1))
    check(len(r["answers"]) == 1 and ip4(r["answers"][0]) == "93.184.216.34", "allow rule overrides parent block")
    r = udp_query(p, build_query("trusted.blocked.test", 1))
    check(len(r["answers"]) == 1 and ip4(r["answers"][0]) == "93.184.216.34", "trusted domain bypasses block")
    r = udp_query(p, build_query("nas.home", 1))
    check(len(r["answers"]) == 1 and ip4(r["answers"][0]) == "10.0.0.5", "local mapping A")
    r = udp_query(p, build_query("nas.home", 28))
    check(r["answers"] == [] and r["rcode"] == 0, "IPv4 mapping + AAAA query -> NODATA")
    r = udp_query(p, build_query("v6.home", 28))
    check(len(r["answers"]) == 1 and r["answers"][0][1][-1] == 5, "local mapping AAAA")
    check(h.upstream.count("nas.home") == 0, "local records never reach upstream")

    print("forwarding + cache")
    r = udp_query(p, build_query("example.test", 1, qid=0x1111))
    check(r["id"] == 0x1111 and ip4(r["answers"][0]) == "93.184.216.34", "forwarded to upstream")
    r = udp_query(p, build_query("example.test", 1, qid=0x2222))
    check(r["id"] == 0x2222 and ip4(r["answers"][0]) == "93.184.216.34", "cached answer carries the new transaction id")
    check(h.upstream.count("example.test") == 1, "second query served from cache (upstream saw 1)")
    r = tcp_query(p, build_query("example.test", 1, qid=0x3333))
    check(r["id"] == 0x3333 and ip4(r["answers"][0]) == "93.184.216.34", "TCP query works")
    check(h.upstream.count("example.test") == 1, "TCP query also served from cache")

    print("large answers")
    r = udp_query(p, build_query("big.test", 1))
    check(r["tc"] and r["answers"] == [], "UDP answer >512B without EDNS is truncated (TC)")
    r = tcp_query(p, build_query("big.test", 1))
    check((not r["tc"]) and len(r["answers"]) == 40, "TCP retry returns the full answer")
    r = udp_query(p, build_query("big.test", 1, edns=4096))
    check((not r["tc"]) and len(r["answers"]) == 40, "UDP with EDNS 4096 returns the full answer")

    print("upstream failure")
    t0 = time.time()
    r = udp_query(p, build_query("drop.test", 1), timeout=10)
    check(r["rcode"] == 2, f"dead upstream -> SERVFAIL (after {time.time() - t0:.1f}s)")

    print("control socket")
    rc, out = h.ctl("status")
    check(rc == 0 and "listening:" in out and "blocked domains" in out, "status")
    rc, out = h.ctl("check", "a.blocked.test")
    check("BLOCKED by a block rule" in out, "check: blocked")
    rc, out = h.ctl("check", "nas.home")
    check("LOCAL mapping" in out, "check: mapping")
    rc, out = h.ctl("logs", "50")
    check("BLOCKED" in out and "ALLOWED" in out and "CACHED" in out and "LOCAL" in out, "logs show all statuses")

    print("pause / resume")
    rc, out = h.ctl("pause", "1m")
    check(rc == 0 and "paused" in out, "pause")
    r = udp_query(p, build_query("ads2.blocked.test", 1))
    check(len(r["answers"]) == 1 and ip4(r["answers"][0]) == "93.184.216.34", "blocked domain is forwarded while paused")
    check("PAUSED" in h.ctl("status")[1], "status shows PAUSED")
    h.ctl("resume")
    r = udp_query(p, build_query("ads3.blocked.test", 1))
    check(ip4(r["answers"][0]) == "0.0.0.0", "blocking restored after resume")

    print("downloaded blocklist (initial sync)")
    ok = wait_for(lambda: "2 from lists" in h.ctl("status")[1], 20)
    check(ok, "first-run sync downloaded the list automatically")
    r = udp_query(p, build_query("x.cdn.tracker.test", 1))
    check(ip4(r["answers"][0]) == "0.0.0.0", "domain from downloaded list is blocked (subdomain match)")
    rc, out = h.ctl("sync")
    check(rc == 0 and out.startswith("synced 1/1"), f"manual sync: {out.strip()}")

    print("reload")
    with open(h.tmp / "rules.conf", "a") as f:
        f.write("block newrule.test\n")
    h.write_conf("block_action=NXDOMAIN\n")
    rc, out = h.ctl("reload")
    check(rc == 0 and "reloaded" in out, f"reload: {out.strip()}")
    r = udp_query(p, build_query("newrule.test", 1))
    check(r["rcode"] == 3 and r["answers"] == [], "new rule + block_action=NXDOMAIN applied live")
    r = udp_query(p, build_query("fromlist.test", 1))
    check(r["rcode"] == 3, "downloaded list survives a reload")
    h.write_conf("upstream_mode=BOGUS\n")
    rc, out = h.ctl("reload")
    check("error" in out and "upstream_mode" in out, "bad config is rejected on reload")
    r = udp_query(p, build_query("newrule.test", 1))
    check(r["rcode"] == 3, "previous settings kept after failed reload")
    h.write_conf("block_action=NXDOMAIN\n")

    print("shutdown + restart")
    rc = h.stop()
    check(rc == 143 or rc == 0, f"clean exit on SIGTERM (rc={rc})")
    check(not h.sock.exists(), "control socket removed on shutdown")
    qlog = h.tmp / "log" / "queries.log"
    lines = qlog.read_text().splitlines() if qlog.exists() else []
    check(len(lines) > 10 and any("\tBLOCKED\t" in l for l in lines) and any("\tALLOWED\t" in l for l in lines),
          f"query log written to disk ({len(lines)} lines)")

    h.start()
    r = udp_query(h.port, build_query("fromlist.test", 1))
    check(r["rcode"] == 3, "cached blocklist active immediately after restart (no re-download)")
    check(h.ctl("status")[0] == 0, "status after restart")

    print("client policy")
    h.write_conf("block_action=NXDOMAIN\nblocked_clients=127.0.0.1\n")
    h.ctl("reload")
    r = udp_query(h.port, build_query("example2.test", 1))
    check(len(r["answers"]) == 1 and ip4(r["answers"][0]) == "0.0.0.0", "blocked client gets sinkholed")
    r = udp_query(h.port, build_query("trusted.blocked.test", 1))
    check(ip4(r["answers"][0]) == "93.184.216.34", "trusted domain works even for a blocked client")


if __name__ == "__main__":
    main()
