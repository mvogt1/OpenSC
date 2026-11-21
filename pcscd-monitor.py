#!/usr/bin/env python3
"""Measure the PC/SC traffic of one client run from a pcscd debug log.

pcscd must run with debug output written to a file, for example:

    pcscd -afd > /tmp/pcscd.log 2>&1

Every pcscd log line starts with the time in microseconds since the
previous log line.  This script adds up those deltas, so the times come
from pcscd itself: they work for a pcscd on another host and do not
depend on when the log file is flushed.

A "run" starts with the first "Authorized PC/SC client" line while no
run is open.  It ends when every client that did an SCardConnect() during
the run has gone away again ("Client die"), or when pcscd shuts down.
Contexts that stay open after that (for example a background process that
only watches the readers) are listed but do not hold the run open.  The reported time goes from
"Authorized PC/SC client" to the last SCardDisconnect() of the run.

Modes:
  follow (default)  skip what is already in the log, wait for the next
                    run, print its statistics and exit
  --exec CMD        like follow, but start CMD after the log position is
                    taken, e.g. a pkcs11-tool --list-objects call
  --wait-exit       with --exec: the run lasts until CMD exits, for
                    long-running programs that connect more than once
  --analyze         read the whole log once and report every run in it
"""

import argparse
import os
import re
import shlex
import subprocess
import sys
import time
from collections import Counter

DEFAULT_LOG = "/tmp/pcscd.log"

# "00000065 ../src/winscard_svc.c:383:ContextThread() Received command: ..."
RE_LINE = re.compile(r"^(\d{8}) (.*)$")
RE_AUTH = re.compile(r"ContextThread\(\) Authorized PC/SC client$")
RE_STARTED = re.compile(r"Thread is started: dwClientID=(\d+)")
RE_DIE = re.compile(r"ContextThread\(\) Client die: (\d+)")
RE_CMD = re.compile(r"Received command: (\S+) from client (\d+)")
RE_DISCONNECT = re.compile(r"SCardDisconnect\(\)")
RE_DISCONNECT_DONE = re.compile(r"ContextThread\(\) DISCONNECT for client (\d+)")
RE_CONNECT_DONE = re.compile(r"ContextThread\(\) CONNECT for client (\d+)")
RE_SHUTDOWN = re.compile(r"Preparing for suicide|at_exit\(\)")

# pcscd caps the delta at 99999999 us (about 100 s)
DELTA_CAP = 99999999


class Run:
    """Statistics for one run (from the first client to the last one)."""

    def __init__(self, number, clock_us):
        self.number = number
        self.start_us = clock_us
        self.last_disconnect_us = None
        self.end_us = None
        self.clients = set()
        self.active = set()
        self.connecting = set()
        self.commands = Counter()
        self.per_client = {}
        self.reason = None
        self.connects = 0
        self.disconnects = 0
        self.capped = False

    @property
    def done(self):
        return self.end_us is not None


class Parser:
    """Feeds log lines and collects runs."""

    def __init__(self, on_run_done=None):
        self.clock_us = 0
        self.run = None
        self.runs = []
        self.on_run_done = on_run_done
        self.pending_auth = False
        self.bad_lines = 0
        # keep the run open until finish(force=True), see --wait-exit
        self.hold = False

    def feed(self, line):
        m = RE_LINE.match(line.rstrip("\n"))
        if not m:
            # APDU dumps and similar continuation lines have no timestamp
            self.bad_lines += 1
            return
        delta = int(m.group(1))
        text = m.group(2)
        self.clock_us += delta
        run = self.run
        if run is not None and delta >= DELTA_CAP:
            run.capped = True

        if RE_AUTH.search(text):
            if run is None:
                run = self.run = Run(len(self.runs) + 1, self.clock_us)
            # the client id follows in the next "Thread is started" line
            self.pending_auth = True
            return

        if run is None:
            return

        m = RE_STARTED.search(text)
        if m and self.pending_auth:
            self.pending_auth = False
            cid = m.group(1)
            run.clients.add(cid)
            run.active.add(cid)
            return

        m = RE_CMD.search(text)
        if m:
            cid = m.group(2)
            if cid in run.clients:
                run.commands[m.group(1)] += 1
                run.per_client.setdefault(cid, Counter())[m.group(1)] += 1
            return

        m = RE_CONNECT_DONE.search(text)
        if m:
            if m.group(1) in run.clients:
                run.connects += 1
                run.connecting.add(m.group(1))
            return

        m = RE_DISCONNECT_DONE.search(text)
        if m:
            run.disconnects += 1
            run.last_disconnect_us = self.clock_us
            return

        if RE_DISCONNECT.search(text):
            run.last_disconnect_us = self.clock_us
            return

        m = RE_DIE.search(text)
        if m:
            run.active.discard(m.group(1))
            if not run.active:
                self.finish("all clients gone")
            elif run.connecting and not (run.connecting & run.active):
                self.finish("all clients with SCardConnect gone")
            return

        if RE_SHUTDOWN.search(text):
            self.finish("pcscd shutdown")

    def finish(self, reason, force=False):
        run = self.run
        if run is None or (self.hold and not force):
            return
        run.end_us = self.clock_us
        run.reason = reason
        self.runs.append(run)
        self.run = None
        self.pending_auth = False
        if self.on_run_done:
            self.on_run_done(run)


def fmt_ms(us):
    return "%.3f ms" % (us / 1000.0)


def report(run, show_all, per_client=False, out=sys.stdout):
    cmd = {k: v for k, v in run.commands.items() if k.startswith("CMD_")}
    other = {k: v for k, v in run.commands.items() if not k.startswith("CMD_")}
    total_cmd = sum(cmd.values())
    total_all = sum(run.commands.values())

    p = lambda *a: print(*a, file=out)
    p("=== run %d ===" % run.number)
    p("clients:                 %s" % ", ".join(sorted(run.clients, key=int)))
    if run.active:
        p("still open at the end:   %s (not waited for)"
          % ", ".join(sorted(run.active, key=int)))
    p("run ended by:            %s" % run.reason)
    p("SCardConnect calls:      %d" % run.connects)
    p("SCardDisconnect calls:   %d" % run.disconnects)
    p("CMD_* calls:")
    for name, n in sorted(cmd.items(), key=lambda kv: (-kv[1], kv[0])):
        p("  %-40s %6d" % (name, n))
    p("  %-40s %6d" % ("total CMD_*", total_cmd))
    if show_all:
        p("other calls:")
        for name, n in sorted(other.items(), key=lambda kv: (-kv[1], kv[0])):
            p("  %-40s %6d" % (name, n))
    p("all calls (round trips): %d" % total_all)
    if per_client:
        for cid in sorted(run.per_client, key=int):
            c = run.per_client[cid]
            p("client %s: %d calls, %d CMD_*" % (
                cid, sum(c.values()),
                sum(v for k, v in c.items() if k.startswith("CMD_"))))
            for name, n in sorted(c.items(), key=lambda kv: (-kv[1], kv[0])):
                p("  %-40s %6d" % (name, n))
    if run.last_disconnect_us is not None:
        p("time Authorized PC/SC client -> last SCardDisconnect: %s"
          % fmt_ms(run.last_disconnect_us - run.start_us))
    else:
        p("time: no SCardDisconnect seen in this run")
    p("time until the end of the run:                      %s"
      % fmt_ms(run.end_us - run.start_us))
    if run.capped:
        p("warning: a log delta hit the pcscd cap of 100 s, times are too low")
    out.flush()


def open_log(path):
    try:
        return open(path, "r", errors="replace")
    except OSError as e:
        sys.exit("%s: cannot open %s: %s" % (sys.argv[0], path, e))


def analyze(args):
    parser = Parser()
    with open_log(args.file) as f:
        for line in f:
            parser.feed(line)
    parser.finish("end of log file")
    if not parser.runs:
        print("no run found in %s" % args.file)
        return 1
    for run in parser.runs:
        report(run, args.all, args.per_client)
    return 0


def follow(args):
    done = []
    parser = Parser(on_run_done=done.append)
    parser.hold = args.wait_exit

    f = open_log(args.file)
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino

    proc = None
    if args.exec:
        cmd = shlex.split(args.exec)
        print("running: %s" % args.exec, file=sys.stderr)
        t0 = time.monotonic()
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL
                                if args.quiet else None)
    else:
        print("waiting for a PC/SC client in %s (Ctrl-C to stop) ..."
              % args.file, file=sys.stderr)

    buf = ""
    idle_since = time.monotonic()
    wall = None
    try:
        while True:
            chunk = f.read()
            if chunk:
                idle_since = time.monotonic()
                buf += chunk
                lines = buf.split("\n")
                buf = lines.pop()
                for line in lines:
                    parser.feed(line)
                if done:
                    break
                continue

            # nothing new for a while after the last disconnect: the run
            # is over even if some client keeps its context open
            if not args.wait_exit and parser.run is not None \
                    and parser.run.last_disconnect_us is not None \
                    and time.monotonic() - idle_since > args.idle:
                parser.finish("idle for %g s after SCardDisconnect" % args.idle)
                break

            if proc is not None and wall is None and proc.poll() is not None:
                wall = time.monotonic() - t0
            # --wait-exit: the command is gone and pcscd has written the rest
            if args.wait_exit and wall is not None and parser.run is not None \
                    and time.monotonic() - idle_since > 0.5:
                parser.finish("command exited", force=True)
                break
            if proc is not None and wall is not None and parser.run is None \
                    and time.monotonic() - idle_since > args.timeout:
                print("command finished but no complete run was seen in the log",
                      file=sys.stderr)
                return 1

            # log rotated or truncated: start reading the new file
            try:
                st = os.stat(args.file)
                if st.st_ino != inode or st.st_size < f.tell():
                    f.close()
                    f = open_log(args.file)
                    inode = os.fstat(f.fileno()).st_ino
            except FileNotFoundError:
                pass
            time.sleep(0.05)
    except KeyboardInterrupt:
        if parser.run is not None:
            print("\ninterrupted, the run was not finished", file=sys.stderr)
        return 130
    finally:
        f.close()

    if proc is not None:
        rc = proc.wait()
        if wall is None:
            wall = time.monotonic() - t0
        if rc != 0:
            print("warning: command exited with %d" % rc, file=sys.stderr)

    report(done[0], args.all, args.per_client)
    if wall is not None:
        print("wall clock of the command:                          %.3f ms"
              % (wall * 1000.0))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        epilog=__doc__.split("\n", 1)[1] + """
examples:
  # wait for the next run, start pkcs11-tool in another shell
  %(prog)s -f /tmp/pcscd.log

  # start pkcs11-tool itself
  %(prog)s -q -e "./src/tools/pkcs11-tool -O --module ./src/pkcs11/.libs/opensc-pkcs11.so"

  # a long-running program, counted until it exits
  %(prog)s -w -e "./p11loop.py ./src/pkcs11/.libs/opensc-pkcs11.so 150"

  # report all runs already in the log
  %(prog)s --analyze
""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-f", "--file", default=DEFAULT_LOG,
                    help="pcscd log file to monitor (default: %(default)s)")
    ap.add_argument("-e", "--exec", metavar="CMD",
                    help="command to start after the log position is taken")
    ap.add_argument("-w", "--wait-exit", action="store_true",
                    help="with --exec: one run from the first client until "
                         "the command exits")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="discard the stdout of the --exec command")
    ap.add_argument("-a", "--analyze", action="store_true",
                    help="report all runs in the whole log and exit")
    ap.add_argument("--all", action="store_true",
                    help="also list the commands without CMD_ prefix "
                         "(CONNECT, TRANSMIT, ...)")
    ap.add_argument("-c", "--per-client", action="store_true",
                    help="also list the calls of each client context")
    ap.add_argument("-i", "--idle", type=float, default=3.0,
                    help="follow mode: end the run when the log is quiet this "
                         "many seconds after an SCardDisconnect "
                         "(default: %(default)s)")
    ap.add_argument("-t", "--timeout", type=float, default=5.0,
                    help="with --exec: seconds to wait for the log after the "
                         "command ended (default: %(default)s)")
    args = ap.parse_args()

    if args.wait_exit and not args.exec:
        ap.error("--wait-exit needs --exec")
    if args.analyze:
        if args.exec:
            ap.error("--analyze and --exec cannot be used together")
        return analyze(args)
    return follow(args)


if __name__ == "__main__":
    sys.exit(main())
