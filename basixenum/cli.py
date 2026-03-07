#!/usr/bin/env python3
import argparse
import datetime as dt
import itertools
import re
import shlex
import shutil
import subprocess
import threading
import time
import sys
from pathlib import Path

from basixenum.report import detect_focus_labels, render_triage_report
from basixenum.vulns import analyze_services

VERSION = "0.2.3"

NMAP_LINE_RE = re.compile(r"^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", re.IGNORECASE)
RUSTSCAN_PORT_RE = re.compile(r"\b(\d{1,5})/tcp\b", re.IGNORECASE)


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)
            s.flush()

    def flush(self):
        for s in self.streams:
            s.flush()


def _spinner(label: str, stop_event: threading.Event) -> None:
    for ch in itertools.cycle("|/-\\"):
        if stop_event.is_set():
            break
        print(f"\r{label} {ch}", end="", flush=True)
        time.sleep(0.12)
    print("\r" + " " * (len(label) + 2) + "\r", end="", flush=True)


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s.strip())[:80] or "unknown"


def timestamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def _prompt_target(current: str | None) -> str:
    if current and current.strip():
        return current.strip()
    while True:
        t = input("Target IP/FQDN: ").strip()
        if t:
            return t


def _prompt_mode(current: str | None) -> str:
    if current in ("fast", "full"):
        return current
    raw = input("Mode [fast/full] (default: fast): ").strip().lower()
    return raw if raw in ("fast", "full") else "fast"


def _prompt_save_txt() -> bool:
    raw = input("Save .txt log? [y/N]: ").strip().lower()
    return raw in ("y", "yes")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="basixenum",
        description="BasiXenuM - baseline enumeration helper",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    enum_p = sub.add_parser("enum", help="Run baseline enumeration against a target")
    enum_p.add_argument("target", nargs="?", help="Target IP or hostname (optional: will prompt)")
    enum_p.add_argument("-p", "--profile", default="default", help="Profile name (folder grouping)")
    enum_p.add_argument("-o", "--out", default="out", help="Output base directory")

    enum_p.add_argument(
        "--mode",
        choices=["fast", "full"],
        default=None,
        help="fast: baseline. full: all-ports + OS + traceroute + reasons",
    )

    enum_p.add_argument(
        "--nmap-args",
        default="-sS -sC -sV",
        help="Extra nmap args (default: -sS -sC -sV)",
    )

    enum_p.add_argument(
        "--rustscan-ports",
        default="1-65535",
        help="RustScan port scope. Use range like 1-65535 or list like 22,80,443 (default: 1-65535)",
    )

    enum_p.add_argument(
        "--rustscan-args",
        default="",
        help='Extra rustscan args (example: "-b 2000 --ulimit 5000")',
    )

    enum_p.add_argument("--udp", action="store_true", help="In full mode, also run a UDP top-ports scan")
    enum_p.add_argument("--udp-top-ports", default="200", help="UDP top ports to scan in full mode (default: 200)")
    enum_p.add_argument("--dry-run", action="store_true", help="Print actions, do not execute scans")

    sub.add_parser("version", help="Print version")
    return p


def run(cmd: list[str], dry_run: bool, cwd: Path | None = None, show_spinner: bool = True) -> int:
    pretty = " ".join(shlex.quote(x) for x in cmd)
    print(f"[cmd] {pretty}")
    if dry_run:
        return 0

    stop = threading.Event()
    t = None
    if show_spinner:
        t = threading.Thread(target=_spinner, args=("running", stop), daemon=True)
        t.start()

    try:
        p = subprocess.run(cmd, cwd=str(cwd) if cwd else None)
        return p.returncode
    except KeyboardInterrupt:
        print("\n[!] cancelled by user (Ctrl+C)")
        return 130
    finally:
        if show_spinner:
            stop.set()
            if t:
                t.join(timeout=1)


def run_capture(cmd: list[str], dry_run: bool, cwd: Path | None = None, show_spinner: bool = True) -> tuple[int, str]:
    pretty = " ".join(shlex.quote(x) for x in cmd)
    print(f"[cmd] {pretty}")
    if dry_run:
        return 0, ""

    stop = threading.Event()
    t = None
    if show_spinner:
        t = threading.Thread(target=_spinner, args=("running", stop), daemon=True)
        t.start()

    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            errors="ignore",
        )
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out
    except KeyboardInterrupt:
        print("\n[!] cancelled by user (Ctrl+C)")
        return 130, ""
    finally:
        if show_spinner:
            stop.set()
            if t:
                t.join(timeout=1)


def parse_open_ports_from_nmap(nmap_file: Path) -> list[dict]:
    if not nmap_file.exists():
        return []

    results = []
    for line in nmap_file.read_text(errors="ignore").splitlines():
        m = NMAP_LINE_RE.match(line.strip())
        if not m:
            continue

        port, proto, service, rest = m.groups()
        rest = rest.strip()

        # Clean Nmap --reason column noise in normal output, e.g.
        # 21/tcp open ftp syn-ack ttl 62 vsftpd 3.0.5
        rest = re.sub(r"^(syn-ack|reset|no-response)\s+ttl\s+\d+\s*", "", rest, flags=re.IGNORECASE)
        rest = re.sub(r"^(syn-ack|reset|no-response)\s*", "", rest, flags=re.IGNORECASE)

        results.append(
            {
                "port": int(port),
                "proto": proto.lower(),
                "service": service.strip(),
                "version": rest,
                "raw": f"{port}/{proto} open {service}" + (f" {rest}" if rest else ""),
            }
        )
    return results


def parse_rustscan_ports(output: str) -> list[int]:
    ports = set()

    for m in RUSTSCAN_PORT_RE.finditer(output):
        p = int(m.group(1))
        if 1 <= p <= 65535:
            ports.add(p)

    for line in output.splitlines():
        if "," in line:
            for token in line.split(","):
                token = token.strip()
                if token.isdigit():
                    p = int(token)
                    if 1 <= p <= 65535:
                        ports.add(p)

    return sorted(ports)


def build_nmap_args(mode: str, base_args: str) -> list[str]:
    args = shlex.split(base_args) if base_args else []
    if mode == "full":
        for flag in ["-O", "--traceroute", "--reason"]:
            if flag not in args:
                args.append(flag)
    return args


def _is_comma_list(s: str) -> bool:
    return bool(re.fullmatch(r"\s*\d{1,5}(\s*,\s*\d{1,5})+\s*", s or ""))


def _is_range(s: str) -> bool:
    return bool(re.fullmatch(r"\s*\d{1,5}\s*-\s*\d{1,5}\s*", s or ""))


def build_rustscan_cmd(target: str, scope: str, extra_args: str) -> list[str]:
    rs_extra = shlex.split(extra_args) if extra_args else []
    scope = (scope or "").strip()

    if _is_range(scope):
        return ["rustscan", "-a", target, "--range", scope, "-g", *rs_extra]
    if _is_comma_list(scope):
        return ["rustscan", "-a", target, "-p", scope.replace(" ", ""), "-g", *rs_extra]

    return ["rustscan", "-a", target, "--range", scope or "1-65535", "-g", *rs_extra]


def cmd_version() -> int:
    print(f"basixenum {VERSION}")
    return 0


def cmd_enum(args: argparse.Namespace) -> int:
    prof = safe_name(args.profile)
    tgt_folder = safe_name(args.target)
    base = Path(args.out).expanduser().resolve()

    outdir = base / prof / tgt_folder / timestamp()
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"[BasiXenuM] profile={prof} target={args.target} mode={args.mode}")
    print(f"[out] {outdir}")

    log_fh = None
    old_stdout = None
    if getattr(args, "save_txt", False) and not args.dry_run:
        log_path = outdir / f"{safe_name(args.target)}.txt"
        log_fh = log_path.open("w", encoding="utf-8", errors="ignore")
        old_stdout = sys.stdout
        sys.stdout = Tee(sys.stdout, log_fh)
        print(f"[log] saving output to {log_path}")

    no_spinner = bool(getattr(args, "save_txt", False))

    def _cleanup_and_return(code: int) -> int:
        if old_stdout is not None:
            sys.stdout = old_stdout
        if log_fh is not None:
            log_fh.close()
        return code

    rustscan_path = shutil.which("rustscan")
    ports_for_nmap: list[int] = []

    if rustscan_path:
        rs_log = outdir / "rustscan.txt"
        rs_cmd = build_rustscan_cmd(args.target, args.rustscan_ports, args.rustscan_args)

        rc_rs, rs_out = run_capture(rs_cmd, args.dry_run, show_spinner=not no_spinner)
        if not args.dry_run:
            rs_log.write_text(rs_out, errors="ignore")

        if rc_rs != 0:
            print(f"[!] rustscan exited with code {rc_rs}. Falling back to nmap.")
        else:
            ports_for_nmap = parse_rustscan_ports(rs_out)
            if ports_for_nmap:
                print(f"[rustscan] open tcp ports: {','.join(map(str, ports_for_nmap))}")
            else:
                print("[rustscan] no open tcp ports discovered (or rustscan output changed).")
    else:
        print("[i] rustscan not found; using nmap only.")

    oA = outdir / "nmap"
    nmap_args = build_nmap_args(args.mode, args.nmap_args)
    user_specified_ports = ("-p" in nmap_args) or ("-p-" in nmap_args)

    if ports_for_nmap:
        nmap_cmd = ["nmap", *nmap_args, "-p", ",".join(map(str, ports_for_nmap)), "-oA", str(oA), args.target]
    else:
        if args.mode == "full" and not user_specified_ports:
            nmap_cmd = ["nmap", *nmap_args, "-p-", "-oA", str(oA), args.target]
        else:
            nmap_cmd = ["nmap", *nmap_args, "-oA", str(oA), args.target]

    rc = run(nmap_cmd, args.dry_run, show_spinner=not no_spinner)
    if rc != 0:
        print(f"[!] nmap exited with code {rc}")
        return _cleanup_and_return(rc)

    if args.dry_run:
        print("[dry-run] skipping parsing/report generation (no output files created).")
        return _cleanup_and_return(0)

    nmap_txt = Path(str(oA) + ".nmap")
    port_entries = parse_open_ports_from_nmap(nmap_txt)
    service_analysis = analyze_services(port_entries)

    print("\nOpen ports found:")
    if port_entries:
        for entry in port_entries:
            print(f"  - {entry['raw']}")
    else:
        print("  No open ports found.")

    focus_labels = detect_focus_labels(port_entries)

    print("\n=== Focus Radar ===")
    if focus_labels:
        for item in focus_labels:
            print(f"[+] {item}")
    else:
        print("[-] No strong signals from common port groups.")

    if args.mode == "full" and args.udp:
        udp_oA = outdir / "nmap_udp"
        udp_cmd = ["nmap", "-sU", "--top-ports", str(args.udp_top_ports), "-sV", "-oA", str(udp_oA), args.target]
        rc2 = run(udp_cmd, args.dry_run, show_spinner=not no_spinner)
        if rc2 != 0:
            print(f"[!] UDP nmap exited with code {rc2}")
        else:
            udp_txt = Path(str(udp_oA) + ".nmap")
            udp_entries = parse_open_ports_from_nmap(udp_txt)
            print("\nUDP open ports found:")
            if udp_entries:
                for entry in udp_entries:
                    print(f"  - {entry['raw']}")
            else:
                print("  No UDP open ports found (in scanned top ports).")

    report_text = render_triage_report(
        target=args.target,
        mode=args.mode,
        outdir=outdir,
        port_entries=port_entries,
        scan_time=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        service_analysis=service_analysis,
    )

    report_path = outdir / "triage_report.txt"
    report_path.write_text(report_text, encoding="utf-8")
    print(f"\n[report] saved triage report to {report_path}")

    print("\n--- triage report preview ---")
    print(report_text)
    print("--- end triage report ---")

    if nmap_txt.exists():
        lines = nmap_txt.read_text(errors="ignore").splitlines()
        tail = lines[-40:] if len(lines) > 40 else lines
        print("\n--- nmap preview (tail) ---")
        for ln in tail:
            print(ln)
        print("--- end preview ---")

    return _cleanup_and_return(0)


def main(argv=None) -> int:
    parser = build_parser()

    if argv is None:
        argv = sys.argv[1:]

    if len(argv) == 0:
        argv = ["enum"]
    elif argv and argv[0] not in ("enum", "version", "-h", "--help"):
        argv = ["enum", *argv]

    args = parser.parse_args(argv)

    if args.cmd == "version":
        return cmd_version()

    if args.cmd == "enum":
        args.target = _prompt_target(getattr(args, "target", None))
        args.mode = _prompt_mode(getattr(args, "mode", None))
        args.save_txt = _prompt_save_txt()
        return cmd_enum(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
