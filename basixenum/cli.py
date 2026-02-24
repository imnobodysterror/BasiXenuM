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

VERSION = "0.1.6"

# --- Focus Radar: port -> signal groups ---
FOCUS_MAP = {
    "WEB": {"ports": {80, 443, 8080, 8443, 8000, 8888}},
    "SMB": {"ports": {139, 445}},
    "WINRM": {"ports": {5985, 5986}},
    "RDP": {"ports": {3389}},
    "DNS": {"ports": {53}},
    "LDAP": {"ports": {389, 636}},
    "KERBEROS": {"ports": {88}},
    "RPC": {"ports": {111, 135}},
    "NFS": {"ports": {2049}},
    "MAIL": {"ports": {25, 110, 143, 465, 587, 993, 995}},
}

# Nmap normal output line: "80/tcp open http Apache ..."
NMAP_LINE_RE = re.compile(r"^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", re.IGNORECASE)

# RustScan output varies by version.
# Matches any "... 80/tcp ..." regardless of wording.
RUSTSCAN_PORT_RE = re.compile(r"\b(\d{1,5})/tcp\b", re.IGNORECASE)

# Extract "80/tcp" from the string lines we store like "80/tcp open http ..."
PORTPROTO_RE = re.compile(r"^(\d{1,5})/(tcp|udp)\b", re.IGNORECASE)


class Tee:
    """Write to multiple streams (stdout + file)."""

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
        default=None,  # prompt if missing
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


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s.strip())[:80] or "unknown"


def timestamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


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


def parse_open_ports_from_nmap(nmap_file: Path) -> list[str]:
    if not nmap_file.exists():
        return []
    out: list[str] = []
    for line in nmap_file.read_text(errors="ignore").splitlines():
        m = NMAP_LINE_RE.match(line.strip())
        if m:
            port, proto, service, rest = m.groups()
            rest = rest.strip()
            out.append(f"{port}/{proto} open {service}" + (f" {rest}" if rest else ""))
    return out


def extract_port_ints(port_lines: list[str]) -> list[int]:
    s = set()
    for ln in port_lines:
        m = PORTPROTO_RE.match(ln.strip())
        if not m:
            continue
        p = int(m.group(1))
        if 1 <= p <= 65535:
            s.add(p)
    return sorted(s)


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


def cmd_version() -> int:
    print(f"basixenum {VERSION}")
    return 0


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


def print_focus_radar(open_ports_int: list[int]) -> None:
    detected = []
    portset = set(open_ports_int)

    for label, meta in FOCUS_MAP.items():
        if portset & meta["ports"]:
            detected.append(label)

    ad_needed = {"KERBEROS", "LDAP", "SMB", "DNS"}
    if ad_needed.issubset(set(detected)):
        detected.append("ACTIVE_DIRECTORY_LIKELY")

    print("\n=== Focus Radar ===")
    if detected:
        for d in detected:
            print(f"[+] {d}")
    else:
        print("[-] No strong signals from common port groups.")


def cmd_enum(args: argparse.Namespace) -> int:
    prof = safe_name(args.profile)
    tgt_folder = safe_name(args.target)
    base = Path(args.out).expanduser().resolve()

    outdir = base / prof / tgt_folder / timestamp()
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"[BasiXenuM] profile={prof} target={args.target} mode={args.mode}")
    print(f"[out] {outdir}")

    # Optional log file: tee stdout to <target>.txt inside outdir
    log_fh = None
    old_stdout = None
    if getattr(args, "save_txt", False) and not args.dry_run:
        log_path = outdir / f"{safe_name(args.target)}.txt"
        log_fh = log_path.open("w", encoding="utf-8", errors="ignore")
        old_stdout = sys.stdout
        sys.stdout = Tee(sys.stdout, log_fh)
        print(f"[log] saving output to {log_path}")

    # If logging, don't spam the file with spinner frames
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
        print("[dry-run] skipping parsing/preview (no output files created).")
        return _cleanup_and_return(0)

    nmap_txt = Path(str(oA) + ".nmap")
    ports = parse_open_ports_from_nmap(nmap_txt)

    print("\nOpen ports found:")
    if ports:
        for p in ports:
            print(f"  - {p}")
    else:
        print("  No open ports found.")

    open_ports_int = ports_for_nmap[:] if ports_for_nmap else extract_port_ints(ports)
    print_focus_radar(open_ports_int)

    if args.mode == "full" and args.udp:
        udp_oA = outdir / "nmap_udp"
        udp_cmd = ["nmap", "-sU", "--top-ports", str(args.udp_top_ports), "-sV", "-oA", str(udp_oA), args.target]
        rc2 = run(udp_cmd, args.dry_run, show_spinner=not no_spinner)
        if rc2 != 0:
            print(f"[!] UDP nmap exited with code {rc2}")
        else:
            udp_txt = Path(str(udp_oA) + ".nmap")
            udp_ports = parse_open_ports_from_nmap(udp_txt)
            print("\nUDP open ports found:")
            if udp_ports:
                for up in udp_ports:
                    print(f"  - {up}")
            else:
                print("  No UDP open ports found (in scanned top ports).")

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

    # Normalize argv so these work:
    # - basixenum
    # - basixenum <target>
    # - basixenum enum <target> --mode full
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
