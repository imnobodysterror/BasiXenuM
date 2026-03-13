#!/usr/bin/env python3
import argparse
import datetime as dt
import itertools
import re
import shlex
import subprocess
import threading
import time
import sys
from pathlib import Path

from basixenum.report import detect_focus_labels, render_triage_report
from basixenum.vulns import analyze_services
from basixenum.runner import run_task
from basixenum.tasks.web import FfufTask
from basixenum.tasks.smb import NetexecSmbTask


VERSION = "0.3.1"

NMAP_LINE_RE = re.compile(r"^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", re.IGNORECASE)


def banner():
    print(r"""

██████╗  █████╗ ███████╗██╗██╗  ██╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗
██╔══██╗██╔══██╗██╔════╝██║╚██╗██╔╝██╔════╝████╗  ██║██║   ██║████╗ ████║
██████╔╝███████║███████╗██║ ╚███╔╝ █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
██╔══██╗██╔══██║╚════██║██║ ██╔██╗ ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
██████╔╝██║  ██║███████║██║██╔╝ ██╗███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝

BasiXenuM - Recon Wrapper / Orchestrator
Author: INBD
""")


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
        try:
            t = input("Target IP/FQDN: ").strip()
        except KeyboardInterrupt:
            print("\n[!] BasiXenuM interrupted by user.")
            sys.exit(0)

        if t:
            return t


def _prompt_mode(current: str | None) -> str:
    if current in ("fast", "full"):
        return current

    try:
        raw = input("Mode [fast/full] (default: fast): ").strip().lower()
    except KeyboardInterrupt:
        print("\n[!] BasiXenuM interrupted by user.")
        sys.exit(0)

    return raw if raw in ("fast", "full") else "fast"


def _prompt_save_txt() -> bool:
    try:
        raw = input("Save .txt log? [y/N]: ").strip().lower()
    except KeyboardInterrupt:
        print("\n[!] BasiXenuM interrupted by user.")
        sys.exit(0)

    return raw in ("y", "yes")


def _prompt_followups(current: bool = False) -> bool:
    if current:
        return True

    try:
        raw = input("Run follow-up recon tasks? [Y/n]: ").strip().lower()
    except KeyboardInterrupt:
        print("\n[!] BasiXenuM interrupted by user.")
        sys.exit(0)

    return raw not in ("n", "no")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="basixenum",
        description="BasiXenuM - baseline enumeration helper",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    enum_p = sub.add_parser("enum", help="Run baseline enumeration against a target")
    enum_p.add_argument("target", nargs="?", help="Target IP or hostname")
    enum_p.add_argument("-p", "--profile", default="default")
    enum_p.add_argument("-o", "--out", default="out")

    enum_p.add_argument(
        "--mode",
        choices=["fast", "full"],
        default=None,
    )

    enum_p.add_argument(
        "--nmap-args",
        default="-sS -sC -sV",
    )

    enum_p.add_argument(
        "--rustscan-ports",
        default="1-65535",
    )

    enum_p.add_argument(
        "--rustscan-args",
        default="",
    )

    enum_p.add_argument("--udp", action="store_true")
    enum_p.add_argument("--udp-top-ports", default="200")
    enum_p.add_argument("--dry-run", action="store_true")
    enum_p.add_argument(
        "--run-followups",
        action="store_true",
        help="Run automatic follow-up recon tasks based on detected attack surface",
    )

    sub.add_parser("version")

    return p


def run(cmd: list[str], dry_run: bool) -> int:
    pretty = " ".join(shlex.quote(x) for x in cmd)
    print(f"[cmd] {pretty}")

    if dry_run:
        return 0

    try:
        p = subprocess.run(cmd)
        return p.returncode
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled by user.")
        return 130


def parse_open_ports_from_nmap(nmap_file: Path) -> list[dict]:
    if not nmap_file.exists():
        return []

    results = []

    for line in nmap_file.read_text(errors="ignore").splitlines():
        m = NMAP_LINE_RE.match(line.strip())
        if not m:
            continue

        port, proto, service, rest = m.groups()
        results.append(
            {
                "port": int(port),
                "proto": proto.lower(),
                "service": service.strip(),
                "version": rest.strip(),
                "raw": f"{port}/{proto} open {service} {rest}".strip(),
            }
        )

    return results


def build_followup_tasks(
    target: str,
    outdir: Path,
    focus_labels: list[str],
) -> list:
    tasks = []

    if "WEB" in focus_labels:
        tasks.append(
            FfufTask(
                name="ffuf_web_dirs",
                category="WEB",
                command=[
                    "ffuf",
                    "-u", f"http://{target}/FUZZ",
                    "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt",
                    "-mc", "200,204,301,302,307,401,403",
                    "-of", "json",
                    "-o", str(outdir / "ffuf_web_dirs.json"),
                ],
                description="Directory bruteforce against detected web service",
            )
        )

    if "SMB" in focus_labels:
        tasks.append(
            NetexecSmbTask(
                name="netexec_smb_enum",
                category="SMB",
                command=["netexec", "smb", target],
                description="Basic SMB enumeration",
            )
        )

    return tasks


def format_followup_section(results: list) -> str:
    if not results:
        return "\nFOLLOW-UP RECON\n--------------\nNo automatic follow-up tasks were run.\n"

    lines = [
        "",
        "FOLLOW-UP RECON",
        "--------------",
    ]

    for result in results:
        cmd_pretty = " ".join(shlex.quote(x) for x in result.command)
        lines.append(f"[{result.name}] rc={result.returncode}")
        lines.append(f"Command: {cmd_pretty}")

        if result.findings:
            lines.append("Findings:")
            for finding in result.findings[:20]:
                lines.append(f"  - {finding}")
        else:
            lines.append("Findings: none parsed")

        if result.artifacts:
            lines.append("Artifacts:")
            for artifact in result.artifacts:
                lines.append(f"  - {artifact}")

        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


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

    oA = outdir / "nmap"
    nmap_cmd = ["nmap", "-sS", "-sC", "-sV", "-oA", str(oA), args.target]

    rc = run(nmap_cmd, args.dry_run)
    if rc != 0:
        print(f"[!] nmap exited with code {rc}")
        return rc

    nmap_txt = Path(str(oA) + ".nmap")
    port_entries = parse_open_ports_from_nmap(nmap_txt)

    service_analysis = analyze_services(port_entries)
    focus_labels = detect_focus_labels(port_entries)

    print(f"[focus] {', '.join(focus_labels) if focus_labels else 'none'}")

    followup_results = []
    if args.run_followups and not args.dry_run:
        tasks = build_followup_tasks(args.target, outdir, focus_labels)
        if tasks:
            print(f"[followups] running {len(tasks)} task(s)")
            followup_results = [run_task(task, outdir) for task in tasks]
        else:
            print("[followups] no matching tasks for detected surface")

    report_text = render_triage_report(
        target=args.target,
        mode=args.mode,
        outdir=outdir,
        port_entries=port_entries,
        scan_time=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        service_analysis=service_analysis,
    )

    report_text += format_followup_section(followup_results)

    report_path = outdir / "triage_report.txt"
    report_path.write_text(report_text, encoding="utf-8")

    print(f"\n[report] saved triage report to {report_path}")
    return 0


def main(argv=None) -> int:
    banner()
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
        args.run_followups = _prompt_followups(getattr(args, "run_followups", False))
        return cmd_enum(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] BasiXenuM interrupted.")
        sys.exit(0)
