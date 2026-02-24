# BasiXenuM (inbd- enum) — v0.1.6

Fast recon helper for Kali Linux.

---

## Usage

### Interactive mode (recommended)

Runs prompts for:

- profile name
- target
- mode (fast/full)
- optional UDP
- optional save log to txt

```bash
basixenum enum
Non-interactive flags (if supported in your CLI)
basixenum enum --mode fast --target 10.10.10.10 --profile thm
Modes
FAST

RustScan → port list

Nmap service + default scripts on discovered ports

Core Nmap style:

-sC -sV
-oA out/<profile>/<target>/<timestamp>/nmap
FULL

Everything in FAST plus:

-O --traceroute --reason

If no ports are specified, uses:

-p-

Optional UDP scan:

--udp --udp-top-ports <N>
Output Structure

Everything lands under:

out/<profile>/<target>/<timestamp>/

Typical files:

rustscan.txt (if rustscan ran)

nmap.nmap

nmap.gnmap

nmap.xml

optional: <target>.txt (log)

Example:

out/thm/10.81.107.101/2026-02-24_21-53-12/
  rustscan.txt
  nmap.nmap
  nmap.gnmap
  nmap.xml
  10.81.107.101.txt
Script Output

Open ports summary (parsed from .nmap)

Last ~40 lines preview (tail output)

Focus Radar signals:

Signal	Ports
WEB	80, 443, 8080, 8443
SMB	445
WINRM	5985, 5986
RDP	3389
DNS	53
LDAP	389, 636
KERBEROS	88
RPC	111, 135
NFS	2049
MAIL	25,110,143,587,993,995
Known Behavior / Gotchas
1) RustScan --no-nmap issue

Some RustScan versions reject:

--no-nmap

Planned fix:

rustscan -a <target> -p <ports> -- echo

If RustScan fails, fallback to Nmap-only scanning.

2) Logging disables spinner

Spinner is disabled during logging to avoid messy output.

3) HTTPS-only targets

Observed test case:

22 → OpenSSH 7.4

111 → rpcbind

443 → nginx (HTTPS required)

If only 443 exists, test HTTPS first.

Example Run

Target:

10.81.107.101

Found:

22 (OpenSSH 7.4)

111 (rpcbind)

443 (nginx HTTPS)

Roadmap

RustScan compatibility fix

Optional quick web enum hooks:

curl -I

whatweb

ffuf templates

License

inbd-0404
