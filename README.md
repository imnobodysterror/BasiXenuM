BasiXenuM

Baseline enumeration helper for fast room/CTF reconnaissance.

Usage
Interactive mode (recommended)
basixenum

Starts the interactive wizard:

asks for Target (IP / FQDN)

asks for mode (fast / full)

optional txt logging

runs enumeration automatically

Direct enum command
basixenum enum
Non-interactive flags (if supported)
basixenum enum --mode fast --target 10.10.10.10 --profile thm
Modes
FAST

Workflow:

RustScan → discover open ports

Nmap service detection + default scripts on discovered ports

Nmap defaults:

-sC -sV
-oA out/<profile>/<target>/<timestamp>/nmap
FULL

Everything in FAST, plus:

-O --traceroute --reason

If no ports are specified:

-p-

Optional UDP scan:

--udp --udp-top-ports <N>
Output Structure

Results are saved to:

out/<profile>/<target>/<timestamp>/

Typical files:

rustscan.txt        # if rustscan ran
nmap.nmap
nmap.gnmap
nmap.xml
<target>.txt        # optional log file

Example:

out/thm/10.81.107.101/2026-02-24_21-53-12/
  rustscan.txt
  nmap.nmap
  nmap.gnmap
  nmap.xml
  10.81.107.101.txt
Script Output

The tool displays:

Open ports summary (parsed from .nmap)

Last ~40 lines preview (tail output)

Focus Radar signals

Focus Radar
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
MAIL	25, 110, 143, 587, 993, 995
Known Behavior / Gotchas
1) RustScan --no-nmap issue

Some RustScan versions reject:

--no-nmap

Planned fix:

rustscan -a <target> -p <ports> -- echo

If RustScan fails, BasiXenuM falls back to Nmap-only scanning.

2) Logging disables spinner

Spinner output is disabled while logging to avoid messy terminal output.

3) HTTPS-only targets

Example observed:

22 → OpenSSH 7.4

111 → rpcbind

443 → nginx (HTTPS required)

If only port 443 is open, test HTTPS first.

Example Run

Target:

10.81.107.101

Detected:

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
