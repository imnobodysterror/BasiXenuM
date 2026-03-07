BasiXenuM

Baseline enumeration helper for fast CTF / lab reconnaissance.

BasiXenuM automates the first stage of target analysis by combining:

RustScan (fast port discovery)

Nmap service detection

Automated triage reporting

The goal is simple:

Quickly understand the attack surface and identify where to start.

Designed mainly for:

TryHackMe

HackTheBox

CTF environments

penetration testing training labs

Features

Interactive scanning workflow

RustScan + Nmap integration

Automatic triage report generation

Focus Radar attack surface detection

Attack Priority suggestions

Likely Initial Attack Path logic

Web service triage

Per-service analysis guidance

The tool attempts to answer the first question in reconnaissance:

“Where should I start attacking first?”

Installation

Clone the repository:

git clone https://github.com/imnobodysterror/BasiXenuM
cd BasiXenuM

Install using pipx (recommended):

pipx install -e .

Verify installation:

basixenum version
Usage
Interactive Mode (recommended)

Run:

basixenum

The wizard will ask for:

Target IP / hostname

Scan mode (fast / full)

Optional logging

Then enumeration begins automatically.

Direct Mode

Run directly against a target:

basixenum enum 10.10.10.10

Example with options:

basixenum enum 10.10.10.10 --mode fast --profile thm
Scan Modes
FAST (default)

Workflow:

RustScan → discover open ports
Nmap → service detection + default scripts

Nmap flags used:

-sC -sV
FULL

Includes everything from FAST, plus:

-O
--traceroute
--reason

If ports were not discovered earlier:

-p-

Optional UDP scan:

--udp
--udp-top-ports <number>
Output Structure

Results are stored in:

out/<profile>/<target>/<timestamp>/

Example:

out/thm/10.113.137.78/20260307_012945/

Typical generated files:

rustscan.txt
nmap.nmap
nmap.gnmap
nmap.xml
triage_report.txt
<target>.txt   (optional log)
Triage Report

BasiXenuM generates a structured triage report including:

Target Information

Basic host and service overview.

Open Ports

Parsed Nmap results.

Service Summary

High-level explanation of exposed services.

Interesting Findings

Signals detected during enumeration.

Attack Priority

Suggested order of investigation.

Likely Initial Attack Path

Logical attack route based on discovered services.

Quick Wins

Immediate checks that often reveal vulnerabilities.

Web Triage

Prioritization and analysis of detected web services.

Possible Vulnerability Matches

Version-based leads requiring manual verification.

Service Analysis

Per-service analysis including:

possible vulnerabilities

misconfiguration checks

manual testing suggestions

why the service matters

Recommended Next Steps

Guided enumeration suggestions.

Focus Radar

Focus Radar highlights likely attack surfaces based on detected ports.

Signal	Ports
WEB	80,443,8080,8443,3128,3333
SMB	139,445
WINRM	5985,5986
RDP	3389
DNS	53
LDAP	389,636
KERBEROS	88
RPC	111,135
NFS	2049
MAIL	25,110,143,587,993,995
Known Behavior
RustScan Compatibility

Some RustScan versions reject:

--no-nmap

Planned workaround:

rustscan -a <target> -p <range> -- echo

If RustScan fails, BasiXenuM automatically falls back to Nmap-only scanning.

Logging

If logging is enabled during interactive mode:

Save [.txt log]? [y/N]

A log file is created in the scan directory containing:

command output

scan progress

execution logs

Example Detection

Target:

10.113.137.78

Detected services:

21  FTP (vsftpd)
22  SSH (OpenSSH)
139 SMB
445 SMB
3128 Squid proxy
3333 Apache web application

Report prioritization:

1. Web application (3333)
2. Proxy exposure (3128)
3. SMB enumeration
4. FTP anonymous access
5. SSH credential path
Roadmap

Planned improvements:

RustScan compatibility fix

optional quick web enumeration hooks

service fingerprint improvements

static vulnerability mapping

smarter service grouping



License

inbd-0404
