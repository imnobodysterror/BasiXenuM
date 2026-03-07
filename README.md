BasiXenuM

<<<<<<< HEAD
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
=======
Baseline enumeration helper for fast CTF / lab reconnaissance.

BasiXenuM automates the first stage of target analysis by combining:

RustScan (fast port discovery)

Nmap service detection

automatic triage reporting

The goal is simple:
quickly understand the attack surface and identify where to start.

Features

Interactive scanning workflow

RustScan + Nmap integration

Automatic triage report generation

Focus Radar attack surface detection

Attack Priority suggestion

Likely Initial Attack Path logic

Web surface triage

Service-level analysis guidance

Designed primarily for:

TryHackMe

HackTheBox

CTF machines

training labs

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
basixenum

Wizard will ask for:

Target IP / hostname

Scan mode (fast / full)

Optional logging

Direct Mode
basixenum enum 10.10.10.10
Example With Flags
basixenum enum 10.10.10.10 --mode fast --profile thm
Scan Modes
FAST (default)

Workflow:

RustScan → discover open ports
Nmap → service detection + default scripts

Nmap flags:
>>>>>>> b95509d (Add triage report intelligence and service analysis)

-sC -sV
FULL

<<<<<<< HEAD
Everything in FAST, plus:
=======
Includes everything from FAST plus:
>>>>>>> b95509d (Add triage report intelligence and service analysis)

-O
--traceroute
--reason

<<<<<<< HEAD
If no ports are specified:
=======
If ports were not discovered first:
>>>>>>> b95509d (Add triage report intelligence and service analysis)

-p-

Optional UDP scan:

--udp
--udp-top-ports <n>
Output Structure

<<<<<<< HEAD
Results are saved to:

out/<profile>/<target>/<timestamp>/

Typical files:

rustscan.txt        # if rustscan ran
nmap.nmap
nmap.gnmap
nmap.xml
<target>.txt        # optional log file

=======
Results are stored in:

out/<profile>/<target>/<timestamp>/

>>>>>>> b95509d (Add triage report intelligence and service analysis)
Example:

out/thm/10.81.107.101/20260307_012945/

<<<<<<< HEAD
The tool displays:

Open ports summary (parsed from .nmap)
=======
Files generated:
>>>>>>> b95509d (Add triage report intelligence and service analysis)

rustscan.txt
nmap.nmap
nmap.gnmap
nmap.xml
triage_report.txt
<target>.txt   (optional log)
Triage Report

<<<<<<< HEAD
Focus Radar signals
=======
BasiXenuM generates a structured triage report including:

Target Information

Basic host and service overview.

Open Ports

Parsed Nmap results.

Service Summary

High-level explanation of exposed services.

Interesting Findings

Notable signals detected during enumeration.

Attack Priority

Suggested order of investigation.

Likely Initial Attack Path

Logical attack route based on discovered services.

Quick Wins

Immediate checks that often reveal vulnerabilities.

Web Triage

Prioritization and analysis of web services.

Possible Vulnerability Matches

Version-based leads requiring manual verification.

Service Analysis

Per-service analysis including:

possible vulnerabilities

misconfiguration checks

manual testing suggestions

why the service matters

Recommended Next Steps

Guided enumeration steps.

Focus Radar

Focus Radar highlights likely attack surfaces based on detected ports.
>>>>>>> b95509d (Add triage report intelligence and service analysis)

Focus Radar
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
<<<<<<< HEAD
MAIL	25, 110, 143, 587, 993, 995
Known Behavior / Gotchas
1) RustScan --no-nmap issue
=======
MAIL	25,110,143,587,993,995
Known Behavior
RustScan Compatibility
>>>>>>> b95509d (Add triage report intelligence and service analysis)

Some RustScan versions reject:

--no-nmap

Planned workaround:

rustscan -a <target> -p <range> -- echo

<<<<<<< HEAD
If RustScan fails, BasiXenuM falls back to Nmap-only scanning.
=======
If RustScan fails, BasiXenuM automatically falls back to Nmap-only scanning.
>>>>>>> b95509d (Add triage report intelligence and service analysis)

Logging

<<<<<<< HEAD
Spinner output is disabled while logging to avoid messy terminal output.
=======
If logging is enabled:
>>>>>>> b95509d (Add triage report intelligence and service analysis)

Save [.txt log]? [y/N]

<<<<<<< HEAD
Example observed:
=======
A log file is saved in the scan directory containing:
>>>>>>> b95509d (Add triage report intelligence and service analysis)

command output

scan progress

terminal results

<<<<<<< HEAD
If only port 443 is open, test HTTPS first.

Example Run
=======
Example Detection
>>>>>>> b95509d (Add triage report intelligence and service analysis)

Target:

10.113.137.78

<<<<<<< HEAD
Detected:
=======
Detected services:
>>>>>>> b95509d (Add triage report intelligence and service analysis)

21  FTP (vsftpd)
22  SSH (OpenSSH)
139 SMB
445 SMB
3128 Squid proxy
3333 Apache web application

Report prioritization:

<<<<<<< HEAD

Logging / Save Output

During interactive mode you will be asked:

Save [.txt log]? [y/N]

If enabled, a log file is created:

out/<profile>/<target>/<timestamp>/<target>.txt

This file contains:

command output

scan summary

execution logs

Roadmap

=======
1. Web application (3333)
2. Proxy exposure (3128)
3. SMB enumeration
4. FTP anonymous access
5. SSH credential path
Roadmap

Planned improvements:
>>>>>>> b95509d (Add triage report intelligence and service analysis)

RustScan compatibility fix

optional quick web enumeration hooks

service fingerprint improvements

static vulnerability mapping

smarter service grouping

License
inbd-0404
