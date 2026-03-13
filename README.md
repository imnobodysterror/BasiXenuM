BasiXenuM

BasiXenuM is a baseline reconnaissance helper designed to quickly identify the attack surface of a target during CTFs and penetration testing practice.

The tool automates the first stage of enumeration by combining port discovery, service analysis, and triage reporting to help answer the question:

Where should I start testing first?

BasiXenuM is mainly intended for practice environments such as:

TryHackMe labs

Hack The Box machines

CTF challenges

penetration testing training labs

Features

Interactive reconnaissance workflow

RustScan + Nmap integration

Automatic triage report generation

Focus Radar attack surface detection

Attack Priority suggestions

Likely Initial Attack Path logic

Per-service analysis guidance

Web service triage

Optional automated follow-up reconnaissance

Follow-up reconnaissance may automatically run:

ffuf (web directory enumeration)

netexec (SMB enumeration)

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

Whether automated follow-up reconnaissance should run

Enumeration will then start automatically.

Direct Mode

Run directly against a target:

basixenum enum 10.10.10.10

Example:

basixenum enum 10.10.10.10 --mode fast --profile thm
Scan Modes
FAST (default)

Workflow:

RustScan → discover open ports  
Nmap → service detection + default scripts

Nmap flags used:

-sC -sV
FULL

Includes everything from FAST plus additional fingerprinting:

-O
--traceroute
--reason

If no ports were discovered earlier:

-p-

Optional UDP scanning:

--udp
--udp-top-ports <number>
Output Structure

Results are stored in:

out/<profile>/<target>/<timestamp>/

Example:

out/thm/10.113.137.78/20260307_012945/

Typical generated files:

nmap.nmap
nmap.gnmap
nmap.xml
triage_report.txt
ffuf_web_dirs.json
<target>.txt   (optional log)
Triage Report

BasiXenuM generates a structured triage report to guide early reconnaissance.

The report includes:

Target Information

Open Ports

Service Summary

Interesting Findings

Attack Priority

Likely Initial Attack Path

Quick Wins

Web Triage

Possible Vulnerability Matches

Service Analysis

Recommended Next Steps

If follow-up tasks are enabled, the report also contains a FOLLOW-UP RECON section summarizing additional findings from tools like ffuf or netexec.

Focus Radar

Focus Radar highlights likely attack surfaces based on detected services.

Signal	Ports
WEB	80, 443, 8080, 8443
SMB	139, 445
WINRM	5985, 5986
RDP	3389
DNS	53
LDAP	389, 636
KERBEROS	88
RPC	111, 135
NFS	2049
MAIL	25, 110, 143, 587, 993, 995

These signals help prioritize reconnaissance.

Known Behavior

Some RustScan versions reject the argument:

--no-nmap

If RustScan fails, BasiXenuM automatically falls back to Nmap-only scanning.

Roadmap

Planned improvements:

RustScan compatibility improvements

smarter service fingerprinting

improved follow-up task logic

enhanced report categorization

License

INBD-0404BasiXenuM

BasiXenuM is a baseline reconnaissance helper designed to quickly identify the attack surface of a target during CTFs and penetration testing practice.

The tool automates the first stage of enumeration by combining port discovery, service analysis, and triage reporting to help answer the question:

Where should I start testing first?

BasiXenuM is mainly intended for practice environments such as:

TryHackMe labs

Hack The Box machines

CTF challenges

penetration testing training labs

Features

Interactive reconnaissance workflow

RustScan + Nmap integration

Automatic triage report generation

Focus Radar attack surface detection

Attack Priority suggestions

Likely Initial Attack Path logic

Per-service analysis guidance

Web service triage

Optional automated follow-up reconnaissance

Follow-up reconnaissance may automatically run:

ffuf (web directory enumeration)

netexec (SMB enumeration)

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

Whether automated follow-up reconnaissance should run

Enumeration will then start automatically.

Direct Mode

Run directly against a target:

basixenum enum 10.10.10.10

Example:

basixenum enum 10.10.10.10 --mode fast --profile thm
Scan Modes
FAST (default)

Workflow:

RustScan → discover open ports  
Nmap → service detection + default scripts

Nmap flags used:

-sC -sV
FULL

Includes everything from FAST plus additional fingerprinting:

-O
--traceroute
--reason

If no ports were discovered earlier:

-p-

Optional UDP scanning:

--udp
--udp-top-ports <number>
Output Structure

Results are stored in:

out/<profile>/<target>/<timestamp>/

Example:

out/thm/10.113.137.78/20260307_012945/

Typical generated files:

nmap.nmap
nmap.gnmap
nmap.xml
triage_report.txt
ffuf_web_dirs.json
<target>.txt   (optional log)
Triage Report

BasiXenuM generates a structured triage report to guide early reconnaissance.

The report includes:

Target Information

Open Ports

Service Summary

Interesting Findings

Attack Priority

Likely Initial Attack Path

Quick Wins

Web Triage

Possible Vulnerability Matches

Service Analysis

Recommended Next Steps

If follow-up tasks are enabled, the report also contains a FOLLOW-UP RECON section summarizing additional findings from tools like ffuf or netexec.

Focus Radar

Focus Radar highlights likely attack surfaces based on detected services.

Signal	Ports
WEB	80, 443, 8080, 8443
SMB	139, 445
WINRM	5985, 5986
RDP	3389
DNS	53
LDAP	389, 636
KERBEROS	88
RPC	111, 135
NFS	2049
MAIL	25, 110, 143, 587, 993, 995

These signals help prioritize reconnaissance.

Known Behavior

Some RustScan versions reject the argument:

--no-nmap

If RustScan fails, BasiXenuM automatically falls back to Nmap-only scanning.

Roadmap

Planned improvements:

RustScan compatibility improvements

smarter service fingerprinting

improved follow-up task logic

enhanced report categorization

License

INBD-0404
