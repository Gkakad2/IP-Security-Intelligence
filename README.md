# 🛡️ IP Security Intelligence

<p align="center">

<img src="https://img.shields.io/badge/Project-IP%20Security%20Intelligence-0A66C2?style=for-the-badge&logo=shield&logoColor=white" alt="IP Security Intelligence">
<img src="https://img.shields.io/badge/Platform-Linux-black?style=for-the-badge&logo=linux&logoColor=white" alt="Linux">
<img src="https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white" alt="Bash">
<img src="https://img.shields.io/badge/Version-6.6-blue?style=for-the-badge" alt="Version">

</p>

<p align="center">
<b>Multi-source IP intelligence, threat assessment and investigation tool.</b>
</p>

<p align="center">
Investigate an IP → Correlate intelligence → Assess risk → Generate evidence-based reports
</p>

---

## 🔎 Overview

**IP Security Intelligence** is a standalone Linux-based security investigation tool that enriches an IPv4 or IPv6 address using multiple public and threat-intelligence sources.

Instead of relying on a single reputation provider, the tool correlates network ownership, ASN/BGP, DNS, geolocation, reputation, DNSBL and Internet-exposure data into a single investigation.

### What it helps answer

* 🌐 Who owns this IP/network?
* 🔢 Which ASN announces the address?
* 🏢 Which organization or provider is associated with it?
* 🔍 Does the IP have a reverse-DNS record?
* 🗺️ What is its approximate geolocation?
* 🚨 Is it reported by threat-intelligence sources?
* 📛 Is it present on DNS blocklists?
* 🛰️ What services or vulnerabilities are publicly observable?
* 🧮 What is the overall risk level?
* 📝 Can the investigation be preserved as evidence?

---

## ✨ Features

| Area                     | Capabilities                                           |
| ------------------------ | ------------------------------------------------------ |
| 🌐 Network Intelligence  | RDAP, WHOIS, CIDR, NetRange, registry and organization |
| 🔢 ASN Intelligence      | ASN lookup, origin ASN and organization                |
| 📡 BGP Intelligence      | Network/prefix and ASN cross-checking                  |
| 🔍 DNS Intelligence      | Reverse DNS / PTR lookup                               |
| 🗺️ Geolocation          | Country, region, city, ISP and network metadata        |
| 🚨 Threat Intelligence   | VirusTotal, AbuseIPDB, GreyNoise and OTX               |
| 🛰️ Internet Exposure    | Shodan InternetDB                                      |
| 📛 DNSBL                 | Spamhaus ZEN, SpamCop and Barracuda                    |
| 🧮 Risk Assessment       | Consolidated score and severity                        |
| 📊 Reporting             | TXT and HTML investigation reports                     |
| 📦 Batch Analysis        | Scan multiple IP addresses                             |
| 💾 Investigation History | Preserve and review previous scans                     |
| 🔐 API Flexibility       | Optional providers do not block no-key investigations  |

---

# 🧠 Investigation Workflow

```text
                    ┌──────────────┐
                    │  IP ADDRESS  │
                    └──────┬───────┘
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
         RDAP/WHOIS       ASN/BGP         DNS
            │              │              │
            └──────────────┼──────────────┘
                           ▼
                  ┌─────────────────┐
                  │   Geolocation   │
                  └────────┬────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
      Reputation         DNSBL        InternetDB
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                 Evidence Correlation
                           │
                           ▼
                   Risk Assessment
                           │
                           ▼
                    Investigation
                       Report
```

The objective is **correlation rather than single-source verdicts**.

---

# 🌐 Network Registration & Ownership

The tool attempts to identify registration and ownership information through RDAP and WHOIS.

Typical information includes:

```text
IP Address
NetRange
CIDR
Organization
Registry
Country
Abuse Contact
Registration Information
```

### Why this matters

An IP address by itself provides limited attribution value. Registration data establishes the network or organization responsible for the address space.

However:

> Network ownership does not necessarily identify the end user, customer, application or device using the IP.

---

# 🔢 ASN & BGP Intelligence

ASN information helps identify the autonomous system responsible for announcing a network prefix.

Example:

```text
IP Address : 151.101.65.44
Prefix     : 151.101.0.0/16
ASN        : AS54113
```

The relationship can be represented as:

```text
IP Address
     │
     ▼
Network Prefix
     │
     ▼
Origin ASN
     │
     ▼
Organization
     │
     ▼
Infrastructure Provider
```

ASN intelligence is particularly useful when investigating:

* ☁️ Cloud providers
* 🌐 CDNs
* 🏢 Hosting providers
* 🔐 VPN infrastructure
* 🔄 Proxy infrastructure
* 📡 Large ISPs
* 🖥️ Shared infrastructure

---

# 🔍 DNS Intelligence

Reverse DNS analysis checks whether the address has an associated PTR record.

```text
IP Address
     │
     ▼
PTR Record
     │
     ▼
hostname.example.com
```

Reverse DNS can provide useful contextual information about hosting providers, infrastructure naming conventions and potentially exposed services.

A missing PTR record does **not** indicate malicious activity.

---

# 🗺️ Geolocation

Where supported, the tool collects available geolocation and network metadata such as:

* Country
* Region
* City
* ISP
* Organization
* ASN
* Network information

> ⚠️ IP geolocation is approximate and must not be interpreted as the precise physical location of a person or device.

---

# 🚨 Threat Intelligence

Optional threat-intelligence providers can add additional reputation and contextual information.

### VirusTotal

May provide:

* IP reputation
* Malicious detections
* Historical intelligence
* Associated indicators

### AbuseIPDB

May provide:

* Abuse reports
* Report count
* Abuse confidence
* Report categories
* Last reported activity

### GreyNoise

Provides intelligence useful for understanding Internet-wide scanning and background scanning activity.

### AlienVault OTX

Provides additional threat intelligence and IOC correlation.

Provider availability depends on configured credentials, service availability and applicable provider limits.

---

# 🛰️ Internet Exposure

The project uses **Shodan InternetDB** where available to obtain publicly observable information associated with an IP.

Potential information includes:

```text
Open Ports
Hostnames
Vulnerabilities
CPEs
Tags
```

This helps answer:

> What publicly observable services or vulnerabilities are associated with this IP?

Internet exposure data should be treated as contextual evidence rather than proof of exploitation.

---

# 📛 DNS Blocklists

The scanner performs DNSBL checks against multiple reputation lists.

Current checks include:

* Spamhaus ZEN
* SpamCop
* Barracuda Reputation Block List

A blocklist hit is treated as **one evidence source**, not definitive proof of malicious behavior.

---

# 🧮 Risk Assessment

The tool generates a consolidated analytical risk score based on the intelligence available during the investigation.

Example:

```text
┌──────────────────────────────────────┐
│          RISK ASSESSMENT             │
├──────────────────────────────────────┤
│                                      │
│  Score:      72 / 100                │
│  Severity:   HIGH                    │
│                                      │
└──────────────────────────────────────┘
```

### Severity Levels

```text
0  ───────── 24     LOW
25 ───────── 49     MEDIUM
50 ───────── 74     HIGH
75 ──────── 100     CRITICAL
```

The risk score is an **analytical indicator**, not a definitive malicious/not-malicious verdict.

Security decisions should consider the underlying evidence.

---

# 🧠 Evidence Correlation

The core principle of the project is:

> **One indicator should not automatically determine the final verdict.**

For example:

```text
                 IP ADDRESS
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
     WHOIS          ASN           DNS
       │             │             │
       └─────────────┼─────────────┘
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
   Reputation       DNSBL       InternetDB
       │             │             │
       └─────────────┼─────────────┘
                     ▼
             Evidence Correlation
                     │
                     ▼
              Risk Assessment
                     │
                     ▼
               Final Report
```

This provides a more useful investigation model than simply returning:

```text
Malicious
```

or

```text
Not Malicious
```

---

# 📊 Example Investigation

```bash
./ip_intel.sh 151.101.65.44
```

Example output:

```text
IP Address       : 151.101.65.44
Organization     : Fastly, Inc.
Network          : 151.101.0.0/16
ASN              : AS54113
Country          : United States
Reverse DNS      : <hostname>

Threat Sources
────────────────────────────
VirusTotal       : Available
AbuseIPDB        : Available
GreyNoise        : Available
OTX              : Available

DNSBL
────────────────────────────
Spamhaus         : Not Listed
SpamCop          : Not Listed
Barracuda        : Not Listed

InternetDB
────────────────────────────
Ports            : Available
Vulnerabilities  : Available

Risk Score       : XX / 100
Severity         : MEDIUM
```

Actual results vary according to the investigated IP, provider responses and availability at scan time.

---

# 📝 Reporting

Investigations can generate timestamped TXT and HTML reports.

Example:

```text
reports/
├── text-reports/
│   └── IP_151.101.65.44_20260820T075922Z.txt
│
└── html-reports/
    └── IP_151.101.65.44_20260820T075922Z.html
```

### HTML Report Contents

Reports can include:

* 🔴 Risk assessment
* 📊 Risk score
* 🚦 Severity
* 🔎 Sources checked
* ⚠️ Major findings
* 🌐 Network information
* 🔢 ASN information
* 🗺️ Geolocation
* 🔍 DNS information
* 🚨 Threat intelligence
* 📛 DNSBL results
* 🛰️ InternetDB information
* 📋 RDAP information
* 📜 WHOIS information
* 🔗 Investigation references

---

# ⚡ Installation

## Requirements

Linux with:

```text
curl
jq
python3
dig
whois
timeout
sed
awk
grep
head
xargs
tr
mktemp
date
```

### Debian / Ubuntu

```bash
sudo apt update

sudo apt install -y \
    curl \
    jq \
    python3 \
    dnsutils \
    whois \
    coreutils
```

---

# 🚀 Quick Start

Clone the repository:

```bash
git clone https://github.com/<YOUR-USERNAME>/ip-security-intelligence.git
cd ip-security-intelligence
```

Make the scanner executable:

```bash
chmod +x ip_intel.sh
```

Scan a specific IP:

```bash
./ip_intel.sh 8.8.8.8
```

Start interactive mode:

```bash
./ip_intel.sh
```

---

# 📦 Batch Scanning

Create an IP list:

```text
# ips.txt

8.8.8.8
1.1.1.1
151.101.65.44
136.243.77.75
```

Run:

```bash
./ip_intel.sh --batch ips.txt
```

This allows multiple addresses to be investigated without manually starting each scan.

---

# ⚙️ Command-Line Options

```text
./ip_intel.sh <IP>

./ip_intel.sh --batch <file>

./ip_intel.sh --output-dir <directory>

./ip_intel.sh --no-color

./ip_intel.sh --help

./ip_intel.sh --version
```

Interactive mode:

```bash
./ip_intel.sh
```

The interactive interface can also provide access to previous investigation history where supported.

---

# 🔑 Optional API Keys

Some intelligence providers require API credentials.

Example:

```bash
export VT_API_KEY="YOUR_API_KEY"
export ABUSEIPDB_API_KEY="YOUR_API_KEY"
export GREYNOISE_API_KEY="YOUR_API_KEY"
export OTX_API_KEY="YOUR_API_KEY"
export IPINFO_TOKEN="YOUR_TOKEN"
```

API keys are **optional**.

The scanner is designed to continue using available no-key sources when optional credentials are unavailable.

Example:

```text
[✓] RDAP
[✓] WHOIS
[✓] Reverse DNS
[✓] ASN
[✓] Shodan InternetDB

[!] VirusTotal API key not configured
[!] AbuseIPDB API key not configured
[!] GreyNoise API key not configured
```

The investigation continues using the available intelligence sources.

---

# 🔐 Security & Secrets

Never commit API keys, tokens or credentials to GitHub.

Recommended `.gitignore` entries:

```gitignore
.env
*.log
cache/
reports/
*.key
*.token
```

Before publishing, check for:

```text
API keys
Tokens
Passwords
Credentials
Internal IP addresses
Private investigation data
Organization-specific paths
```

---

# 🗂️ Project Structure

```text
ip-security-intelligence/
│
├── ip_intel.sh
├── README.md
├── LICENSE
├── .gitignore
│
├── config/
│   └── config.example
│
├── docs/
│   ├── architecture.md
│   └── data-sources.md
│
├── examples/
│   └── ips.txt
│
└── tests/
```

---

# 🎯 Use Cases

### 🔎 Security Investigation

Investigate an unknown external IP observed in logs, firewall alerts or security events.

### 🛡️ Threat Hunting

Correlate suspicious IP addresses against multiple public intelligence sources.

### 🌐 Network Investigation

Determine:

```text
Who owns the network?
Which ASN announces it?
Where is it registered?
Does it have reverse DNS?
Is it reported by reputation services?
Is it present on DNSBLs?
What services are publicly observable?
```

### 🚨 Incident Response

Quickly enrich an IP observed during an incident and preserve the results for further investigation.

### 🧪 Security Research

Collect structured IP intelligence for authorized defensive research.

### 📊 Threat Intelligence

Generate reusable TXT and HTML investigation reports.

---

# ⚠️ Attribution Limitation

An important principle of IP intelligence is:

> **Network ownership does not equal end-user attribution.**

For example:

```text
151.101.x.x
      │
      ▼
     CDN
      │
      ▼
Shared Infrastructure
      │
      ▼
Multiple Customers
```

Identifying the organization responsible for an IP address does not necessarily identify the person, application or customer using that infrastructure.

This limitation is particularly important for:

* CDNs
* Cloud providers
* VPN providers
* Proxy services
* Hosting providers
* Shared infrastructure

The project therefore reports **observable intelligence and supporting evidence** rather than making unsupported attribution claims.

---

# 🧩 Design Principles

The project follows several core principles:

### 1. Multi-source correlation

No single intelligence source should determine the final assessment.

### 2. Graceful degradation

Optional APIs should not prevent the scanner from using available public sources.

### 3. Evidence preservation

Investigation results should be available as timestamped reports.

### 4. Attribution awareness

Network ownership and infrastructure location should not be confused with end-user identity.

### 5. Analyst-oriented output

Results should be understandable and useful during security investigations.

### 6. Standalone operation

The scanner should remain useful without requiring a specific SIEM, firewall or cloud platform.

---

# 📈 Roadmap

* [ ] Modular provider architecture
* [ ] JSON-native output
* [ ] Passive DNS integration
* [ ] Certificate Transparency integration
* [ ] Censys integration
* [ ] Historical IP intelligence
* [ ] Historical ASN tracking
* [ ] Historical DNS tracking
* [ ] Enhanced evidence correlation
* [ ] Confidence scoring
* [ ] Report indexing
* [ ] Additional threat-intelligence providers
* [ ] Automated test framework
* [ ] Configuration file support

---

# 🚫 Out of Scope

This project intentionally operates as a **standalone IP intelligence platform**.

It does not require:

```text
SonicWall
Elasticsearch
Wazuh
OpenStack
```

The scanner can therefore be deployed independently on an analyst workstation, Linux server or authorized security research environment.

---

# ⚖️ Responsible Use

This tool is intended for:

* Authorized security investigations
* Defensive security operations
* Threat intelligence
* Network administration
* Security research
* Incident response
* Educational purposes

Users are responsible for complying with applicable laws, organizational policies, privacy requirements and third-party terms of service.

---

# ⚠️ Disclaimer

Third-party intelligence sources may contain incomplete, outdated or inaccurate information.

A reputation listing does not automatically prove that an IP is malicious.

Risk scores are analytical indicators and should be validated against additional evidence before defensive, investigative or operational action is taken.

Geolocation data should not be interpreted as precise physical attribution.

The authors are not responsible for misuse of this software.

---

# 📜 License

If this repository is released as open source, add the appropriate license file.

For example:

```text
MIT License
```

Do not claim the project is released under a license until the corresponding `LICENSE` file has been added to the repository.

---

# 🛡️ IP Security Intelligence

```text
              ┌──────────────┐
              │      IP      │
              └──────┬───────┘
                     │
                 COLLECT
                     │
                     ▼
              ┌──────────────┐
              │  INTELLIGENCE│
              └──────┬───────┘
                     │
                 CORRELATE
                     │
                     ▼
              ┌──────────────┐
              │   EVIDENCE   │
              └──────┬───────┘
                     │
                  ASSESS
                     │
                     ▼
              ┌──────────────┐
              │     RISK     │
              └──────┬───────┘
                     │
                 REPORT
                     │
                     ▼
              ┌──────────────┐
              │ INVESTIGATION│
              └──────────────┘
```

**Investigate smarter. Correlate more evidence. Make better security decisions.**
