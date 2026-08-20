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
  Investigate an IP → Correlate intelligence → Calculate risk → Generate an evidence-based report
</p>

---

## 🔎 Overview

**IP Security Intelligence** is a standalone security investigation tool designed to collect and correlate information about an IPv4 or IPv6 address from multiple public and intelligence sources.

Instead of relying on a single IP reputation service, the tool combines:

- 🌐 Network ownership information
- 🏢 Organization and ISP information
- 🔢 ASN and BGP intelligence
- 🗺️ Geolocation
- 🔍 Reverse DNS
- 🧠 Threat intelligence
- 🚨 IP reputation
- 🛰️ Internet exposure information
- 📛 DNS blocklist results
- 📊 Risk scoring
- 📝 Investigation reports

The objective is to provide a **single consolidated view of an IP address** and help analysts determine whether additional investigation is required.

---

# ✨ Key Features

| Category | Capabilities |
|---|---|
| 🌐 Network Intelligence | RDAP, WHOIS, CIDR, NetRange, Organization |
| 🔢 ASN Intelligence | ASN lookup, origin ASN, ASN organization, BGP cross-check |
| 🔍 DNS Intelligence | Reverse DNS / PTR lookup |
| 🗺️ Geolocation | Country, region, city, ISP, organization |
| 🚨 Threat Intelligence | VirusTotal, AbuseIPDB, GreyNoise, OTX |
| 🛰️ Internet Exposure | Shodan InternetDB |
| 📛 DNSBL | Spamhaus ZEN, SpamCop, Barracuda |
| 🧮 Risk Analysis | Risk score, severity, findings |
| 📑 Reporting | HTML and TXT reports |
| 📦 Batch Analysis | Scan multiple IP addresses |
| 🕘 History | Browse previously scanned IPs |
| ⚙️ Automation | CLI and batch execution |
| 🔐 API Flexibility | Optional API keys; core functionality works without them |

---

# 🏗️ How It Works

```text
                         ┌─────────────────┐
                         │   USER / SOC    │
                         │  Enters an IP   │
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │ IP VALIDATION   │
                         │ IPv4 / IPv6     │
                         └────────┬────────┘
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
             ▼                    ▼                    ▼
      ┌────────────┐       ┌────────────┐       ┌────────────┐
      │ RDAP/WHOIS │       │  ASN/BGP   │       │    DNS     │
      └──────┬─────┘       └──────┬─────┘       └──────┬─────┘
             │                    │                    │
             └────────────────────┼────────────────────┘
                                  │
                                  ▼
                       ┌─────────────────────┐
                       │ NETWORK INTELLIGENCE│
                       └──────────┬──────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
        ┌───────────┐       ┌────────────┐      ┌────────────┐
        │  GeoIP    │       │ Reputation │      │   DNSBL    │
        └─────┬─────┘       └──────┬─────┘      └──────┬─────┘
              │                    │                   │
              │          ┌─────────┼─────────┐         │
              │          │         │         │         │
              │          ▼         ▼         ▼         │
              │      VirusTotal AbuseIPDB GreyNoise    │
              │          │         │         │         │
              └──────────┴─────────┼─────────┴─────────┘
                                   │
                                   ▼
                         ┌────────────────────┐
                         │ SHODAN INTERNETDB  │
                         │ Ports / CVEs / CPE │
                         └─────────┬──────────┘
                                   │
                                   ▼
                         ┌────────────────────┐
                         │ CORRELATION ENGINE │
                         └─────────┬──────────┘
                                   │
                                   ▼
                         ┌────────────────────┐
                         │   RISK ASSESSMENT  │
                         │ Score + Severity   │
                         └─────────┬──────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
             ┌──────────────┐              ┌──────────────┐
             │  TXT REPORT  │              │ HTML REPORT  │
             └──────────────┘              └──────────────┘
