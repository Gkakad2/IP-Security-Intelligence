# IP Security Intelligence

A multi-source IP security intelligence and threat assessment tool for investigating IPv4 and IPv6 addresses.

The tool collects network ownership, ASN, DNS, geolocation, reputation, blocklist, and internet-exposure information from multiple sources and generates a consolidated risk assessment with detailed investigation reports.

## Features

- IPv4/IPv6 validation
- RDAP lookup
- WHOIS lookup
- Reverse DNS / PTR lookup
- ASN and BGP intelligence
- Team Cymru ASN cross-check
- IPinfo network and geolocation intelligence
- VirusTotal reputation
- AbuseIPDB reputation
- GreyNoise intelligence
- AlienVault OTX intelligence
- Shodan InternetDB
- Spamhaus ZEN
- SpamCop
- Barracuda DNSBL
- Risk scoring
- Severity classification
- Major findings detection
- Source availability tracking
- Interactive scanning
- Single-IP scanning
- Batch IP scanning
- HTML reports
- Text reports
- Investigation history
- Custom report directories
- Optional API integrations

## Architecture

```text
                         IP ADDRESS
                              |
                              v
                     +----------------+
                     | Input Validation|
                     +-------+--------+
                             |
          +------------------+------------------+
          |                  |                  |
          v                  v                  v
       RDAP/WHOIS           DNS              ASN/BGP
          |                  |                  |
          +------------------+------------------+
                             |
                             v
                    Network Intelligence
                             |
             +---------------+---------------+
             |               |               |
             v               v               v
           GeoIP          Reverse DNS      Organization
             |               |               |
             +---------------+---------------+
                             |
                             v
                    Threat Intelligence
                             |
          +------------------+------------------+
          |                  |                  |
          v                  v                  v
      VirusTotal         AbuseIPDB          GreyNoise
          |                  |                  |
          +------------------+------------------+
                             |
                 +-----------+-----------+
                 |                       |
                 v                       v
             DNSBLs              Shodan InternetDB
                 |                       |
                 +-----------+-----------+
                             |
                             v
                     Risk Assessment
                             |
                    +--------+--------+
                    |                 |
                    v                 v
                TXT Report        HTML Report
