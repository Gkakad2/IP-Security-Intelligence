# Architecture

IP Security Intelligence is a multi-source IP investigation and threat assessment tool.

```text
                         IP Address
                              |
             +----------------+----------------+
             |                |                |
            RDAP            ASN/BGP           DNS
             |                |                |
             +----------------+----------------+
                              |
                    Threat Intelligence
                              |
             +----------------+----------------+
             |                |                |
         Reputation          DNSBL        InternetDB
             |                |                |
             +----------------+----------------+
                              |
                    Evidence Correlation
                              |
                      Risk Assessment
                              |
                    Investigation Report
```

## Investigation Workflow

1. Validate the target IP.
2. Collect registration and ownership information.
3. Determine ASN and network information.
4. Perform reverse DNS lookup.
5. Collect available geolocation information.
6. Query available threat intelligence providers.
7. Perform DNS blocklist checks.
8. Collect Internet exposure information.
9. Correlate evidence from multiple sources.
10. Calculate a consolidated risk score.
11. Generate an investigation report.

## Intelligence Sources

### Registration
- RDAP
- WHOIS

### Network
- ASN
- BGP
- Network ownership

### DNS
- Reverse DNS / PTR

### Threat Intelligence
- VirusTotal
- AbuseIPDB
- GreyNoise
- AlienVault OTX

### Internet Exposure
- Shodan InternetDB

### DNS Blocklists
- Spamhaus
- SpamCop
- Barracuda

The tool does not treat a single intelligence source as definitive evidence. Results are correlated to produce an overall security assessment.
