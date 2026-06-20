# Phishing Detection & Analysis — SOC Investigation

## Executive Summary

This investigation analyzed email logs to identify potential phishing attempts targeting employees. Using Splunk SIEM and the `rex` command, I extracted key email fields (From, To, Subject) and identified multiple suspicious patterns including spoofed domains, urgent language, and requests for sensitive information.

## Key Findings

| Finding | Detail |
|---------|--------|
| **Suspicious Senders** | suspicious@phishattack.com, noreply@bank-secure.com, support@microsoft-verify.com, alerts@paypal-secure.com |
| **Suspicious Domains** | phishattack.com, secure-bank-verify.xyz, paypal-security-verify.org, microsoft-account-verify.net |
| **Common Keywords** | "verify", "urgent", "password", "action required" |
| **Legitimate Email** | ceo@company.com (no suspicious indicators) |

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|-----|
| Phishing | T1566 |
| Spearphishing Link | T1566.002 |

## Indicators of Compromise (IoCs)

| Type | Value |
|------|-------|
| Domain | phishattack.com |
| Domain | secure-bank-verify.xyz |
| Domain | paypal-security-verify.org |
| Domain | microsoft-account-verify.net |
| Keyword | "verify your account" |
| Keyword | "action required" |

## Recommendations

1. Block suspicious domains at the email gateway
2. Implement SPF/DKIM/DMARC to prevent spoofing
3. Conduct security awareness training on phishing
4. Enable email filtering for suspicious keywords
5. Monitor outbound links in emails

## Investigation Queries Used

### Extract Email Fields
```
index=phishing
| rex field=_raw "From:\s(?<from>.*)"
| rex field=_raw "To:\s(?<to>.*)"
| rex field=_raw "Subject:\s(?<subject>.*)"
| table _time, from, to, subject
```

### Find Suspicious Senders
```
index=phishing
| rex field=_raw "From:\s(?<from>.*)"
| stats count by from
| sort - count
```

### Find Suspicious Subjects
```
index=phishing
| rex field=_raw "Subject:\s(?<subject>.*)"
| search subject="*password*" OR subject="*verify*" OR subject="*urgent*" OR subject="*reset*"
| stats count by subject
| sort - count
```

### Find Suspicious Domains
```
index=phishing
| rex field=_raw "From:\s(?<from>.*)"
| search from="*phish*" OR from="*verify*" OR from="*secure*" OR from="*xyz*" OR from="*net*"
| stats count by from
| sort - count
```
