# Email Phishing Detection Tool
This Python-based tool analyzes email headers to detect potential phishing attempts. It checks several aspects, including SPF, DKIM, DMARC, subject line, sender domain, routing, and suspicious links, to provide a risk score and detailed findings.

## Features:
### SPF Check: 
Verifies if the email passed SPF (Sender Policy Framework) checks.
### DKIM Check: 
Verifies if the email passed DKIM (DomainKeys Identified Mail) checks.
### DMARC Check: 
Verifies if the email passed DMARC (Domain-based Message Authentication, Reporting, and Conformance) checks.
### Sender Domain Mismatch: 
Checks if the sender domain matches the Return-Path domain.
### Suspicious Routing: 
Analyzes the "Received" headers for suspicious routing and verification issues.
### Subject Line Analysis: 
Scans for common phishing keywords in the subject line.
### Suspicious Links: 
Detects suspicious URLs and domains, including URL shorteners and deceptive domains.

## Installation Instructions
Clone the repository or download the script: You can either clone the repository using Git or download the Python script directly.

git clone https://github.com/oussamamellakh/phishing-detection-tool
cd 
