# Email Phishing Detection Tool 📧
This Python-based tool analyzes email headers to detect potential phishing attempts. It checks several aspects, including SPF, DKIM, DMARC, subject line, sender domain, routing, and suspicious links, to provide a risk score and detailed findings.

## Features
#### SPF Check: 
Verifies if the email passed SPF (Sender Policy Framework) checks.
#### DKIM Check: 
Verifies if the email passed DKIM (DomainKeys Identified Mail) checks.
#### DMARC Check: 
Verifies if the email passed DMARC (Domain-based Message Authentication, Reporting, and Conformance) checks.
#### Sender Domain Mismatch: 
Checks if the sender domain matches the Return-Path domain.
#### Suspicious Routing: 
Analyzes the "Received" headers for suspicious routing and verification issues.
#### Subject Line Analysis: 
Scans for common phishing keywords in the subject line.
#### Suspicious Links: 
Detects suspicious URLs and domains, including URL shorteners and deceptive domains.

## Installation Instructions
1. Clone the repository or download the script: You can either clone the repository using Git or download the Python script directly.

```bash
git clone https://github.com/oussamamellakh/email-phishing-detection-tool
cd email-phishing-detection-tool
```
2. Install the required dependencies: This project requires Python 3.x and the following libraries:
Install the necessary libraries by running:

```bash
pip install -r requirements.txt
```
