# Email Phishing Detection Tool 📧
This Python-based tool analyzes email headers to detect potential phishing attempts. It checks several aspects, including SPF, DKIM, DMARC, subject line, sender domain, routing, and suspicious links, to provide a risk score and detailed findings.

## Features 📌
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

## Installation Instructions 📕
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

## How to Use 📗
#### Option 1: Analyze an Email File
1. Save your raw email (including headers) as a .eml file.
2. Run the script with the file path as an argument:

```bash
python phishing_email_detection_tool.py path_to_your_email_file.eml
```

Example:
```bash
python phishing_email_detection_tool.py sample_email.eml
```

#### Option 2: Paste Email Content Directly
1. Run the script without providing a file path:
```bash
python phishing_email_detection_tool.py
```

2. You will be prompted to either provide a file or paste the email content directly into the terminal.
To paste the email content:
- Copy the raw email content (including headers).
- Paste it into the terminal and press Enter (on Windows, press Ctrl+Z to end input).

#### Example Output:
```bash
===== Email Phishing Analysis Report =====
Risk Score: 75/100
Risk Level: HIGH

Findings:
- SPF authentication failed
- DKIM signature verification failed
- Subject contains phishing keywords (2 instances)
- Suspicious links detected (3 instances)

Recommendation:
This email shows strong indicators of a phishing attempt. Do not click any links or open attachments.
```

## How the Tool Works 📙
#### 1. SPF, DKIM, DMARC Verification:
The script checks the Authentication-Results header for SPF, DKIM, and DMARC results. If any of these fail, the risk score increases.
#### 2. Sender Domain Mismatch: 
The script compares the domain in the From header and the Return-Path header. A mismatch increases the risk score.
#### 3. Suspicious Routing: 
The tool checks the "Received" headers for suspicious routing behavior, such as unverified servers or unexpected hops.
#### 4. Phishing Keywords: 
The subject line is checked for common phishing-related terms (e.g., "urgent", "suspend", "login", etc.).
#### 5. Suspicious Links: 
The script analyzes URLs in the email body. It checks for:
- URL shorteners (e.g., bit.ly, goo.gl)
- IP addresses instead of domain names
- Deceptive domains (e.g., "paypa1.com" instead of "paypal.com")
#### 6. Risk Score Calculation: 
Each indicator is assigned a risk score. If the total risk score exceeds predefined thresholds, the email is flagged as "HIGH", "MEDIUM", or "LOW" risk.

## Customization 📘
You can customize the tool to better suit your needs by modifying:
- Trusted Domains: Modify the self.trusted_domains set to include more legitimate domains.
- Phishing Keywords: Add or remove phishing keywords in the self.phishing_keywords list.
- Suspicious Domains: Modify the self.suspicious_tracking_domains list to include more suspicious tracking services.

## Contributing 
If you'd like to contribute to the development of this tool, feel free to submit pull requests. You can:
- Fix bugs
- Add new features (e.g., additional checks or improvements)
- Enhance the documentation
Please make sure to follow the project's coding style and add tests for new features.

