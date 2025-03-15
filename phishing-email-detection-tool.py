import email
import re
import socket
import argparse
from datetime import datetime
from email.parser import HeaderParser
from urllib.parse import urlparse

class PhishingDetector:
    def __init__(self):
        # Known legitimate domains for sender verification
        self.trusted_domains = set(['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com', 'apple.com', 'microsoft.com'])
        # Common phishing keywords in subject lines
        self.phishing_keywords = ['urgent', 'verify', 'suspend', 'account', 'login', 'click', 'confirm', 'update',
                                'security', 'alert', 'attention', 'important', 'verify', 'limited', 'expires']
        # Tracking domains often used in phishing
        self.suspicious_tracking_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd']
        # Risk score thresholds
        self.low_risk_threshold = 30
        self.medium_risk_threshold = 60
        
    def parse_email_headers(self, email_content):
        """Parse the email headers from raw email content"""
        parser = HeaderParser()
        msg = email.message_from_string(email_content)
        return msg
    
    def check_spf_record(self, headers):
        """Check if the email passes SPF verification"""
        auth_results = headers.get('Authentication-Results', '')
        if 'spf=pass' in auth_results.lower():
            return True
        elif 'spf=fail' in auth_results.lower():
            return False
        return None  # SPF result not found or inconclusive
    
    def check_dkim_record(self, headers):
        """Check if the email passes DKIM verification"""
        auth_results = headers.get('Authentication-Results', '')
        if 'dkim=pass' in auth_results.lower():
            return True
        elif 'dkim=fail' in auth_results.lower():
            return False
        return None  # DKIM result not found or inconclusive
    
    def check_dmarc_record(self, headers):
        """Check if the email passes DMARC verification"""
        auth_results = headers.get('Authentication-Results', '')
        if 'dmarc=pass' in auth_results.lower():
            return True
        elif 'dmarc=fail' in auth_results.lower():
            return False
        return None  # DMARC result not found or inconclusive
    
    def check_sender_domain_mismatch(self, headers):
        """Check if from domain matches return-path domain"""
        sender_domain = None
        return_path_domain = None
        
        from_header = headers.get('From', '')
        return_path_header = headers.get('Return-Path', '')
        
        from_match = re.search(r'@([^>\s]*)', from_header)
        if from_match:
            sender_domain = from_match.group(1)
                
        return_match = re.search(r'@([^>\s]*)', return_path_header)
        if return_match:
            return_path_domain = return_match.group(1)
                
        if sender_domain and return_path_domain and sender_domain != return_path_domain:
            return True  # Mismatch found
        return False
    
    def check_suspicious_routing(self, headers):
        """Check for suspicious email routing in Received headers"""
        suspicious_count = 0
        
        # Get all 'Received' headers
        received_headers = []
        
        # Handle multiple Received headers
        for key in headers.keys():
            if key.lower() == 'received':
                # Add all values of the same header
                if isinstance(headers[key], list):
                    received_headers.extend(headers[key])
                else:
                    received_headers.append(headers[key])
            
        if len(received_headers) > 5:
            suspicious_count += min(len(received_headers) - 5, 3)  # Cap at 3 points
            
        for header in received_headers:
            if any(x in header.lower() for x in ['unknown', 'unverified']):
                suspicious_count += 1
        return suspicious_count
    
    def check_subject_for_phishing(self, headers):
        """Check subject line for common phishing keywords"""
        phishing_word_count = 0
        subject = headers.get('Subject', '').lower()
        for word in self.phishing_keywords:
            if word in subject:
                phishing_word_count += 1
        return phishing_word_count
    
    def check_suspicious_links(self, email_content):
        """Check for suspicious URLs in email body"""
        suspicious_link_count = 0
        msg = email.message_from_string(email_content)
        
        # Extract all URLs from email body
        urls = []
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ['text/plain', 'text/html']:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        content = payload.decode('utf-8', errors='ignore')
                        # Simple URL extraction with regex
                        found_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
                        urls.extend(found_urls)
                except Exception:
                    # Skip parts that can't be decoded
                    continue
        
        # Check each URL for suspicious characteristics
        for url in urls:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Check for URL shorteners
            if any(td in domain for td in self.suspicious_tracking_domains):
                suspicious_link_count += 1
                
            # Check for IP addresses instead of domains
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                suspicious_link_count += 1
                
            # Check for deceptive domains (e.g., paypa1.com instead of paypal.com)
            for trusted in self.trusted_domains:
                if domain != trusted and self.levenshtein_distance(domain, trusted) <= 2:
                    suspicious_link_count += 2
        
        return suspicious_link_count
    
    def levenshtein_distance(self, s1, s2):
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
            
        return previous_row[-1]
    
    def check_reply_to_mismatch(self, headers):
        """Check if Reply-To differs from From address"""
        from_header = headers.get('From', '')
        reply_to_header = headers.get('Reply-To', '')
        
        if from_header and reply_to_header:
            from_domain = re.search(r'@([^>\s]*)', from_header)
            reply_domain = re.search(r'@([^>\s]*)', reply_to_header)
            
            if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
                return True
        return False
    
    def analyze_headers(self, email_content):
        """Analyze email headers for phishing indicators"""
        headers = self.parse_email_headers(email_content)
        risk_score = 0
        findings = []
        
        # Check SPF
        spf_result = self.check_spf_record(headers)
        if spf_result is False:
            risk_score += 20
            findings.append("SPF authentication failed")
        elif spf_result is None:
            risk_score += 5
            findings.append("No SPF authentication found")
            
        # Check DKIM
        dkim_result = self.check_dkim_record(headers)
        if dkim_result is False:
            risk_score += 15
            findings.append("DKIM signature verification failed")
        elif dkim_result is None:
            risk_score += 5
            findings.append("No DKIM signature found")
            
        # Check DMARC
        dmarc_result = self.check_dmarc_record(headers)
        if dmarc_result is False:
            risk_score += 15
            findings.append("DMARC verification failed")
        elif dmarc_result is None:
            risk_score += 5
            findings.append("No DMARC record found")
            
        # Check sender domain mismatch
        if self.check_sender_domain_mismatch(headers):
            risk_score += 25
            findings.append("Sender domain mismatch in From and Return-Path")
            
        # Check suspicious routing
        suspicious_routing = self.check_suspicious_routing(headers)
        if suspicious_routing > 0:
            risk_score += suspicious_routing * 5
            findings.append(f"Suspicious routing detected ({suspicious_routing} instances)")
            
        # Check subject for phishing words
        phishing_words = self.check_subject_for_phishing(headers)
        if phishing_words > 0:
            risk_score += min(phishing_words * 3, 15)  # Cap at 15 points
            findings.append(f"Subject contains phishing keywords ({phishing_words} instances)")
            
        # Check for Reply-To mismatch
        if self.check_reply_to_mismatch(headers):
            risk_score += 10
            findings.append("Reply-To address differs from From address")
            
        # Check for suspicious links
        suspicious_links = self.check_suspicious_links(email_content)
        if suspicious_links > 0:
            risk_score += min(suspicious_links * 5, 20)  # Cap at 20 points
            findings.append(f"Suspicious links detected ({suspicious_links} instances)")
            
        # Determine risk level
        if risk_score >= self.medium_risk_threshold:
            risk_level = "HIGH"
        elif risk_score >= self.low_risk_threshold:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        result = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings": findings
        }
        
        return result

def analyze_from_file(file_path):
    """Analyze email from a file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            email_content = file.read()
            
        detector = PhishingDetector()
        result = detector.analyze_headers(email_content)
        
        print("\n===== Email Phishing Analysis Report =====")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Risk Level: {result['risk_level']}")
        print("\nFindings:")
        if result['findings']:
            for finding in result['findings']:
                print(f"- {finding}")
        else:
            print("- No suspicious indicators found")
            
        print("\nRecommendation:")
        if result['risk_level'] == "HIGH":
            print("This email shows strong indicators of a phishing attempt. Do not click any links or open attachments.")
        elif result['risk_level'] == "MEDIUM":
            print("This email shows some suspicious characteristics. Exercise caution with links and attachments.")
        else:
            print("This email appears to be legitimate based on header analysis.")
            
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
    except Exception as e:
        print(f"Error analyzing email: {str(e)}")

def analyze_from_input():
    """Analyze email from user input"""
    print("Enter the email content with headers (press Ctrl+D on Unix or Ctrl+Z then Enter on Windows when finished):")
    try:
        lines = []
        while True:
            try:
                line = input()
                lines.append(line)
            except EOFError:
                break
        
        email_content = '\n'.join(lines)
        
        detector = PhishingDetector()
        result = detector.analyze_headers(email_content)
        
        print("\n===== Email Phishing Analysis Report =====")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Risk Level: {result['risk_level']}")
        print("\nFindings:")
        if result['findings']:
            for finding in result['findings']:
                print(f"- {finding}")
        else:
            print("- No suspicious indicators found")
            
        print("\nRecommendation:")
        if result['risk_level'] == "HIGH":
            print("This email shows strong indicators of a phishing attempt. Do not click any links or open attachments.")
        elif result['risk_level'] == "MEDIUM":
            print("This email shows some suspicious characteristics. Exercise caution with links and attachments.")
        else:
            print("This email appears to be legitimate based on header analysis.")
            
    except Exception as e:
        print(f"Error analyzing email: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Email Header Phishing Detection Tool')
    parser.add_argument('email_file', nargs='?', help='Path to email file (with headers)')
    args = parser.parse_args()
    
    if args.email_file:
        analyze_from_file(args.email_file)
    else:
        print("No email file provided. You can either:")
        print("1. Provide a file path")
        print("2. Paste email content directly")
        
        while True:
            choice = input("\nEnter your choice (1/2): ")
            if choice == '1':
                file_path = input("Enter the path to your email file: ")
                analyze_from_file(file_path)
                break
            elif choice == '2':
                analyze_from_input()
                break
            else:
                print("Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess interrupted by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
