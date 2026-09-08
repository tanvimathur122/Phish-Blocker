#!/usr/bin/env python3

from main import enhanced_predict

# Test URLs that should be phishing
test_urls = [
    "http://secure-login-paypal.com/verify",
    "http://appleid.apple.com.login.verify-user.com/",
    "http://192.168.1.100/bankofamerica/login",
    "https://www.goog1e.com/account-security",
    "http://update-account-info.com/amazon",
    "http://facebook.com.security-check.ru/",
    "http://login.microsoftonline.com.verify-user.net/",
    "http://paypal.com.user-authentication.com/login"
]

print("Testing phishing detection...")
print("="*60)

for url in test_urls:
    try:
        result, probability, risk_details, features = enhanced_predict(url)
        print(f"URL: {url}")
        print(f"Result: {result}")
        print(f"Probability: {probability:.3f}")
        if risk_details:
            print(f"Risk Details: {risk_details}")
        print("-" * 60)
    except Exception as e:
        print(f"Error testing {url}: {e}")
        print("-" * 60)