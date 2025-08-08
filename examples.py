#!/usr/bin/env python3
"""
Usage examples for the Input Validation Library

This demonstrates how to use each validation component to secure user input
in different contexts and prevent common web application vulnerabilities.
"""

from input_validation import InputValidator


def sql_injection_examples():
    """Examples of SQL injection prevention"""
    print("=== SQL Injection Prevention ===")
    
    validator = InputValidator()
    
    # Safe parameterized query
    try:
        query = "SELECT * FROM users WHERE id = ? AND name = ?"
        params = [123, "john'; DROP TABLE users; --"]
        
        safe_query, safe_params = validator.sql.prevent_injection(query, params)
        print(f"Safe query: {safe_query}")
        print(f"Safe params: {safe_params}")
    except ValueError as e:
        print(f"Blocked dangerous query: {e}")
    
    # Dangerous query patterns blocked
    try:
        dangerous_query = "SELECT * FROM users; DROP TABLE users; --"
        validator.sql.prevent_injection(dangerous_query, [])
    except ValueError as e:
        print(f"✓ Blocked: {e}")
    
    print()


def xss_prevention_examples():
    """Examples of XSS prevention for different contexts"""
    print("=== XSS Prevention Examples ===")
    
    validator = InputValidator()
    
    # HTML context
    malicious_html = "<script>alert('XSS')</script>"
    safe_html = validator.xss.sanitize_html(malicious_html)
    print(f"HTML Input: {malicious_html}")
    print(f"HTML Safe:  {safe_html}")
    
    # JavaScript context
    malicious_js = "'; alert('XSS'); var x='"
    safe_js = validator.xss.sanitize_js(malicious_js)
    print(f"JS Input: {malicious_js}")
    print(f"JS Safe:  {safe_js}")
    
    # URL context
    malicious_url = "javascript:alert('XSS')"
    try:
        safe_url = validator.xss.sanitize_url(malicious_url)
        print(f"URL Safe: {safe_url}")
    except ValueError as e:
        print(f"✓ Blocked URL: {e}")
    
    # CSS context
    malicious_css = "expression(alert('XSS'))"
    safe_css = validator.xss.sanitize_css(malicious_css)
    print(f"CSS Input: {malicious_css}")
    print(f"CSS Safe:  {safe_css}")
    
    print()


def format_validation_examples():
    """Examples of email and URL format validation"""
    print("=== Format Validation Examples ===")
    
    validator = InputValidator()
    
    # Email validation
    emails = [
        "valid@example.com",
        "invalid.email",
        "user@domain",
        "test@sub.domain.com",
        "<script>@evil.com",
    ]
    
    print("Email Validation:")
    for email in emails:
        is_valid = validator.format.is_valid_email(email)
        status = "✓" if is_valid else "✗"
        print(f"  {status} {email}")
    
    # URL validation
    urls = [
        "https://example.com",
        "http://sub.domain.com:8080/path?query=1",
        "javascript:alert('xss')",
        "ftp://files.example.com",
        "not-a-url",
    ]
    
    print("\nURL Validation:")
    for url in urls:
        is_valid = validator.format.is_valid_url(url)
        status = "✓" if is_valid else "✗"
        print(f"  {status} {url}")
    
    print()


def path_traversal_examples():
    """Examples of path traversal prevention"""
    print("=== Path Traversal Prevention ===")
    
    validator = InputValidator()
    
    # Safe paths
    safe_paths = [
        "uploads/document.pdf",
        "images/photo.jpg",
        "data/report.txt",
    ]
    
    print("Safe Paths:")
    for path in safe_paths:
        try:
            safe_path = validator.path.prevent_traversal(path)
            print(f"  ✓ {path} -> {safe_path}")
        except ValueError as e:
            print(f"  ✗ {path} -> {e}")
    
    # Dangerous paths
    dangerous_paths = [
        "../../../etc/passwd",
        "..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/absolute/path/to/file",
        "file<with>dangerous:chars",
    ]
    
    print("\nDangerous Paths (blocked):")
    for path in dangerous_paths:
        try:
            safe_path = validator.path.prevent_traversal(path)
            print(f"  ? {path} -> {safe_path}")
        except ValueError as e:
            print(f"  ✓ {path} -> Blocked: {e}")
    
    # Base path restriction
    print("\nBase Path Restriction:")
    try:
        safe_path = validator.path.prevent_traversal(
            "documents/secret.txt", 
            allowed_base_path="/var/www/public"
        )
        print(f"  ✓ Restricted access: {safe_path}")
    except ValueError as e:
        print(f"  ✓ Access denied: {e}")
    
    print()


def web_application_example():
    """Complete web application example"""
    print("=== Complete Web Application Example ===")
    
    validator = InputValidator()
    
    # Simulated user registration form
    user_data = {
        "username": "<script>alert('xss')</script>",
        "email": "user@example.com",
        "profile_url": "https://github.com/user",
        "avatar_path": "../../../etc/passwd",
    }
    
    print("Processing user registration:")
    
    # Validate and sanitize each field
    try:
        # Sanitize username for HTML display
        safe_username = validator.xss.sanitize_html(user_data["username"])
        print(f"  Username: {user_data['username']} -> {safe_username}")
        
        # Validate email format
        if validator.format.is_valid_email(user_data["email"]):
            print(f"  ✓ Email: {user_data['email']}")
        else:
            print(f"  ✗ Invalid email: {user_data['email']}")
        
        # Validate profile URL
        if validator.format.is_valid_url(user_data["profile_url"]):
            print(f"  ✓ Profile URL: {user_data['profile_url']}")
        else:
            print(f"  ✗ Invalid URL: {user_data['profile_url']}")
        
        # Prevent path traversal for avatar upload
        safe_avatar_path = validator.path.prevent_traversal(
            user_data["avatar_path"],
            allowed_base_path="/uploads/avatars"
        )
        print(f"  ✓ Avatar path: {safe_avatar_path}")
        
    except ValueError as e:
        print(f"  ✗ Security violation: {e}")
    
    print()


def main():
    """Run all examples"""
    print("Input Validation Library - Security Examples\n")
    
    sql_injection_examples()
    xss_prevention_examples()
    format_validation_examples()
    path_traversal_examples()
    web_application_example()
    
    print("All examples completed. The library successfully prevents:")
    print("  ✓ SQL Injection attacks")
    print("  ✓ Cross-Site Scripting (XSS)")
    print("  ✓ Path Traversal attacks")
    print("  ✓ Invalid email/URL formats")


if __name__ == "__main__":
    main()