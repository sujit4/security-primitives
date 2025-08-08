class InputValidator:
    def __init__(self):
        self.sql = SQLValidator()
        self.xss = XSSValidator()
        self.format = FormatValidator()
        self.path = PathValidator()


class SQLValidator:
    def prevent_injection(self, query, params):
        """
        Creates a safe parameterized query to prevent SQL injection.
        Returns tuple of (safe_query, safe_params)
        """
        if not isinstance(query, str):
            raise ValueError("Query must be a string")
        
        if params is None:
            params = []
        elif isinstance(params, dict):
            params = list(params.values())
        elif not isinstance(params, (list, tuple)):
            params = [params]
        
        # Basic validation: check for suspicious patterns in the base query
        dangerous_patterns = [
            r';\s*--',  # Comment after semicolon
            r';\s*/\*',  # Comment block after semicolon
            r'union\s+select',  # Union injection
            r'drop\s+table',  # Drop table
            r'delete\s+from',  # Delete injection
        ]
        
        import re
        query_lower = query.lower()
        for pattern in dangerous_patterns:
            if re.search(pattern, query_lower):
                raise ValueError(f"Potentially unsafe query pattern detected: {pattern}")
        
        # Validate parameters
        safe_params = []
        for param in params:
            safe_params.append(self._sanitize_param(param))
        
        return query, safe_params
    
    def _sanitize_param(self, param):
        """Sanitize individual parameters"""
        if param is None:
            return None
        elif isinstance(param, (int, float, bool)):
            return param
        elif isinstance(param, str):
            # Remove null bytes and control characters
            sanitized = param.replace('\x00', '')
            sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\t\n\r')
            return sanitized
        else:
            return str(param)


class XSSValidator:
    def __init__(self):
        # HTML entities mapping for escaping
        self.html_escape_table = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
        }
    
    def sanitize_html(self, input_text):
        """
        Escapes HTML special characters to prevent XSS in HTML context.
        Safe for rendering user input in HTML content.
        """
        if not isinstance(input_text, str):
            input_text = str(input_text)
        
        # Escape HTML special characters
        escaped = input_text
        for char, entity in self.html_escape_table.items():
            escaped = escaped.replace(char, entity)
        
        return escaped
    
    def sanitize_js(self, input_text):
        """
        Escapes JavaScript special characters to prevent XSS in JS context.
        Safe for inserting user input into JavaScript strings.
        """
        if not isinstance(input_text, str):
            input_text = str(input_text)
        
        # JavaScript escape mapping
        js_escape_table = {
            '\\': '\\\\',
            '"': '\\"',
            "'": "\\'",
            '\n': '\\n',
            '\r': '\\r',
            '\t': '\\t',
            '\b': '\\b',
            '\f': '\\f',
            '/': '\\/',
            '<': '\\u003c',
            '>': '\\u003e',
            '&': '\\u0026',
        }
        
        escaped = input_text
        for char, escape_seq in js_escape_table.items():
            escaped = escaped.replace(char, escape_seq)
        
        return escaped
    
    def sanitize_url(self, input_text):
        """
        Sanitizes input for use in URL contexts to prevent XSS.
        Only allows safe URL schemes and encodes dangerous characters.
        """
        import urllib.parse
        
        if not isinstance(input_text, str):
            input_text = str(input_text)
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in input_text if ord(char) >= 32)
        
        # Check for safe URL schemes
        safe_schemes = ['http', 'https', 'mailto', 'tel', 'ftp']
        if '://' in sanitized:
            scheme = sanitized.split('://')[0].lower()
            if scheme not in safe_schemes:
                raise ValueError(f"Unsafe URL scheme: {scheme}")
        
        # URL encode the input
        return urllib.parse.quote(sanitized, safe=':/?#[]@!$&\'()*+,;=')
    
    def sanitize_css(self, input_text):
        """
        Sanitizes input for use in CSS contexts to prevent XSS.
        Removes dangerous CSS constructs and characters.
        """
        if not isinstance(input_text, str):
            input_text = str(input_text)
        
        # Remove dangerous CSS patterns
        import re
        
        # Remove CSS comments
        sanitized = re.sub(r'/\*.*?\*/', '', input_text, flags=re.DOTALL)
        
        # Remove dangerous CSS functions and keywords
        dangerous_patterns = [
            r'expression\s*\(',  # IE expression()
            r'javascript\s*:',   # javascript: URLs
            r'vbscript\s*:',     # vbscript: URLs
            r'data\s*:',         # data: URLs
            r'@import',          # @import rules
            r'url\s*\(',         # url() functions
            r'behavior\s*:',     # IE behavior
        ]
        
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        # Remove control characters and null bytes
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\t\n\r')
        
        # Escape backslashes and quotes
        sanitized = sanitized.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
        
        return sanitized


class FormatValidator:
    def __init__(self):
        import re
        
        # Email regex pattern (RFC 5322 compliant but practical)
        self.email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        
        # URL regex pattern
        self.url_pattern = re.compile(
            r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'
        )
    
    def is_valid_email(self, email):
        """
        Validates email format using regex.
        Returns True if email format is valid, False otherwise.
        """
        if not isinstance(email, str):
            return False
        
        # Basic length check
        if len(email) > 254:  # RFC 5321 limit
            return False
        
        # Check for null bytes and control characters
        if any(ord(char) < 32 for char in email if char not in '\t\n\r'):
            return False
        
        # Regex validation
        if not self.email_pattern.match(email):
            return False
        
        # Additional checks
        local, domain = email.split('@', 1)
        
        # Local part checks
        if len(local) > 64:  # RFC 5321 limit
            return False
        if local.startswith('.') or local.endswith('.'):
            return False
        if '..' in local:
            return False
        
        # Domain part checks
        if len(domain) > 253:  # RFC 5321 limit
            return False
        if domain.startswith('.') or domain.endswith('.'):
            return False
        if '..' in domain:
            return False
        
        return True
    
    def is_valid_url(self, url):
        """
        Validates URL format using regex.
        Returns True if URL format is valid, False otherwise.
        """
        if not isinstance(url, str):
            return False
        
        # Basic length check
        if len(url) > 2048:  # Common browser limit
            return False
        
        # Check for null bytes and control characters
        if any(ord(char) < 32 for char in url if char not in '\t\n\r'):
            return False
        
        # Regex validation
        if not self.url_pattern.match(url):
            return False
        
        # Additional security checks
        url_lower = url.lower()
        
        # Block dangerous schemes (should only be http/https due to regex)
        dangerous_schemes = ['javascript:', 'data:', 'vbscript:', 'file:']
        for scheme in dangerous_schemes:
            if url_lower.startswith(scheme):
                return False
        
        return True


class PathValidator:
    def __init__(self):
        import re
        
        # Dangerous path patterns
        self.dangerous_patterns = [
            r'\.\./',      # Basic directory traversal
            r'\.\.\.',     # Triple dot traversal
            r'\.\.\\',     # Windows directory traversal
            r'%2e%2e%2f',  # URL encoded ../
            r'%2e%2e\\',   # URL encoded ..\
            r'%252e',      # Double URL encoded dot
            r'%c0%ae',     # UTF-8 encoded dot
            r'%c1%9c',     # UTF-8 encoded backslash
        ]
        
        self.pattern_regex = re.compile('|'.join(self.dangerous_patterns), re.IGNORECASE)
    
    def prevent_traversal(self, path, allowed_base_path=None):
        """
        Prevents path traversal attacks by sanitizing file paths.
        Returns a safe path or raises ValueError if path is dangerous.
        
        Args:
            path: The file path to validate
            allowed_base_path: Optional base path to restrict access to
        """
        # Step 1: Basic sanitization
        sanitized_path = self._sanitize_path_input(path)
        
        # Step 2: Decode and validate patterns
        decoded_path = self._decode_and_validate_patterns(sanitized_path)
        
        # Step 3: Normalize and validate structure
        normalized_path = self._normalize_and_validate_structure(decoded_path)
        
        # Step 4: Validate against base path if provided
        if allowed_base_path:
            self._validate_base_path_restriction(normalized_path, allowed_base_path)
        
        # Step 5: Final character validation
        self._validate_dangerous_characters(normalized_path)
        
        return normalized_path
    
    def _sanitize_path_input(self, path):
        """Sanitize basic path input"""
        if not isinstance(path, str):
            path = str(path)
        return path.replace('\x00', '')
    
    def _decode_and_validate_patterns(self, path):
        """URL decode path and check for dangerous patterns"""
        import urllib.parse
        
        try:
            decoded_path = urllib.parse.unquote(path)
        except:
            decoded_path = path
        
        if self.pattern_regex.search(decoded_path):
            raise ValueError("Path contains directory traversal patterns")
        
        return decoded_path
    
    def _normalize_and_validate_structure(self, path):
        """Normalize path and validate structure"""
        import os
        
        try:
            normalized_path = os.path.normpath(path)
        except:
            raise ValueError("Invalid path format")
        
        if os.path.isabs(normalized_path):
            raise ValueError("Absolute paths are not allowed")
        
        if self._contains_parent_references(normalized_path):
            raise ValueError("Path attempts to access parent directories")
        
        return normalized_path
    
    def _contains_parent_references(self, path):
        """Check if path contains parent directory references"""
        return (path.startswith('..') or 
                '/..' in path or 
                '\\..\\' in path)
    
    def _validate_base_path_restriction(self, path, allowed_base_path):
        """Validate that path stays within allowed base directory"""
        import os
        
        try:
            base_abs = os.path.abspath(allowed_base_path)
            full_path = os.path.join(base_abs, path)
            resolved_path = os.path.abspath(full_path)
            
            if not self._is_within_base_path(resolved_path, base_abs):
                raise ValueError("Path attempts to access files outside allowed directory")
        except ValueError:
            raise
        except:
            raise ValueError("Path resolution failed")
    
    def _is_within_base_path(self, resolved_path, base_path):
        """Check if resolved path is within base path"""
        import os
        return (resolved_path.startswith(base_path + os.sep) or 
                resolved_path == base_path)
    
    def _validate_dangerous_characters(self, path):
        """Validate path doesn't contain dangerous characters"""
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*']
        for char in dangerous_chars:
            if char in path:
                raise ValueError(f"Path contains dangerous character: {char}")