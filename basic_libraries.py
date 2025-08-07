from cryptography.fernet import Fernet
import bcrypt
import jwt
import validators
import secrets
import ssl
import sqlparse

# Test 1: Symmetric encryption
key = Fernet.generate_key()
f = Fernet(key)
encrypted = f.encrypt(b"test_payload")
decrypted = f.decrypt(encrypted)
assert decrypted == b"test_payload"

# Test 2: Password hashing
password = b"super_secret_pwd"
hashed = bcrypt.hashpw(password,bcrypt.gensalt())
assert bcrypt.checkpw(password, hashed)

# Test 3: JWT token creation/validation
payload = {"user": "test"}
token = jwt.encode(payload, "secret", algorithm="HS256")
decoded = jwt.decode(token, "secret", algorithms=["HS256"])

# Test 4: Input validation
assert validators.email("test@example.com") == True
assert validators.url("https://example.com") == True

# Test 5: Secure random generation
random_token = secrets.token_urlsafe(32)
assert len(random_token) > 0

# Test 6: TLS context creation
context = ssl.create_default_context()
assert context.check_hostname == True

# Test 7: SQL parsing (injection detection prep)
parsed = sqlparse.parse("SELECT * FROM users WHERE id = 1")[0]
assert len(parsed.tokens) > 0
