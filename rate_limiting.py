import time
import threading
from collections import defaultdict, deque
from typing import Dict, Optional, Tuple, Any


class RateLimiter:
    """
    Main rate limiting coordinator class that provides access to different rate limiting algorithms.

    This follows the same pattern as InputValidator - it acts as a factory/coordinator
    that gives you access to specific rate limiting implementations.
    """
    def __init__(self):
        self.sliding_window = SlidingWindowLimiter()
        self.token_bucket = TokenBucketLimiter()


class SlidingWindowLimiter:
    """
    Sliding Window Rate Limiter Implementation

    CONCEPT EXPLANATION:
    The sliding window algorithm tracks requests within a moving time window.
    Unlike fixed windows (which reset at specific intervals), sliding windows
    continuously move forward, providing more accurate rate limiting.

    HOW IT WORKS:
    1. We maintain a queue of timestamps for each client/key
    2. For each new request, we remove old timestamps outside our window
    3. If remaining requests < limit, we allow the request
    4. We add the current timestamp to track this request

    ADVANTAGES:
    - More accurate than fixed windows
    - Prevents burst traffic at window boundaries
    - Memory efficient (only stores timestamps)

    DISADVANTAGES:
    - Memory usage grows with request volume
    - Requires cleanup of old timestamps
    """

    def __init__(self):
        # Dictionary to store request timestamps for each client/key
        # Key: client identifier, Value: deque of timestamps
        self._request_windows: Dict[str, deque] = defaultdict(deque)

        # Thread lock for concurrent access safety
        # CRITICAL: Rate limiters must be thread-safe since multiple requests
        # can hit the same endpoint simultaneously
        self._lock = threading.RLock()

    def is_allowed(self,
                   key: str,
                   limit: int,
                   window_seconds: int,
                   current_time: Optional[float] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if a request should be allowed based on sliding window rate limiting.

        Args:
            key: Unique identifier for the client/resource (e.g., IP address, user ID)
            limit: Maximum number of requests allowed in the window
            window_seconds: Size of the sliding window in seconds
            current_time: Current timestamp (defaults to time.time(), mainly for testing)

        Returns:
            Tuple of (is_allowed: bool, info: dict)
            - is_allowed: True if request should be allowed, False otherwise
            - info: Dictionary with metadata about the rate limiting decision

        SECURITY CONSIDERATIONS:
        - Key should be validated/sanitized before use
        - Consider hash-based keys for privacy
        - Monitor for memory exhaustion attacks
        """

        # Input validation - critical for security
        if not isinstance(key, str) or not key.strip():
            raise ValueError("Key must be a non-empty string")

        if not isinstance(limit, int) or limit <= 0:
            raise ValueError("Limit must be a positive integer")

        if not isinstance(window_seconds, int) or window_seconds <= 0:
            raise ValueError("Window seconds must be a positive integer")

        # Use current time if not provided (allows for testing with specific times)
        if current_time is None:
            current_time = time.time()

        # Thread-safe execution block
        with self._lock:
            # Get the request window for this key (creates empty deque if not exists)
            window = self._request_windows[key]

            # STEP 1: Clean up old requests outside the sliding window
            # This is crucial - we need to remove timestamps older than our window
            cutoff_time = current_time - window_seconds

            # Remove timestamps from the left (oldest) that are outside our window
            # deque.popleft() is O(1), making this operation efficient
            while window and window[0] <= cutoff_time:
                window.popleft()

            # STEP 2: Check if we're within the rate limit
            current_request_count = len(window)

            if current_request_count >= limit:
                # Rate limit exceeded
                # Calculate when the oldest request will expire
                if window:
                    reset_time = window[0] + window_seconds
                    retry_after = max(0, int(reset_time - current_time))
                else:
                    reset_time = None
                    retry_after = 0

                return False, {
                    'allowed': False,
                    'current_requests': current_request_count,
                    'limit': limit,
                    'window_seconds': window_seconds,
                    'retry_after': retry_after,
                    'reset_time': reset_time
                }

            # STEP 3: Allow the request and record it
            # Add current timestamp to the right (newest) of the deque
            window.append(current_time)

            return True, {
                'allowed': True,
                'current_requests': current_request_count + 1,  # Include this request
                'limit': limit,
                'window_seconds': window_seconds,
                'remaining': limit - current_request_count - 1,
                'reset_time': current_time + window_seconds
            }

    def get_current_usage(self, key: str, window_seconds: int,
                         current_time: Optional[float] = None) -> Dict[str, Any]:
        """
        Get current usage statistics for a key without making a request.

        This is useful for monitoring and providing rate limit headers
        without actually consuming a request from the limit.
        """
        if current_time is None:
            current_time = time.time()

        with self._lock:
            if key not in self._request_windows:
                return {
                    'current_requests': 0,
                    'window_seconds': window_seconds
                }

            window = self._request_windows[key]
            cutoff_time = current_time - window_seconds

            # Clean up old requests (same logic as is_allowed)
            while window and window[0] <= cutoff_time:
                window.popleft()

            return {
                'current_requests': len(window),
                'window_seconds': window_seconds,
                'oldest_request_time': window[0] if window else None
            }

    def cleanup_expired_keys(self, max_idle_seconds: int = 3600):
        """
        Clean up keys that haven't been used recently to prevent memory leaks.

        SECURITY NOTE: This prevents memory exhaustion attacks where an attacker
        creates many unique keys to consume server memory.

        Args:
            max_idle_seconds: Remove keys idle longer than this (default 1 hour)
        """
        current_time = time.time()
        cutoff_time = current_time - max_idle_seconds

        with self._lock:
            keys_to_remove = []

            for key, window in self._request_windows.items():
                # If window is empty or all requests are very old, mark for removal
                if not window or (window and window[-1] <= cutoff_time):
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self._request_windows[key]

        return len(keys_to_remove)


class TokenBucketLimiter:
    """
    Token Bucket Rate Limiter Implementation

    CONCEPT EXPLANATION:
    The token bucket algorithm is like a bucket that holds tokens. Tokens are added
    to the bucket at a steady rate (refill rate). Each request consumes one or more tokens.
    If no tokens are available, the request is rejected.

    HOW IT WORKS:
    1. Each client has a bucket with a maximum capacity
    2. Tokens are added to the bucket at a constant rate (e.g., 10 tokens per second)
    3. Each request tries to consume a token
    4. If tokens are available, request is allowed and tokens are consumed
    5. If no tokens available, request is rejected
    6. The bucket never exceeds its maximum capacity (tokens are dropped)

    ADVANTAGES:
    - Allows for burst traffic (if bucket has accumulated tokens)
    - Simple to understand and implement
    - Constant memory usage per client
    - Natural handling of temporary spikes

    DISADVANTAGES:
    - Can allow larger bursts than intended if not tuned properly
    - Requires careful tuning of capacity vs refill rate

    REAL-WORLD EXAMPLE:
    Think of an API that allows 100 requests per minute, but can handle
    bursts of up to 20 requests instantly:
    - Capacity: 20 tokens
    - Refill rate: 100 tokens / 60 seconds = ~1.67 tokens/second
    """

    def __init__(self):
        # Dictionary to store bucket state for each client/key
        # Key: client identifier, Value: bucket state dictionary
        self._buckets: Dict[str, Dict[str, float]] = defaultdict(dict)

        # Thread lock for concurrent access safety
        self._lock = threading.RLock()

    def is_allowed(self,
                   key: str,
                   capacity: int,
                   refill_rate: float,
                   tokens_requested: int = 1,
                   current_time: Optional[float] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if a request should be allowed based on token bucket rate limiting.

        Args:
            key: Unique identifier for the client/resource
            capacity: Maximum number of tokens the bucket can hold
            refill_rate: Rate at which tokens are added (tokens per second)
            tokens_requested: Number of tokens this request needs (default 1)
            current_time: Current timestamp (for testing)

        Returns:
            Tuple of (is_allowed: bool, info: dict)

        PARAMETER EXPLANATION:
        - capacity: Think of this as "burst allowance" - how many requests
          can happen instantly if the bucket is full
        - refill_rate: This is your "sustained rate" - how many requests
          per second you can handle over time
        - tokens_requested: Usually 1, but some requests might cost more
          (e.g., expensive operations cost more tokens)
        """

        # Input validation
        if not isinstance(key, str) or not key.strip():
            raise ValueError("Key must be a non-empty string")

        if not isinstance(capacity, int) or capacity <= 0:
            raise ValueError("Capacity must be a positive integer")

        if not isinstance(refill_rate, (int, float)) or refill_rate <= 0:
            raise ValueError("Refill rate must be a positive number")

        if not isinstance(tokens_requested, int) or tokens_requested <= 0:
            raise ValueError("Tokens requested must be a positive integer")

        if tokens_requested > capacity:
            raise ValueError("Tokens requested cannot exceed bucket capacity")

        if current_time is None:
            current_time = time.time()

        with self._lock:
            # Get or initialize bucket for this key
            bucket = self._buckets[key]

            # Initialize bucket if it's new
            if 'tokens' not in bucket:
                bucket['tokens'] = float(capacity)  # Start with full bucket
                bucket['last_refill'] = current_time

            # STEP 1: Refill the bucket based on time passed
            self._refill_bucket(bucket, capacity, refill_rate, current_time)

            # STEP 2: Check if we have enough tokens
            available_tokens = bucket['tokens']

            if available_tokens >= tokens_requested:
                # STEP 3a: Allow the request and consume tokens
                bucket['tokens'] -= tokens_requested

                return True, {
                    'allowed': True,
                    'tokens_consumed': tokens_requested,
                    'tokens_remaining': bucket['tokens'],
                    'capacity': capacity,
                    'refill_rate': refill_rate,
                    'retry_after': 0
                }
            else:
                # STEP 3b: Reject the request - not enough tokens
                # Calculate when enough tokens will be available
                tokens_needed = tokens_requested - available_tokens
                time_to_wait = tokens_needed / refill_rate

                return False, {
                    'allowed': False,
                    'tokens_requested': tokens_requested,
                    'tokens_available': available_tokens,
                    'tokens_needed': tokens_needed,
                    'capacity': capacity,
                    'refill_rate': refill_rate,
                    'retry_after': int(time_to_wait) + 1  # Round up
                }

    def _refill_bucket(self, bucket: Dict[str, float], capacity: int,
                      refill_rate: float, current_time: float) -> None:
        """
        Refill the token bucket based on elapsed time.

        This is the core logic of the token bucket algorithm:
        1. Calculate how much time has passed since last refill
        2. Calculate how many tokens to add (time * refill_rate)
        3. Add tokens but don't exceed capacity
        4. Update last refill time

        MATHEMATICAL EXPLANATION:
        If refill_rate = 10 tokens/second and 0.5 seconds have passed,
        we should add 10 * 0.5 = 5 tokens to the bucket.
        """
        time_passed = current_time - bucket['last_refill']

        # Calculate tokens to add (can be fractional)
        tokens_to_add = time_passed * refill_rate

        # Add tokens but don't exceed capacity
        bucket['tokens'] = min(capacity, bucket['tokens'] + tokens_to_add)

        # Update last refill time
        bucket['last_refill'] = current_time

    def get_current_tokens(self, key: str, capacity: int, refill_rate: float,
                          current_time: Optional[float] = None) -> Dict[str, Any]:
        """
        Get current token count for a key without consuming tokens.

        This is useful for monitoring and providing rate limit information
        in HTTP headers.
        """
        if current_time is None:
            current_time = time.time()

        with self._lock:
            bucket = self._buckets.get(key, {})

            if 'tokens' not in bucket:
                # New bucket - return full capacity
                return {
                    'tokens': float(capacity),
                    'capacity': capacity,
                    'refill_rate': refill_rate
                }

            # Make a copy to avoid modifying the actual bucket
            bucket_copy = bucket.copy()
            self._refill_bucket(bucket_copy, capacity, refill_rate, current_time)

            return {
                'tokens': bucket_copy['tokens'],
                'capacity': capacity,
                'refill_rate': refill_rate,
                'last_refill': bucket_copy['last_refill']
            }

    def add_tokens(self, key: str, tokens_to_add: int, capacity: int) -> bool:
        """
        Manually add tokens to a bucket (useful for premium features, etc.).

        SECURITY NOTE: This could be abused if not properly protected.
        Only allow trusted sources to call this method.

        Returns True if tokens were added, False if bucket was already full.
        """
        if not isinstance(tokens_to_add, int) or tokens_to_add <= 0:
            raise ValueError("Tokens to add must be a positive integer")

        with self._lock:
            bucket = self._buckets[key]

            if 'tokens' not in bucket:
                bucket['tokens'] = float(capacity)
                bucket['last_refill'] = time.time()
                return False  # Bucket was new/full

            old_tokens = bucket['tokens']
            bucket['tokens'] = min(capacity, bucket['tokens'] + tokens_to_add)

            return bucket['tokens'] > old_tokens

    def cleanup_expired_keys(self, max_idle_seconds: int = 3600):
        """
        Clean up buckets that haven't been used recently.

        Unlike sliding window, token buckets don't naturally expire,
        so we need periodic cleanup to prevent memory leaks.
        """
        current_time = time.time()
        cutoff_time = current_time - max_idle_seconds

        with self._lock:
            keys_to_remove = []

            for key, bucket in self._buckets.items():
                if 'last_refill' in bucket and bucket['last_refill'] <= cutoff_time:
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self._buckets[key]

        return len(keys_to_remove)


# ========== USAGE EXAMPLES AND PATTERNS ==========
#
# This section demonstrates practical usage of the rate limiting implementations
# with real-world scenarios and security considerations.

def demonstrate_sliding_window():
    """
    SLIDING WINDOW EXAMPLE: API Rate Limiting

    Scenario: You have an API endpoint that should allow:
    - Maximum 100 requests per minute per user
    - You want to prevent burst attacks

    Sliding window is perfect for this because it provides smooth,
    accurate rate limiting without the "reset boundary" problem
    of fixed windows.
    """
    print("=== Sliding Window Rate Limiting Demo ===")

    # Initialize the rate limiter
    rate_limiter = RateLimiter()
    sliding = rate_limiter.sliding_window

    # Simulate API requests from different users
    user_1 = "user_192.168.1.100"  # IP-based key
    user_2 = "user_api_key_abc123"  # API key-based key

    # Configuration: 5 requests per 10 seconds (scaled down for demo)
    limit = 5
    window_seconds = 10

    print(f"Rate limit: {limit} requests per {window_seconds} seconds")
    print()

    # Simulate normal usage
    for i in range(3):
        allowed, info = sliding.is_allowed(user_1, limit, window_seconds)
        print(f"User 1 Request {i+1}: {'ALLOWED' if allowed else 'DENIED'}")
        print(f"  Current requests: {info['current_requests']}/{info['limit']}")
        print(f"  Remaining: {info.get('remaining', 0)}")
        print()

    # Simulate burst attack
    print("--- Simulating burst attack ---")
    for i in range(5):
        allowed, info = sliding.is_allowed(user_2, limit, window_seconds)
        status = 'ALLOWED' if allowed else 'DENIED'
        print(f"Burst request {i+1}: {status}")
        if not allowed:
            print(f"  Retry after: {info['retry_after']} seconds")

    print("\n" + "="*50 + "\n")


def demonstrate_token_bucket():
    """
    TOKEN BUCKET EXAMPLE: API with Burst Allowance

    Scenario: You have an API that should:
    - Allow normal rate of 2 requests per second
    - Allow bursts of up to 10 requests when bucket is full
    - Handle expensive operations that cost more tokens

    Token bucket is perfect for this because it naturally handles
    bursts while maintaining a steady long-term rate.
    """
    print("=== Token Bucket Rate Limiting Demo ===")

    # Initialize the rate limiter
    rate_limiter = RateLimiter()
    bucket = rate_limiter.token_bucket

    client_key = "client_premium_user"

    # Configuration: Allow bursts of 10, refill at 2 tokens/second
    capacity = 10
    refill_rate = 2.0  # tokens per second

    print(f"Bucket capacity: {capacity} tokens")
    print(f"Refill rate: {refill_rate} tokens/second")
    print()

    # Simulate burst usage (should work since bucket starts full)
    print("--- Initial burst (bucket starts full) ---")
    for i in range(8):
        allowed, info = bucket.is_allowed(client_key, capacity, refill_rate)
        print(f"Burst request {i+1}: {'ALLOWED' if allowed else 'DENIED'}")
        print(f"  Tokens remaining: {info.get('tokens_remaining', 0):.1f}")
    print()

    # Try to make more requests (should be denied)
    print("--- Continued requests (should be limited) ---")
    for i in range(3):
        allowed, info = bucket.is_allowed(client_key, capacity, refill_rate)
        status = 'ALLOWED' if allowed else 'DENIED'
        print(f"Request {i+1}: {status}")
        if not allowed:
            print(f"  Need {info['tokens_needed']:.1f} more tokens")
            print(f"  Retry after: {info['retry_after']} seconds")

    # Demonstrate expensive operations
    print("\n--- Expensive operation (costs 5 tokens) ---")
    allowed, info = bucket.is_allowed(client_key, capacity, refill_rate,
                                    tokens_requested=5)
    print(f"Expensive request: {'ALLOWED' if allowed else 'DENIED'}")

    print("\n" + "="*50 + "\n")


def demonstrate_security_considerations():
    """
    SECURITY CONSIDERATIONS DEMO

    This demonstrates important security aspects of rate limiting
    that are crucial for real-world applications.
    """
    print("=== Security Considerations Demo ===")

    rate_limiter = RateLimiter()
    sliding = rate_limiter.sliding_window

    # 1. Key Normalization and Validation
    print("1. Key Normalization:")
    try:
        # This should fail - empty key
        sliding.is_allowed("", 10, 60)
    except ValueError as e:
        print(f"   Empty key rejected: {e}")

    try:
        # This should fail - invalid limit
        sliding.is_allowed("user1", -5, 60)
    except ValueError as e:
        print(f"   Invalid limit rejected: {e}")

    # 2. Key-based attack prevention
    print("\n2. Different users are isolated:")
    attacker = "attacker_192.168.1.999"
    legitimate = "user_192.168.1.100"

    # Attacker hits rate limit
    for _ in range(6):
        sliding.is_allowed(attacker, 5, 60)

    # Legitimate user should still work
    allowed, _ = sliding.is_allowed(legitimate, 5, 60)
    print(f"   Legitimate user unaffected: {'YES' if allowed else 'NO'}")

    # 3. Memory management
    print("\n3. Memory cleanup:")
    initial_keys = len(sliding._request_windows)
    cleaned = sliding.cleanup_expired_keys(max_idle_seconds=0)  # Clean all
    print(f"   Cleaned up {cleaned} expired keys")
    print(f"   Keys before: {initial_keys}, after: {len(sliding._request_windows)}")

    print("\n" + "="*50 + "\n")


def demonstrate_real_world_patterns():
    """
    REAL-WORLD INTEGRATION PATTERNS

    Shows how to integrate rate limiting into common application patterns
    like web APIs, authentication systems, etc.
    """
    print("=== Real-World Integration Patterns ===")

    def api_endpoint_middleware(user_id: str, endpoint: str,
                               rate_limiter: RateLimiter) -> dict:
        """
        Example middleware for a web API endpoint.

        This shows how you'd integrate rate limiting into a real application.
        """
        # Different endpoints might have different limits
        endpoint_configs = {
            '/api/login': {'limit': 5, 'window': 300},      # 5 per 5 minutes
            '/api/data': {'limit': 100, 'window': 3600},    # 100 per hour
            '/api/upload': {'limit': 10, 'window': 3600},   # 10 per hour
        }

        config = endpoint_configs.get(endpoint, {'limit': 60, 'window': 3600})

        # Create a unique key combining user and endpoint
        rate_key = f"user:{user_id}:endpoint:{endpoint}"

        # Check rate limit
        allowed, info = rate_limiter.sliding_window.is_allowed(
            rate_key,
            config['limit'],
            config['window']
        )

        # Prepare response headers (common in HTTP APIs)
        headers = {
            'X-RateLimit-Limit': str(config['limit']),
            'X-RateLimit-Window': str(config['window']),
            'X-RateLimit-Remaining': str(info.get('remaining', 0)),
        }

        if not allowed:
            headers['X-RateLimit-Reset'] = str(info.get('reset_time', 0))
            headers['Retry-After'] = str(info.get('retry_after', 60))

        return {
            'allowed': allowed,
            'headers': headers,
            'status_code': 200 if allowed else 429,
            'info': info
        }

    # Demonstrate the middleware
    rate_limiter = RateLimiter()

    print("1. API Middleware Pattern:")

    # Normal API usage
    result = api_endpoint_middleware("user123", "/api/data", rate_limiter)
    print(f"   API call result: {result['status_code']} - {'ALLOWED' if result['allowed'] else 'DENIED'}")
    print(f"   Headers: {result['headers']}")

    # Login endpoint (stricter limits)
    for i in range(6):  # Try to exceed login rate limit
        result = api_endpoint_middleware("user123", "/api/login", rate_limiter)
        if not result['allowed']:
            print(f"   Login attempt {i+1}: BLOCKED (429 Too Many Requests)")
            print(f"   Retry-After: {result['headers']['Retry-After']} seconds")
            break

    print("\n2. Multi-tier Rate Limiting:")
    # You might want different limits for different user types
    def get_user_tier_limits(user_id: str) -> dict:
        """In a real app, this would check user's subscription tier"""
        if user_id.startswith("premium_"):
            return {'capacity': 1000, 'refill_rate': 10.0}  # Premium tier
        else:
            return {'capacity': 100, 'refill_rate': 2.0}    # Free tier

    bucket = rate_limiter.token_bucket

    free_user = "free_user_456"
    premium_user = "premium_user_789"

    free_limits = get_user_tier_limits(free_user)
    premium_limits = get_user_tier_limits(premium_user)

    # Compare what each user can do
    free_allowed, free_info = bucket.is_allowed(
        free_user, free_limits['capacity'], free_limits['refill_rate'],
        tokens_requested=50
    )

    premium_allowed, premium_info = bucket.is_allowed(
        premium_user, premium_limits['capacity'], premium_limits['refill_rate'],
        tokens_requested=50
    )

    print(f"   Free user (50 token request): {'ALLOWED' if free_allowed else 'DENIED'}")
    print(f"   Premium user (50 token request): {'ALLOWED' if premium_allowed else 'DENIED'}")

    print("\n" + "="*50 + "\n")


# Main demonstration function
def run_all_examples():
    """
    Run all the rate limiting examples.

    This gives you a comprehensive overview of both algorithms
    and how to use them in practice.
    """
    print("RATE LIMITING COMPREHENSIVE DEMO")
    print("="*50)
    print()

    demonstrate_sliding_window()
    demonstrate_token_bucket()
    demonstrate_security_considerations()
    demonstrate_real_world_patterns()

    print("ALGORITHM COMPARISON SUMMARY:")
    print("="*50)
    print()
    print("SLIDING WINDOW:")
    print("  ✓ More accurate rate limiting")
    print("  ✓ Prevents boundary burst attacks")
    print("  ✓ Memory usage proportional to requests")
    print("  ✗ Higher memory usage under load")
    print("  ✗ More complex implementation")
    print()
    print("TOKEN BUCKET:")
    print("  ✓ Naturally handles burst traffic")
    print("  ✓ Constant memory per client")
    print("  ✓ Simple to understand and tune")
    print("  ✗ Can allow larger bursts than intended")
    print("  ✗ Requires careful capacity/rate tuning")
    print()
    print("WHEN TO USE WHICH:")
    print("  - Use Sliding Window for strict, accurate rate limiting")
    print("  - Use Token Bucket for APIs that should allow bursts")
    print("  - Use both together for different endpoints in the same app")


if __name__ == "__main__":
    # Run examples if script is executed directly
    run_all_examples()
