"""
DARKSTAR WEB FB TOOL - Utility Module
=======================================
Additional utility functions and helper classes
Enhanced Edition - Extended Module
"""

import os
import sys
import re
import json
import time
import hashlib
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import random
import string
import base64
from urllib.parse import urlencode, urlparse, parse_qs

# ============================================================================
# CONFIGURATION
# ============================================================================

logger = logging.getLogger(__name__)

# ============================================================================
# ENUMS AND DATA CLASSES
# ============================================================================

class EncryptionType(Enum):
    """Supported encryption types"""
    BASE64 = "base64"
    MARSHAL = "marshal"
    ZLIB = "zlib"
    COMBINED = "combined"
    ROT13 = "rot13"
    HEX = "hex"
    URL = "url"

class ProxyType(Enum):
    """Proxy types"""
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"

@dataclass
class ProxyConfig:
    """Proxy configuration"""
    host: str
    port: int
    proxy_type: ProxyType = ProxyType.HTTP
    username: Optional[str] = None
    password: Optional[str] = None
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for requests"""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        else:
            auth = ""
        
        proxy_url = f"{self.proxy_type.value}://{auth}{self.host}:{self.port}"
        return {
            'http': proxy_url,
            'https': proxy_url
        }

@dataclass
class FacebookRequestConfig:
    """Configuration for Facebook API requests"""
    user_agent: str
    cookies: Dict[str, str]
    proxy: Optional[ProxyConfig] = None
    timeout: int = 10
    retry_count: int = 3
    retry_delay: float = 2.0

@dataclass
class BatchResult:
    """Result of batch operation"""
    total: int
    successful: int
    failed: int
    results: List[Any] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        if self.total == 0:
            return 0.0
        return (self.successful / self.total) * 100

# ============================================================================
# STRING UTILITIES
# ============================================================================

def generate_random_string(length: int = 32, include_special: bool = False) -> str:
    """Generate random string
    
    Args:
        length: Length of string to generate
        include_special: Whether to include special characters
        
    Returns:
        Random string
    """
    chars = string.ascii_letters + string.digits
    if include_special:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return ''.join(random.choice(chars) for _ in range(length))

def generate_device_id() -> str:
    """Generate a unique device ID
    
    Returns:
        Device ID string
    """
    timestamp = str(int(time.time()))
    random_str = generate_random_string(16)
    combined = timestamp + random_str
    return hashlib.sha256(combined.encode()).hexdigest()[:32]

def generate_session_id() -> str:
    """Generate a unique session ID
    
    Returns:
        Session ID string
    """
    return hashlib.md5(
        (str(time.time()) + generate_random_string(16)).encode()
    ).hexdigest()

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def format_duration(seconds: float) -> str:
    """Format duration in human readable format
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.2f}h"

def truncate_string(text: str, max_length: int = 50, suffix: str = "...") -> str:
    """Truncate string to maximum length
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix

def clean_html(html: str) -> str:
    """Clean HTML tags from string
    
    Args:
        html: HTML string
        
    Returns:
        Cleaned text
    """
    # Remove script and style tags
    html = re.sub(r'<(script|style).*?>.*?</\1>', '', html, flags=re.DOTALL)
    # Remove HTML tags
    html = re.sub(r'<[^>]+>', '', html)
    # Decode HTML entities
    html = html.replace('&lt;', '<').replace('&gt;', '>')
    html = html.replace('&amp;', '&').replace('&quot;', '"')
    # Clean up whitespace
    html = re.sub(r'\s+', ' ', html).strip()
    return html

def extract_urls(text: str) -> List[str]:
    """Extract URLs from text
    
    Args:
        text: Text to extract URLs from
        
    Returns:
        List of URLs
    """
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .-]*/?'
    return re.findall(url_pattern, text)

def validate_url(url: str) -> bool:
    """Validate URL format
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

# ============================================================================
# FILE UTILITIES
# ============================================================================

def ensure_directory(path: str) -> None:
    """Ensure directory exists, create if not
    
    Args:
        path: Directory path
    """
    os.makedirs(path, exist_ok=True)

def get_file_hash(filepath: str, algorithm: str = 'md5') -> str:
    """Calculate file hash
    
    Args:
        filepath: Path to file
        algorithm: Hash algorithm to use
        
    Returns:
        File hash string
    """
    hash_func = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def safe_delete(filepath: str) -> bool:
    """Safely delete file with error handling
    
    Args:
        filepath: Path to file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
        return True
    except Exception as e:
        logger.error(f"Error deleting file {filepath}: {e}")
        return False

def read_file_lines(filepath: str, encoding: str = 'utf-8') -> Optional[List[str]]:
    """Read file lines with error handling
    
    Args:
        filepath: Path to file
        encoding: File encoding
        
    Returns:
        List of lines or None if error
    """
    try:
        with open(filepath, 'r', encoding=encoding) as f:
            return f.readlines()
    except Exception as e:
        logger.error(f"Error reading file {filepath}: {e}")
        return None

def write_file_lines(filepath: str, lines: List[str], encoding: str = 'utf-8') -> bool:
    """Write lines to file with error handling
    
    Args:
        filepath: Path to file
        lines: Lines to write
        encoding: File encoding
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(filepath, 'w', encoding=encoding) as f:
            f.writelines(lines)
        return True
    except Exception as e:
        logger.error(f"Error writing file {filepath}: {e}")
        return False

def append_to_file(filepath: str, content: str, encoding: str = 'utf-8') -> bool:
    """Append content to file
    
    Args:
        filepath: Path to file
        content: Content to append
        encoding: File encoding
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(filepath, 'a', encoding=encoding) as f:
            f.write(content + '\n')
        return True
    except Exception as e:
        logger.error(f"Error appending to file {filepath}: {e}")
        return False

# ============================================================================
# NETWORK UTILITIES
# ============================================================================

def make_request_with_retry(
    url: str,
    method: str = 'GET',
    config: Optional[FacebookRequestConfig] = None,
    **kwargs
) -> Optional[requests.Response]:
    """Make HTTP request with retry logic
    
    Args:
        url: URL to request
        method: HTTP method
        config: Request configuration
        **kwargs: Additional arguments for requests
        
    Returns:
        Response object or None if failed
    """
    if config is None:
        return None
    
    headers = kwargs.get('headers', {})
    headers['User-Agent'] = config.user_agent
    
    if config.cookies:
        headers['Cookie'] = '; '.join(f'{k}={v}' for k, v in config.cookies.items())
    
    proxies = None
    if config.proxy:
        proxies = config.proxy.to_dict()
    
    for attempt in range(config.retry_count):
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                proxies=proxies,
                timeout=config.timeout,
                **kwargs
            )
            return response
        except Exception as e:
            logger.error(f"Request attempt {attempt + 1} failed: {e}")
            if attempt < config.retry_count - 1:
                time.sleep(config.retry_delay)
    
    return None

def check_internet_connection() -> bool:
    """Check if internet connection is available
    
    Returns:
        True if connected, False otherwise
    """
    try:
        response = requests.get('https://www.google.com', timeout=5)
        return response.status_code == 200
    except:
        return False

def get_public_ip() -> Optional[str]:
    """Get public IP address
    
    Returns:
        Public IP address or None if failed
    """
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        data = response.json()
        return data.get('ip')
    except:
        return None

# ============================================================================
# ENCRYPTION UTILITIES (Extended)
# ============================================================================

def rot13_encrypt(text: str) -> str:
    """ROT13 encryption
    
    Args:
        text: Text to encrypt
        
    Returns:
        Encrypted text
    """
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + 13) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)

def hex_encode(text: str) -> str:
    """Encode text to hexadecimal
    
    Args:
        text: Text to encode
        
    Returns:
        Hexadecimal string
    """
    return text.encode('utf-8').hex()

def hex_decode(hex_string: str) -> str:
    """Decode hexadecimal to text
    
    Args:
        hex_string: Hexadecimal string
        
    Returns:
        Decoded text
    """
    return bytes.fromhex(hex_string).decode('utf-8')

def url_encode(text: str) -> str:
    """URL encode text
    
    Args:
        text: Text to encode
        
    Returns:
        URL encoded string
    """
    from urllib.parse import quote
    return quote(text, safe='')

def url_decode(text: str) -> str:
    """URL decode text
    
    Args:
        text: Text to decode
        
    Returns:
        URL decoded string
    """
    from urllib.parse import unquote
    return unquote(text)

def vigenere_encrypt(text: str, key: str) -> str:
    """Vigenère cipher encryption
    
    Args:
        text: Text to encrypt
        key: Encryption key
        
    Returns:
        Encrypted text
    """
    result = []
    key_repeated = (key * ((len(text) // len(key)) + 1))[:len(text)]
    
    for i, char in enumerate(text):
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            key_char = key_repeated[i].upper()
            key_shift = ord(key_char) - ord('A')
            result.append(chr((ord(char) - base + key_shift) % 26 + base))
        else:
            result.append(char)
    
    return ''.join(result)

def vigenere_decrypt(text: str, key: str) -> str:
    """Vigenère cipher decryption
    
    Args:
        text: Text to decrypt
        key: Decryption key
        
    Returns:
        Decrypted text
    """
    result = []
    key_repeated = (key * ((len(text) // len(key)) + 1))[:len(text)]
    
    for i, char in enumerate(text):
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            key_char = key_repeated[i].upper()
            key_shift = ord(key_char) - ord('A')
            result.append(chr((ord(char) - base - key_shift) % 26 + base))
        else:
            result.append(char)
    
    return ''.join(result)

def xor_encrypt(text: str, key: str) -> str:
    """XOR encryption
    
    Args:
        text: Text to encrypt
        key: Encryption key
        
    Returns:
        Encrypted text (hex encoded)
    """
    result = []
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    
    for i, char in enumerate(text):
        encrypted_byte = ord(char) ^ key_bytes[i % key_len]
        result.append(f'{encrypted_byte:02x}')
    
    return ''.join(result)

def xor_decrypt(hex_string: str, key: str) -> str:
    """XOR decryption
    
    Args:
        hex_string: Hex encoded encrypted text
        key: Decryption key
        
    Returns:
        Decrypted text
    """
    result = []
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    
    for i in range(0, len(hex_string), 2):
        encrypted_byte = int(hex_string[i:i+2], 16)
        decrypted_byte = encrypted_byte ^ key_bytes[(i // 2) % key_len]
        result.append(chr(decrypted_byte))
    
    return ''.join(result)

# ============================================================================
# FACEBOOK SPECIFIC UTILITIES
# ============================================================================

def extract_fb_id_from_url(url: str) -> Optional[str]:
    """Extract Facebook ID from URL
    
    Args:
        url: Facebook URL
        
    Returns:
        Facebook ID or None if not found
    """
    patterns = [
        r'facebook\.com/(\d+)',
        r'profile\.php\?id=(\d+)',
        r'facebook\.com/([^/?]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    
    return None

def validate_fb_token(token: str) -> bool:
    """Basic validation of Facebook access token
    
    Args:
        token: Access token string
        
    Returns:
        True if token appears valid, False otherwise
    """
    # Basic format check
    if not token or len(token) < 50:
        return False
    
    # Check for common token prefixes
    valid_prefixes = ['EAA', 'EAAB', 'EAAD', 'EAAU']
    return any(token.startswith(prefix) for prefix in valid_prefixes)

def parse_fb_cookies(cookie_string: str) -> Dict[str, str]:
    """Parse Facebook cookie string
    
    Args:
        cookie_string: Cookie string
        
    Returns:
        Dictionary of cookies
    """
    cookies = {}
    if not cookie_string:
        return cookies
    
    for item in cookie_string.split(';'):
        item = item.strip()
        if '=' in item:
            key, value = item.split('=', 1)
            cookies[key.strip()] = value.strip()
    
    return cookies

def extract_fb_dtsg(cookies: Dict[str, str], html_content: str = '') -> Optional[str]:
    """Extract fb_dtsg token from cookies or HTML
    
    Args:
        cookies: Cookie dictionary
        html_content: HTML content to search
        
    Returns:
        fb_dtsg token or None if not found
    """
    # Try to get from cookies first
    if 'fb_dtsg' in cookies:
        return cookies['fb_dtsg']
    
    if html_content:
        # Try to extract from HTML
        patterns = [
            r'"fb_dtsg":"([^"]+)"',
            r'"token":"([^"]+)"',
            r'name="fb_dtsg" value="([^"]+)"'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content)
            if match:
                return match.group(1)
    
    return None

# ============================================================================
# DATA VALIDATION
# ============================================================================

def validate_email(email: str) -> bool:
    """Validate email address
    
    Args:
        email: Email address
        
    Returns:
        True if valid, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone: str) -> bool:
    """Validate phone number
    
    Args:
        phone: Phone number
        
    Returns:
        True if valid, False otherwise
    """
    # Remove common separators
    phone = re.sub(r'[\s\-\(\)\+]', '', phone)
    # Check if it's all digits and reasonable length
    return phone.isdigit() and 10 <= len(phone) <= 15

def validate_facebook_id(fb_id: str) -> bool:
    """Validate Facebook ID
    
    Args:
        fb_id: Facebook ID
        
    Returns:
        True if valid, False otherwise
    """
    # Facebook IDs are typically numeric but can sometimes be usernames
    return bool(re.match(r'^[\w.]+$', fb_id))

# ============================================================================
# BATCH PROCESSING
# ============================================================================

def process_batch(
    items: List[Any],
    processor: callable,
    batch_size: int = 10,
    delay: float = 1.0
) -> BatchResult:
    """Process items in batches
    
    Args:
        items: Items to process
        processor: Function to process each item
        batch_size: Number of items per batch
        delay: Delay between batches
        
    Returns:
        BatchResult object
    """
    result = BatchResult(total=len(items), successful=0, failed=0)
    
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        
        for item in batch:
            try:
                processed = processor(item)
                result.results.append(processed)
                result.successful += 1
            except Exception as e:
                result.failed += 1
                result.errors.append(str(e))
                logger.error(f"Error processing item: {e}")
        
        if i + batch_size < len(items):
            time.sleep(delay)
    
    return result

# ============================================================================
# PROGRESS TRACKING
# ============================================================================

class ProgressTracker:
    """Track progress of long-running operations"""
    
    def __init__(self, total: int, description: str = "Processing"):
        """Initialize progress tracker
        
        Args:
            total: Total number of items
            description: Description of operation
        """
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
        self.last_update = 0
    
    def update(self, increment: int = 1) -> None:
        """Update progress
        
        Args:
            increment: Number of items completed
        """
        self.current += increment
        self.last_update = time.time()
    
    def get_progress(self) -> float:
        """Get progress percentage
        
        Returns:
            Progress percentage (0-100)
        """
        if self.total == 0:
            return 0.0
        return (self.current / self.total) * 100
    
    def get_eta(self) -> Optional[float]:
        """Get estimated time remaining
        
        Returns:
            ETA in seconds or None if cannot calculate
        """
        if self.current == 0:
            return None
        
        elapsed = self.last_update - self.start_time
        rate = self.current / elapsed
        
        if rate == 0:
            return None
        
        remaining = self.total - self.current
        return remaining / rate
    
    def is_complete(self) -> bool:
        """Check if operation is complete
        
        Returns:
            True if complete, False otherwise
        """
        return self.current >= self.total
    
    def __str__(self) -> str:
        """String representation of progress"""
        progress = self.get_progress()
        eta = self.get_eta()
        eta_str = format_duration(eta) if eta else "Calculating..."
        
        return f"{self.description}: {progress:.1f}% ({self.current}/{self.total}) - ETA: {eta_str}"

# ============================================================================
# LOGGING UTILITIES
# ============================================================================

def setup_logger(
    name: str,
    log_file: str,
    level: int = logging.INFO,
    format_string: Optional[str] = None
) -> logging.Logger:
    """Setup logger with file and console handlers
    
    Args:
        name: Logger name
        log_file: Path to log file
        level: Logging level
        format_string: Custom format string
        
    Returns:
        Configured logger
    """
    if format_string is None:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers = []
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(format_string)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(format_string)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger

def log_function_call(logger: logging.Logger):
    """Decorator to log function calls
    
    Args:
        logger: Logger instance
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger.info(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
            try:
                result = func(*args, **kwargs)
                logger.info(f"{func.__name__} returned successfully")
                return result
            except Exception as e:
                logger.error(f"{func.__name__} failed with error: {e}")
                raise
        return wrapper
    return decorator

# ============================================================================
# TIME UTILITIES
# ============================================================================

def get_timestamp(format_string: str = '%Y-%m-%d %H:%M:%S') -> str:
    """Get current timestamp
    
    Args:
        format_string: Timestamp format
        
    Returns:
        Formatted timestamp string
    """
    return datetime.now().strftime(format_string)

def parse_timestamp(timestamp: str, format_string: str = '%Y-%m-%d %H:%M:%S') -> Optional[datetime]:
    """Parse timestamp string
    
    Args:
        timestamp: Timestamp string
        format_string: Timestamp format
        
    Returns:
        DateTime object or None if parsing failed
    """
    try:
        return datetime.strptime(timestamp, format_string)
    except:
        return None

def time_ago(timestamp: datetime) -> str:
    """Get human readable time ago string
    
    Args:
        timestamp: DateTime object
        
    Returns:
        Human readable time ago string
    """
    now = datetime.now()
    delta = now - timestamp
    
    seconds = delta.total_seconds()
    
    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif seconds < 604800:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days > 1 else ''} ago"
    elif seconds < 2592000:
        weeks = int(seconds / 604800)
        return f"{weeks} week{'s' if weeks > 1 else ''} ago"
    elif seconds < 31536000:
        months = int(seconds / 2592000)
        return f"{months} month{'s' if months > 1 else ''} ago"
    else:
        years = int(seconds / 31536000)
        return f"{years} year{'s' if years > 1 else ''} ago"

def is_future_timestamp(timestamp: datetime) -> bool:
    """Check if timestamp is in the future
    
    Args:
        timestamp: DateTime object
        
    Returns:
        True if future, False otherwise
    """
    return timestamp > datetime.now()

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

class ConfigManager:
    """Manage configuration files"""
    
    def __init__(self, config_file: str):
        """Initialize config manager
        
        Args:
            config_file: Path to config file
        """
        self.config_file = config_file
        self.config = {}
        self.load()
    
    def load(self) -> None:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.config = {}
    
    def save(self) -> bool:
        """Save configuration to file
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value
        
        Args:
            key: Configuration key
            value: Value to set
        """
        self.config[key] = value
    
    def remove(self, key: str) -> bool:
        """Remove configuration value
        
        Args:
            key: Configuration key
            
        Returns:
            True if removed, False if not found
        """
        if key in self.config:
            del self.config[key]
            return True
        return False

# ============================================================================
# CACHE MANAGEMENT
# ============================================================================

class SimpleCache:
    """Simple in-memory cache with TTL"""
    
    def __init__(self, ttl: int = 3600):
        """Initialize cache
        
        Args:
            ttl: Time to live in seconds
        """
        self.cache: Dict[str, Tuple[Any, float]] = {}
        self.ttl = ttl
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if expired/not found
        """
        if key not in self.cache:
            return None
        
        value, timestamp = self.cache[key]
        
        if time.time() - timestamp > self.ttl:
            del self.cache[key]
            return None
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache
        """
        self.cache[key] = (value, time.time())
    
    def clear(self) -> None:
        """Clear all cache entries"""
        self.cache.clear()
    
    def remove_expired(self) -> None:
        """Remove expired entries from cache"""
        current_time = time.time()
        expired_keys = [
            key for key, (_, timestamp) in self.cache.items()
            if current_time - timestamp > self.ttl
        ]
        for key in expired_keys:
            del self.cache[key]

# ============================================================================
# EXPORTED FUNCTIONS
# ============================================================================

__all__ = [
    # Enums
    'EncryptionType',
    'ProxyType',
    # Data Classes
    'ProxyConfig',
    'FacebookRequestConfig',
    'BatchResult',
    # String Utilities
    'generate_random_string',
    'generate_device_id',
    'generate_session_id',
    'format_file_size',
    'format_duration',
    'truncate_string',
    'clean_html',
    'extract_urls',
    'validate_url',
    # File Utilities
    'ensure_directory',
    'get_file_hash',
    'safe_delete',
    'read_file_lines',
    'write_file_lines',
    'append_to_file',
    # Network Utilities
    'make_request_with_retry',
    'check_internet_connection',
    'get_public_ip',
    # Encryption Utilities
    'rot13_encrypt',
    'hex_encode',
    'hex_decode',
    'url_encode',
    'url_decode',
    'vigenere_encrypt',
    'vigenere_decrypt',
    'xor_encrypt',
    'xor_decrypt',
    # Facebook Utilities
    'extract_fb_id_from_url',
    'validate_fb_token',
    'parse_fb_cookies',
    'extract_fb_dtsg',
    # Validation
    'validate_email',
    'validate_phone',
    'validate_facebook_id',
    # Batch Processing
    'process_batch',
    # Progress Tracking
    'ProgressTracker',
    # Logging
    'setup_logger',
    'log_function_call',
    # Time Utilities
    'get_timestamp',
    'parse_timestamp',
    'time_ago',
    'is_future_timestamp',
    # Configuration
    'ConfigManager',
    # Cache
    'SimpleCache',
]