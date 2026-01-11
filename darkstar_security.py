"""
DARKSTAR WEB FB TOOL - Security Module
=======================================
Security and encryption utilities
Enhanced Edition - Extended Module
"""

import os
import sys
import json
import hashlib
import logging
import secrets
import base64
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import re

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
    from Cryptodome.Util.Padding import pad, unpad
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Signature import pkcs1_15
    from Cryptodome.Hash import SHA256
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256

# ============================================================================
# CONFIGURATION
# ============================================================================

logger = logging.getLogger(__name__)

# ============================================================================
# ENUMS AND DATA CLASSES
# ============================================================================

class EncryptionAlgorithm(Enum):
    """Encryption algorithms"""
    AES_256_CBC = "AES-256-CBC"
    AES_256_GCM = "AES-256-GCM"
    RSA_2048 = "RSA-2048"
    RSA_4096 = "RSA-4096"

class HashAlgorithm(Enum):
    """Hash algorithms"""
    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"

@dataclass
class EncryptionResult:
    """Result of encryption operation"""
    success: bool
    encrypted_data: bytes = b""
    iv: bytes = b""
    salt: bytes = b""
    tag: bytes = b""
    error_message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'success': self.success,
            'encrypted_data': base64.b64encode(self.encrypted_data).decode() if self.encrypted_data else "",
            'iv': base64.b64encode(self.iv).decode() if self.iv else "",
            'salt': base64.b64encode(self.salt).decode() if self.salt else "",
            'tag': base64.b64encode(self.tag).decode() if self.tag else "",
            'error_message': self.error_message
        }

@dataclass
class DecryptionResult:
    """Result of decryption operation"""
    success: bool
    decrypted_data: str = ""
    error_message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'success': self.success,
            'decrypted_data': self.decrypted_data,
            'error_message': self.error_message
        }

@dataclass
class SecurityConfig:
    """Security configuration"""
    use_aes_gcm: bool = True
    key_length: int = 32  # 256 bits
    iterations: int = 100000
    salt_length: int = 16
    iv_length: int = 12
    enable_compression: bool = False

# ============================================================================
# HASH UTILITIES
# ============================================================================

class HashGenerator:
    """Generate hashes for data"""
    
    @staticmethod
    def hash_string(
        data: str,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256
    ) -> str:
        """Hash a string
        
        Args:
            data: String to hash
            algorithm: Hash algorithm to use
            
        Returns:
            Hash string
        """
        hash_obj = {
            HashAlgorithm.MD5: hashlib.md5,
            HashAlgorithm.SHA1: hashlib.sha1,
            HashAlgorithm.SHA256: hashlib.sha256,
            HashAlgorithm.SHA384: hashlib.sha384,
            HashAlgorithm.SHA512: hashlib.sha512,
        }[algorithm](data.encode())
        
        return hash_obj.hexdigest()
    
    @staticmethod
    def hash_file(
        filepath: str,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        chunk_size: int = 65536
    ) -> Optional[str]:
        """Hash a file
        
        Args:
            filepath: Path to file
            algorithm: Hash algorithm to use
            chunk_size: Size of chunks to read
            
        Returns:
            Hash string or None if error
        """
        try:
            hash_obj = {
                HashAlgorithm.MD5: hashlib.md5,
                HashAlgorithm.SHA1: hashlib.sha1,
                HashAlgorithm.SHA256: hashlib.sha256,
                HashAlgorithm.SHA384: hashlib.sha384,
                HashAlgorithm.SHA512: hashlib.sha512,
            }[algorithm]()
            
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(chunk_size), b''):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing file: {e}")
            return None
    
    @staticmethod
    def generate_key_from_password(
        password: str,
        salt: bytes = None,
        config: SecurityConfig = None
    ) -> Tuple[bytes, bytes]:
        """Generate encryption key from password
        
        Args:
            password: Password string
            salt: Salt for key derivation
            config: Security configuration
            
        Returns:
            Tuple of (key, salt)
        """
        if config is None:
            config = SecurityConfig()
        
        if salt is None:
            salt = get_random_bytes(config.salt_length)
        
        key = PBKDF2(
            password,
            salt,
            dkLen=config.key_length,
            count=config.iterations,
            hmac_hash_module=SHA256
        )
        
        return key, salt

# ============================================================================
# AES ENCRYPTION
# ============================================================================

class AESEncryption:
    """AES encryption/decryption"""
    
    def __init__(self, config: SecurityConfig = None):
        """Initialize AES encryption
        
        Args:
            config: Security configuration
        """
        self.config = config or SecurityConfig()
    
    def encrypt(
        self,
        plaintext: str,
        password: str
    ) -> EncryptionResult:
        """Encrypt plaintext
        
        Args:
            plaintext: Text to encrypt
            password: Password for encryption
            
        Returns:
            EncryptionResult object
        """
        try:
            # Generate key from password
            key, salt = HashGenerator.generate_key_from_password(
                password,
                config=self.config
            )
            
            # Generate IV
            iv = get_random_bytes(self.config.iv_length)
            
            # Create cipher
            if self.config.use_aes_gcm:
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
                return EncryptionResult(
                    success=True,
                    encrypted_data=ciphertext,
                    iv=iv,
                    salt=salt,
                    tag=tag
                )
            else:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                padded_data = pad(plaintext.encode(), AES.block_size)
                ciphertext = cipher.encrypt(padded_data)
                return EncryptionResult(
                    success=True,
                    encrypted_data=ciphertext,
                    iv=iv,
                    salt=salt
                )
                
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return EncryptionResult(
                success=False,
                error_message=str(e)
            )
    
    def decrypt(
        self,
        encrypted_data: bytes,
        password: str,
        iv: bytes,
        salt: bytes,
        tag: bytes = None
    ) -> DecryptionResult:
        """Decrypt encrypted data
        
        Args:
            encrypted_data: Encrypted data
            password: Password for decryption
            iv: Initialization vector
            salt: Salt used for key derivation
            tag: Authentication tag (for GCM mode)
            
        Returns:
            DecryptionResult object
        """
        try:
            # Generate key from password
            key, _ = HashGenerator.generate_key_from_password(
                password,
                salt=salt,
                config=self.config
            )
            
            # Create cipher
            if self.config.use_aes_gcm:
                if tag is None:
                    return DecryptionResult(
                        success=False,
                        error_message="Tag required for GCM mode"
                    )
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                plaintext = cipher.decrypt_and_verify(encrypted_data, tag)
            else:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                padded_plaintext = cipher.decrypt(encrypted_data)
                plaintext = unpad(padded_plaintext, AES.block_size)
            
            return DecryptionResult(
                success=True,
                decrypted_data=plaintext.decode()
            )
            
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return DecryptionResult(
                success=False,
                error_message=str(e)
            )

# ============================================================================
# RSA ENCRYPTION
# ============================================================================

class RSAEncryption:
    """RSA encryption/decryption"""
    
    def __init__(self, key_size: int = 2048):
        """Initialize RSA encryption
        
        Args:
            key_size: RSA key size (2048 or 4096)
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """Generate RSA key pair
        
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        try:
            key = RSA.generate(self.key_size)
            private_key_pem = key.export_key()
            public_key_pem = key.publickey().export_key()
            
            self.private_key = key
            self.public_key = key.publickey()
            
            return private_key_pem, public_key_pem
            
        except Exception as e:
            logger.error(f"Error generating key pair: {e}")
            return b"", b""
    
    def load_keys(
        self,
        private_key_pem: bytes = None,
        public_key_pem: bytes = None
    ) -> bool:
        """Load RSA keys from PEM format
        
        Args:
            private_key_pem: Private key in PEM format
            public_key_pem: Public key in PEM format
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if private_key_pem:
                self.private_key = RSA.import_key(private_key_pem)
            if public_key_pem:
                self.public_key = RSA.import_key(public_key_pem)
            return True
        except Exception as e:
            logger.error(f"Error loading keys: {e}")
            return False
    
    def encrypt(self, plaintext: str) -> EncryptionResult:
        """Encrypt plaintext with public key
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            EncryptionResult object
        """
        try:
            if not self.public_key:
                return EncryptionResult(
                    success=False,
                    error_message="Public key not loaded"
                )
            
            # RSA can only encrypt small amounts of data
            # Use hybrid encryption for larger data
            if len(plaintext) > 190:
                # Generate random AES key
                aes_key = get_random_bytes(32)
                aes = AESEncryption()
                
                # Encrypt data with AES
                aes_result = aes.encrypt(plaintext, aes_key.hex())
                
                # Encrypt AES key with RSA
                encrypted_key = self.public_key.encrypt(
                    aes_key,
                    None
                )[0]
                
                return EncryptionResult(
                    success=True,
                    encrypted_data=aes_result.encrypted_data,
                    iv=aes_result.iv,
                    tag=aes_result.tag
                )
            else:
                encrypted_data = self.public_key.encrypt(
                    plaintext.encode(),
                    None
                )[0]
                
                return EncryptionResult(
                    success=True,
                    encrypted_data=encrypted_data
                )
                
        except Exception as e:
            logger.error(f"RSA encryption error: {e}")
            return EncryptionResult(
                success=False,
                error_message=str(e)
            )
    
    def decrypt(
        self,
        encrypted_data: bytes,
        encrypted_key: bytes = None,
        iv: bytes = None,
        tag: bytes = None
    ) -> DecryptionResult:
        """Decrypt encrypted data with private key
        
        Args:
            encrypted_data: Encrypted data
            encrypted_key: Encrypted AES key (for hybrid encryption)
            iv: Initialization vector (for hybrid encryption)
            tag: Authentication tag (for hybrid encryption)
            
        Returns:
            DecryptionResult object
        """
        try:
            if not self.private_key:
                return DecryptionResult(
                    success=False,
                    error_message="Private key not loaded"
                )
            
            # Check if this is hybrid encryption
            if encrypted_key and iv:
                # Decrypt AES key with RSA
                aes_key = self.private_key.decrypt(encrypted_key)
                
                # Decrypt data with AES
                aes = AESEncryption()
                result = aes.decrypt(encrypted_data, aes_key.hex(), iv, tag, tag)
                
                return result
            else:
                plaintext = self.private_key.decrypt(encrypted_data)
                return DecryptionResult(
                    success=True,
                    decrypted_data=plaintext.decode()
                )
                
        except Exception as e:
            logger.error(f"RSA decryption error: {e}")
            return DecryptionResult(
                success=False,
                error_message=str(e)
            )
    
    def sign(self, data: str) -> Optional[bytes]:
        """Sign data with private key
        
        Args:
            data: Data to sign
            
        Returns:
            Signature or None if error
        """
        try:
            if not self.private_key:
                return None
            
            h = SHA256.new(data.encode())
            signer = pkcs1_15.new(self.private_key)
            signature = signer.sign(h)
            return signature
            
        except Exception as e:
            logger.error(f"Signing error: {e}")
            return None
    
    def verify(self, data: str, signature: bytes) -> bool:
        """Verify signature with public key
        
        Args:
            data: Original data
            signature: Signature to verify
            
        Returns:
            True if valid, False otherwise
        """
        try:
            if not self.public_key:
                return False
            
            h = SHA256.new(data.encode())
            verifier = pkcs1_15.new(self.public_key)
            
            try:
                verifier.verify(h, signature)
                return True
            except:
                return False
                
        except Exception as e:
            logger.error(f"Verification error: {e}")
            return False

# ============================================================================
# SECURE STORAGE
# ============================================================================

class SecureStorage:
    """Secure storage for sensitive data"""
    
    def __init__(self, password: str, config: SecurityConfig = None):
        """Initialize secure storage
        
        Args:
            password: Master password
            config: Security configuration
        """
        self.password = password
        self.config = config or SecurityConfig()
        self.aes = AESEncryption(config)
        self.data: Dict[str, str] = {}
    
    def store(self, key: str, value: str) -> bool:
        """Store value securely
        
        Args:
            key: Storage key
            value: Value to store
            
        Returns:
            True if successful, False otherwise
        """
        try:
            result = self.aes.encrypt(value, self.password)
            if result.success:
                self.data[key] = result.to_dict()
                return True
            return False
        except Exception as e:
            logger.error(f"Error storing data: {e}")
            return False
    
    def retrieve(self, key: str) -> Optional[str]:
        """Retrieve value from storage
        
        Args:
            key: Storage key
            
        Returns:
            Decrypted value or None if not found/error
        """
        try:
            if key not in self.data:
                return None
            
            encrypted_data = self.data[key]
            result = self.aes.decrypt(
                base64.b64decode(encrypted_data['encrypted_data']),
                self.password,
                base64.b64decode(encrypted_data['iv']),
                base64.b64decode(encrypted_data['salt']),
                base64.b64decode(encrypted_data['tag']) if encrypted_data.get('tag') else None
            )
            
            if result.success:
                return result.decrypted_data
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving data: {e}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete value from storage
        
        Args:
            key: Storage key
            
        Returns:
            True if deleted, False if not found
        """
        if key in self.data:
            del self.data[key]
            return True
        return False
    
    def export_to_file(self, filepath: str) -> bool:
        """Export encrypted storage to file
        
        Args:
            filepath: Path to save file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(filepath, 'w') as f:
                json.dump(self.data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error exporting storage: {e}")
            return False
    
    def import_from_file(self, filepath: str) -> bool:
        """Import encrypted storage from file
        
        Args:
            filepath: Path to load file from
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(filepath, 'r') as f:
                self.data = json.load(f)
            return True
        except Exception as e:
            logger.error(f"Error importing storage: {e}")
            return False

# ============================================================================
# PASSWORD GENERATOR
# ============================================================================

class PasswordGenerator:
    """Generate secure passwords"""
    
    def __init__(self):
        """Initialize password generator"""
        pass
    
    def generate_password(
        self,
        length: int = 16,
        include_uppercase: bool = True,
        include_lowercase: bool = True,
        include_digits: bool = True,
        include_special: bool = True,
        exclude_similar: bool = True
    ) -> str:
        """Generate secure random password
        
        Args:
            length: Password length
            include_uppercase: Include uppercase letters
            include_lowercase: Include lowercase letters
            include_digits: Include digits
            include_special: Include special characters
            exclude_similar: Exclude similar characters (0, O, 1, l, I)
            
        Returns:
            Generated password
        """
        import string
        
        chars = ""
        
        if include_lowercase:
            chars += string.ascii_lowercase
        if include_uppercase:
            chars += string.ascii_uppercase
        if include_digits:
            chars += string.digits
        if include_special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if exclude_similar:
            chars = chars.translate(str.maketrans('', '', '0O1lI'))
        
        if not chars:
            chars = string.ascii_letters + string.digits
        
        # Ensure password meets requirements
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        return password
    
    def generate_passphrase(
        self,
        word_count: int = 4,
        separator: str = "-",
        capitalize: bool = False
    ) -> str:
        """Generate memorable passphrase
        
        Args:
            word_count: Number of words
            separator: Separator between words
            capitalize: Capitalize first letter of each word
            
        Returns:
            Generated passphrase
        """
        # Common words for passphrases
        words = [
            "correct", "horse", "battery", "staple", "cloud", "mountain", "river",
            "forest", "ocean", "desert", "valley", "castle", "dragon", "phoenix",
            "shadow", "lightning", "thunder", "whisper", "echo", "harmony", "melody",
            "rhythm", "crystal", "diamond", "emerald", "silver", "golden", "bronze",
            "marble", "granite", "velvet", "silk", "cotton", "linen", "denim"
        ]
        
        selected_words = secrets.SystemRandom().sample(words, min(word_count, len(words)))
        
        if capitalize:
            selected_words = [word.capitalize() for word in selected_words]
        
        return separator.join(selected_words)

# ============================================================================
# VALIDATION
# ============================================================================

class SecurityValidator:
    """Validate security-related inputs"""
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, str, int]:
        """Validate password strength
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_strong, message, strength_score)
        """
        score = 0
        issues = []
        
        # Length check
        if len(password) < 8:
            issues.append("Password is too short (minimum 8 characters)")
        elif len(password) >= 12:
            score += 2
        else:
            score += 1
        
        # Complexity checks
        if re.search(r'[a-z]', password):
            score += 1
        else:
            issues.append("Missing lowercase letters")
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            issues.append("Missing uppercase letters")
        
        if re.search(r'\d', password):
            score += 1
        else:
            issues.append("Missing digits")
        
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            score += 2
        else:
            issues.append("Missing special characters")
        
        # Overall strength
        if score >= 6:
            is_strong = True
            message = "Strong password"
        elif score >= 4:
            is_strong = True
            message = "Moderate password " + (", ".join(issues) if issues else "")
        else:
            is_strong = False
            message = "Weak password: " + ", ".join(issues)
        
        return is_strong, message, score
    
    @staticmethod
    def validate_token_format(token: str) -> bool:
        """Validate Facebook token format
        
        Args:
            token: Token to validate
            
        Returns:
            True if valid format, False otherwise
        """
        if not token or len(token) < 50:
            return False
        
        valid_prefixes = ['EAA', 'EAAB', 'EAAD', 'EAAU', 'EAABw', 'EAAAG', 'EAAAH', 'EAAA']
        return any(token.startswith(prefix) for prefix in valid_prefixes)
    
    @staticmethod
    def sanitize_input(input_string: str, max_length: int = 1000) -> str:
        """Sanitize user input
        
        Args:
            input_string: Input to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not input_string:
            return ""
        
        # Trim to max length
        input_string = input_string[:max_length]
        
        # Remove null bytes
        input_string = input_string.replace('\x00', '')
        
        # Remove control characters except newlines and tabs
        input_string = ''.join(char for char in input_string if char.isprintable() or char in '\n\t')
        
        # Strip leading/trailing whitespace
        input_string = input_string.strip()
        
        return input_string

# ============================================================================
# EXPORTED FUNCTIONS
# ============================================================================

__all__ = [
    # Enums
    'EncryptionAlgorithm',
    'HashAlgorithm',
    # Data Classes
    'EncryptionResult',
    'DecryptionResult',
    'SecurityConfig',
    # Hash
    'HashGenerator',
    # AES Encryption
    'AESEncryption',
    # RSA Encryption
    'RSAEncryption',
    # Secure Storage
    'SecureStorage',
    # Password
    'PasswordGenerator',
    # Validation
    'SecurityValidator',
]