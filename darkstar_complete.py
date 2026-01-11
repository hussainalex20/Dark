#!/usr/bin/env python3
"""
DARKSTAR FACEBOOK TOOL - COMPLETE VERSION
A comprehensive Facebook automation tool with multiple features
Version: 8.07.06 (Enhanced)
Author: SahiiL (DarkStar)
Last Updated: 2025-01-29

This tool includes:
- Token generation and validation
- Cookie conversion
- Post and comment automation
- Message flooding
- Group member extraction
- Page token generation
- Encryption tools
- And much more...
"""

import base64
import json
import re
import uuid
import io
import struct
import time
import urllib3
import requests
import colorama
from colorama import Fore, Back, Style, init
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import pyotp
import random
import string
import sys
import os
from urllib.parse import urlparse, parse_qs, unquote, quote
import pyfiglet
import rich
from rich import box
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
import marshal
import zlib
from rich.text import Text
import signal
import subprocess
import hashlib
from requests import exceptions
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import queue
from typing import Dict, List, Optional, Tuple, Any
import logging
from dataclasses import dataclass, field
from enum import Enum

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)
console = Console()

# Constants
SAVE_DIR = '/sdcard/EncryptedFiles'
GITHUB_APPROVAL_URL = 'https://raw.githubusercontent.com/darkstar602/Web-panel-approval-key/main/approval.txt'
APP_VERSION = '8.07.06'
TOOL_NAME = 'DARKSTAR'

# Color definitions
RED = '\x1b[1;31m'
GREEN = '\x1b[1;32m'
YELLOW = '\x1b[1;33m'
BLUE = '\x1b[1;34m'
MAGENTA = '\x1b[1;35m'
CYAN = '\x1b[1;36m'
WHITE = '\x1b[1;37m'
RESET = '\x1b[0m'

PRIMARY_COLOR = Fore.CYAN
INPUT_COLOR = Fore.YELLOW
LINE_COLOR = Fore.MAGENTA
ERROR_COLOR = Fore.RED
SUCCESS_COLOR = Fore.GREEN
WHITE_COLOR = Fore.WHITE

# User Agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    '[FBAN/FB4A;FBAV/520.0.0.45.73;FBBV/751323900;FBDM/{density=3.0,width=1080,height=2400};FBLC/en_US;FBRV/0;FBCR/Samsung;FBMF/Samsung;FBBD/Samsung;FBPN/com.facebook.katana;FBDV/SM-G998B;FBSV/14;FBOP/1;FBCA/arm64-v8a:arm64-v8a;]',
    '[FB_IAB/FB4A;FBAV/420.0.0.38.92;FBBV/70623280;FBDM/{density=2.0,width=720,height=1280};FBLC/ru_RU;FBRV/87537820;FBCR/Samsung;FBMF/Samsung;FBBD/Samsung;FBPN/com.facebook.katana;FBDV/SM-G570F;FBSV/6.0.1;FBOP/1;FBCA/arm64-v8a;]'
]

# Proxy settings
ENABLE_PROXY = False
PROXIES = [
    'http://proxy1.example.com:8080',
    'http://proxy2.example.com:8080'
]

# Enumerations
class TokenStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    CHECKPOINT = "checkpoint"

class ToolOption(Enum):
    ENCRYPTOR = "1"
    CHECK_TOKEN = "2"
    CHECK_COOKIES = "3"
    FETCH_GC_UID = "4"
    GET_PAGE_TOKEN = "5"
    POST_LOADER = "6"
    CONVO_LOADER = "7"
    COOKIES_POST_LOADER = "8"
    EAAD6_VIA_COOKIES = "9"
    EAAD_NORMAL = "10"
    EAABWZ_IPAD = "11"
    EAAAU_FB_LOGIN = "12"
    EAAD6_2FA = "13"
    POST_LOADER_PAGE = "14"
    EXIT = "15"

# Data Classes
@dataclass
class TokenInfo:
    token: str
    status: TokenStatus
    user_id: str
    name: str
    email: str
    error_message: str = ""

@dataclass
class CookieInfo:
    cookies: str
    status: TokenStatus
    user_id: str
    name: str
    cookies_dict: Dict[str, str] = field(default_factory=dict)

@dataclass
class PostResult:
    success: bool
    message: str
    timestamp: str
    status_code: int = 0

# Logging configuration
def setup_logging():
    """Setup comprehensive logging"""
    log_dir = os.path.join(SAVE_DIR, 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f'darkstar_{datetime.now().strftime("%Y%m%d")}.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)

logger = setup_logging()

# Utility Functions
def clear_screen():
    """Clear terminal screen"""
    if os.name == 'posix':
        os.system('clear')
    else:
        os.system('cls')

def print_stylish_line():
    """Print a stylish line separator"""
    print(Style.BRIGHT + Fore.CYAN + '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + Style.RESET_ALL)

def bold_unicode(text):
    """Make text bold with unicode"""
    return f"\033[1m{text}\033[0m"

def get_random_proxy():
    """Get a random proxy from the list"""
    if ENABLE_PROXY and PROXIES:
        proxy = random.choice(PROXIES)
        return {
            'http': proxy,
            'https': proxy
        }
    return None

def get_random_user_agent():
    """Get a random user agent"""
    return random.choice(USER_AGENTS)

def get_unique_id():
    """Generate unique ID for device"""
    try:
        unique_str = str(os.getuid()) + os.getlogin() if os.name != 'nt' else str(os.getlogin())
        return hashlib.sha256(unique_str.encode()).hexdigest()
    except:
        return hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()

def send_whatsapp_message(message):
    """Send approval request via WhatsApp"""
    url = f"https://wa.me/+9779824204204?text={quote(message)}"
    try:
        if os.name == 'posix':
            os.system(f"am start '{url}' >/dev/null 2>&1")
        else:
            print(f"{YELLOW}Please send this WhatsApp message: {message}")
    except:
        pass

def check_permission(unique_key):
    """Check GitHub approval list - DISABLED for testing"""
    # DISABLED: Approval system bypassed for testing
    print(Style.BRIGHT + Fore.GREEN + '[✓] Approval bypassed - Running in unrestricted mode.')
    print_stylish_line()
    print(Style.BRIGHT + Fore.YELLOW + f'[!] Your Key: {unique_key}')
    return True


def banner():
    """Display tool banner"""
    clear_screen()
    try:
        text = pyfiglet.figlet_format('DarkStar', font='slant')
    except:
        text = "DARKSTAR"
    
    lines = text.split('\n')
    colors = [Fore.LIGHTCYAN_EX, Fore.LIGHTMAGENTA_EX, Fore.YELLOW, Fore.RED, Fore.LIGHTGREEN_EX, Fore.CYAN, Fore.MAGENTA]
    
    for i, line in enumerate(lines):
        if line.strip():
            print(Style.BRIGHT + colors[i % len(colors)] + line)
    
    print_stylish_line()
    print(f"{CYAN}Version: {APP_VERSION} | Enhanced Edition")
    print_stylish_line()

def print_developer_info():
    """Display developer information"""
    console.print(Panel(
        f"{RED}[•] Developer    ▶ {GREEN}SahiiL                   \n"
        f"{GREEN}[•] Facebook     ▶ {RED}Thew Hitler              \n"
        f"{YELLOW}[•] Github       ▶ {BLUE}Darkstar xd              \n"
        f"{BLUE}[•] Team         ▶ {YELLOW}Darkstar                 ",
        title=f"{CYAN}Developer Info",
        subtitle=f"{CYAN}DarkStar",
        style="bold cyan",
        width=70
    ))

def print_tool_info():
    """Display tool information"""
    console.print(Panel(
        f"{BLUE}[•] Tool Type    ▶ {YELLOW}Termux Post Convo        \n"
        f"{GREEN}[•] Version      ▶ {BLUE}{APP_VERSION}                  \n"
        f"{YELLOW}[•] Updates      ▶ {MAGENTA}Last Update On 29/Dec/2025",
        title=f"{CYAN}Tool Info",
        style="bold cyan",
        width=70
    ))

def print_subscription_info():
    """Display subscription information"""
    console.print(Panel(
        f"{RED}[•] Access Type  ▶ {GREEN}Paid Tool                \n"
        f"{GREEN}[•] Monthly Plan ▶ {YELLOW}150 Rs / Month           \n"
        f"{YELLOW}[•] Yearly Plan  ▶ {MAGENTA}1500 Rs / Year           ",
        title=f"{CYAN}Subscription Info",
        style="bold cyan",
        width=70
    ))

def print_time_info():
    """Display current time and date"""
    now = datetime.now()
    date = now.strftime('%Y-%m-%d')
    time_str = now.strftime('%I:%M:%S %p')
    console.print(Panel(
        f"{RED}[•] Time Now     ▶ {CYAN}{time_str}                \n"
        f"{YELLOW}[•] Today Date   ▶ {CYAN}{date}                    ",
        title=f"{CYAN}Today Time",
        style="bold cyan",
        width=70
    ))

def print_ip_info():
    """Display IP information"""
    try:
        res = requests.get('https://ipinfo.io/json', timeout=5, proxies=get_random_proxy())
        data = res.json()
        ip = data.get('ip', 'Unknown')
        country = data.get('country', 'Unknown')
        region = data.get('region', 'Unknown')
        city = data.get('city', 'Unknown')
        console.print(Panel(
            f"{GREEN}[•] IP           ▶ {ip}\n"
            f"{GREEN}[•] Country      ▶ {country}\n"
            f"{GREEN}[•] Region       ▶ {region}\n"
            f"{GREEN}[•] City         ▶ {city}",
            title=f"{CYAN}IP Info",
            style="bold cyan",
            width=70
        ))
    except Exception as e:
        logger.error(f"Error getting IP info: {e}")
        pass

def display_boxes():
    """Display all information boxes"""
    print_developer_info()
    print_tool_info()
    print_time_info()
    print_subscription_info()
    print_ip_info()

def check_password():
    """Check tool password"""
    password = 'DARKSTAR_X'
    attempts = 3
    
    while attempts > 0:
        print_stylish_line()
        entered_password = input(Style.BRIGHT + Fore.YELLOW + '[•] ENTER PASSWORD ▶ ')
        
        if entered_password == password:
            print(Style.BRIGHT + Fore.GREEN + '[✓] Password correct! Proceeding...')
            print_stylish_line()
            return True
        
        attempts -= 1
        print(Style.BRIGHT + Fore.RED + f'[✗] Incorrect password! You have {attempts} attempts left.')
        print_stylish_line()
    
    print(Style.BRIGHT + Fore.RED + '[✗] Too many incorrect attempts. Exiting')
    print_stylish_line()
    sys.exit(1)

def make_folder():
    """Create necessary folders"""
    folders = [SAVE_DIR, os.path.join(SAVE_DIR, 'logs'), os.path.join(SAVE_DIR, 'backups')]
    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder)

# ============================================================================
# TOKEN VALIDATION FUNCTIONS
# ============================================================================

def validate_single_token(token: str) -> TokenInfo:
    """Validate a single Facebook token"""
    try:
        url = f"https://graph.facebook.com/me?access_token={token}&fields=id,name,email"
        response = requests.get(url, timeout=10, proxies=get_random_proxy())
        
        if response.status_code == 200:
            data = response.json()
            return TokenInfo(
                token=token,
                status=TokenStatus.VALID,
                user_id=data.get('id', ''),
                name=data.get('name', 'Unknown'),
                email=data.get('email', ''),
                error_message=""
            )
        elif response.status_code == 400:
            data = response.json()
            error = data.get('error', {})
            if error.get('code') == 190:
                return TokenInfo(
                    token=token,
                    status=TokenStatus.EXPIRED,
                    user_id="",
                    name="",
                    email="",
                    error_message="Token expired"
                )
            else:
                return TokenInfo(
                    token=token,
                    status=TokenStatus.CHECKPOINT,
                    user_id="",
                    name="",
                    email="",
                    error_message=error.get('message', 'Checkpoint required')
                )
        else:
            return TokenInfo(
                token=token,
                status=TokenStatus.INVALID,
                user_id="",
                name="",
                email="",
                error_message=f"HTTP {response.status_code}"
            )
    except Exception as e:
        logger.error(f"Error validating token: {e}")
        return TokenInfo(
            token=token,
            status=TokenStatus.INVALID,
            user_id="",
            name="",
            email="",
            error_message=str(e)
        )

def validate_tokens(token_file: str) -> Tuple[List[TokenInfo], List[TokenInfo]]:
    """Validate tokens from file"""
    valid_tokens = []
    invalid_tokens = []
    
    try:
        with open(token_file, 'r') as f:
            tokens = [line.strip() for line in f if line.strip()]
        
        if not tokens:
            print(f"{RED}[✗] No tokens found in file")
            return valid_tokens, invalid_tokens
        
        print(f"{CYAN}[•] Validating {len(tokens)} tokens...")
        print_stylish_line()
        
        for idx, token in enumerate(tokens, 1):
            print(f"{CYAN}[{idx}/{len(tokens)}] Validating token...", end='\r')
            token_info = validate_single_token(token)
            
            if token_info.status == TokenStatus.VALID:
                valid_tokens.append(token_info)
                print(f"{GREEN}[✓] Token {idx} Valid: {token_info.name} (ID: {token_info.user_id})")
            else:
                invalid_tokens.append(token_info)
                print(f"{RED}[✗] Token {idx} {token_info.status.value}: {token_info.error_message}")
        
        print_stylish_line()
        print(f"{GREEN}[✓] Validation Complete: {len(valid_tokens)} valid, {len(invalid_tokens)} invalid")
        
    except FileNotFoundError:
        print(f"{RED}[✗] File not found: {token_file}")
    except Exception as e:
        print(f"{RED}[✗] Error reading file: {e}")
        logger.error(f"Error validating tokens: {e}")
    
    return valid_tokens, invalid_tokens

# ============================================================================
# COOKIE FUNCTIONS
# ============================================================================

def parse_cookies(cookie_string: str) -> Dict[str, str]:
    """Parse cookie string into dictionary"""
    cookies_dict = {}
    if not cookie_string:
        return cookies_dict
    for item in cookie_string.split(';'):
        item = item.strip()
        if item and '=' in item:
            key, value = item.split('=', 1)
            cookies_dict[key.strip()] = value.strip()
    return cookies_dict

def validate_single_cookie(cookie_string: str) -> CookieInfo:
    """Validate a single Facebook cookie"""
    try:
        cookies_dict = parse_cookies(cookie_string)
        
        if 'c_user' not in cookies_dict:
            return CookieInfo(
                cookies=cookie_string,
                status=TokenStatus.INVALID,
                user_id="",
                name="",
                cookies_dict={},
            )
        
        user_id = cookies_dict.get('c_user', '')
        
        # Validate with Facebook
        url = "https://www.facebook.com/"
        headers = {
            'User-Agent': get_random_user_agent(),
            'Cookie': cookie_string,
            'Accept-Language': 'en-US,en;q=0.9'
        }
        
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
        
        if response.status_code == 200:
            # Try to get user name from profile
            profile_url = f"https://www.facebook.com/{user_id}"
            profile_response = requests.get(profile_url, headers=headers, timeout=10)
            
            # Simple regex to extract name (this is basic)
            name_match = re.search(r'"name":"([^"]+)"', profile_response.text)
            name = name_match.group(1) if name_match else f"User {user_id}"
            
            return CookieInfo(
                cookies=cookie_string,
                status=TokenStatus.VALID,
                user_id=user_id,
                name=name,
                cookies_dict=cookies_dict
            )
        else:
            return CookieInfo(
                cookies=cookie_string,
                status=TokenStatus.INVALID,
                user_id=user_id,
                name="",
                cookies_dict=cookies_dict
            )
    except Exception as e:
        logger.error(f"Error validating cookie: {e}")
        return CookieInfo(
            cookies=cookie_string,
            status=TokenStatus.INVALID,
            user_id="",
            name="",
            cookies_dict={}
        )

def cookies_checker_menu():
    """Cookie checker menu"""
    print(Style.BRIGHT + Fore.CYAN + '╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + bold_unicode(' COOKIES CHECKER ') + '━━━━━━━━━━━━━━━━━━━━━━━━━━╮')
    cookie_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Cookie File Path ▶ ')
    
    if not os.path.exists(cookie_file):
        print(f"{RED}[✗] File not found: {cookie_file}")
        input(Style.BRIGHT + Fore.MAGENTA + '[✔] Press Enter to return to menu ')
        return
    
    try:
        with open(cookie_file, 'r') as f:
            cookies = [line.strip() for line in f if line.strip()]
        
        if not cookies:
            print(f"{RED}[✗] No cookies found in file")
            input(Style.BRIGHT + Fore.MAGENTA + '[✔] Press Enter to return to menu ')
            return
        
        print(f"{CYAN}[•] Validating {len(cookies)} cookies...")
        print_stylish_line()
        
        valid_cookies = 0
        invalid_cookies = 0
        
        for idx, cookie_string in enumerate(cookies, 1):
            print(f"{CYAN}[{idx}/{len(cookies)}] Validating cookie...", end='\r')
            cookie_info = validate_single_cookie(cookie_string)
            
            if cookie_info.status == TokenStatus.VALID:
                valid_cookies += 1
                print(f"{GREEN}[✓] Cookie {idx} Valid: {cookie_info.name} (ID: {cookie_info.user_id})")
            else:
                invalid_cookies += 1
                print(f"{RED}[✗] Cookie {idx} Invalid")
        
        print_stylish_line()
        print(f"{GREEN}[✓] Validation Complete: {valid_cookies} valid, {invalid_cookies} invalid")
        
    except Exception as e:
        print(f"{RED}[✗] Error: {e}")
        logger.error(f"Error in cookies checker: {e}")
    
    input(Style.BRIGHT + Fore.MAGENTA + '[✔] Press Enter to return to menu ')

# ============================================================================
# TOKEN GENERATION FUNCTIONS
# ============================================================================

def eaad_via_cookie():
    """Generate EAAD6 token via cookies"""
    print(Style.BRIGHT + Fore.CYAN + '╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + bold_unicode(' EAAD6 VIA COOKIES ') + '━━━━━━━━━━━━━━━━━━━━━━━━━━╮')
    cookie_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Cookie File Path ▶ ')
    
    if not os.path.exists(cookie_file):
        print(f"{RED}[✗] File not found: {cookie_file}")
        return
    
    try:
        with open(cookie_file, 'r') as f:
            cookies = [line.strip() for line in f if line.strip()]
        
        if not cookies:
            print(f"{RED}[✗] No cookies found")
            return
        
        print(f"{CYAN}[•] Processing {len(cookies)} cookies...")
        print_stylish_line()
        
        success_count = 0
        output_file = os.path.join(SAVE_DIR, 'eaad6_tokens.txt')
        
        with open(output_file, 'a') as out:
            for idx, cookie_string in enumerate(cookies, 1):
                try:
                    cookies_dict = parse_cookies(cookie_string)
                    c_user = cookies_dict.get('c_user', '')
                    xs = cookies_dict.get('xs', '')
                    
                    if not c_user or not xs:
                        print(f"{RED}[✗] Cookie {idx}: Missing c_user or xs")
                        continue
                    
                    # Generate token
                    url = f"https://b-graph.facebook.com/auth/login"
                    headers = {
                        'User-Agent': get_random_user_agent(),
                        'Cookie': cookie_string,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                    
                    response = requests.post(url, headers=headers, data={
                        'email': c_user,
                        'password': 'dummy'
                    })
                    
                    # Try to extract token from response
                    token_match = re.search(r'EAAD[a-zA-Z0-9_\-]+', response.text)
                    if token_match:
                        token = token_match.group()
                        out.write(f"{token}\n")
                        print(f"{GREEN}[✓] Cookie {idx}: Token generated")
                        success_count += 1
                    else:
                        print(f"{RED}[✗] Cookie {idx}: Failed to generate token")
                    
                    time.sleep(2)
                
                except Exception as e:
                    print(f"{RED}[✗] Cookie {idx}: Error - {str(e)}")
        
        print_stylish_line()
        print(f"{GREEN}[✓] Complete: {success_count} tokens generated")
        print(f"{CYAN}[•] Saved to: {output_file}")
    
    except Exception as e:
        print(f"{RED}[✗] Error: {e}")
        logger.error(f"Error in eaad_via_cookie: {e}")
    
    input(Style.BRIGHT + Fore.MAGENTA + '[✔] Press Enter to continue ')

def eaad_normal():
    """Generate EAAD token normally"""
    print(Style.BRIGHT + Fore.CYAN + '╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + bold_unicode(' EAAD NORMAL ') + '━━━━━━━━━━━━━━━━━━━━━━━━━━╮')
    print(f"{YELLOW}[•] This function converts existing tokens to EAAD6 format")
    token_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Token File Path ▶ ')
    
    if not os.path.exists(token_file):
        print(f"{RED}[✗] File not found: {token_file}")
        return
    
    try:
        with open(token_file, 'r') as f:
            tokens = [line.strip() for line in f if line.strip()]
        
        if not tokens:
            print(f"{RED}[✗] No tokens found")
            return
        
        print(f"{CYAN}[•] Converting {len(tokens)} tokens...")
        print_stylish_line()
        
        output_file = os.path.join(SAVE_DIR, 'eaad_converted.txt')
        success_count = 0
        
        with open(output_file, 'a') as out:
            for idx, token in enumerate(tokens, 1):
                try:
                    url = 'https://api.facebook.com/method/auth.getSessionforApp'
                    params = {
                        'access_token': token,
                        'format': 'json',
                        'new_app_id': '275254692598279',
                        'generate_session_cookies': '1'
                    }
                    
                    response = requests.post(url, params=params, timeout=20)
                    
                    if response.status_code == 200:
                        data = response.json()
                        new_token = data.get('access_token')
                        
                        if new_token and new_token.startswith('EAAD'):
                            out.write(f"{new_token}\n")
                            print(f"{GREEN}[✓] Token {idx}: Converted successfully")
                            success_count += 1
                        else:
                            print(f"{RED}[✗] Token {idx}: Conversion failed")
                    else:
                        print(f"{RED}[✗] Token {idx}: HTTP {response.status_code}")
                    
                    time.sleep(1)
                
                except Exception as e:
                    print(f"{RED}[✗] Token {idx}: Error - {str(e)}")
        
        print_stylish_line()
        print(f"{GREEN}[✓] Complete: {success_count} tokens converted")
        print(f"{CYAN}[•] Saved to: {output_file}")
    
    except Exception as e:
        print(f"{RED}[✗] Error: {e}")
        logger.error(f"Error in eaad_normal: {e}")
    
    input(Style.BRIGHT + Fore.MAGENTA + '[✔] Press Enter to continue ')

def insta_token():
    """Generate EAABwz token (iPad)"""
    print(Style.BRIGHT + Fore.CYAN + '╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + bold_unicode(' EAABWZ IPAD ') + '━━━━━━━━━━━━━━━━━━━━━━━━━━╮')
    cookie_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Cookie File Path ▶ ')
    
    if not os.path.exists(cookie_file):
        print(f"{RED}[✗] File not found: {cookie_file}")
        return
    
    try:
        with open(cookie_file, 'r') as f:
            cookies = [line.strip() for line in f if line.strip()]
        
        print(f"{CYAN}[•] Processing {len(cookies)} cookies...")
        print_stylish_line()
        
        success_count = 0
        output_file = os.path.join(SAVE_DIR, 'eaabwz_tokens.txt')
        
        with open(output_file, 'a') as out:
            for idx, cookie_string in enumerate(cookies, 1):
                try:
                    # iPad user agent
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
                        'Cookie': cookie_string
                    }
                    
                    url = "https://touch.facebook.com/dialog/oauth"
                    params = {
                        'client_id': '275254692598279',
                        'redirect_uri': 'fbconnect://success',
                        'scope': 'email,publish_stream',
                        'response_type': 'token'
                    }
                    
                    response = requests.get(url, params=params, headers=headers, allow_redirects=False)
                    
                    # Extract token from location header or response
                    token_match = re.search(r'access_token=([^&]+)', response.text)
                    if token_match:
                        token = token_match.group(1)
                        out.write(f"{token}\n")
                        print(f"{GREEN}[✓] Cookie {idx}: Token generated")
                        success_count += 1
                    else:
                        print(f"{RED}[✗] Cookie {idx}: Failed to generate token")
                    
                    time.sleep(2)
                
                except Exception as e:
                    print(f"{RED}[✗] Cookie {idx}: Error - {str(e)}")
        
        print_stylish_line()
        print(f"{GREEN}[✓] Complete: {success_count} tokens generated")
        print(f"{CYAN}[•] Saved to: {output_file}")
    
    except Exception as e:
        print(f"{RED}[✗] Error: {e}")
        logger.error(f"Error in insta_token: {e}")
    
    input(Style.BRIGHT + Fore.MAGENTA + '[✔] Press Enter to continue ')

def login_token_menu():
    """Login token menu"""
    print(Style.BRIGHT + Fore.CYAN + '╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + bold_unicode(' FB LOGIN TOKEN ') + '━━━━━━━━━━━━━━━━━━━━━━━━━━╮')
    
    username = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Username/Email/Phone ▶ ')
    password = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Password ▶ ')
    two_fa_secret = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter 2FA Secret (Optional, press Enter to skip) ▶ ')
    
    print(f"{CYAN}[•] Attempting login...")
    print_stylish_line()
    
    try:
        from facebook_token_generator import FacebookTokenGenerator
        generator = FacebookTokenGenerator()
        result = generator.login(username, password, two_fa_secret)
        
        if result.get('success'):
            token = result.get('access_token', '')
            print(f"{GREEN}[✓] Login Successful!")
            print(f"{CYAN}[•] Token: {token}")
            
            # Save token
            output_file = os.path.join(SAVE_DIR, 'login_tokens.txt')
            with open(output_file, 'a') as out:
                out.write(f"{token}\n")
            print(f"{CYAN}[•] Saved to: {output_file}")
        else:
            print(f"{RED}[✗] Login Failed: {result.get('message')}")
    
    except ImportError:
        print(f"{RED}[✗] Facebook token generator module not available")
        print(f"{YELLOW}[•] Using basic login method...")
        
        # Basic fallback method
        try:
            url = "https://m.facebook.com/login.php"
            session = requests.Session()
            response = session.get(url)
            
            # Parse login form
            post_data = {
                'email': username,
                'pass': password,
                'login': 'Log In'
            }
            
            response = session.post(url, data=post_data)
            
            if 'c_user' in session.cookies:
                print(f"{GREEN}[✓] Login Successful!")
                print(f"{CYAN}[•] Cookies obtained")
                
                # Convert cookies to token
                cookies_str = '; '.join([f"{k}={v}" for k, v in session.cookies.items()])
                print(f"{CYAN}[•] Cookies: {cookies_str}")
            else:
                print(f"{RED}[✗] Login Failed: Invalid credentials")
        
        except Exception as e:
            print(f"{RED}[✗] Error: {e}")
    
    input(Style.BRIGHT + Fore.MAGENTA + '[✔] Press Enter to continue ')

def Token_by_2fa():
    """Get token with 2FA support"""
    print(Style.BRIGHT + Fore.CYAN + '╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + bold_unicode(' 2FA TOKEN ') + '━━━━━━━━━━━━━━━━━━━━━━━━━━╮')
    
    username = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Username/Email/Phone ▶ ')
    password = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Password ▶ ')
    two_fa_secret = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter 2FA Secret (Required) ▶ ')
    
    if not two_fa_secret:
        print(f"{RED}[✗] 2FA secret is required")
        return
    
    print(f"{CYAN}[•] Attempting login with 2FA...")
    print_stylish_line()
    
    try:
        from facebook_token_generator import FacebookTokenGenerator
        generator = FacebookTokenGenerator()
        result = generator.login(username, password, two_fa_secret)
        
        if result.get('success'):
            token = result.get('access_token', '')
            cookies = result.get('cookies', '')
            
            print(f"{GREEN}[✓] Login Successful with 2FA!")
            print(f"{CYAN}[•] Token: {token}")
            print(f"{CYAN}[•] Cookies: {cookies}")
            
            # Save to file
            output_file = os.path.join(SAVE_DIR, '2fa_tokens.txt')
            with open(output_file, 'a') as out:
                out.write(f"Token: {token}\nCookies: {cookies}\n\n")
            print(f"{CYAN}[•] Saved to: {output_file}")
        else:
            print(f"{RED}[✗] Login Failed: {result.get('message')}")
    
    except ImportError:
        print(f"{RED}[✗] Facebook token generator module not available")
    
    input(Style.BRIGHT + Fore.MAGENTA + '[✔] Press Enter to continue ')

def run_token_generator():
    """Run token generator"""
    print(Style.BRIGHT + Fore.CYAN + '╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + bold_unicode(' TOKEN GENERATOR ') + '━━━━━━━━━━━━━━━━━━━━━━━━━━╮')
    print(f"{YELLOW}[•] Select token generation method:")
    print(f"{GREEN}[1] Via Cookies")
    print(f"{GREEN}[2] Via Login")
    print(f"{GREEN}[3] Via 2FA")
    
    choice = input(Style.BRIGHT + INPUT_COLOR + '[?] Enter choice ▶ ')
    
    if choice == '1':
        eaad_via_cookie()
    elif choice == '2':
        login_token_menu()
    elif choice == '3':
        Token_by_2fa()
    else:
        print(f"{RED}[✗] Invalid choice")

# ============================================================================
# POST AND COMMENT FUNCTIONS
# ============================================================================

def send_post_comment(token: str, post_id: str, comment: str) -> PostResult:
    """Send a comment to a Facebook post"""
    try:
        url = f"https://graph.facebook.com/v18.0/{post_id}/comments"
        headers = {
            'Authorization': f'Bearer {token}',
            'User-Agent': get_random_user_agent()
        }
        data = {'message': comment}
        
        response = requests.post(url, headers=headers, json=data, timeout=10)
        
        return PostResult(
            success=response.status_code == 200,
            message="Comment posted successfully" if response.status_code == 200 else "Failed to post comment",
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            status_code=response.status_code
        )
    except Exception as e:
        logger.error(f"Error sending comment: {e}")
        return PostResult(
            success=False,
            message=str(e),
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            status_code=0
        )

def send_convo_message(token: str, thread_id: str, message: str) -> PostResult:
    """Send a message to a Facebook conversation"""
    try:
        url = f"https://graph.facebook.com/v18.0/t_{thread_id}/messages"
        headers = {
            'Authorization': f'Bearer {token}',
            'User-Agent': get_random_user_agent()
        }
        data = {'message': message}
        
        response = requests.post(url, headers=headers, json=data, timeout=10)
        
        return PostResult(
            success=response.status_code == 200,
            message="Message sent successfully" if response.status_code == 200 else "Failed to send message",
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            status_code=response.status_code
        )
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        return PostResult(
            success=False,
            message=str(e),
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            status_code=0
        )

def start_loader():
    """Start post comment loader"""
    print(Style.BRIGHT + Fore.CYAN + '╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + bold_unicode(' POST LOADER ') + '━━━━━━━━━━━━━━━━━━━━━━━━━━╮')
    
    token_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Token File Path ▶ ')
    print_stylish_line()
    post_id = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Facebook Post ID ▶ ')
    print_stylish_line()
    haters_name = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Haters Name ▶ ')
    print_stylish_line()
    comment_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Comment File Path ▶ ')
    print_stylish_line()
    
    try:
        delay = int(input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Time Delay (Seconds) ▶ '))
    except:
        delay = 5
    
    print_stylish_line()
    
    # Validate tokens
    valid_tokens, _ = validate_tokens(token_file)
    if not valid_tokens:
        print(Style.BRIGHT + Fore.RED + '[✗] No valid tokens found. Exiting...')
        return
    
    # Load comments
    try:
        with open(comment_file, 'r') as f:
            comments = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Style.BRIGHT + Fore.RED + '[✗] Comment file not found!')
        return
    
    if not comments:
        print(Style.BRIGHT + Fore.RED + '[✗] No comments found in file!')
        return
    
    # Start posting loop
    comment_idx = 0
    token_idx = 0
    
    try:
        while True:
            token_info = valid_tokens[token_idx]
            comment_text = comments[comment_idx]
            final_comment = f"{haters_name} {comment_text}"
            
            print_stylish_line()
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Post ID    ▶ {post_id}')
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Sender     ▶ {token_info.name}')
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Token ID   ▶ {token_info.user_id}')
            
            result = send_post_comment(token_info.token, post_id, final_comment)
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Time       ▶ {timestamp}')
            
            if result.success:
                print(Style.BRIGHT + SUCCESS_COLOR + '[✓] Status     ▶ Comment Posted Successfully')
            else:
                print(Style.BRIGHT + ERROR_COLOR + f'[✗] Status     ▶ Failed ({result.status_code}) - {result.message}')
            
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Comment    ▶ {final_comment}')
            print_stylish_line()
            
            comment_idx = (comment_idx + 1) % len(comments)
            token_idx = (token_idx + 1) % len(valid_tokens)
            
            time.sleep(delay)
    
    except KeyboardInterrupt:
        print(RED + "\n[!] Process stopped by user")
    except Exception as e:
        print(RED + f"[!] Error: {str(e)}")
        logger.error(f"Error in start_loader: {e}")

def start_convo():
    """Start conversation message loader"""
    print(Style.BRIGHT + Fore.CYAN + '╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + bold_unicode(' CONVO TOOL ') + '━━━━━━━━━━━━━━━━━━━━━━━━━━╮')
    
    token_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Token File Path ▶ ')
    print_stylish_line()
    thread_id = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Conversation (Thread) ID ▶ ')
    print_stylish_line()
    haters_name = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Haters Name ▶ ')
    print_stylish_line()
    message_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Message File Path ▶ ')
    print_stylish_line()
    
    try:
        delay = int(input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Time Delay (Seconds) ▶ '))
    except:
        delay = 5
    
    print_stylish_line()
    
    # Validate tokens
    valid_tokens, _ = validate_tokens(token_file)
    if not valid_tokens:
        print(Style.BRIGHT + Fore.RED + '[✗] No valid tokens found. Exiting...')
        return
    
    # Load messages
    try:
        with open(message_file, 'r') as f:
            messages = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Style.BRIGHT + Fore.RED + '[✗] Message file not found!')
        return
    
    if not messages:
        print(Style.BRIGHT + Fore.RED + '[✗] No messages found in file!')
        return
    
    # Start messaging loop
    message_idx = 0
    token_idx = 0
    
    try:
        while True:
            token_info = valid_tokens[token_idx]
            message_text = messages[message_idx]
            final_message = f"{haters_name} {message_text}"
            
            print_stylish_line()
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Thread ID  ▶ {thread_id}')
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Sender     ▶ {token_info.name}')
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Token ID   ▶ {token_info.user_id}')
            
            result = send_convo_message(token_info.token, thread_id, final_message)
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Time       ▶ {timestamp}')
            
            if result.success:
                print(Style.BRIGHT + SUCCESS_COLOR + '[✓] Status     ▶ Message Sent Successfully')
            else:
                print(Style.BRIGHT + ERROR_COLOR + f'[✗] Status     ▶ Failed ({result.status_code}) - {result.message}')
            
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Message    ▶ {final_message}')
            print_stylish_line()
            
            message_idx = (message_idx + 1) % len(messages)
            token_idx = (token_idx + 1) % len(valid_tokens)
            
            time.sleep(delay)
    
    except KeyboardInterrupt:
        print(RED + "\n[!] Process stopped by user")
    except Exception as e:
        print(RED + f"[!] Error: {str(e)}")
        logger.error(f"Error in start_convo: {e}")

def Wall():
    """Cookies post loader"""
    print(CYAN + "┏━━━━━━━━━━━━━━━━━━━━━━━━━━ < COOKIES POST LOADER > ━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    
    cookie_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Cookie File Path ▶ ')
    post_id = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Facebook Post ID ▶ ')
    haters_name = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Haters Name ▶ ')
    comment_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Comment File Path ▶ ')
    
    try:
        delay = int(input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Time Delay (Seconds) ▶ '))
    except:
        delay = 5
    
    try:
        with open(cookie_file, 'r') as f:
            cookies = [line.strip() for line in f if line.strip()]
        
        with open(comment_file, 'r') as f:
            comments = [line.strip() for line in f if line.strip()]
    
    except Exception as e:
        print(RED + f"Error reading files: {e}")
        return
    
    if not cookies or not comments:
        print(RED + "Cookies or Comments empty")
        return
    
    idx_cookie = 0
    idx_comment = 0
    
    try:
        while True:
            cookie = cookies[idx_cookie]
            comment = comments[idx_comment]
            final_comment = f"{haters_name} {comment}"
            
            url = f"https://graph.facebook.com/v18.0/{post_id}/comments"
            headers = {
                'Cookie': cookie,
                'User-Agent': get_random_user_agent()
            }
            data = {'message': final_comment}
            
            print_stylish_line()
            print(f"{GREEN}[•] Posting with Cookie {idx_cookie + 1}")
            
            response = requests.post(url, headers=headers, data=data)
            
            if response.status_code == 200:
                print(f"{GREEN}[✓] Comment Posted: {final_comment}")
            else:
                print(f"{RED}[✗] Failed ({response.status_code})")
            
            idx_cookie = (idx_cookie + 1) % len(cookies)
            idx_comment = (idx_comment + 1) % len(comments)
            
            time.sleep(delay)
    
    except KeyboardInterrupt:
        print(RED + "\n[!] Process stopped by user")
    except Exception as e:
        print(RED + f"[!] Error: {e}")
        logger.error(f"Error in Wall: {e}")

def comment_by_page():
    """Post comments using page ID token"""
    print(Style.BRIGHT + Fore.CYAN + '╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + bold_unicode(' PAGE TOKEN POSTER ') + '━━━━━━━━━━━━━━━━━━━━━━━━━━╮')
    
    token_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Page Token File Path ▶ ')
    print_stylish_line()
    post_id = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Facebook Post ID ▶ ')
    print_stylish_line()
    haters_name = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Haters Name ▶ ')
    print_stylish_line()
    comment_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Comment File Path ▶ ')
    print_stylish_line()
    
    try:
        delay = int(input(Style.BRIGHT + INPUT_COLOR + '[•] Enter Time Delay (Seconds) ▶ '))
    except:
        delay = 5
    
    print_stylish_line()
    
    # Load page tokens
    try:
        with open(token_file, 'r') as f:
            tokens = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Style.BRIGHT + Fore.RED + '[✗] Token file not found!')
        return
    
    if not tokens:
        print(Style.BRIGHT + Fore.RED + '[✗] No tokens found!')
        return
    
    # Load comments
    try:
        with open(comment_file, 'r') as f:
            comments = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Style.BRIGHT + Fore.RED + '[✗] Comment file not found!')
        return
    
    if not comments:
        print(Style.BRIGHT + Fore.RED + '[✗] No comments found!')
        return
    
    # Start posting loop
    comment_idx = 0
    token_idx = 0
    
    try:
        while True:
            token = tokens[token_idx]
            comment_text = comments[comment_idx]
            final_comment = f"{haters_name} {comment_text}"
            
            print_stylish_line()
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Post ID    ▶ {post_id}')
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Using Page Token {token_idx + 1}')
            
            result = send_post_comment(token, post_id, final_comment)
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Time       ▶ {timestamp}')
            
            if result.success:
                print(Style.BRIGHT + SUCCESS_COLOR + '[✓] Status     ▶ Comment Posted Successfully')
            else:
                print(Style.BRIGHT + ERROR_COLOR + f'[✗] Status     ▶ Failed ({result.status_code}) - {result.message}')
            
            print(Style.BRIGHT + SUCCESS_COLOR + f'[•] Comment    ▶ {final_comment}')
            print_stylish_line()
            
            comment_idx = (comment_idx + 1) % len(comments)
            token_idx = (token_idx + 1) % len(tokens)
            
            time.sleep(delay)
    
    except KeyboardInterrupt:
        print(RED + "\n[!] Process stopped by user")
    except Exception as e:
        print(RED + f"[!] Error: {str(e)}")
        logger.error(f"Error in comment_by_page: {e}")

# ============================================================================
# EXTRACTION FUNCTIONS
# ============================================================================

def fetch_gc_info():
    """Fetch group conversation info"""
    print(Style.BRIGHT + Fore.GREEN + '[+] Fetch Group Conversation Info')
    
    access_token = input(Style.BRIGHT + SUCCESS_COLOR + '[•] Enter your Facebook access token ▶ ')
    
    if not access_token:
        print(RED + "[✗] Token is required")
        return
    
    def get_group_name(group_id, token):
        """Get group name from ID"""
        try:
            url = f"https://graph.facebook.com/v18.0/{group_id}?access_token={token}&fields=name"
            res = requests.get(url, timeout=10)
            return res.json().get('name', f'Group {group_id}')
        except:
            return f'Group {group_id}'
    
    try:
        # Verify token
        account_url = 'https://graph.facebook.com/v18.0/me'
        params = {'access_token': access_token, 'fields': 'name,id'}
        account_response = requests.get(account_url, params=params, timeout=10)
        
        if account_response.status_code != 200:
            print(RED + "[✗] Invalid Token")
            return
        
        account_data = account_response.json()
        account_name = account_data.get('name', 'Unknown')
        account_id = account_data.get('id', 'Unknown')
        
        print_stylish_line()
        print(f"{CYAN}[✓] Account Name: {account_name}")
        print(f"{CYAN}[✓] Account ID: {account_id}")
        print_stylish_line()
        
        # Get conversations
        url = 'https://graph.facebook.com/v18.0/me/conversations'
        params = {
            'access_token': access_token,
            'fields': 'id,name,participants',
            'limit': 50
        }
        
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        
        if 'data' in data:
            chats = data['data']
            print(f"{GREEN}[✓] Total Chats Found: {len(chats)}")
            print_stylish_line()
            
            output_file = os.path.join(SAVE_DIR, 'gc_info.txt')
            
            with open(output_file, 'a') as out:
                out.write(f"Account: {account_name} ({account_id})\n")
                out.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                out.write("=" * 50 + "\n\n")
                
                for idx, chat in enumerate(chats, 1):
                    chat_id = chat['id'].replace('t_', '')
                    chat_name = chat.get('name', get_group_name(chat_id, access_token))
                    participants = chat.get('participants', {})
                    participant_count = len(participants.get('data', []))
                    
                    print(f"{idx}. {chat_name} (ID: {chat_id}) - {participant_count} members")
                    out.write(f"{idx}. {chat_name}\n")
                    out.write(f"   ID: {chat_id}\n")
                    out.write(f"   Members: {participant_count}\n\n")
            
            print(f"{GREEN}[✓] Saved to: {output_file}")
        else:
            print(RED + "[✗] No conversations found")
    
    except Exception as e:
        print(RED + f"[!] Error: {e}")
        logger.error(f"Error in fetch_gc_info: {e}")
    
    input(Style.BRIGHT + Fore.MAGENTA + '[✔] Press Enter to continue ')

def extract_page_tokens():
    """Extract page tokens from user token"""
    print(Style.BRIGHT + Fore.GREEN + '[+] Extract Page Tokens')
    
    user_token = input(Style.BRIGHT + Fore.GREEN + '[•] Enter Your Facebook Token ▶ ').strip()
    
    if not user_token:
        print(RED + "[✗] Token is required")
        return
    
    try:
        # Verify user token
        r = requests.get(f"https://graph.facebook.com/me?access_token={user_token}&fields=id,name", timeout=10)
        data = r.json()
        
        if 'error' in data:
            print(RED + f"[!] Error: {data['error']['message']}")
            return
        
        print(GREEN + f"[✓] Name: {data.get('name')}")
        print(GREEN + f"[✓] ID: {data.get('id')}")
        print_stylish_line()
        
        # Get pages
        r = requests.get(f"https://graph.facebook.com/me/accounts?access_token={user_token}", timeout=10)
        pages = r.json()
        
        if 'data' not in pages or not pages['data']:
            print(RED + "[!] No pages found")
            return
        
        save_name = input(Style.BRIGHT + Fore.YELLOW + '[•] File name to save (e.g., pages) ▶ ').strip()
        if not save_name:
            save_name = "pages"
        
        filename = f"{save_name}.txt"
        output_path = os.path.join(SAVE_DIR, filename)
        
        with open(output_path, 'w') as f:
            f.write(f"Extracted on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            
            for page in pages['data']:
                token = page.get('access_token')
                name = page.get('name')
                page_id = page.get('id')
                
                print(GREEN + f"[+] Found Page: {name} (ID: {page_id})")
                f.write(f"Page: {name}\n")
                f.write(f"ID: {page_id}\n")
                f.write(f"Token: {token}\n\n")
        
        print(GREEN + f"[✓] Saved all page tokens to {output_path}")
    
    except Exception as e:
        print(RED + f"[!] Error: {e}")
        logger.error(f"Error in extract_page_tokens: {e}")
    
    input(Style.BRIGHT + Fore.MAGENTA + '[✔] Press Enter to continue ')

# ============================================================================
# ENCRYPTION FUNCTIONS
# ============================================================================

def encrypt_base64(code):
    """Encrypt code using base64"""
    encoded = base64.b64encode(code.encode()).decode()
    return f"import base64\nexec(base64.b64decode('{encoded}').decode())"

def encrypt_marshal(code):
    """Encrypt code using marshal"""
    compiled = compile(code, '<string>', 'exec')
    marshaled = marshal.dumps(compiled)
    return f"import marshal\nexec(marshal.loads({repr(marshaled)}))"

def encrypt_zlib(code):
    """Encrypt code using zlib"""
    compressed = zlib.compress(code.encode())
    return f"import zlib\nexec(zlib.decompress({repr(compressed)}).decode())"

def encrypt_all(code):
    """Encrypt code using all methods (base64 + marshal + zlib)"""
    compiled = compile(code, '<string>', 'exec')
    marshaled = marshal.dumps(compiled)
    compressed = zlib.compress(marshaled)
    encoded = base64.b64encode(compressed).decode()
    return f"import zlib, marshal, base64\nexec(marshal.loads(zlib.decompress(base64.b64decode('{encoded}'))))"

def save_file(original_path, encrypted_code, suffix):
    """Save encrypted file"""
    make_folder()
    name = os.path.splitext(os.path.basename(original_path))[0]
    out_path = os.path.join(SAVE_DIR, f"{name}_{suffix}_encrypted.py")
    
    with open(out_path, 'w') as f:
        f.write(encrypted_code)
    
    print(f"{GREEN}[✓] Saved to: {out_path}")

def Enc():
    """Encryptor menu"""
    print(Style.BRIGHT + Fore.CYAN + '┏━━━━━━━━━━━━━━━━━━━━━━━━━━' + ' < ' + Fore.CYAN + '𝗘𝗡𝗖𝗥𝗬𝗣𝗧𝗢𝗥' + Fore.CYAN + ' > ' + '━━━━━━━━━━━━━━━━━━━━━━━━━━┓')
    print(Style.BRIGHT + Fore.YELLOW + '┃ ' + Style.BRIGHT + Fore.GREEN + '[1]' + ' 𝗕𝗮𝘀𝗲𝟲𝟰 𝗘𝗻𝗰𝗿𝘆𝗽𝘁𝗶𝗼𝗻'.ljust(63) + Fore.BLUE + '┃')
    print(Style.BRIGHT + Fore.BLUE + '┃ ' + Style.BRIGHT + Fore.GREEN + '[2]' + ' 𝗠𝗮𝗿𝘀𝗵𝗮𝗹 𝗘𝗻𝗰𝗿𝘆𝗽𝘁𝗶𝗼𝗻'.ljust(63) + Fore.YELLOW + '┃')
    print(Style.BRIGHT + Fore.RED + '┃ ' + Style.BRIGHT + Fore.GREEN + '[3]' + ' 𝗭𝗹𝗶𝗯 𝗘𝗻𝗰𝗿𝘆𝗽𝘁𝗶𝗼𝗻'.ljust(63) + Fore.GREEN + '┃')
    print(Style.BRIGHT + Fore.GREEN + '┃ ' + Style.BRIGHT + Fore.GREEN + '[4]' + ' 𝗔𝗹𝗹 (𝗕𝗮𝘀𝗲𝟲𝟺 + 𝗠𝗮𝗿𝘀𝗵𝗮𝗹 + 𝗭𝗹𝗶𝗯)'.ljust(63) + Fore.MAGENTA + '┃')
    print(Style.BRIGHT + Fore.CYAN + '┃ ' + Style.BRIGHT + Fore.GREEN + '[5]' + ' 𝗕𝗮𝗰𝗸 𝗧𝗼 𝗠𝗲𝗻𝘂'.ljust(63) + Fore.CYAN + '┃')
    print(Style.BRIGHT + Fore.CYAN + '┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛' + Style.RESET_ALL)
    print_stylish_line()
    
    choice = input(Fore.YELLOW + Style.BRIGHT + '[?] Enter your choice ▶ ').strip()
    
    if choice == '5':
        return
    
    path = input(Style.BRIGHT + Fore.YELLOW + '[+] Enter full path of .py file to encrypt ▶ ').strip()
    
    if not os.path.isfile(path):
        print(Fore.RED + Style.BRIGHT + '[✗] File not found.')
        return
    
    try:
        with open(path, 'r') as f:
            code = f.read()
        
        if choice == '1':
            save_file(path, encrypt_base64(code), 'base64')
        elif choice == '2':
            save_file(path, encrypt_marshal(code), 'marshal')
        elif choice == '3':
            save_file(path, encrypt_zlib(code), 'zlib')
        elif choice == '4':
            save_file(path, encrypt_all(code), 'all')
        else:
            print(RED + "Invalid Choice")
    
    except Exception as e:
        print(RED + f"Error: {e}")
        logger.error(f"Error in Enc: {e}")
    
    input("Press Enter...")

# ============================================================================
# MAIN MENU AND EXECUTION
# ============================================================================

def show_menu():
    """Display main menu"""
    while True:
        try:
            banner()
            display_boxes()
            print_stylish_line()
            
            print(Style.BRIGHT + Fore.CYAN + '╭─━━━━━━━━━━━━━━━━━━━━━━━━━━━━' + bold_unicode(' < MENU > ') + '━━━━━━━━━━━━━━━━━━━━━━━━━━━─╮')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[01]' + bold_unicode(' Encryptor').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[02]' + bold_unicode(' Check Token').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[03]' + bold_unicode(' Check Cookies').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[04]' + bold_unicode(' Fetch Gc UID').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[05]' + bold_unicode(' Get Page Token').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[06]' + bold_unicode(' Run Post Loader').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[07]' + bold_unicode(' Run Convo Loader').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[08]' + bold_unicode(' Cookies Post Loader').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[09]' + bold_unicode(' Get EAAD6 Token (via Cookies)').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[10]' + bold_unicode(' Get Eaad Token By Cookies (Normal)').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[11]' + bold_unicode(' Get EAABwz Token By Cookies (iPad)').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[12]' + bold_unicode(' Get EAAAU Token By FB Login').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[13]' + bold_unicode(' Get EAAD6 Token + Cookies By 2FA').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.GREEN + '[14]' + bold_unicode(' Run Post Loader Using Page Id Token').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.MAGENTA + '┃ ' + Style.BRIGHT + Fore.RED + '[15]' + bold_unicode(' EXIT').ljust(62) + Fore.MAGENTA + '┃')
            print(Style.BRIGHT + Fore.CYAN + '╰─━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━─╯' + Style.RESET_ALL)
            print_stylish_line()
            
            choice = input(Style.BRIGHT + INPUT_COLOR + '[?] 𝗖𝗵𝗼𝗼𝘀𝗲 𝗔𝗻 𝗢𝗽𝘁𝗶𝗼𝗻 ▶ ')
            print_stylish_line()
            
            if choice == '1':
                Enc()
            elif choice == '2':
                token_file = input(Style.BRIGHT + INPUT_COLOR + '[•] Token File Path ▶ ')
                validate_tokens(token_file)
                input(Style.BRIGHT + Fore.MAGENTA + '[✔] Press Enter to return to menu ')
            elif choice == '3':
                cookies_checker_menu()
            elif choice == '4':
                fetch_gc_info()
            elif choice == '5':
                extract_page_tokens()
            elif choice == '6':
                start_loader()
            elif choice == '7':
                start_convo()
            elif choice == '8':
                Wall()
            elif choice == '9':
                eaad_via_cookie()
            elif choice == '10':
                eaad_normal()
            elif choice == '11':
                insta_token()
            elif choice == '12':
                login_token_menu()
            elif choice == '13':
                Token_by_2fa()
            elif choice == '14':
                comment_by_page()
            elif choice == '15':
                print(RED + "Exiting... Goodbye!")
                sys.exit(0)
            else:
                print(RED + "Invalid Option")
                time.sleep(1)
        
        except KeyboardInterrupt:
            print(RED + "\n[!] User Interrupted")
            time.sleep(1)
            continue
        except Exception as e:
            print(RED + f"[!] Error: {e}")
            logger.error(f"Error in show_menu: {e}")
            time.sleep(2)

def main():
    """Main execution function"""
    try:
        # Display banner and info
        banner()
        display_boxes()
        print_stylish_line()
        
        # Check approval
        unique_key = get_unique_id()
        check_permission(unique_key)
        
        # Check password
        if check_password():
            # Show main menu
            show_menu()
    
    except KeyboardInterrupt:
        print(RED + "\n[!] User Interrupted")
        sys.exit(0)
    except Exception as e:
        print(RED + f"[!] Fatal Error: {e}")
        logger.error(f"Fatal error in main: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()