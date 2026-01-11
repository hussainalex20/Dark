#!/usr/bin/env python3
"""
FACEBOOK TOKEN GENERATOR MODULE
Comprehensive Facebook login and token generation with 2FA support
"""

import base64
import json
import re
import uuid
import io
import struct
import time
import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import pyotp
from typing import Dict, Optional
from dataclasses import dataclass

# User agents
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    '[FBAN/FB4A;FBAV/520.0.0.45.73;FBBV/751323900;FBDM/{density=3.0,width=1080,height=2400};FBLC/en_US;FBRV/0;FBCR/Samsung;FBMF/Samsung;FBBD/Samsung;FBPN/com.facebook.katana;FBDV/SM-G998B;FBSV/14;FBOP/1;FBCA/arm64-v8a:arm64-v8a;]'
]

@dataclass
class LoginResult:
    """Data class for login results"""
    success: bool
    message: str
    access_token: str = ""
    cookies: str = ""
    user_id: str = ""
    session_key: str = ""
    machine_id: str = ""
    secret: str = ""
    raw_data: Dict = None
    
    def __post_init__(self):
        if self.raw_data is None:
            self.raw_data = {}


class FacebookTokenGenerator:
    """Facebook Token Generator Class"""
    
    def __init__(self):
        self.session = requests.Session()
        self.device_id = str(uuid.uuid4())
    
    def get_random_user_agent(self) -> str:
        """Get random user agent"""
        import random
        return random.choice(USER_AGENTS)
    
    def login(self, username: str, password: str, two_fa_secret: str = "") -> LoginResult:
        """
        Login to Facebook and generate token
        
        Args:
            username: Email, phone, or username
            password: Facebook password
            two_fa_secret: 2FA secret key (optional)
        
        Returns:
            LoginResult object with success status and token data
        """
        try:
            print(f"🔄 Processing login for: {username}")
            
            if not username or not password:
                return LoginResult(
                    success=False,
                    message="Username and password must not be empty"
                )
            
            # Send login request
            response = self._send_login_request(username, password)
            
            if not response:
                return LoginResult(
                    success=False,
                    message="Cannot connect to Facebook server"
                )
            
            # Parse response
            return self._parse_login_response(response, two_fa_secret)
        
        except Exception as ex:
            print(f"❌ Error: {str(ex)}")
            return LoginResult(
                success=False,
                message=f"An internal server error occurred: {str(ex)}"
            )
    
    def _send_login_request(self, username: str, password: str) -> str:
        """Send login request to Facebook"""
        try:
            print("🔐 Encrypting password...")
            
            # Fetch password encryption key
            pwd_key_fetch = 'https://b-graph.facebook.com/pwd_key_fetch'
            pwd_key_fetch_data = {
                'version': '2',
                'flow': 'CONTROLLER_INITIALIZATION',
                'method': 'GET',
                'fb_api_req_friendly_name': 'pwdKeyFetch',
                'fb_api_caller_class': 'com.facebook.auth.login.AuthOperations',
                'access_token': '438142079694454|fc0a7caa49b192f64f6f5a6d9643bb28'
            }
            
            response = requests.post(pwd_key_fetch, params=pwd_key_fetch_data).json()
            public_key = response.get('public_key')
            key_id = str(response.get('key_id', '25'))
            
            # Encrypt password
            rand_key = get_random_bytes(32)
            iv = get_random_bytes(12)
            pubkey = RSA.import_key(public_key)
            cipher_rsa = PKCS1_v1_5.new(pubkey)
            encrypted_rand_key = cipher_rsa.encrypt(rand_key)
            cipher_aes = AES.new(rand_key, AES.MODE_GCM, nonce=iv)
            current_time = int(time.time())
            cipher_aes.update(str(current_time).encode("utf-8"))
            encrypted_passwd, auth_tag = cipher_aes.encrypt_and_digest(password.encode("utf-8"))
            
            # Build encrypted password string
            buf = io.BytesIO()
            buf.write(bytes([1, int(key_id)]))
            buf.write(iv)
            buf.write(struct.pack("<h", len(encrypted_rand_key)))
            buf.write(encrypted_rand_key)
            buf.write(auth_tag)
            buf.write(encrypted_passwd)
            encoded = base64.b64encode(buf.getvalue()).decode("utf-8")
            encrypted_password = f"#PWD_FB4A:2:{current_time}:{encoded}"
            
            # Build login request payload
            variables = {
                "params": {
                    "params": json.dumps({
                        "client_input_params": {
                            "password": encrypted_password,
                            "device_id": self.device_id,
                            "family_device_id": self.device_id,
                            "contact_point": username,
                            "login_attempt_count": 1,
                            "event_flow": "login_manual",
                            "sim_phones": [],
                            "secure_family_device_id": str(uuid.uuid4()),
                            "attestation_result": {
                                "data": base64.b64encode(json.dumps({
                                    "challenge_nonce": base64.b64encode(get_random_bytes(32)).decode(),
                                    "username": username
                                }).encode()).decode(),
                                "signature": "MEQCIDHrmQ86yvC7yeVBi0eYpIr2cnhtaSWxYm8I+ZcZ081fAiBLzhHez6CMvaQqaFrCvfCMYker7WNLiQ4L99JpVR9K+Q==",
                                "keyHash": "9c620c1c59a053c07d9ce2f1166b1385e359254b6c461b3b55ca256d75e0976e"
                            },
                            "auth_secure_device_id": "",
                            "has_whatsapp_installed": 0,
                            "sso_token_map_json_string": "",
                            "password_contains_non_ascii": "false",
                            "sim_serials": [],
                            "client_known_key_hash": "",
                            "encrypted_msisdn": "",
                            "should_show_nested_nta_from_aymh": 0,
                            "machine_id": "",
                            "flash_call_permission_status": {
                                "READ_PHONE_STATE": "DENIED",
                                "READ_CALL_LOG": "DENIED",
                                "ANSWER_PHONE_CALLS": "DENIED"
                            },
                            "accounts_list": [],
                            "fb_ig_device_id": [],
                            "device_emails": [],
                            "try_num": 1,
                            "lois_settings": {"lois_token": "", "lara_override": ""},
                            "event_step": "home_page",
                            "headers_infra_flow_id": str(uuid.uuid4()),
                            "openid_tokens": {}
                        },
                        "server_params": {
                            "should_trigger_override_login_2fa_action": 0,
                            "is_from_logged_out": 0,
                            "should_trigger_override_login_success_action": 0,
                            "login_credential_type": "none",
                            "server_login_source": "login",
                            "waterfall_id": str(uuid.uuid4()),
                            "login_source": "Login",
                            "is_platform_login": 0,
                            "pw_encryption_try_count": 1,
                            "INTERNAL__latency_qpl_marker_id": 36707139,
                            "offline_experiment_group": "caa_iteration_v6_perf_fb_2",
                            "is_from_landing_page": 0,
                            "password_text_input_id": "nmi7ws:95",
                            "is_from_empty_password": 0,
                            "ar_event_source": "login_home_page",
                            "username_text_input_id": "nmi7ws:94",
                            "layered_homepage_experiment_group": None,
                            "device_id": self.device_id,
                            "INTERNAL__latency_qpl_instance_id": 1.42852366000951E14,
                            "reg_flow_source": "login_home_native_integration_point",
                            "is_caa_perf_enabled": 1,
                            "credential_type": "password",
                            "is_from_password_entry_page": 0,
                            "caller": "gslr",
                            "family_device_id": self.device_id,
                            "INTERNAL_INFRA_THEME": "harm_f",
                            "is_from_assistive_id": 0,
                            "access_flow_version": "F2_FLOW",
                            "is_from_logged_in_switcher": 0
                        }
                    }),
                    "bloks_versioning_id": "3469837656910fc29c9aa968ab33845cd52eb5253ae110610b944c8e9028d8f6",
                    "app_id": "com.bloks.www.bloks.caa.login.async.send_login_request"
                },
                "scale": "2",
                "nt_context": {
                    "using_white_navbar": True,
                    "styles_id": "964d559c1e2aa0142b5069bc8cb1adea",
                    "pixel_ratio": 2,
                    "is_push_on": True,
                    "debug_tooling_metadata_token": None,
                    "is_flipper_enabled": False,
                    "theme_params": [],
                    "bloks_version": "3469837656910fc29c9aa968ab33845cd52eb5253ae110610b944c8e9028d8f6"
                }
            }
            
            payload = {
                "method": "post",
                "pretty": "false",
                "format": "json",
                "server_timestamps": "true",
                "locale": "en_US",
                "purpose": "fetch",
                "fb_api_req_friendly_name": "FbBloksActionRootQuery-com.bloks.www.bloks.caa.login.async.send_login_request",
                "fb_api_caller_class": "graphservice",
                "client_doc_id": "119940804214876861379510865434",
                "variables": json.dumps(variables),
                "fb_api_analytics_tags": "[&quot;GraphServices&quot;]",
                "client_trace_id": str(uuid.uuid4())
            }
            
            headers = {
                "X-Fb-Connection-Type": "WIFI",
                "X-Fb-Http-Engine": "Tigon/Liger",
                "X-Fb-Client-Ip": "True",
                "X-Fb-Server-Cluster": "True",
                "X-Tigon-Is-Retry": "False",
                "User-Agent": self.get_random_user_agent(),
                "X-Fb-Device-Group": "5427",
                "X-Graphql-Request-Purpose": "fetch",
                "X-Fb-Privacy-Context": "3643298472347298",
                "X-Graphql-Client-Library": "graphservice",
                "X-Fb-Net-Hni": "45201",
                "X-Fb-Sim-Hni": "45201",
                "Authorization": "OAuth 350685531728|62f8ce9f74b12f84c123cc23437a4a32",
                "X-Fb-Request-Analytics-Tags": "{&quot;network_tags&quot;:{&quot;product&quot;:&quot;350685531728&quot;,&quot;purpose&quot;:&quot;fetch&quot;,&quot;request_category&quot;:&quot;graphql&quot;,&quot;retry_attempt&quot;:&quot;0&quot;},&quot;application_tags&quot;:&quot;graphservice&quot;}",
                "Accept": "application/json, text/json, text/x-json, text/javascript, application/xml, text/xml",
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "Host": "b-graph.facebook.com"
            }
            
            print("📡 Sending login request to Facebook...")
            response = requests.post(
                "https://b-graph.facebook.com/graphql",
                data=payload,
                headers={k: v for k, v in headers.items() if k.lower() != "content-type"}
            )
            
            if response.status_code == 200:
                print("✅ Facebook responded successfully")
                return response.text
            else:
                print(f"❌ Facebook responded with error: {response.status_code}")
                return ""
        
        except Exception as ex:
            print(f"❌ Error sending login request: {str(ex)}")
            return ""
    
    def _parse_login_response(self, json_response: str, two_fa_secret: str) -> LoginResult:
        """Parse login response"""
        try:
            action_string = self._extract_action_string(json_response)
            print("🔍 Parsing login response...")
            
            # Check for successful login
            if "session_key" in action_string:
                print("✅ Detected successful login!")
                return self._parse_successful_login(action_string)
            
            # Check for 2FA requirement
            elif "two_step_verification" in action_string or "two_fac" in action_string:
                print("🔐 Detected 2FA requirement!")
                return self._handle_2fa(action_string, two_fa_secret)
            
            # Check for wrong credentials
            elif any(x in action_string.lower() for x in ["wrong credentials", "invalid username", "login_failed"]):
                print("❌ Detected wrong credentials!")
                return LoginResult(
                    success=False,
                    message="Wrong username or password."
                )
            
            # Check for checkpoint
            elif "checkpoint" in action_string or "security_check" in action_string:
                print("🛡️ Detected checkpoint!")
                return LoginResult(
                    success=False,
                    message="Account checkpointed. Please verify your account on Facebook."
                )
            
            # Unknown response
            print("❓ Detected unknown response!")
            return LoginResult(
                success=False,
                message="An unknown error occurred. Please try again or check your credentials."
            )
        
        except Exception as ex:
            print(f"❌ Error parsing: {str(ex)}")
            return LoginResult(
                success=False,
                message="An unknown error occurred while processing the login response."
            )
    
    def _extract_action_string(self, json_response: str) -> str:
        """Extract action string from JSON response"""
        try:
            data = json.loads(json_response)
            action_bundle = data["data"]["fb_bloks_action"]["root_action"]["action"]["action_bundle"]["bloks_bundle_action"]
            bloks_data = json.loads(action_bundle)
            return bloks_data["layout"]["bloks_payload"]["action"]
        except Exception as ex:
            print(f"❌ Error extracting action string: {str(ex)}")
            return ""
    
    def _handle_2fa(self, action_string: str, two_fa_secret: str) -> LoginResult:
        """Handle 2FA authentication"""
        two_fa_context = self._extract_two_fa_context(action_string)
        
        if not two_fa_context:
            return LoginResult(
                success=False,
                message="Unable to process 2FA; context missing."
            )
        
        print(f"✅ Found 2FA context")
        
        # Generate 2FA code
        two_fa_code = self._generate_two_factor_code(two_fa_secret)
        
        if not two_fa_code:
            return LoginResult(
                success=False,
                message="Unable to generate 2FA code. Please check your 2FA secret."
            )
        
        print(f"🔐 Generated 2FA code")
        
        # Call 2FA entrypoint
        self._call_2fa_entrypoint(two_fa_context)
        
        # Verify 2FA code
        result = self._verify_2fa_code(two_fa_code, two_fa_context)
        
        if not result.success:
            return LoginResult(
                success=False,
                message="Invalid 2FA code. Please try again."
            )
        
        return result
    
    def _generate_two_factor_code(self, two_fa_secret: str) -> str:
        """Generate 2FA code from secret"""
        try:
            totp = pyotp.TOTP(two_fa_secret.replace(" ", "").upper())
            code = totp.now()
            print(f"🔐 Auto-generated 2FA code from secret")
            return code
        except Exception as ex:
            print(f"❌ Error generating 2FA code: {str(ex)}")
            return ""
    
    def _extract_two_fa_context(self, action_string: str) -> str:
        """Extract 2FA context from action string"""
        try:
            bundle = action_string
            for _ in range(3):
                bundle = bundle.replace('\&quot;', '"').replace('\\\\', '\\')
            bundle = bundle.replace('\\', '')
            
            patterns = [
                r'"two_step_verification_context",\s*"([^"]+)"',
                r'"(ARG[A-Za-z0-9_\-+/=]{400,})"',
                r'two_step_verification_context.*?"([A-Za-z0-9_\-+/=]{400,})"'
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, bundle, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    context_value = match.group(1)
                    if len(context_value) > 400 and (context_value.startswith("ARG") or len(context_value) > 600):
                        return context_value
            return ""
        except Exception as ex:
            print(f"❌ Error extracting 2FA context: {str(ex)}")
            return ""
    
    def _call_2fa_entrypoint(self, two_fa_context: str):
        """Call 2FA entrypoint"""
        try:
            payload = {
                "params": {
                    "params": json.dumps({
                        "client_input_params": {},
                        "server_params": {
                            "two_step_verification_context": two_fa_context
                        }
                    }),
                    "bloks_versioning_id": "cb6ac324faea83da28649a4d5046c3a4f0486cb987f8ab769765e316b075a76c",
                    "app_id": "com.bloks.www.two_step_verification.entrypoint.async"
                },
                "scale": "3",
                "nt_context": {
                    "using_white_navbar": True,
                    "styles_id": "55d2af294359fa6bbdb8e045ff01fc5e",
                    "pixel_ratio": 3,
                    "is_push_on": True,
                    "debug_tooling_metadata_token": None,
                    "is_flipper_enabled": False,
                    "theme_params": [],
                    "bloks_version": "cb6ac324faea83da28649a4d5046c3a4f0486cb987f8ab769765e316b075a76c"
                }
            }
            
            headers = {
                "User-Agent": self.get_random_user_agent(),
                "Authorization": "OAuth 350685531728|62f8ce9f74b12f84c123cc23437a4a32",
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
            }
            
            requests.post(
                "https://b-graph.facebook.com/graphql",
                data={"variables": json.dumps(payload)},
                headers=headers
            )
        except:
            pass
    
    def _verify_2fa_code(self, two_fa_code: str, two_fa_context: str) -> LoginResult:
        """Verify 2FA code with Facebook"""
        try:
            payload = {
                "params": {
                    "params": json.dumps({
                        "client_input_params": {
                            "auth_secure_device_id": "",
                            "machine_id": "sd83aCE9TA19IdDgfW-9tPJ-",
                            "code": two_fa_code,
                            "should_trust_device": 1,
                            "family_device_id": self.device_id,
                            "device_id": self.device_id
                        },
                        "server_params": {
                            "INTERNAL__latency_qpl_marker_id": 36707139,
                            "device_id": self.device_id,
                            "challenge": "totp",
                            "machine_id": "sd83aCE9TA19IdDgfW-9tPJ-",
                            "INTERNAL__latency_qpl_instance_id": 1.71160241100066E14,
                            "two_step_verification_context": two_fa_context,
                            "flow_source": "two_factor_login"
                        }
                    }),
                    "bloks_versioning_id": "cb6ac324faea83da28649a4d5046c3a4f0486cb987f8ab769765e316b075a76c",
                    "app_id": "com.bloks.www.two_step_verification.verify_code.async"
                },
                "scale": "3",
                "nt_context": {
                    "using_white_navbar": True,
                    "styles_id": "55d2af294359fa6bbdb8e045ff01fc5e",
                    "pixel_ratio": 3,
                    "is_push_on": True,
                    "debug_tooling_metadata_token": None,
                    "is_flipper_enabled": False,
                    "theme_params": [],
                    "bloks_version": "cb6ac324faea83da28649a4d5046c3a4f0486cb987f8ab769765e316b075a76c"
                }
            }
            
            headers = {
                "X-Fb-Connection-Type": "WIFI",
                "X-Fb-Http-Engine": "Tigon/Liger",
                "X-Fb-Client-Ip": "True",
                "X-Fb-Server-Cluster": "True",
                "X-Tigon-Is-Retry": "False",
                "User-Agent": self.get_random_user_agent(),
                "X-Fb-Device-Group": "5427",
                "X-Graphql-Request-Purpose": "fetch",
                "X-Fb-Privacy-Context": "3643298472347298",
                "X-Graphql-Client-Library": "graphservice",
                "X-Fb-Net-Hni": "45201",
                "X-Fb-Sim-Hni": "45201",
                "Authorization": "OAuth 350685531728|62f8ce9f74b12f84c123cc23437a4a32",
                "X-Fb-Request-Analytics-Tags": "{&quot;network_tags&quot;:{&quot;product&quot;:&quot;350685531728&quot;,&quot;purpose&quot;:&quot;fetch&quot;,&quot;request_category&quot;:&quot;graphql&quot;,&quot;retry_attempt&quot;:&quot;0&quot;},&quot;application_tags&quot;:&quot;graphservice&quot;}",
                "Accept": "application/json, text/json, text/x-json, text/javascript, application/xml, text/xml",
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "Host": "b-graph.facebook.com"
            }
            
            request_params = {
                "method": "post",
                "pretty": "false",
                "format": "json",
                "server_timestamps": "true",
                "locale": "en_US",
                "purpose": "fetch",
                "fb_api_req_friendly_name": "FbBloksActionRootQuery-com.bloks.www.two_step_verification.verify_code.async",
                "fb_api_caller_class": "graphservice",
                "client_doc_id": "119940804214876861379510865434",
                "variables": json.dumps(payload),
                "fb_api_analytics_tags": "[&quot;GraphServices&quot;]",
                "generate_session_cookies": "1"
            }
            
            response = requests.post(
                "https://b-graph.facebook.com/graphql",
                data=request_params,
                headers=headers
            )
            
            if response.status_code != 200:
                return LoginResult(
                    success=False,
                    message="Invalid 2FA code. Please try again."
                )
            
            response_text = response.text
            session_data = self._extract_session_data(response_text)
            access_token = session_data.get("access_token")
            
            if access_token:
                print("✅ 2FA verification successful!")
                return LoginResult(
                    success=True,
                    access_token=access_token,
                    user_id=session_data.get("uid", ""),
                    session_key=session_data.get("session_key", ""),
                    machine_id=session_data.get("machine_id", ""),
                    secret=session_data.get("secret", ""),
                    cookies=session_data.get("cookies", ""),
                    message="Login successful with 2FA"
                )
            
            return LoginResult(
                success=False,
                message="Invalid 2FA code. Please try again."
            )
        
        except Exception as ex:
            print(f"❌ Error verifying 2FA: {str(ex)}")
            return LoginResult(
                success=False,
                message="Invalid 2FA code. Please try again."
            )
    
    def _extract_session_data(self, response_text: str) -> Dict:
        """Extract session data from response"""
        try:
            bundle = self._extract_bundle_from_response(response_text)
            if not bundle:
                return {}
            
            for _ in range(3):
                bundle = bundle.replace('\&quot;', '"').replace('\\\\', '\\')
            bundle = bundle.replace('\\', '')
            
            patterns = {
                "access_token": r'"access_token"\s*:\s*"([^"]+)"',
                "session_key": r'"session_key"\s*:\s*"([^"]+)"',
                "uid": r'"uid"\s*:\s*["]?(\d+)["]?',
                "machine_id": r'"machine_id"\s*:\s*"([^"]+)"',
                "secret": r'"secret"\s*:\s*"([a-f0-9]{32})"',
                "session_cookies": r'"session_cookies"\s*:\s*\[([^\]]+)\]'
            }
            
            valid_cookies = {"c_user", "xs", "fr", "datr", "sb"}
            result = {}
            
            for key, pattern in patterns.items():
                if key == "session_cookies":
                    continue
                match = re.search(pattern, bundle, re.IGNORECASE | re.DOTALL)
                if match:
                    value = match.group(1).strip()
                    if value and len(value) > 3:
                        result[key] = value
            
            # Extract cookies
            cookies = []
            cookie_match = re.search(patterns["session_cookies"], bundle, re.IGNORECASE | re.DOTALL)
            if cookie_match:
                cookies_text = cookie_match.group(1)
                cookie_pattern = r'\{[^}]*"name"\s*:\s*"([^"]+)"[^}]*"value"\s*:\s*"([^"]+)"'
                for match in re.finditer(cookie_pattern, cookies_text, re.IGNORECASE):
                    name, value = match.groups()
                    if name in valid_cookies and value:
                        cookies.append(f"{name}={value}")
            
            result["cookies"] = "; ".join(cookies) if cookies else ""
            return result
        
        except Exception as ex:
            print(f"❌ Error extracting session data: {str(ex)}")
            return {}
    
    def _extract_bundle_from_response(self, response_text: str) -> str:
        """Extract bundle from response"""
        try:
            data = json.loads(response_text)
            bundle = data["data"]["fb_bloks_action"]["root_action"]["action"]["action_bundle"]["bloks_bundle_action"]
            return bundle
        except Exception as ex:
            print(f"❌ Error extracting bundle: {str(ex)}")
            return ""
    
    def _parse_successful_login(self, action_string: str) -> LoginResult:
        """Parse successful login response"""
        try:
            session_data = self._extract_session_data(action_string)
            
            if session_data.get("access_token"):
                print("✅ Parsed successful login!")
                return LoginResult(
                    success=True,
                    access_token=session_data.get("access_token", ""),
                    cookies=session_data.get("cookies", ""),
                    message="Login successful",
                    user_id=session_data.get("uid", ""),
                    session_key=session_data.get("session_key", ""),
                    machine_id=session_data.get("machine_id", ""),
                    secret=session_data.get("secret", "")
                )
            
            return LoginResult(
                success=False,
                message="Unable to extract session data"
            )
        
        except Exception as ex:
            print(f"❌ Error parsing successful login: {str(ex)}")
            return LoginResult(
                success=False,
                message=f"Error parsing successful login: {str(ex)}"
            )


def convert_eaa_to_eaad(eaa_token: str) -> str:
    """
    Convert EAA/EAAA token to EAAD6V7 token
    
    Args:
        eaa_token: EAA or EAAA format token
    
    Returns:
        EAAD6V7 format token or empty string on failure
    """
    try:
        token = (eaa_token or "").strip()
        
        if not token:
            print("⚠️ No token provided for EAAD conversion.")
            return ""
        
        if not (token.startswith("EAA") or token.startswith("EAAA")):
            print("⚠️ Provided token does not start with EAA/EAAA prefix; attempting conversion anyway.")
        
        print("📡 Requesting EAAD6V7 token from api.facebook.com...")
        
        try:
            response = requests.post(
                'https://api.facebook.com/method/auth.getSessionforApp',
                data={
                    'access_token': token,
                    'format': 'json',
                    'new_app_id': '275254692598279',
                    'generate_session_cookies': '1'
                },
                timeout=20
            )
        except Exception as ex:
            print(f"❌ HTTP request failed for EAAD conversion: {ex}")
            return ""
        
        if response.status_code != 200:
            print(f"❌ EAAD conversion HTTP error: {response.status_code}")
            return ""
        
        # Try JSON parse
        data = {}
        try:
            data = response.json()
        except Exception:
            # Not JSON - fallback to regex search
            text = response.text or ""
            m = re.search(r'"access_token"\s*:\s*"([^"]+)"', text)
            if m:
                token_new = m.group(1)
                print("✅ EAAD6V7 Token Generated Successfully (regex fallback)")
                return token_new
            
            print("⚠️ EAAD conversion response is not JSON and no token was found by regex.")
            return ""
        
        # First: straightforward access_token at top-level
        token_new = data.get("access_token") or None
        if token_new:
            print("✅ EAAD6V7 Token Generated Successfully (top-level)")
            return token_new
        
        # Second: sometimes the API returns a 'session_key' field which contains a JSON string.
        session_key_field = data.get("session_key") or data.get("session") or None
        if session_key_field and isinstance(session_key_field, str):
            # Attempt to parse the JSON contained inside the string
            try:
                inner = json.loads(session_key_field)
                token_new = inner.get("access_token") or None
                if token_new:
                    print("✅ EAAD6V7 Token Generated Successfully (extracted from session_key JSON)")
                    return token_new
            except Exception:
                # not JSON - try regex inside the string
                m = re.search(r'"access_token"\s*:\s*"([^"]+)"', session_key_field)
                if m:
                    token_new = m.group(1)
                    print("✅ EAAD6V7 Token Generated Successfully (extracted from session_key by regex)")
                    return token_new
        
        # Third: sometimes nested in other keys like 'result'
        if isinstance(data.get("result"), dict):
            token_new = data["result"].get("access_token")
            if token_new:
                print("✅ EAAD6V7 Token Generated Successfully (result.access_token)")
                return token_new
        
        # fallback: try regex against full response text
        text = response.text or ""
        m = re.search(r'"access_token"\s*:\s*"([^"]+)"', text)
        if m:
            token_new = m.group(1)
            print("✅ EAAD6V7 Token Generated Successfully (regex fallback)")
            return token_new
        
        print("❌ Failed to convert token to EAAD6V7")
        print("Response from api.facebook.com:", data)
        return ""
    
    except Exception as e:
        print(f"❌ Error converting token: {e}")
        return ""


if __name__ == '__main__':
    print("🚀 FACEBOOK TOKEN GENERATOR")
    print("=" * 50)
    
    generator = FacebookTokenGenerator()
    
    username = input("📧 Username / Email / Phone: ").strip()
    password = input("🔑 Password: ").strip()
    two_fa_secret = input("🔐 2FA Secret (optional, press Enter to skip): ").strip()
    
    print("\n⏳ Logging in, please wait...\n")
    
    result = generator.login(username, password, two_fa_secret)
    
    print("\n📊 RESULT")
    print("=" * 50)
    print(f"Status : {'SUCCESS ✅' if result.success else 'FAILED ❌'}")
    print(f"Message: {result.message}")
    
    if result.success:
        access_token = result.access_token
        print("\n🔑 ACCESS TOKEN:")
        print(access_token or "Not found")
        
        if access_token:
            print("\n🔄 Converting to EAAD6V7 token...")
            eaad = convert_eaa_to_eaad(access_token)
            
            if eaad:
                print("\n✅ EAAD6V7 TOKEN:")
                print(eaad)
            else:
                print("❌ EAAD conversion failed")
        
        if result.cookies:
            print("\n🍪 COOKIES:")
            print(result.cookies)
    
    print("\n⏹️ Press Enter to exit...")
    input()