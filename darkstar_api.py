"""
DARKSTAR WEB FB TOOL - API Module
===================================
Facebook API interaction module
Enhanced Edition - Extended Module
"""

import os
import sys
import re
import json
import time
import logging
import requests
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlencode, quote

# Import utilities
from darkstar_utils import (
    ProxyConfig, FacebookRequestConfig, BatchResult,
    make_request_with_retry, ProgressTracker, SimpleCache,
    validate_fb_token, parse_fb_cookies, extract_fb_dtsg
)

# ============================================================================
# CONFIGURATION
# ============================================================================

logger = logging.getLogger(__name__)

BASE_URL = "https://www.facebook.com"
GRAPH_API_URL = "https://graph.facebook.com"

# User agents for different devices
USER_AGENTS = {
    'desktop': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'mobile': 'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'ipad': 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1',
    'iphone': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
}

# ============================================================================
# ENUMS AND DATA CLASSES
# ============================================================================

class TokenType(Enum):
    """Types of Facebook access tokens"""
    EAAD = "EAAD"
    EAAB = "EAAB"
    EAAU = "EAAU"
    EAABw = "EAABw"
    EAAAG = "EAAAG"
    EAAAH = "EAAAH"
    EAAA = "EAAA"

class APIEndpoint(Enum):
    """Facebook API endpoints"""
    ME = "me"
    FEED = "me/feed"
    POSTS = "me/posts"
    COMMENTS = "me/comments"
    LIKES = "me/likes"
    GROUPS = "me/groups"
    FRIENDS = "me/friends"
    PHOTOS = "me/photos"
    VIDEOS = "me/videos"
    NOTIFICATIONS = "me/notifications"
    INBOX = "me/inbox"

class PostPrivacy(Enum):
    """Post privacy settings"""
    PUBLIC = "EVERYONE"
    FRIENDS = "ALL_FRIENDS"
    FRIENDS_OF_FRIENDS = "FRIENDS_OF_FRIENDS"
    SELF = "SELF"
    CUSTOM = "CUSTOM"

@dataclass
class FacebookPost:
    """Facebook post data structure"""
    post_id: str
    message: str
    created_time: str
    likes_count: int = 0
    comments_count: int = 0
    shares_count: int = 0
    privacy: str = PostPrivacy.PUBLIC.value
    permalink_url: str = ""
    full_picture: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'post_id': self.post_id,
            'message': self.message,
            'created_time': self.created_time,
            'likes_count': self.likes_count,
            'comments_count': self.comments_count,
            'shares_count': self.shares_count,
            'privacy': self.privacy,
            'permalink_url': self.permalink_url,
            'full_picture': self.full_picture,
        }

@dataclass
class FacebookComment:
    """Facebook comment data structure"""
    comment_id: str
    message: str
    from_name: str
    from_id: str
    created_time: str
    likes_count: int = 0
    parent_comment_id: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'comment_id': self.comment_id,
            'message': self.message,
            'from_name': self.from_name,
            'from_id': self.from_id,
            'created_time': self.created_time,
            'likes_count': self.likes_count,
            'parent_comment_id': self.parent_comment_id,
        }

@dataclass
class FacebookUser:
    """Facebook user data structure"""
    user_id: str
    name: str
    first_name: str = ""
    last_name: str = ""
    email: str = ""
    profile_picture: str = ""
    gender: str = ""
    locale: str = ""
    timezone: int = 0
    verified: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'user_id': self.user_id,
            'name': self.name,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'profile_picture': self.profile_picture,
            'gender': self.gender,
            'locale': self.locale,
            'timezone': self.timezone,
            'verified': self.verified,
        }

@dataclass
class FacebookGroup:
    """Facebook group data structure"""
    group_id: str
    name: str
    description: str = ""
    member_count: int = 0
    privacy: str = ""
    cover_photo: str = ""
    administrator: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'group_id': self.group_id,
            'name': self.name,
            'description': self.description,
            'member_count': self.member_count,
            'privacy': self.privacy,
            'cover_photo': self.cover_photo,
            'administrator': self.administrator,
        }

@dataclass
class APICallResult:
    """Result of API call"""
    success: bool
    data: Optional[Any] = None
    error_message: str = ""
    error_code: int = 0
    status_code: int = 0
    
    def is_success(self) -> bool:
        """Check if call was successful"""
        return self.success

# ============================================================================
# FACEBOOK API CLIENT
# ============================================================================

class FacebookAPIClient:
    """Facebook API client for making authenticated requests"""
    
    def __init__(
        self,
        access_token: str,
        user_agent: str = None,
        proxy: ProxyConfig = None
    ):
        """Initialize API client
        
        Args:
            access_token: Facebook access token
            user_agent: Custom user agent
            proxy: Proxy configuration
        """
        self.access_token = access_token
        self.user_agent = user_agent or USER_AGENTS['desktop']
        self.proxy = proxy
        self.cache = SimpleCache(ttl=300)  # 5 minute cache
        self.request_config = FacebookRequestConfig(
            user_agent=self.user_agent,
            cookies={},
            proxy=self.proxy,
            timeout=10,
            retry_count=3
        )
    
    def _make_graph_request(
        self,
        endpoint: str,
        params: Dict[str, Any] = None,
        method: str = 'GET'
    ) -> APICallResult:
        """Make request to Graph API
        
        Args:
            endpoint: API endpoint
            params: Request parameters
            method: HTTP method
            
        Returns:
            APICallResult object
        """
        if params is None:
            params = {}
        
        params['access_token'] = self.access_token
        
        url = f"{GRAPH_API_URL}/{endpoint}"
        
        try:
            if method == 'GET':
                response = requests.get(url, params=params, timeout=10)
            elif method == 'POST':
                response = requests.post(url, data=params, timeout=10)
            else:
                return APICallResult(
                    success=False,
                    error_message=f"Unsupported method: {method}"
                )
            
            result = response.json()
            
            if 'error' in result:
                error = result['error']
                return APICallResult(
                    success=False,
                    error_message=error.get('message', 'Unknown error'),
                    error_code=error.get('code', 0),
                    status_code=response.status_code
                )
            
            return APICallResult(
                success=True,
                data=result,
                status_code=response.status_code
            )
            
        except Exception as e:
            logger.error(f"API request failed: {e}")
            return APICallResult(
                success=False,
                error_message=str(e)
            )
    
    def get_user_info(self) -> Optional[FacebookUser]:
        """Get current user information
        
        Returns:
            FacebookUser object or None if failed
        """
        # Check cache first
        cached = self.cache.get('user_info')
        if cached:
            return cached
        
        result = self._make_graph_request('me', fields='id,name,first_name,last_name,email,picture,gender,locale,timezone,verified')
        
        if not result.is_success():
            return None
        
        try:
            data = result.data
            picture_url = data.get('picture', {}).get('data', {}).get('url', '')
            
            user = FacebookUser(
                user_id=data['id'],
                name=data['name'],
                first_name=data.get('first_name', ''),
                last_name=data.get('last_name', ''),
                email=data.get('email', ''),
                profile_picture=picture_url,
                gender=data.get('gender', ''),
                locale=data.get('locale', ''),
                timezone=data.get('timezone', 0),
                verified=data.get('verified', False)
            )
            
            # Cache the result
            self.cache.set('user_info', user)
            return user
            
        except Exception as e:
            logger.error(f"Error parsing user info: {e}")
            return None
    
    def get_posts(self, limit: int = 25, fields: str = None) -> List[FacebookPost]:
        """Get user's posts
        
        Args:
            limit: Number of posts to fetch
            fields: Fields to request
            
        Returns:
            List of FacebookPost objects
        """
        if fields is None:
            fields = 'id,message,created_time,likes.summary(true),comments.summary(true),shares,privacy,permalink_url,full_picture'
        
        result = self._make_graph_request('me/posts', params={
            'fields': fields,
            'limit': limit
        })
        
        if not result.is_success():
            return []
        
        posts = []
        try:
            for post_data in result.data.get('data', []):
                likes_count = post_data.get('likes', {}).get('summary', {}).get('total_count', 0)
                comments_count = post_data.get('comments', {}).get('summary', {}).get('total_count', 0)
                shares_count = post_data.get('shares', {}).get('count', 0)
                privacy = post_data.get('privacy', {}).get('value', 'EVERYONE')
                
                post = FacebookPost(
                    post_id=post_data['id'],
                    message=post_data.get('message', ''),
                    created_time=post_data.get('created_time', ''),
                    likes_count=likes_count,
                    comments_count=comments_count,
                    shares_count=shares_count,
                    privacy=privacy,
                    permalink_url=post_data.get('permalink_url', ''),
                    full_picture=post_data.get('full_picture', '')
                )
                posts.append(post)
        except Exception as e:
            logger.error(f"Error parsing posts: {e}")
        
        return posts
    
    def create_post(
        self,
        message: str,
        link: str = None,
        image_url: str = None,
        privacy: PostPrivacy = PostPrivacy.PUBLIC
    ) -> APICallResult:
        """Create a new post
        
        Args:
            message: Post message
            link: URL to share
            image_url: Image URL to post
            privacy: Post privacy setting
            
        Returns:
            APICallResult object
        """
        params = {'message': message, 'privacy': f'{{"value":"{privacy.value}"}}'}
        
        if link:
            params['link'] = link
        
        if image_url:
            params['url'] = image_url
        
        return self._make_graph_request('me/feed', params=params, method='POST')
    
    def like_post(self, post_id: str) -> APICallResult:
        """Like a post
        
        Args:
            post_id: Post ID to like
            
        Returns:
            APICallResult object
        """
        return self._make_graph_request(f'{post_id}/likes', method='POST')
    
    def unlike_post(self, post_id: str) -> APICallResult:
        """Unlike a post
        
        Args:
            post_id: Post ID to unlike
            
        Returns:
            APICallResult object
        """
        return self._make_graph_request(f'{post_id}/likes', method='DELETE')
    
    def create_comment(
        self,
        object_id: str,
        message: str
    ) -> APICallResult:
        """Create a comment on a post
        
        Args:
            object_id: Object ID (post or comment)
            message: Comment message
            
        Returns:
            APICallResult object
        """
        return self._make_graph_request(
            f'{object_id}/comments',
            params={'message': message},
            method='POST'
        )
    
    def get_comments(self, object_id: str, limit: int = 25) -> List[FacebookComment]:
        """Get comments for an object
        
        Args:
            object_id: Object ID (post or comment)
            limit: Number of comments to fetch
            
        Returns:
            List of FacebookComment objects
        """
        result = self._make_graph_request(
            f'{object_id}/comments',
            params={
                'fields': 'id,message,from,created_time,like_count,parent',
                'limit': limit
            }
        )
        
        if not result.is_success():
            return []
        
        comments = []
        try:
            for comment_data in result.data.get('data', []):
                from_data = comment_data.get('from', {})
                parent = comment_data.get('parent', {})
                
                comment = FacebookComment(
                    comment_id=comment_data['id'],
                    message=comment_data.get('message', ''),
                    from_name=from_data.get('name', ''),
                    from_id=from_data.get('id', ''),
                    created_time=comment_data.get('created_time', ''),
                    likes_count=comment_data.get('like_count', 0),
                    parent_comment_id=parent.get('id', '')
                )
                comments.append(comment)
        except Exception as e:
            logger.error(f"Error parsing comments: {e}")
        
        return comments
    
    def get_groups(self, limit: int = 25) -> List[FacebookGroup]:
        """Get user's groups
        
        Args:
            limit: Number of groups to fetch
            
        Returns:
            List of FacebookGroup objects
        """
        result = self._make_graph_request(
            'me/groups',
            params={
                'fields': 'id,name,description,member_count,privacy,cover,administrator',
                'limit': limit
            }
        )
        
        if not result.is_success():
            return []
        
        groups = []
        try:
            for group_data in result.data.get('data', []):
                cover = group_data.get('cover', {})
                
                group = FacebookGroup(
                    group_id=group_data['id'],
                    name=group_data.get('name', ''),
                    description=group_data.get('description', ''),
                    member_count=group_data.get('member_count', 0),
                    privacy=group_data.get('privacy', ''),
                    cover_photo=cover.get('source', ''),
                    administrator=group_data.get('administrator', False)
                )
                groups.append(group)
        except Exception as e:
            logger.error(f"Error parsing groups: {e}")
        
        return groups
    
    def search(self, query: str, type: str = 'page', limit: int = 25) -> List[Dict[str, Any]]:
        """Search Facebook
        
        Args:
            query: Search query
            type: Type of search (page, user, group, event)
            limit: Number of results
            
        Returns:
            List of search results
        """
        result = self._make_graph_request(
            'search',
            params={
                'q': query,
                'type': type,
                'limit': limit
            }
        )
        
        if not result.is_success():
            return []
        
        return result.data.get('data', [])
    
    def validate_token(self) -> bool:
        """Validate access token
        
        Returns:
            True if valid, False otherwise
        """
        result = self._make_graph_request('me', fields='id')
        return result.is_success()
    
    def get_token_info(self) -> Optional[Dict[str, Any]]:
        """Get token information
        
        Returns:
            Token info dictionary or None if failed
        """
        result = self._make_graph_request(
            'debug_token',
            params={
                'input_token': self.access_token,
                'fields': 'type,is_valid,expires_at,data_access_expires_at,granular_scopes,scopes'
            }
        )
        
        if not result.is_success():
            return None
        
        return result.data.get('data')

# ============================================================================
# TOKEN VALIDATION
# ============================================================================

class TokenValidator:
    """Validate and analyze Facebook access tokens"""
    
    def __init__(self):
        """Initialize token validator"""
        self.cache = SimpleCache(ttl=600)  # 10 minute cache
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate a single token
        
        Args:
            token: Access token to validate
            
        Returns:
            Validation result dictionary
        """
        # Check cache first
        cache_key = f"token_{token}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        client = FacebookAPIClient(access_token=token)
        is_valid = client.validate_token()
        
        result = {
            'token': token,
            'is_valid': is_valid,
            'user_info': None,
            'token_info': None
        }
        
        if is_valid:
            user_info = client.get_user_info()
            token_info = client.get_token_info()
            
            result['user_info'] = user_info.to_dict() if user_info else None
            result['token_info'] = token_info
        
        # Cache the result
        self.cache.set(cache_key, result)
        return result
    
    def validate_batch(self, tokens: List[str]) -> List[Dict[str, Any]]:
        """Validate multiple tokens
        
        Args:
            tokens: List of tokens to validate
            
        Returns:
            List of validation results
        """
        results = []
        progress = ProgressTracker(len(tokens), "Validating tokens")
        
        for token in tokens:
            result = self.validate_token(token)
            results.append(result)
            progress.update()
            logger.info(f"Progress: {progress}")
        
        return results
    
    def get_token_type(self, token: str) -> Optional[str]:
        """Get token type from token string
        
        Args:
            token: Access token
            
        Returns:
            Token type or None if unknown
        """
        for token_type in TokenType:
            if token.startswith(token_type.value):
                return token_type.value
        return None

# ============================================================================
# BATCH OPERATIONS
# ============================================================================

class BatchOperations:
    """Batch operations for Facebook API"""
    
    def __init__(self, access_token: str):
        """Initialize batch operations
        
        Args:
            access_token: Facebook access token
        """
        self.client = FacebookAPIClient(access_token=access_token)
    
    def batch_like_posts(self, post_ids: List[str], delay: float = 2.0) -> BatchResult:
        """Like multiple posts
        
        Args:
            post_ids: List of post IDs
            delay: Delay between requests
            
        Returns:
            BatchResult object
        """
        def like_post(post_id: str) -> Dict[str, Any]:
            result = self.client.like_post(post_id)
            return {
                'post_id': post_id,
                'success': result.is_success(),
                'error': result.error_message
            }
        
        from darkstar_utils import process_batch
        return process_batch(post_ids, like_post, batch_size=10, delay=delay)
    
    def batch_create_comments(
        self,
        post_ids: List[str],
        message: str,
        delay: float = 2.0
    ) -> BatchResult:
        """Create comments on multiple posts
        
        Args:
            post_ids: List of post IDs
            message: Comment message
            delay: Delay between requests
            
        Returns:
            BatchResult object
        """
        def create_comment(post_id: str) -> Dict[str, Any]:
            result = self.client.create_comment(post_id, message)
            return {
                'post_id': post_id,
                'success': result.is_success(),
                'error': result.error_message
            }
        
        from darkstar_utils import process_batch
        return process_batch(post_ids, create_comment, batch_size=10, delay=delay)
    
    def batch_create_posts(
        self,
        messages: List[str],
        privacy: PostPrivacy = PostPrivacy.PUBLIC,
        delay: float = 2.0
    ) -> BatchResult:
        """Create multiple posts
        
        Args:
            messages: List of post messages
            privacy: Post privacy setting
            delay: Delay between requests
            
        Returns:
            BatchResult object
        """
        def create_post(message: str) -> Dict[str, Any]:
            result = self.client.create_post(message, privacy=privacy)
            return {
                'message': message,
                'success': result.is_success(),
                'post_id': result.data.get('id') if result.data else None,
                'error': result.error_message
            }
        
        from darkstar_utils import process_batch
        return process_batch(messages, create_post, batch_size=5, delay=delay)

# ============================================================================
# EXPORTED FUNCTIONS
# ============================================================================

__all__ = [
    # Enums
    'TokenType',
    'APIEndpoint',
    'PostPrivacy',
    # Data Classes
    'FacebookPost',
    'FacebookComment',
    'FacebookUser',
    'FacebookGroup',
    'APICallResult',
    # API Client
    'FacebookAPIClient',
    # Token Validation
    'TokenValidator',
    # Batch Operations
    'BatchOperations',
]