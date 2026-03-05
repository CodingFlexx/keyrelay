"""
KeyRelay Proxy Middleware

Security, rate limiting, and request validation middleware.
"""

import re
import time
import logging
import os
from typing import Optional, Callable
from functools import wraps

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for input validation and sanitization."""
    
    # Allowed service name pattern (alphanumeric, underscore, hyphen)
    SERVICE_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    
    # Blocked path patterns (path traversal attempts)
    BLOCKED_PATTERNS = [
        re.compile(r'\.\./'),  # ../ path traversal
        re.compile(r'\.\.\\'),  # Windows path traversal
        re.compile(r'%2e%2e[/\\]', re.IGNORECASE),  # URL encoded ../ (case insensitive)
        re.compile(r'%2e%2e%2f', re.IGNORECASE),  # URL encoded ../
        re.compile(r'%2e%2e%5c', re.IGNORECASE),  # URL encoded ..\
        re.compile(r'\x00'),  # Null bytes
        re.compile(r'[~]'),  # Tilde expansion
    ]
    
    # Maximum path length
    MAX_PATH_LENGTH = 2048
    MAX_SERVICE_LENGTH = 64
    
    async def dispatch(self, request: Request, call_next: Callable):
        """Validate and sanitize incoming requests."""
        
        # Check request size
        content_length = request.headers.get('content-length')
        if content_length and int(content_length) > 100 * 1024 * 1024:  # 100MB limit
            logger.warning(f"Request too large: {content_length} bytes")
            return JSONResponse(
                status_code=413,
                content={"detail": "Request entity too large"}
            )
        
        # Check URL path for null bytes and traversal patterns (before path_params)
        raw_path = request.url.path
        
        # Check for null bytes in URL
        if '\x00' in raw_path or '%00' in raw_path:
            logger.warning(f"Null byte detected in URL: {raw_path}")
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid path"}
            )
        
        # Check total URL path length
        if len(raw_path) > self.MAX_PATH_LENGTH:
            logger.warning(f"Path too long: {len(raw_path)} chars")
            return JSONResponse(
                status_code=414,
                content={"detail": "Request URI too long"}
            )
        
        # Check for path traversal patterns in raw URL
        for pattern in self.BLOCKED_PATTERNS:
            if pattern.search(raw_path):
                logger.warning(f"Blocked path pattern detected in URL: {raw_path}")
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid path"}
                )
        
        # Validate path parameters if present
        path_params = request.path_params
        if 'service' in path_params:
            service = path_params['service']
            
            # Check service name length
            if len(service) > self.MAX_SERVICE_LENGTH:
                logger.warning(f"Service name too long: {len(service)} chars")
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Service name too long"}
                )
            
            # Validate service name format
            if not self.SERVICE_PATTERN.match(service):
                logger.warning(f"Invalid service name format: {service}")
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid service name format"}
                )
        
        if 'path' in path_params:
            path = path_params['path']
            
            # Check path length
            if len(path) > self.MAX_PATH_LENGTH:
                logger.warning(f"Path too long: {len(path)} chars")
                return JSONResponse(
                    status_code=414,
                    content={"detail": "Request URI too long"}
                )
            
            # Check for blocked patterns in decoded path
            for pattern in self.BLOCKED_PATTERNS:
                if pattern.search(path):
                    logger.warning(f"Blocked path pattern detected: {path}")
                    return JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid path"}
                    )
        
        # Add security headers to response
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting middleware."""
    
    def __init__(
        self,
        app: ASGIApp,
        requests_per_minute: int = 60,
        burst_size: int = 10
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.requests: dict = {}  # IP -> list of timestamps
        self.blocked: dict = {}  # IP -> unblock time
        # Disable rate limiting in test mode
        self._disabled = os.getenv("AGENT_VAULT_TEST_MODE") == "1"
        
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check for forwarded IP (behind proxy)
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _is_rate_limited(self, client_ip: str) -> bool:
        """Check if client is rate limited."""
        now = time.time()
        
        # Check if IP is blocked
        if client_ip in self.blocked:
            if now < self.blocked[client_ip]:
                return True
            else:
                del self.blocked[client_ip]
        
        # Clean old requests
        if client_ip in self.requests:
            self.requests[client_ip] = [
                ts for ts in self.requests[client_ip]
                if now - ts < 60  # Keep last 60 seconds
            ]
        
        # Check rate limit
        request_count = len(self.requests.get(client_ip, []))
        
        if request_count >= self.requests_per_minute:
            # Block for 5 minutes
            self.blocked[client_ip] = now + 300
            logger.warning(f"Rate limit exceeded for {client_ip}, blocked for 5 minutes")
            return True
        
        # Track request
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        self.requests[client_ip].append(now)
        
        return False
    
    async def dispatch(self, request: Request, call_next: Callable):
        """Apply rate limiting."""
        # Skip rate limiting in test mode
        if self._disabled:
            return await call_next(request)
        
        client_ip = self._get_client_ip(request)
        
        if self._is_rate_limited(client_ip):
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": 60
                },
                headers={"Retry-After": "60"}
            )
        
        return await call_next(request)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Request/Response logging middleware."""
    
    async def dispatch(self, request: Request, call_next: Callable):
        """Log request and response details."""
        start_time = time.time()
        
        # Log request
        client_ip = request.headers.get('X-Forwarded-For', request.client.host if request.client else 'unknown')
        logger.info(f"→ {request.method} {request.url.path} from {client_ip}")
        
        try:
            response = await call_next(request)
            
            # Log response
            duration = time.time() - start_time
            logger.info(f"← {response.status_code} in {duration:.3f}s")
            
            # Add timing header
            response.headers['X-Response-Time'] = f"{duration:.3f}s"
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"✗ Error after {duration:.3f}s: {e}")
            raise


def validate_service_name(service: str) -> bool:
    """Validate service name format."""
    if not service:
        return False
    if len(service) > 64:
        return False
    return bool(SecurityMiddleware.SERVICE_PATTERN.match(service))


def sanitize_path(path: str) -> str:
    """Sanitize API path to prevent traversal attacks."""
    if not path:
        return ""
    
    # Remove null bytes
    path = path.replace('\x00', '')
    
    # Normalize slashes
    path = path.replace('\\', '/')
    
    # Remove traversal attempts
    while '..' in path:
        path = path.replace('..', '')
    
    # Remove double slashes
    while '//' in path:
        path = path.replace('//', '/')
    
    return path.strip('/')
