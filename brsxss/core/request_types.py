#!/usr/bin/env python3

"""
BRS-XSS Request Types

Data types and enums for HTTP request building.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict, Optional, Union
from dataclasses import dataclass, field
from enum import Enum


class RequestMethod(Enum):
    """HTTP request methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class PayloadLocation(Enum):
    """Where to inject the payload"""
    URL_PARAM = "url_param"
    FORM_DATA = "form_data"
    JSON_VALUE = "json_value"
    JSON_KEY = "json_key"
    HEADER = "header"
    COOKIE = "cookie"


@dataclass
class RequestConfig:
    """Configuration for building test requests"""
    method: RequestMethod = RequestMethod.GET
    content_type: str = "application/x-www-form-urlencoded"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True
    

@dataclass
class TestRequest:
    """Prepared test request"""
    method: str
    url: str
    headers: Dict[str, str]
    data: Optional[Union[str, Dict, bytes]] = None
    params: Optional[Dict[str, str]] = None
    payload_location: PayloadLocation = PayloadLocation.URL_PARAM
    injected_parameter: str = ""