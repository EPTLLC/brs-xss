#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

JavaScript String Context - Remediation
"""

REMEDIATION = """
DEFENSE-IN-DEPTH STRATEGY:

1. PROPER JAVASCRIPT STRING ESCAPING:
   
   Must escape these characters:
   - \\\\ (backslash) - ESCAPE FIRST!
   - ' (single quote) → \\'
   - " (double quote) → \\"
   - \\n (newline) → \\\\n
   - \\r (carriage return) → \\\\r
   - \\t (tab) → \\\\t
   - \\u2028 (line separator) → \\\\u2028
   - \\u2029 (paragraph separator) → \\\\u2029
   - </script> → <\\/script>
   - <!-- → <\\!--
   
   Python:
   import json
   safe_string = json.dumps(user_input)[1:-1]  # Remove outer quotes
   
   Or manually:
   def escape_js_string(s):
       return s.replace('\\\\', '\\\\\\\\')\\
               .replace("'", "\\\\'")\\
               .replace('"', '\\\\"')\\
               .replace('\\n', '\\\\n')\\
               .replace('\\r', '\\\\r')\\
               .replace('\\u2028', '\\\\u2028')\\
               .replace('\\u2029', '\\\\u2029')\\
               .replace('</', '<\\\\/')
   
   PHP:
   function escapeJsString($str) {
       return json_encode($str, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
   }
   
   JavaScript (Node.js):
   function escapeJsString(str) {
       return str
           .replace(/\\\\/g, '\\\\\\\\')
           .replace(/'/g, "\\\\'")
           .replace(/"/g, '\\\\"')
           .replace(/\\n/g, '\\\\n')
           .replace(/\\r/g, '\\\\r')
           .replace(/\\u2028/g, '\\\\u2028')
           .replace(/\\u2029/g, '\\\\u2029')
           .replace(/<\\//g, '<\\\\/');
   }

2. AVOID INLINE JAVASCRIPT ENTIRELY:
   
   BAD:
   <script>
   var username = '<?php echo $username ?>';
   </script>
   
   GOOD - Use data attributes:
   <div id="user-data" data-username="<?php echo htmlspecialchars($username) ?>"></div>
   
   <script>
   const userData = document.getElementById('user-data');
   const username = userData.dataset.username; // Safe!
   </script>

3. USE JSON SERIALIZATION:
   
   BAD:
   <script>
   var config = {
       name: '<?php echo $name ?>',
       email: '<?php echo $email ?>'
   };
   </script>
   
   GOOD:
   <script>
   var config = <?php echo json_encode($config, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
   </script>

4. SCRIPT TYPE='APPLICATION/JSON':
   
   Best practice:
   <script type="application/json" id="config-data">
   <?php echo json_encode($config, JSON_HEX_TAG | JSON_HEX_AMP); ?>
   </script>
   
   <script>
   const configData = JSON.parse(
       document.getElementById('config-data').textContent
   );
   </script>

5. CONTENT SECURITY POLICY:
   
   Block inline event handlers:
   Content-Security-Policy: 
     default-src 'self';
     script-src 'self' 'nonce-RANDOM123';
   
   This prevents onclick="..." attacks

6. USE SAFE APIS:
   
   GOOD:
   element.textContent = userInput;
   element.setAttribute('data-value', userInput);
   
   BAD:
   element.onclick = "doSomething('" + userInput + "')";
   element.setAttribute('onclick', code);

7. FRAMEWORK AUTO-ESCAPING:
   
   React (Safe by default):
   const username = userInput; // No need to escape in JSX
   return <div>{username}</div>;
   
   Vue (Safe in templates):
   <template>
     <div>{{ userInput }}</div>
   </template>
   
   Angular (Safe by default):
   <div>{{ userInput }}</div>
   
   All automatically escape for JavaScript string context

8. TEMPLATE ENGINE CONFIGURATION:
   
   EJS:
   <%= userInput %>  <!-- HTML escaped -->
   <%- userInput %>  <!-- Raw, dangerous -->
   
   Handlebars:
   {{userInput}}     <!-- Escaped -->
   {{{userInput}}}   <!-- Raw, dangerous -->
   
   Jinja2:
   {{ user_input }}  <!-- Auto-escaped if configured -->
   {{ user_input|e }}  <!-- Explicitly escaped -->

9. VALIDATE INPUT:
   
   For expected formats:
   
   Username:
   if (!preg_match('/^[a-zA-Z0-9_-]{3,20}$/', $username)) {
       die('Invalid username');
   }
   
   Numeric:
   $age = intval($_POST['age']);
   if ($age < 0 || $age > 150) die('Invalid age');

10. TRUSTED TYPES API:
    
    Content-Security-Policy: require-trusted-types-for 'script'
    
    JavaScript:
    const policy = trustedTypes.createPolicy('default', {
        createScript: (input) => {
            // Sanitize
            return sanitize(input);
        }
    });

SECURITY CHECKLIST:

[ ] No user input placed directly in JavaScript strings
[ ] All JavaScript strings properly escaped (backslash first!)
[ ] Escape \\u2028 and \\u2029 (line/paragraph separators)
[ ] Escape </script> and <!-- in strings
[ ] Use data attributes instead of inline JavaScript
[ ] Use JSON serialization with proper flags
[ ] CSP configured to block inline event handlers
[ ] Framework auto-escaping enabled
[ ] Template engine escape syntax used correctly
[ ] No eval() or Function() with user input
[ ] Input validation for expected formats
[ ] Regular security testing
[ ] Code review for all JavaScript string usage
[ ] Developer training on string context XSS

TESTING PAYLOADS:

Single quote breakout:
'; alert(1); var x='
'; alert(1);//

Double quote breakout:
"; alert(1); var x="
"; alert(1);//

Template literal:
${alert(1)}

Unicode escape:
\\u0027; alert(1); var x=\\u0027

Script tag breakout:
</script><script>alert(1)</script><script>

Regex breakout:
/; alert(1); var x=/

Line separator:
\\u2028alert(1)//

OWASP REFERENCES:
- OWASP XSS Prevention Cheat Sheet: Rule #3
- CWE-79: Improper Neutralization of Input During Web Page Generation
- JavaScript String Escape Sequences
- Content Security Policy Level 3
- OWASP Testing Guide: Testing for JavaScript Execution
"""

