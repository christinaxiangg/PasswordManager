User Requirement: Chrome Extension Authentication with Local Password Manager
1. Overview

The system shall allow a browser extension to securely access credentials stored in the desktop password manager application.

The authentication mechanism shall use a local HTTP API and temporary session token to establish trust between the browser extension and the password manager.

Access to credentials must only be granted after explicit user approval.

The extension must not be able to access the vault without:

The password manager application running

The vault being unlocked

The user approving the extension connection

2. System Components

The system consists of the following components:

Desktop Password Manager Application

Runs locally on the user's machine

Stores encrypted credentials

Exposes a local HTTP API server

Chrome Browser Extension

Installed in the browser

Detects login forms

Requests credentials from the password manager

Local Communication Channel

HTTP server running on localhost

Example:

http://127.0.0.1:48512

This channel is only accessible from the user's machine.

3. Preconditions

Before the extension can access credentials, the following conditions must be met:

The password manager application must be running.

The vault must be unlocked by the user.

The local API server must be active.

The extension must request connection approval.

If any of these conditions fail, the extension must not receive credentials.

4. Connection Flow
Step 1 — Extension Requests Connection

When the extension needs access to credentials, it shall send a connection request to the password manager.

Example request:

POST /connect

Request body:

{
  "extension_id": "abcdef12345"
}

The extension_id uniquely identifies the installed browser extension.

Step 2 — User Approval Prompt

When the password manager receives a connection request, it shall display a prompt to the user.

Example:

Browser extension requests access to your vault.

Extension ID: abcdef12345

[Allow] [Deny]

User approval is mandatory.

If the user selects Deny, the connection request must be rejected.

Step 3 — Session Token Generation

If the user selects Allow, the password manager shall generate a secure session token.

Token properties:

Random

Cryptographically secure

Minimum 128-bit entropy

Short lifetime

Example response:

{
  "token": "random-128-bit-token"
}

This token represents the authenticated session.

Step 4 — Extension Stores Token

The browser extension shall temporarily store the token in memory or secure extension storage.

The token must not be permanently stored.

5. Authenticated Requests

All requests from the extension to the password manager must include the session token.

Example request:

GET /credentials?domain=github.com
Authorization: Bearer random-128-bit-token

The password manager must verify the token before processing the request.

If the token is invalid, expired, or missing, the request must be rejected.

6. Credential Retrieval

After successful authentication, the extension may request credentials for a specific domain.

Example request:

GET /credentials?domain=github.com

Example response:

{
  "credentials": [
    {
      "username": "user@example.com",
      "password": "encrypted-or-plain"
    }
  ]
}

The extension then autofills the login form.

7. Session Expiration

Session tokens must expire under the following conditions:

After a configurable timeout (example: 10 minutes)

When the vault is locked

When the password manager application closes

When the user manually revokes the session

When the token expires, the extension must repeat the connection flow.

8. Security Requirements

The system must implement the following protections:

Localhost Only

The API server must only listen on:

127.0.0.1

External network access must be blocked.

Extension Verification

The password manager must verify that the connection originates from the expected browser extension.

Possible validation mechanisms:

extension ID validation

signed request headers

origin checks

Token Security

Session tokens must:

be cryptographically random

be unguessable

expire automatically

User Consent

No credential access may occur without explicit user approval.

9. Error Handling

The password manager must return clear responses for failed requests.

Examples:

Invalid token:

401 Unauthorized

Vault locked:

403 Vault Locked

Connection denied:

403 Access Denied
10. User Experience Requirements

From the user's perspective:

The user unlocks the password manager vault.

The user visits a login page.

The extension requests access.

The password manager asks permission.

The user clicks Allow.

Credentials autofill automatically.

This approval should normally happen only once per session.

11. Optional Enhancements

Future improvements may include:

TLS for localhost communication

cryptographic handshake instead of plain tokens

device pairing system

persistent trusted extensions

rate limiting

Here’s a fun twist that many developers miss: this model is basically OAuth shrunk down to localhost scale. Same philosophy—temporary tokens, explicit consent, scoped access—just without the internet circus.

If you're building a real password manager, there are also three more secure architectures used by serious tools like Bitwarden and 1Password:

Native Messaging API (Chrome → native app pipe)

Local WebSocket secure channel

Public-key challenge handshake

Those dramatically reduce the attack surface compared to plain localhost HTTP. The security rabbit hole gets deep in a delightful way.