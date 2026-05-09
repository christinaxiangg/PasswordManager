Secure Local Password Manager

User Requirements Document (URD)
1. Overview

The Secure Local Password Manager is a desktop application that allows users to securely store, manage, and retrieve passwords locally on their computer. The application encrypts all stored credentials using strong cryptography and protects access through a master password.

The system provides features for:

Secure credential storage

Password generation

Credential management (add, edit, delete)

Search and filtering

Auto-fill capability

Vault export

Master password management

The application is implemented as a Python desktop GUI application using Tkinter.

2. Objectives

The system must allow users to:

Securely store credentials locally.

Protect all stored passwords with encryption.

Access credentials quickly through a graphical interface.

Generate strong random passwords.

Automatically fill login credentials into websites.

Export vault data when needed.

3. Target Users

Primary users include:

Individual users who want a local password manager

Users who prefer offline password storage

Users requiring simple GUI-based password management

4. System Architecture

The system consists of several logical components:

4.1 Core Modules
Module	Purpose
CryptoManager	Encryption and decryption of vault data
VaultModel	Password storage and persistence
PasswordGenerator	Secure password generation
PasswordManager UI	GUI interface and user interactions
AutoFill Module	Optional automated credential entry
5. Functional Requirements
5.1 Vault Initialization
Requirement

The system must allow users to create a secure vault.

Behavior

When no vault exists:

The system prompts the user to create a master password.

The password must be minimum 8 characters.

The system generates a random salt.

A cryptographic key is derived using:

PBKDF2-HMAC-SHA256
100,000 iterations
Files Created

The vault system stores data in:

~/.password_manager/

Files include:

File	Purpose
vault.enc	Encrypted password vault
vault.salt	Salt used for key derivation
vault.hash	Hash of master password
5.2 User Authentication
Requirement

Users must authenticate using the master password.

Behavior

Upon login:

User enters master password.

System hashes the password using SHA256.

Hash is compared to stored hash.

If correct:

Encryption key is derived

Vault is decrypted

If incorrect:

Access is denied.

5.3 Password Storage

The system must allow users to store credentials with the following attributes:

Field	Required	Description
Website	Yes	Service or website name
Username	Yes	Login username or email
Password	Yes	Account password
Category	No	Classification of account
Notes	No	Additional information
Created	Auto	Timestamp of creation
Modified	Auto	Timestamp of last modification

Passwords are stored as objects:

PasswordEntry
5.4 Encryption

All password data must be encrypted before being written to disk.

Encryption Details

Algorithm:

Fernet symmetric encryption
AES-128 in CBC mode
HMAC authentication

Key derivation:

PBKDF2-HMAC-SHA256
100000 iterations
5.5 Password Management

The system must allow users to perform the following operations:

Add Password

Users can add credentials including:

Website

Username

Password

Category

Notes

Edit Password

Users can modify existing password entries.

Delete Password

Users can permanently delete stored credentials.

View Password

Users can view stored password details including:

Toggle visibility

Copy values to clipboard

5.6 Password Generator

The system must provide a built-in password generator.

Configurable Parameters
Option	Description
Password length	8 – 32 characters
Uppercase letters	Optional
Lowercase letters	Optional
Digits	Optional
Symbols	Optional
Randomness

Passwords must be generated using:

Python secrets module
5.7 Search and Filtering

Users must be able to search passwords by:

Website name

Username

Search must be case-insensitive.

5.8 Clipboard Integration

The system must allow users to copy credentials to clipboard.

Clipboard access should support:

pyperclip

Tkinter clipboard fallback

5.9 Auto-Fill Feature (Optional)

If the pyautogui library is installed, the system should allow automatic credential entry.

Behavior

Open website URL.

Wait for browser load.

Type username.

Press TAB.

Type password.

5.10 Export Vault

Users must be able to export vault contents.

Export Format
JSON
Export Content

All entries including:

Website

Username

Password

Category

Notes

Timestamps

⚠ Exported files are not encrypted and must be handled securely.

5.11 Change Master Password

Users must be able to change the master password.

Process

Verify current password.

Generate new salt.

Derive new encryption key.

Re-encrypt vault.

6. User Interface Requirements
6.1 Login Screen

The login screen must display:

Application title

Master password field

Create vault / Login button

Vault storage location

6.2 Main Application Window

The main interface must contain:

Toolbar

Application title

Search bar

Password List

Displayed columns:

Column
Website
Username
Category
Last Modified
Action Buttons
Button	Action
Add Password	Create new entry
View	Show entry details
Edit	Modify entry
Delete	Remove entry
Auto-Fill	Fill credentials
Export	Export vault
Change Master Password	Update master password
7. Non-Functional Requirements
7.1 Security

All stored passwords must be encrypted.

Master password must not be stored in plain text.

Encryption keys must be derived using secure KDF.

7.2 Performance

Vault operations should complete within < 1 second for typical datasets (<1000 entries).

7.3 Reliability

Vault files must not become corrupted during normal operation.

Failed authentication attempts must not expose data.

7.4 Usability

The interface must provide:

Clear navigation

Simple password management

Easy copy-to-clipboard functions

8. Dependencies

Required libraries:

cryptography

Optional libraries:

pyperclip
pyautogui
9. Data Storage

Vault files stored in:

~/.password_manager/

File structure:

.password_manager
 ├── vault.enc
 ├── vault.salt
 └── vault.hash
10. Limitations

Current system limitations:

Desktop only

No cloud synchronization

Export files are unencrypted

Auto-fill relies on timing and may fail on some websites

11. Future Enhancements

Possible improvements include:

Browser extensions

Biometric authentication

Secure vault export

Multi-device sync

Password strength analysis

Breach detection integration8 Fixed using Github Copilot initial check in Github
