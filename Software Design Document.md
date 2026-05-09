Enhanced Local Password Manager
Software Design Document
1. System Overview

The Enhanced Local Password Manager is a desktop application that securely stores user credentials using encryption. The system provides a graphical user interface for managing passwords, generating secure credentials, and automatically filling login forms in web browsers.

The application follows a Model–View–Controller inspired structure, separating:

Data Model (password storage and encryption)

Business Logic

User Interface

Core goals:

• Secure local storage of passwords
• Encryption using strong cryptographic primitives
• Easy credential management through a GUI
• Password generation tools
• Browser auto-fill capability

The application is written in Python using:

Tkinter for the interface

cryptography for encryption

pyautogui for auto-typing credentials

2. System Architecture

The application is organized into five major subsystems.

+--------------------------------------------------+
|                User Interface                    |
|           (PasswordManager GUI)                  |
+-----------------------+--------------------------+
                        |
                        v
+--------------------------------------------------+
|                Application Logic                 |
|    Password Generator | AutoFill | Validation    |
+-----------------------+--------------------------+
                        |
                        v
+--------------------------------------------------+
|                 Vault Model                      |
|           Password Storage & Retrieval           |
+-----------------------+--------------------------+
                        |
                        v
+--------------------------------------------------+
|              Encryption Layer                    |
|      Key Derivation | Encrypt | Decrypt          |
+-----------------------+--------------------------+
                        |
                        v
+--------------------------------------------------+
|                File Storage                      |
|     vault.enc | vault.salt | vault.hash          |
+--------------------------------------------------+

The architecture ensures that sensitive cryptographic operations are isolated from the user interface layer.

3. Data Model
PasswordEntry

The system represents each credential as a structured object.

Attributes:

Field	Description
website	Website or service URL
username	Login username
password	Account password
notes	Optional notes
created	Creation timestamp
modified	Last modification timestamp
category	Category label

Example structure:

PasswordEntry
 ├─ website
 ├─ username
 ├─ password
 ├─ notes
 ├─ created
 ├─ modified
 └─ category

Entries are stored in memory inside a dictionary.

Dict[str, PasswordEntry]

The key represents a generated entry identifier.

4. Cryptography Design

Security relies on a password-derived encryption key.

Key Derivation

The master password is transformed into a symmetric encryption key using:

• PBKDF2 key derivation
• SHA-256 hash function
• 100,000 iterations
• Random salt

This slows brute-force attacks.

Encryption Algorithm

Data is encrypted using:

Fernet

Fernet provides:

• AES-128 encryption
• authentication (tamper detection)
• timestamping support

Encrypted data is stored in vault.enc.

Master Password Verification

A hash of the master password is stored for authentication:

SHA256(master_password)

The hash is stored in vault.hash.

5. Vault Storage Design

The application stores vault data inside the user’s home directory.

~/.password_manager/

Files:

File	Purpose
vault.enc	Encrypted password database
vault.salt	Salt used for key derivation
vault.hash	Master password hash

Vault contents before encryption:

{
  "entry_id_1": {PasswordEntry},
  "entry_id_2": {PasswordEntry}
}

Encrypted vault format:

Fernet(encrypted_json)
6. Core Modules
CryptoManager

Handles cryptographic operations.

Functions:

Function	Purpose
derive_key	Generates encryption key from password
encrypt_data	Encrypts vault data
decrypt_data	Decrypts stored vault
hash_password	Generates verification hash
PasswordGenerator

Creates secure random passwords using:

uppercase letters

lowercase letters

digits

symbols

Randomness is produced using Python’s secure generator:

secrets.choice()

This module allows users to customize password strength and length.

VaultModel

Responsible for vault management.

Primary responsibilities:

• authentication
• encrypted storage
• CRUD operations for password entries
• vault export
• password search

Key methods:

Method	Purpose
create_vault	Initialize encrypted vault
authenticate	Verify master password
add_password	Add credential
update_password	Modify entry
delete_password	Remove entry
search_passwords	Search vault
export_vault	Export vault data
change_master_password	Re-encrypt vault
7. User Interface Design

The graphical interface is implemented using Tkinter.

Main components:

Login Screen

Functions:

• Create new vault
• Authenticate user
• Initialize encryption key

UI Elements:

password input

confirm password (for new vault)

login/create button

Main Application Window

Components:

Component	Function
Toolbar	Application title and search box
Password Table	Displays stored credentials
Action Buttons	Perform operations on entries
Status Bar	Shows number of stored passwords

Password entries are displayed using:

Treeview widget
Password Generator Dialog

Allows users to configure:

• password length
• uppercase inclusion
• lowercase inclusion
• digits
• symbols

Generated password can be inserted directly into forms.

Password Management Dialogs

Operations supported:

• Add password
• View password
• Edit password
• Delete password

Viewing passwords includes:

• show/hide password toggle
• copy to clipboard
• notes display

8. Auto-Fill Mechanism

Auto-fill automates login actions.

Steps:

Open website in browser

Wait for page load

Simulate keyboard typing

Insert username

Press TAB

Insert password

Automation is performed using:

pyautogui

This approach simulates human input rather than integrating directly with browsers.

9. Clipboard Integration

The system supports copying credentials using:

pyperclip

If unavailable, Tkinter clipboard functions are used.

This ensures cross-platform compatibility.

10. Search and Filtering

Users can filter stored credentials using a search bar.

Search fields include:

• website name
• username

Filtering is performed dynamically as the user types.

11. Error Handling

The system handles common failures:

Scenario	Response
Missing cryptography library	Error dialog
Authentication failure	Login rejection
Vault corruption	Exception message
Clipboard failure	Manual copy fallback
Auto-fill unavailable	Warning dialog
12. Security Considerations

Implemented security features:

• encrypted vault storage
• key derivation using PBKDF2
• random salt generation
• authenticated encryption
• secure random password generation

Potential limitations:

• passwords temporarily exist in memory
• exported vault is stored unencrypted
• clipboard exposure risk
• auto-fill depends on timing

13. Application Flow

Typical usage flow:

Application Start
        │
        ▼
Check Dependencies
        │
        ▼
Vault Exists?
   ├─ No → Create Vault
   └─ Yes → Login
        │
        ▼
Derive Encryption Key
        │
        ▼
Decrypt Vault
        │
        ▼
Display Main UI
        │
        ▼
User Operations
   ├─ Add password
   ├─ Edit password
   ├─ Delete password
   ├─ Search
   ├─ Auto-fill
   └─ Export vault
14. Dependencies

Required:

Python 3.8+

cryptography

Optional:

pyperclip

pyautogui

15. Future Improvements

Possible enhancements:

• stronger password hashing (Argon2)
• encrypted vault export
• browser extension integration
• automatic clipboard clearing
• vault lock timeout
• multi-vault support
• biometric authentication

The fascinating thing about password managers is that they slowly turn into mini operating systems for secrets. Once you add sync, browser integration, hardware keys, and secure memory management, you are essentially building a security platform, not just an app.

Your current design already has the bones of that architecture.

If you want, I can also generate:

• SRS (Software Requirements Specification)
• UML diagrams (class + sequence)
• threat model / security analysis
• improved architecture used by real password managers (KeePass / Bitwarden style).

