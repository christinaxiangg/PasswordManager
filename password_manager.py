"""
Enhanced Local Password Manager
A secure, user-friendly password manager with encryption and auto-fill capabilities
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
import base64
import hashlib
import secrets
import string
import webbrowser
import time
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, Dict
from pathlib import Path

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography library not installed. Install with: pip install cryptography")
    # Define placeholders so names exist even when the package is missing
    Fernet = None
    PBKDF2HMAC = None
    hashes = None

try:
    import pyautogui
    AUTOFILL_AVAILABLE = True
except ImportError:
    AUTOFILL_AVAILABLE = False
    # Ensure name exists to avoid lint/runtime warnings
    pyautogui = None


# ==================== Data Models ====================

@dataclass
class PasswordEntry:
    website: str
    username: str
    password: str
    notes: str = ""
    created: str = ""
    modified: str = ""
    category: str = "General"

    def __post_init__(self):
        if not self.created:
            self.created = datetime.now().isoformat()
        if not self.modified:
            self.modified = datetime.now().isoformat()


# ==================== Encryption Utilities ====================

class CryptoManager:
    """Handles all encryption/decryption operations"""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Cryptography library not available")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def encrypt_data(data: dict, key: bytes) -> bytes:
        """Encrypt dictionary data"""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Cryptography library not available")

        f = Fernet(key)
        json_data = json.dumps(data).encode()
        return f.encrypt(json_data)

    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> dict:
        """Decrypt data back to dictionary"""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Cryptography library not available")

        f = Fernet(key)
        decrypted = f.decrypt(encrypted_data)
        return json.loads(decrypted.decode())

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password for verification"""
        return hashlib.sha256(password.encode()).hexdigest()


# ==================== Password Generator ====================

class PasswordGenerator:
    """Generate secure random passwords"""

    @staticmethod
    def generate(length=16, use_upper=True, use_lower=True,
                use_digits=True, use_symbols=True) -> str:
        """Generate a random password with specified criteria"""
        chars = ""
        if use_upper:
            chars += string.ascii_uppercase
        if use_lower:
            chars += string.ascii_lowercase
        if use_digits:
            chars += string.digits
        if use_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        if not chars:
            chars = string.ascii_letters + string.digits

        password = ''.join(secrets.choice(chars) for _ in range(length))
        return password


# ==================== Vault Model ====================

class VaultModel:
    """Manages password storage and encryption"""

    def __init__(self):
        self.passwords: Dict[str, PasswordEntry] = {}
        self.key: Optional[bytes] = None
        self.data_dir = Path.home() / ".password_manager"
        self.data_dir.mkdir(exist_ok=True)
        self.data_file = self.data_dir / "vault.enc"
        self.salt_file = self.data_dir / "vault.salt"
        self.hash_file = self.data_dir / "vault.hash"

    def vault_exists(self) -> bool:
        """Check if a vault already exists"""
        return self.hash_file.exists()

    def create_vault(self, master_password: str) -> bool:
        """Create a new vault with master password"""
        if len(master_password) < 8:
            raise ValueError("Master password must be at least 8 characters")

        salt = os.urandom(16)
        self.key = CryptoManager.derive_key(master_password, salt)

        # Save salt and password hash
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        with open(self.hash_file, 'w') as f:
            f.write(CryptoManager.hash_password(master_password))

        self.passwords = {}
        self._save_vault()
        return True

    def authenticate(self, master_password: str) -> bool:
        """Authenticate with master password"""
        if not self.vault_exists():
            return False

        # Verify password hash
        with open(self.hash_file, 'r') as f:
            stored_hash = f.read().strip()

        if CryptoManager.hash_password(master_password) != stored_hash:
            return False

        # Derive key and decrypt vault
        with open(self.salt_file, 'rb') as f:
            salt = f.read()

        self.key = CryptoManager.derive_key(master_password, salt)

        # Load passwords if file exists
        if self.data_file.exists():
            with open(self.data_file, 'rb') as f:
                encrypted_data = f.read()

            if encrypted_data:
                password_dict = CryptoManager.decrypt_data(encrypted_data, self.key)
                self.passwords = {
                    k: PasswordEntry(**v) for k, v in password_dict.items()
                }

        return True

    def add_password(self, entry: PasswordEntry) -> str:
        """Add a new password entry"""
        entry_id = f"{entry.website}_{entry.username}_{len(self.passwords)}"
        self.passwords[entry_id] = entry
        self._save_vault()
        return entry_id

    def update_password(self, entry_id: str, entry: PasswordEntry) -> bool:
        """Update an existing password"""
        if entry_id not in self.passwords:
            return False

        entry.modified = datetime.now().isoformat()
        self.passwords[entry_id] = entry
        self._save_vault()
        return True

    def delete_password(self, entry_id: str) -> bool:
        """Delete a password entry"""
        if entry_id not in self.passwords:
            return False

        del self.passwords[entry_id]
        self._save_vault()
        return True

    def get_password(self, entry_id: str) -> Optional[PasswordEntry]:
        """Get a specific password entry"""
        return self.passwords.get(entry_id)

    def get_all_passwords(self) -> Dict[str, PasswordEntry]:
        """Get all password entries"""
        return self.passwords

    def search_passwords(self, query: str) -> Dict[str, PasswordEntry]:
        """Search passwords by website or username"""
        query = query.lower()
        return {
            k: v for k, v in self.passwords.items()
            if query in v.website.lower() or query in v.username.lower()
        }

    def export_vault(self, filepath: str, password: str) -> bool:
        """Export vault to file"""
        try:
            export_data = {
                k: asdict(v) for k, v in self.passwords.items()
            }
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            return True
        except Exception:
            return False

    def _save_vault(self):
        """Save encrypted vault to disk"""
        if self.key is None:
            raise RuntimeError("Vault not authenticated")

        password_dict = {k: asdict(v) for k, v in self.passwords.items()}
        encrypted_data = CryptoManager.encrypt_data(password_dict, self.key)

        with open(self.data_file, 'wb') as f:
            f.write(encrypted_data)

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """Change the master password"""
        # Verify old password
        with open(self.hash_file, 'r') as f:
            stored_hash = f.read().strip()

        if CryptoManager.hash_password(old_password) != stored_hash:
            return False

        # Generate new salt and key
        new_salt = os.urandom(16)
        new_key = CryptoManager.derive_key(new_password, new_salt)

        # Re-encrypt with new key
        self.key = new_key
        self._save_vault()

        # Update salt and hash
        with open(self.salt_file, 'wb') as f:
            f.write(new_salt)
        with open(self.hash_file, 'w') as f:
            f.write(CryptoManager.hash_password(new_password))

        return True


# ==================== UI Components ====================

class PasswordGeneratorDialog:
    """Dialog for generating passwords"""

    def __init__(self, parent):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Password Generator")
        self.dialog.geometry("400x350")
        self.dialog.configure(bg='#34495e')
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self._setup_ui()

    def _setup_ui(self):
        # Length slider
        tk.Label(self.dialog, text="Password Length:",
                bg='#34495e', fg='#ecf0f1', font=('Arial', 10, 'bold')).pack(pady=10)

        self.length_var = tk.IntVar(value=16)
        length_frame = tk.Frame(self.dialog, bg='#34495e')
        length_frame.pack(pady=5)

        tk.Scale(length_frame, from_=8, to=32, orient=tk.HORIZONTAL,
                variable=self.length_var, bg='#34495e', fg='#ecf0f1',
                highlightthickness=0).pack(side=tk.LEFT)
        tk.Label(length_frame, textvariable=self.length_var,
                bg='#34495e', fg='#ecf0f1', width=3).pack(side=tk.LEFT, padx=5)

        # Character options
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)

        options_frame = tk.Frame(self.dialog, bg='#34495e')
        options_frame.pack(pady=10)

        for text, var in [
            ("Uppercase (A-Z)", self.use_upper),
            ("Lowercase (a-z)", self.use_lower),
            ("Digits (0-9)", self.use_digits),
            ("Symbols (!@#$...)", self.use_symbols)
        ]:
            tk.Checkbutton(options_frame, text=text, variable=var,
                          bg='#34495e', fg='#ecf0f1', selectcolor='#2c3e50',
                          font=('Arial', 9)).pack(anchor='w', pady=2)

        # Generated password display
        tk.Label(self.dialog, text="Generated Password:",
                bg='#34495e', fg='#ecf0f1', font=('Arial', 10, 'bold')).pack(pady=10)

        self.password_entry = tk.Entry(self.dialog, width=30, font=('Courier', 11))
        self.password_entry.pack(pady=5)

        # Buttons
        btn_frame = tk.Frame(self.dialog, bg='#34495e')
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="Generate", command=self._generate,
                 bg='#3498db', fg='white', padx=20, font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Use This", command=self._use_password,
                 bg='#27ae60', fg='white', padx=20, font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Cancel", command=self.dialog.destroy,
                 bg='#e74c3c', fg='white', padx=20, font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=5)

        # Generate initial password
        self._generate()

    def _generate(self):
        password = PasswordGenerator.generate(
            length=self.length_var.get(),
            use_upper=self.use_upper.get(),
            use_lower=self.use_lower.get(),
            use_digits=self.use_digits.get(),
            use_symbols=self.use_symbols.get()
        )
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

    def _use_password(self):
        self.result = self.password_entry.get()
        self.dialog.destroy()


# ==================== Main Application ====================

class PasswordManager:
    """Main password manager application"""

    def __init__(self):
        if not CRYPTO_AVAILABLE:
            messagebox.showerror("Error",
                "Cryptography library not installed!\n\n"
                "Please install it using:\n"
                "pip install cryptography")
            return

        self.root = tk.Tk()
        self.root.title("Secure Password Manager")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2c3e50')

        # Set icon (optional)
        try:
            self.root.iconbitmap(default='password.ico')
        except:
            pass

        self.model = VaultModel()
        self.current_filter = ""

        self._setup_styles()
        self._show_login_screen()

    def _setup_context_menu(self, widget):
        """Setup right-click context menu with paste for Entry widgets"""
        context_menu = tk.Menu(widget, tearoff=False, bg='#34495e', fg='#ecf0f1')
        context_menu.add_command(label="Paste",
                                command=lambda: self._paste_from_clipboard(widget))

        def show_context_menu(event):
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()

        widget.bind("<Button-3>", show_context_menu)  # Right-click

    def _paste_from_clipboard(self, widget):
        """Paste text from clipboard into Entry widget"""
        try:
            # Try pyperclip first if available
            if CLIPBOARD_AVAILABLE:
                import pyperclip
                text = pyperclip.paste()
                widget.insert(tk.INSERT, text)
                return
        except:
            pass

        try:
            # Try Tkinter clipboard
            text = self.root.clipboard_get()
            widget.insert(tk.INSERT, text)
        except Exception as e:
            messagebox.showerror("Clipboard Error",
                               f"Could not paste from clipboard.\n\nError: {str(e)}")

    def _setup_styles(self):
        """Configure ttk styles for dark theme"""
        style = ttk.Style()
        style.theme_use('default')

        # Treeview style
        style.configure("Treeview",
                       background="#34495e",
                       foreground="#ecf0f1",
                       fieldbackground="#34495e",
                       rowheight=30,
                       font=('Arial', 10))
        style.configure("Treeview.Heading",
                       background="#2c3e50",
                       foreground="#ecf0f1",
                       font=('Arial', 11, 'bold'))
        style.map('Treeview', background=[('selected', '#2980b9')])

    def _show_login_screen(self):
        """Display login/create vault screen"""
        self.login_frame = tk.Frame(self.root, bg='#2c3e50')
        self.login_frame.pack(fill=tk.BOTH, expand=True, padx=50, pady=50)

        # Title
        tk.Label(self.login_frame, text="�� Secure Password Manager",
                font=('Arial', 28, 'bold'), bg='#2c3e50', fg='#ecf0f1').pack(pady=30)

        # Login box
        login_box = tk.Frame(self.login_frame, bg='#34495e', relief=tk.RAISED, bd=2)
        login_box.pack(pady=20, padx=100)

        vault_exists = self.model.vault_exists()
        title_text = "Enter Master Password" if vault_exists else "Create Master Password"

        tk.Label(login_box, text=title_text, font=('Arial', 14, 'bold'),
                bg='#34495e', fg='#ecf0f1').pack(pady=20)

        tk.Label(login_box, text="Master Password:", font=('Arial', 11),
                bg='#34495e', fg='#ecf0f1').pack(pady=5)

        self.master_pw_entry = tk.Entry(login_box, show="●", font=('Arial', 12), width=30)
        self.master_pw_entry.pack(pady=10, padx=20)
        self.master_pw_entry.bind('<Return>', lambda e: self._handle_login())

        if not vault_exists:
            tk.Label(login_box, text="Confirm Password:", font=('Arial', 11),
                    bg='#34495e', fg='#ecf0f1').pack(pady=5)
            self.confirm_pw_entry = tk.Entry(login_box, show="●", font=('Arial', 12), width=30)
            self.confirm_pw_entry.pack(pady=10, padx=20)
            self.confirm_pw_entry.bind('<Return>', lambda e: self._handle_create_vault())

        # Buttons
        btn_frame = tk.Frame(login_box, bg='#34495e')
        btn_frame.pack(pady=20)

        if vault_exists:
            tk.Button(btn_frame, text="Login", command=self._handle_login,
                     bg='#3498db', fg='white', font=('Arial', 11, 'bold'),
                     padx=30, pady=5).pack(pady=10)
        else:
            tk.Button(btn_frame, text="Create Vault", command=self._handle_create_vault,
                     bg='#27ae60', fg='white', font=('Arial', 11, 'bold'),
                     padx=30, pady=5).pack(pady=10)

        # Info label
        info_text = "Vault location: " + str(self.model.data_dir)
        tk.Label(self.login_frame, text=info_text, font=('Arial', 9),
                bg='#2c3e50', fg='#95a5a6').pack(side=tk.BOTTOM, pady=10)

        self.master_pw_entry.focus()

    def _handle_login(self):
        """Handle login attempt"""
        password = self.master_pw_entry.get()

        if not password:
            messagebox.showerror("Error", "Please enter your master password")
            return

        try:
            if self.model.authenticate(password):
                self.login_frame.destroy()
                self._show_main_app()
            else:
                messagebox.showerror("Error", "Incorrect master password")
                self.master_pw_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Authentication failed: {str(e)}")

    def _handle_create_vault(self):
        """Handle vault creation"""
        password = self.master_pw_entry.get()
        confirm = self.confirm_pw_entry.get()

        if not password or not confirm:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return

        try:
            self.model.create_vault(password)
            messagebox.showinfo("Success", "Vault created successfully!")
            self.login_frame.destroy()
            self._show_main_app()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create vault: {str(e)}")

    def _show_main_app(self):
        """Display main application interface"""
        # Top toolbar
        toolbar = tk.Frame(self.root, bg='#34495e', height=60)
        toolbar.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(toolbar, text="�� Password Vault", font=('Arial', 16, 'bold'),
                bg='#34495e', fg='#ecf0f1').pack(side=tk.LEFT, padx=10)

        # Search box
        search_frame = tk.Frame(toolbar, bg='#34495e')
        search_frame.pack(side=tk.RIGHT, padx=10)

        tk.Label(search_frame, text="��", font=('Arial', 14),
                bg='#34495e', fg='#ecf0f1').pack(side=tk.LEFT, padx=5)

        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self._filter_passwords())
        search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                               font=('Arial', 11), width=25)
        search_entry.pack(side=tk.LEFT, padx=5)

        # Password list
        list_frame = tk.Frame(self.root, bg='#2c3e50')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ('Website', 'Username', 'Category', 'Modified')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)

        # Column configuration
        self.tree.heading('Website', text='Website')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Category', text='Category')
        self.tree.heading('Modified', text='Last Modified')

        self.tree.column('Website', width=300)
        self.tree.column('Username', width=250)
        self.tree.column('Category', width=150)
        self.tree.column('Modified', width=200)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Double-click to view
        self.tree.bind('<Double-1>', lambda e: self._view_password())

        # Action buttons
        btn_frame = tk.Frame(self.root, bg='#2c3e50')
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        buttons = [
            ("➕ Add Password", self._add_password, '#27ae60'),
            ("�� View", self._view_password, '#3498db'),
            ("✏ Edit", self._edit_password, '#e67e22'),
            ("�� Delete", self._delete_password, '#e74c3c'),
            ("�� Auto-Fill", self._auto_fill, '#9b59b6'),
            ("�� Export", self._export_vault, '#16a085'),
            ("�� Change Master PW", self._change_master_password, '#d35400'),
        ]

        for text, command, color in buttons:
            btn = tk.Button(btn_frame, text=text, command=command,
                          bg=color, fg='white', font=('Arial', 10, 'bold'),
                          padx=15, pady=5)
            btn.pack(side=tk.LEFT, padx=5)

        # Status bar
        self.status_label = tk.Label(self.root, text="", bg='#34495e',
                                     fg='#ecf0f1', font=('Arial', 9))
        self.status_label.pack(fill=tk.X, side=tk.BOTTOM)

        self._refresh_password_list()

    def _refresh_password_list(self):
        """Refresh the password list display"""
        self.tree.delete(*self.tree.get_children())

        passwords = self.model.search_passwords(self.current_filter) if self.current_filter else self.model.get_all_passwords()

        for entry_id, entry in passwords.items():
            try:
                modified_date = datetime.fromisoformat(entry.modified).strftime('%Y-%m-%d %H:%M')
            except:
                modified_date = "Unknown"

            self.tree.insert('', 'end', values=(
                entry.website,
                entry.username,
                entry.category,
                modified_date
            ), tags=(entry_id,))

        count = len(passwords)
        self.status_label.config(text=f"Total passwords: {count}")

    def _filter_passwords(self):
        """Filter passwords based on search"""
        self.current_filter = self.search_var.get()
        self._refresh_password_list()

    def _add_password(self):
        """Show dialog to add new password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("500x550")
        dialog.configure(bg='#34495e')
        dialog.transient(self.root)
        dialog.grab_set()

        entries = {}

        # Website
        tk.Label(dialog, text="Website/Service:", bg='#34495e', fg='#ecf0f1',
                font=('Arial', 10, 'bold')).pack(pady=5, anchor='w', padx=20)
        entries['website'] = tk.Entry(dialog, width=40, font=('Arial', 10))
        entries['website'].pack(pady=5, padx=20)

        # Username
        tk.Label(dialog, text="Username/Email:", bg='#34495e', fg='#ecf0f1',
                font=('Arial', 10, 'bold')).pack(pady=5, anchor='w', padx=20)
        entries['username'] = tk.Entry(dialog, width=40, font=('Arial', 10))
        entries['username'].pack(pady=5, padx=20)

        # Password
        tk.Label(dialog, text="Password:", bg='#34495e', fg='#ecf0f1',
                font=('Arial', 10, 'bold')).pack(pady=5, anchor='w', padx=20)

        pw_frame = tk.Frame(dialog, bg='#34495e')
        pw_frame.pack(pady=5, padx=20, fill=tk.X)

        entries['password'] = tk.Entry(pw_frame, width=30, font=('Arial', 10), show='●')
        entries['password'].pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(pw_frame, text="Generate", command=lambda: self._generate_password(entries['password']),
                 bg='#3498db', fg='white', font=('Arial', 9)).pack(side=tk.LEFT)

        # Category
        tk.Label(dialog, text="Category:", bg='#34495e', fg='#ecf0f1',
                font=('Arial', 10, 'bold')).pack(pady=5, anchor='w', padx=20)

        categories = ['General', 'Social Media', 'Banking', 'Email', 'Shopping', 'Work', 'Other']
        entries['category'] = ttk.Combobox(dialog, values=categories, width=37, font=('Arial', 10))
        entries['category'].set('General')
        entries['category'].pack(pady=5, padx=20)

        # Notes
        tk.Label(dialog, text="Notes:", bg='#34495e', fg='#ecf0f1',
                font=('Arial', 10, 'bold')).pack(pady=5, anchor='w', padx=20)
        entries['notes'] = tk.Text(dialog, width=40, height=4, font=('Arial', 10))
        entries['notes'].pack(pady=5, padx=20)

        # Save button
        def save():
            website = entries['website'].get().strip()
            username = entries['username'].get().strip()
            password = entries['password'].get()
            category = entries['category'].get()
            notes = entries['notes'].get('1.0', tk.END).strip()

            if not website or not username or not password:
                messagebox.showerror("Error", "Website, username, and password are required")
                return

            entry = PasswordEntry(
                website=website,
                username=username,
                password=password,
                category=category,
                notes=notes
            )

            try:
                self.model.add_password(entry)
                self._refresh_password_list()
                messagebox.showinfo("Success", "Password added successfully!")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add password: {str(e)}")

        tk.Button(dialog, text="�� Save Password", command=save,
                 bg='#27ae60', fg='white', font=('Arial', 11, 'bold'),
                 padx=20, pady=8).pack(pady=20)

        # Setup context menu for paste functionality
        self._setup_context_menu(entries['website'])
        self._setup_context_menu(entries['username'])
        self._setup_context_menu(entries['password'])
        self._setup_context_menu(entries['notes'])

    def _generate_password(self, entry_widget):
        """Generate and insert password"""
        gen_dialog = PasswordGeneratorDialog(self.root)
        self.root.wait_window(gen_dialog.dialog)

        if gen_dialog.result:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, gen_dialog.result)

    def _view_password(self):
        """View selected password details"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to view")
            return

        item = self.tree.item(selection[0])
        entry_id = item['tags'][0]
        entry = self.model.get_password(entry_id)

        if not entry:
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Password Details")
        dialog.geometry("800x750")
        dialog.configure(bg='#34495e')
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(True, True)  # Allow resizing for flexibility

        # Reusable clipboard helper for this dialog
        def _copy_to_clipboard(text, btn):
            try:
                if CLIPBOARD_AVAILABLE:
                    import pyperclip
                    pyperclip.copy(text)
                    btn.config(text='✓ Copied!', bg='#16a085')
                    dialog.after(2000, lambda: btn.config(text='�� Copy', bg='#27ae60'))
                    return
            except:
                pass

            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                self.root.update()
                btn.config(text='✓ Copied!', bg='#16a085')
                dialog.after(2000, lambda: btn.config(text='�� Copy', bg='#27ae60'))
            except Exception:
                try:
                    dialog.clipboard_clear()
                    dialog.clipboard_append(text)
                    dialog.update_idletasks()
                    dialog.update()
                    btn.config(text='✓ Copied!', bg='#16a085')
                    dialog.after(2000, lambda: btn.config(text='�� Copy', bg='#27ae60'))
                except Exception as e2:
                    messagebox.showerror("Clipboard Error",
                                           f"Could not copy to clipboard.\n\n"
                                           f"The text is: {text}\n\n"
                                           f"Please copy it manually.\n\nError: {str(e2)}")

        # Display fields
        fields = [
            ("�� Website", entry.website),
            ("�� Username", entry.username),
            ("�� Password", entry.password),
            ("�� Category", entry.category),
            ("�� Notes", entry.notes or "None"),
            ("�� Created", datetime.fromisoformat(entry.created).strftime('%Y-%m-%d %H:%M')),
            ("�� Modified", datetime.fromisoformat(entry.modified).strftime('%Y-%m-%d %H:%M'))
        ]

        for label, value in fields:
            tk.Label(dialog, text=label, bg='#34495e', fg='#ecf0f1',
                    font=('Arial', 11, 'bold')).pack(anchor='w', padx=30, pady=(10, 2))

            if label == "�� Password":
                pw_frame = tk.Frame(dialog, bg='#34495e')
                pw_frame.pack(anchor='w', padx=50, pady=5)

                pw_display = tk.Entry(pw_frame, width=35, font=('Courier', 11), show='●')
                pw_display.insert(0, value)
                pw_display.config(state='readonly')
                pw_display.pack(side=tk.LEFT, padx=(0, 5))

                def toggle_visibility():
                    current = pw_display.cget('show')
                    pw_display.config(show='' if current == '●' else '●')
                    toggle_btn.config(text='��' if current == '' else '��‍��')

                toggle_btn = tk.Button(pw_frame, text='��‍��', command=toggle_visibility,
                                      bg='#3498db', fg='white', font=('Arial', 10))
                toggle_btn.pack(side=tk.LEFT, padx=2)

                # Store password in a variable accessible to the copy function
                password_to_copy = value

                copy_btn = tk.Button(pw_frame, text='�� Copy',
                         command=lambda text=password_to_copy, b=None: _copy_to_clipboard(text, copy_btn),
                         bg='#27ae60', fg='white', font=('Arial', 10))
                copy_btn.pack(side=tk.LEFT, padx=2)

            elif label == "�� Notes":
                note_text = tk.Text(dialog, width=50, height=4, font=('Arial', 10))
                note_text.insert('1.0', value)
                note_text.config(state='disabled', bg='#2c3e50', fg='#ecf0f1')
                note_text.pack(anchor='w', padx=50, pady=5)

            elif label == "�� Website" or label == "�� Username":
                # Show read-only entry with copy button for Website and Username
                frame = tk.Frame(dialog, bg='#34495e')
                frame.pack(anchor='w', padx=50, pady=5)

                entry_display = tk.Entry(frame, width=50, font=('Arial', 11))
                entry_display.insert(0, value)
                entry_display.config(state='readonly')
                entry_display.pack(side=tk.LEFT, padx=(0, 5))

                # Create a local copy of value to bind to the lambda
                text_to_copy = value

                copy_btn = tk.Button(frame, text='�� Copy',
                                     command=lambda text=text_to_copy, b=None: _copy_to_clipboard(text, copy_btn),
                                     bg='#27ae60', fg='white', font=('Arial', 10))
                copy_btn.pack(side=tk.LEFT, padx=2)

            else:
                tk.Label(dialog, text=value, bg='#34495e', fg='#bdc3c7',
                        font=('Arial', 11)).pack(anchor='w', padx=50)

        tk.Button(dialog, text="✖ Close", command=dialog.destroy,
                 bg='#e74c3c', fg='white', font=('Arial', 10, 'bold'),
                 padx=20, pady=5).pack(pady=20)

    def _edit_password(self):
        """Edit selected password"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to edit")
            return

        item = self.tree.item(selection[0])
        entry_id = item['tags'][0]
        entry = self.model.get_password(entry_id)

        if not entry:
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Password")
        dialog.geometry("500x550")
        dialog.configure(bg='#34495e')
        dialog.transient(self.root)
        dialog.grab_set()

        entries = {}

        # Pre-fill fields
        fields_data = [
            ("Website/Service:", 'website', entry.website),
            ("Username/Email:", 'username', entry.username),
            ("Password:", 'password', entry.password),
        ]

        for label_text, key, value in fields_data:
            tk.Label(dialog, text=label_text, bg='#34495e', fg='#ecf0f1',
                    font=('Arial', 10, 'bold')).pack(pady=5, anchor='w', padx=20)

            if key == 'password':
                pw_frame = tk.Frame(dialog, bg='#34495e')
                pw_frame.pack(pady=5, padx=20, fill=tk.X)

                entries[key] = tk.Entry(pw_frame, width=30, font=('Arial', 10), show='●')
                entries[key].insert(0, value)
                entries[key].pack(side=tk.LEFT, padx=(0, 5))

                tk.Button(pw_frame, text="Generate", command=lambda: self._generate_password(entries['password']),
                         bg='#3498db', fg='white', font=('Arial', 9)).pack(side=tk.LEFT)
            else:
                entries[key] = tk.Entry(dialog, width=40, font=('Arial', 10))
                entries[key].insert(0, value)
                entries[key].pack(pady=5, padx=20)

        # Category
        tk.Label(dialog, text="Category:", bg='#34495e', fg='#ecf0f1',
                font=('Arial', 10, 'bold')).pack(pady=5, anchor='w', padx=20)

        categories = ['General', 'Social Media', 'Banking', 'Email', 'Shopping', 'Work', 'Other']
        entries['category'] = ttk.Combobox(dialog, values=categories, width=37, font=('Arial', 10))
        entries['category'].set(entry.category)
        entries['category'].pack(pady=5, padx=20)

        # Notes
        tk.Label(dialog, text="Notes:", bg='#34495e', fg='#ecf0f1',
                font=('Arial', 10, 'bold')).pack(pady=5, anchor='w', padx=20)
        entries['notes'] = tk.Text(dialog, width=40, height=4, font=('Arial', 10))
        entries['notes'].insert('1.0', entry.notes or "")
        entries['notes'].pack(pady=5, padx=20)

        def save():
            updated_entry = PasswordEntry(
                website=entries['website'].get().strip(),
                username=entries['username'].get().strip(),
                password=entries['password'].get(),
                category=entries['category'].get(),
                notes=entries['notes'].get('1.0', tk.END).strip(),
                created=entry.created
            )

            if not updated_entry.website or not updated_entry.username or not updated_entry.password:
                messagebox.showerror("Error", "Website, username, and password are required")
                return

            try:
                self.model.update_password(entry_id, updated_entry)
                self._refresh_password_list()
                messagebox.showinfo("Success", "Password updated successfully!")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update password: {str(e)}")

        tk.Button(dialog, text="�� Save Changes", command=save,
                 bg='#e67e22', fg='white', font=('Arial', 11, 'bold'),
                 padx=20, pady=8).pack(pady=20)

        # Setup context menu for paste functionality
        self._setup_context_menu(entries['website'])
        self._setup_context_menu(entries['username'])
        self._setup_context_menu(entries['password'])
        self._setup_context_menu(entries['notes'])

    def _delete_password(self):
        """Delete selected password"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to delete")
            return

        if not messagebox.askyesno("Confirm Delete",
                                   "Are you sure you want to delete this password?\n\nThis action cannot be undone."):
            return

        item = self.tree.item(selection[0])
        entry_id = item['tags'][0]

        try:
            self.model.delete_password(entry_id)
            self._refresh_password_list()
            messagebox.showinfo("Success", "Password deleted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete password: {str(e)}")

    def _auto_fill(self):
        """Auto-fill credentials in browser"""
        if not AUTOFILL_AVAILABLE:
            messagebox.showwarning("Feature Unavailable",
                                  "Auto-fill requires pyautogui.\n\n"
                                  "Install with: pip install pyautogui")
            return

        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password entry first")
            return

        item = self.tree.item(selection[0])
        entry_id = item['tags'][0]
        entry = self.model.get_password(entry_id)

        if not entry:
            return

        if messagebox.askyesno("Auto-Fill",
                              f"This will:\n"
                              f"1. Open {entry.website}\n"
                              f"2. Auto-type username and password\n\n"
                              f"Make sure your browser window is ready.\n\n"
                              f"Continue?"):
            try:
                webbrowser.open(entry.website)
                time.sleep(3)
                pyautogui.typewrite(entry.username, interval=0.1)
                pyautogui.press('tab')
                pyautogui.typewrite(entry.password, interval=0.1)
                messagebox.showinfo("Success", "Credentials auto-filled!\n\nPress Enter to submit if needed.")
            except Exception as e:
                messagebox.showerror("Error", f"Auto-fill failed: {str(e)}")

    def _export_vault(self):
        """Export vault to JSON file"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Vault"
        )

        if not filepath:
            return

        try:
            if self.model.export_vault(filepath, ""):
                messagebox.showinfo("Success", f"Vault exported to:\n{filepath}\n\n⚠ Keep this file secure!")
            else:
                messagebox.showerror("Error", "Failed to export vault")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")

    def _change_master_password(self):
        """Change master password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Master Password")
        dialog.geometry("450x350")
        dialog.configure(bg='#34495e')
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="⚠ Change Master Password", font=('Arial', 14, 'bold'),
                bg='#34495e', fg='#ecf0f1').pack(pady=20)

        entries = {}
        for label in ['Old Password:', 'New Password:', 'Confirm New Password:']:
            tk.Label(dialog, text=label, bg='#34495e', fg='#ecf0f1',
                    font=('Arial', 10, 'bold')).pack(pady=5, anchor='w', padx=30)
            entry = tk.Entry(dialog, show='●', font=('Arial', 11), width=30)
            entry.pack(pady=5, padx=30)
            entries[label] = entry

        def change():
            old_pw = entries['Old Password:'].get()
            new_pw = entries['New Password:'].get()
            confirm_pw = entries['Confirm New Password:'].get()

            if not old_pw or not new_pw or not confirm_pw:
                messagebox.showerror("Error", "All fields are required")
                return

            if new_pw != confirm_pw:
                messagebox.showerror("Error", "New passwords do not match")
                return

            if len(new_pw) < 8:
                messagebox.showerror("Error", "New password must be at least 8 characters")
                return

            try:
                if self.model.change_master_password(old_pw, new_pw):
                    dialog.destroy()
                    messagebox.showinfo("Success",
                                       "Master password changed successfully!\n\n"
                                       "Please remember your new password.")
                else:
                    messagebox.showerror("Error", "Old password is incorrect")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to change password: {str(e)}")

        tk.Button(dialog, text="�� Change Password", command=change,
                 bg='#e67e22', fg='white', font=('Arial', 11, 'bold'),
                 padx=20, pady=8).pack(pady=30)

    def run(self):
        """Start the application"""
        self.root.mainloop()


# ==================== Entry Point ====================

def main():
    """Main entry point"""
    if not CRYPTO_AVAILABLE:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Missing Dependencies",
            "Required library 'cryptography' is not installed.\n\n"
            "Please install it using:\n"
            "pip install cryptography\n\n"
            "Optional libraries for full functionality:\n"
            "pip install pyperclip pyautogui"
        )
        return

    app = PasswordManager()
    app.run()


if __name__ == "__main__":
    main()
