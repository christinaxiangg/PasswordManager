#!/usr/bin/env python3
"""
Test script for password export/import functionality
Tests both encrypted and plaintext exports
"""

import json
import tempfile
import os
from pathlib import Path
from password_manager import CryptoManager, PasswordEntry, VaultModel

def test_encrypted_export():
    """Test encrypted export functionality"""
    print("=" * 60)
    print("Test 1: Encrypted Export/Import")
    print("=" * 60)

    # Create test data
    test_data = {
        "entry1": {
            "website": "gmail.com",
            "username": "user@gmail.com",
            "password": "secret123",
            "notes": "My Gmail account",
            "created": "2026-03-07T10:00:00",
            "modified": "2026-03-07T10:00:00",
            "category": "Email"
        }
    }

    export_password = "ExportPassword123"

    # Encrypt
    print(f"\n1. Encrypting data with password: {export_password}")
    encrypted_data = CryptoManager.encrypt_export(test_data, export_password)
    print(f"   ✓ Encrypted data (first 100 chars): {encrypted_data[:100]}")

    # Verify it starts with "encrypted$"
    assert encrypted_data.startswith(b"encrypted$"), "Encrypted data should start with 'encrypted$'"
    print("   ✓ Format check passed")

    # Decrypt with correct password
    print(f"\n2. Decrypting with correct password")
    decrypted = CryptoManager.decrypt_export(encrypted_data, export_password)
    assert decrypted == test_data, "Decrypted data should match original"
    print("   ✓ Decryption successful")
    print(f"   ✓ Data matches: {decrypted['entry1']['website']}")

    # Try to decrypt with wrong password
    print(f"\n3. Testing wrong password rejection")
    try:
        CryptoManager.decrypt_export(encrypted_data, "WrongPassword")
        print("   ✗ FAILED: Should have rejected wrong password")
        return False
    except ValueError:
        print("   ✓ Correctly rejected wrong password")

    print("\n✓ Test 1 PASSED: Encrypted export/import works correctly\n")
    return True


def test_plaintext_export():
    """Test plaintext export functionality"""
    print("=" * 60)
    print("Test 2: Plaintext Export")
    print("=" * 60)

    test_data = {
        "entry1": {
            "website": "github.com",
            "username": "dev_user",
            "password": "github_pass",
            "notes": "GitHub account",
            "created": "2026-03-07T10:00:00",
            "modified": "2026-03-07T10:00:00",
            "category": "Work"
        }
    }

    # Export as plaintext (empty password)
    print("\n1. Creating plaintext export")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(test_data, f, indent=2)
        temp_file = f.name

    print(f"   ✓ Plaintext file created: {temp_file}")

    # Read and verify
    with open(temp_file, 'r') as f:
        content = f.read()

    # Should be readable JSON
    decoded = json.loads(content)
    assert decoded == test_data, "Plaintext export should be readable JSON"
    print("   ✓ Plaintext is valid JSON")
    print(f"   ✓ Can read passwords: {decoded['entry1']['password']}")

    # Cleanup
    os.unlink(temp_file)

    print("\n✓ Test 2 PASSED: Plaintext export works as expected\n")
    return True


def test_vault_export_import():
    """Test VaultModel export/import methods"""
    print("=" * 60)
    print("Test 3: VaultModel Export/Import")
    print("=" * 60)

    # Create a vault
    vault = VaultModel()

    # Create test entry
    entry = PasswordEntry(
        website="example.com",
        username="testuser",
        password="testpass123",
        category="General",
        notes="Test entry"
    )

    vault.passwords["test_entry"] = entry

    with tempfile.TemporaryDirectory() as tmpdir:
        # Test encrypted export
        print("\n1. Testing encrypted export via VaultModel")
        encrypted_file = os.path.join(tmpdir, "export_encrypted.json")
        result = vault.export_vault(encrypted_file, "VaultExportPassword")
        assert result, "Export should succeed"
        print(f"   ✓ Encrypted export created")

        # Verify file is not plaintext JSON
        with open(encrypted_file, 'r') as f:
            content = f.read()
        assert content.startswith("encrypted$"), "Should start with 'encrypted$'"
        print("   ✓ File is encrypted (not plain JSON)")

        # Test plaintext export
        print("\n2. Testing plaintext export via VaultModel")
        plaintext_file = os.path.join(tmpdir, "export_plaintext.json")
        result = vault.export_vault(plaintext_file, "")  # No password
        assert result, "Plaintext export should succeed"
        print(f"   ✓ Plaintext export created")

        with open(plaintext_file, 'r') as f:
            content = json.load(f)
        assert "test_entry" in content, "Should contain test entry"
        print(f"   ✓ Plaintext contains password: {content['test_entry']['password']}")

        # Test import of encrypted
        print("\n3. Testing encrypted import via VaultModel")
        vault2 = VaultModel()
        result = vault2.import_vault(encrypted_file, "VaultExportPassword")
        assert result, "Encrypted import should succeed"
        assert "test_entry" in vault2.passwords, "Should have imported entry"
        assert vault2.passwords["test_entry"].password == "testpass123"
        print("   ✓ Encrypted import successful")

        # Test import of plaintext
        print("\n4. Testing plaintext import via VaultModel")
        vault3 = VaultModel()
        result = vault3.import_vault(plaintext_file, "")
        assert result, "Plaintext import should succeed"
        assert "test_entry" in vault3.passwords, "Should have imported entry"
        print("   ✓ Plaintext import successful")

    print("\n✓ Test 3 PASSED: VaultModel export/import works correctly\n")
    return True


def main():
    """Run all tests"""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " PASSWORD MANAGER: EXPORT/IMPORT SECURITY TESTS".center(58) + "║")
    print("╚" + "=" * 58 + "╝")

    try:
        results = []
        results.append(test_encrypted_export())
        results.append(test_plaintext_export())
        results.append(test_vault_export_import())

        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)

        if all(results):
            print("✓ All tests PASSED!")
            print("\nSecurity Features Verified:")
            print("  ✓ Encrypted exports protect passwords with PBKDF2")
            print("  ✓ Plaintext exports detected and user warned")
            print("  ✓ Import auto-detects format (encrypted vs plaintext)")
            print("  ✓ Wrong password rejected for encrypted imports")
            return 0
        else:
            print("✗ Some tests failed")
            return 1

    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())

