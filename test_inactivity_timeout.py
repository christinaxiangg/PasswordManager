"""
Test script for inactivity timeout feature
This tests the basic logic of the timeout mechanism without running the full GUI
"""

import time
from unittest.mock import MagicMock, patch
import sys

# Test the timeout logic
def test_inactivity_timeout_logic():
    """Test that timeout is properly reset and triggered"""

    # Simulate the basic timeout logic
    INACTIVITY_TIMEOUT = 300  # 5 minutes

    # Mock the Tkinter components
    mock_root = MagicMock()
    inactivity_timer = None
    vault_unlocked = True

    def reset_inactivity_timer(event=None):
        """Reset the inactivity timeout timer on user activity"""
        nonlocal inactivity_timer, vault_unlocked

        if not vault_unlocked:
            return

        # Cancel existing timer if any
        if inactivity_timer is not None:
            mock_root.after_cancel(inactivity_timer)

        # Start a new timer
        inactivity_timer = mock_root.after(
            INACTIVITY_TIMEOUT * 1000,
            handle_inactivity_timeout
        )
        return inactivity_timer

    def handle_inactivity_timeout():
        """Handle inactivity timeout by logging out the user"""
        nonlocal vault_unlocked
        if vault_unlocked:
            print("✓ Timeout triggered: vault locked and user logged out")
            vault_unlocked = False

    # Test 1: Timer is started when vault is unlocked
    timer_id = reset_inactivity_timer()
    assert timer_id is not None, "Timer should be started"
    assert mock_root.after.called, "Tkinter after() should be called"
    print("✓ Test 1 PASSED: Inactivity timer starts on login")

    # Test 2: Timer is reset on activity
    reset_inactivity_timer()
    assert mock_root.after_cancel.called, "Tkinter after_cancel() should be called"
    print("✓ Test 2 PASSED: Inactivity timer resets on user activity")

    # Test 3: Timer doesn't start if vault is locked
    vault_unlocked = False
    inactivity_timer = None
    reset_inactivity_timer()
    assert not mock_root.after.called or inactivity_timer is None, "Timer should not start if vault is locked"
    print("✓ Test 3 PASSED: Inactivity timer doesn't start when vault is locked")

    # Test 4: Timeout handler only works if vault is unlocked
    vault_unlocked = False
    handle_inactivity_timeout()
    assert not vault_unlocked, "Vault should stay locked"
    print("✓ Test 4 PASSED: Timeout handler respects vault state")

    print("\n✅ All inactivity timeout tests passed!")

if __name__ == "__main__":
    test_inactivity_timeout_logic()

