"""
login_helper.py
---------------
Site-specific login helpers for the Secure Password Manager.

Architecture
============

  LoginStep          – immutable dataclass: one atomic browser action
  LoginFlow          – ordered list of steps + metadata for one site
  BaseLoginHelper    – abstract base; subclass once per site
  LoginExecutor      – runs a LoginFlow (swap for FakeExecutor in tests)
  LoginHelperRegistry– discovers all registered helpers; finds by URL

Quick integration with password_manager.py
==========================================

    from login_helper import LoginHelperRegistry, LoginExecutor

    registry = LoginHelperRegistry.default()
    executor = LoginExecutor()

    entry   = vault_model.get_password(entry_id)     # PasswordEntry
    helper  = registry.find(entry.website)
    if helper:
        result = helper.login(entry.username, entry.password, executor)
        print(result.message)
    else:
        print("No login helper registered for", entry.website)

Extending
=========
To add a new site (e.g. Twitter), create a subclass and decorate it:

    @LoginHelperRegistry.register
    class TwitterLoginHelper(BaseLoginHelper):
        NAME    = "Twitter / X"
        DOMAINS = ["twitter.com", "x.com"]

        def get_flow(self, username: str, password: str) -> LoginFlow:
            return LoginFlow(
                name=self.NAME,
                url="https://x.com/i/flow/login",
                steps=[
                    Step.wait(2.0),
                    Step.type_text(username),
                    Step.press("enter"),
                    Step.wait(1.5),
                    Step.type_text(password),
                    Step.press("enter"),
                ],
            )

Testing
=======
Use FakeExecutor to capture steps without touching a real browser:

    from login_helper import FakeExecutor, GoogleLoginHelper

    fake    = FakeExecutor()
    helper  = GoogleLoginHelper()
    result  = helper.login("user@gmail.com", "s3cr3t", fake)

    assert result.success
    typed_texts = [s.value for s in fake.executed if s.action == StepAction.TYPE]
    assert "user@gmail.com" in typed_texts
    assert "s3cr3t"        in typed_texts
"""

from __future__ import annotations

import time
import webbrowser
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional


# ---------------------------------------------------------------------------
# Optional dependency: pyautogui
# ---------------------------------------------------------------------------

try:
    import pyautogui  # type: ignore
    _AUTOFILL_AVAILABLE = True
except ImportError:
    pyautogui = None          # type: ignore[assignment]
    _AUTOFILL_AVAILABLE = False


# ===========================================================================
# Step model  (pure data — no side-effects, trivially testable)
# ===========================================================================

class StepAction(Enum):
    """Every atomic action a login flow can perform."""
    OPEN_URL = auto()   # open a URL in the default browser
    WAIT     = auto()   # sleep for N seconds
    TYPE     = auto()   # type a string of text
    PRESS    = auto()   # press a single key  (e.g. "tab", "enter")
    HOTKEY   = auto()   # press a key combo   (e.g. "ctrl", "a")


@dataclass(frozen=True)
class LoginStep:
    """
    One atomic step in a login flow.

    Fields
    ------
    action  – what to do (StepAction)
    value   – string payload whose meaning depends on *action*:
                OPEN_URL → the URL to open
                WAIT     → seconds as a string, e.g. "2.0"
                TYPE     → the literal text to type
                PRESS    → key name accepted by pyautogui.press()
                HOTKEY   → comma-separated keys, e.g. "ctrl,a"
    label   – optional human-readable description (helps with logging/tests)
    """
    action: StepAction
    value:  str
    label:  str = ""

    def __str__(self) -> str:
        tag = self.label or self.action.name
        return f"[{tag}] {self.value!r}"


class Step:
    """
    Factory helpers so call-sites read like English:

        Step.open("https://github.com/login"),
        Step.wait(2.0),
        Step.type_text(username),
        Step.press("tab"),
    """

    @staticmethod
    def open(url: str) -> LoginStep:
        return LoginStep(StepAction.OPEN_URL, url, label="open")

    @staticmethod
    def wait(seconds: float) -> LoginStep:
        return LoginStep(StepAction.WAIT, str(seconds), label=f"wait {seconds}s")

    @staticmethod
    def type_text(text: str, label: str = "type") -> LoginStep:
        return LoginStep(StepAction.TYPE, text, label=label)

    @staticmethod
    def press(key: str) -> LoginStep:
        return LoginStep(StepAction.PRESS, key, label=f"press {key}")

    @staticmethod
    def hotkey(*keys: str) -> LoginStep:
        return LoginStep(StepAction.HOTKEY, ",".join(keys), label=f"hotkey {'+'.join(keys)}")


# ===========================================================================
# Login flow  (ordered steps + metadata)
# ===========================================================================

@dataclass
class LoginFlow:
    """
    A complete description of how to log into one site.

    Attributes
    ----------
    name  – human-readable site name shown in messages / logs
    url   – the login page URL (also stored as the first OPEN_URL step
              if you use Step.open(); kept here for easy introspection)
    steps – ordered list of LoginStep objects
    """
    name:  str
    url:   str
    steps: List[LoginStep] = field(default_factory=list)


# ===========================================================================
# Result
# ===========================================================================

@dataclass
class LoginResult:
    """Outcome returned by LoginHelper.login()."""
    success: bool
    message: str
    helper_name: str = ""


# ===========================================================================
# Executors  (side-effect layer — swap in tests)
# ===========================================================================

class BaseExecutor(ABC):
    """Abstract executor.  Implement this to change *how* steps are run."""

    @abstractmethod
    def run(self, flow: LoginFlow) -> LoginResult:
        ...


class LoginExecutor(BaseExecutor):
    """
    Real executor: opens the browser and drives it via pyautogui.

    Requires:  pip install pyautogui
    """

    def run(self, flow: LoginFlow) -> LoginResult:
        if not _AUTOFILL_AVAILABLE:
            return LoginResult(
                success=False,
                message=(
                    "pyautogui is not installed.\n"
                    "Install it with:  pip install pyautogui"
                ),
                helper_name=flow.name,
            )

        try:
            for step in flow.steps:
                self._execute_step(step)
            return LoginResult(
                success=True,
                message=f"Login flow for {flow.name!r} completed successfully.",
                helper_name=flow.name,
            )
        except Exception as exc:
            return LoginResult(
                success=False,
                message=f"Login flow for {flow.name!r} failed: {exc}",
                helper_name=flow.name,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _execute_step(step: LoginStep) -> None:
        if step.action == StepAction.OPEN_URL:
            webbrowser.open(step.value)

        elif step.action == StepAction.WAIT:
            time.sleep(float(step.value))

        elif step.action == StepAction.TYPE:
            # interval=0.05 is intentionally slower than the default (0)
            # to give sites time to process each keystroke.
            pyautogui.typewrite(step.value, interval=0.05)

        elif step.action == StepAction.PRESS:
            pyautogui.press(step.value)

        elif step.action == StepAction.HOTKEY:
            keys = step.value.split(",")
            pyautogui.hotkey(*keys)

        else:
            raise ValueError(f"Unknown StepAction: {step.action}")


class FakeExecutor(BaseExecutor):
    """
    Test-double executor: records every step without side-effects.

    Usage
    -----
        fake   = FakeExecutor()
        helper = GoogleLoginHelper()
        result = helper.login("u@g.com", "pw", fake)

        assert result.success
        assert fake.executed[0].action == StepAction.OPEN_URL
        typed = [s.value for s in fake.executed if s.action == StepAction.TYPE]
        assert "u@g.com" in typed
    """

    def __init__(self) -> None:
        self.executed: List[LoginStep] = []

    def run(self, flow: LoginFlow) -> LoginResult:
        self.executed = list(flow.steps)
        return LoginResult(
            success=True,
            message=f"[FakeExecutor] Recorded {len(self.executed)} steps for {flow.name!r}.",
            helper_name=flow.name,
        )

    def reset(self) -> None:
        """Clear recorded steps between test cases."""
        self.executed = []

    def steps_of_type(self, action: StepAction) -> List[LoginStep]:
        """Convenience filter for assertions."""
        return [s for s in self.executed if s.action == action]

    def typed_values(self) -> List[str]:
        """Return every text typed in order."""
        return [s.value for s in self.steps_of_type(StepAction.TYPE)]


# ===========================================================================
# Base helper
# ===========================================================================

class BaseLoginHelper(ABC):
    """
    Abstract base for all site-specific login helpers.

    Subclass contract
    -----------------
    NAME    – human-readable site name  (class attribute)
    DOMAINS – list of domain strings to match against  (class attribute)
              Use lowercase; the registry matches case-insensitively.
              Examples: ["github.com"], ["google.com", "gmail.com", "accounts.google.com"]

    get_flow(username, password) – return a LoginFlow with the step sequence
    """

    NAME:    str       = ""
    DOMAINS: List[str] = []

    @abstractmethod
    def get_flow(self, username: str, password: str) -> LoginFlow:
        """Build and return the LoginFlow for this site."""
        ...

    # ------------------------------------------------------------------
    # Public API (no need to override)
    # ------------------------------------------------------------------

    def login(
        self,
        username: str,
        password: str,
        executor: Optional[BaseExecutor] = None,
    ) -> LoginResult:
        """
        Build the flow and execute it.

        Parameters
        ----------
        username – credential username / email
        password – credential password
        executor – defaults to LoginExecutor() if not provided
        """
        if executor is None:
            executor = LoginExecutor()
        flow = self.get_flow(username, password)
        return executor.run(flow)

    def matches(self, url_or_domain: str) -> bool:
        """
        Return True when this helper supports the given URL or domain string.

        Matching is substring-based and case-insensitive so that both
        "github.com" and "https://github.com/login" resolve to the same helper.
        """
        needle = url_or_domain.lower()
        return any(domain.lower() in needle for domain in self.DOMAINS)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.NAME!r}, domains={self.DOMAINS})"


# ===========================================================================
# Google / Gmail login helper
# ===========================================================================

class GoogleLoginHelper(BaseLoginHelper):
    """
    Login helper for Google accounts (Gmail, Google Workspace, etc.).

    Google's sign-in is a two-page flow:
      Page 1 – enter email/username → click Next
      Page 2 – enter password       → click Next

    Timing notes
    ------------
    The 2-second waits account for:
      * page load after webbrowser.open()
      * JavaScript animation between the email and password screens

    Increase WAIT_AFTER_OPEN / WAIT_BETWEEN_PAGES if you observe timeouts
    on a slow connection.
    """

    NAME    = "Google / Gmail"
    DOMAINS = ["google.com", "gmail.com", "accounts.google.com"]

    # Tuneable timing constants
    WAIT_AFTER_OPEN:     float = 2.5   # seconds to wait after opening the URL
    WAIT_BETWEEN_PAGES:  float = 2.0   # seconds to wait between email and password screens

    LOGIN_URL = "https://accounts.google.com/signin/v2/identifier"

    def get_flow(self, username: str, password: str) -> LoginFlow:
        return LoginFlow(
            name=self.NAME,
            url=self.LOGIN_URL,
            steps=[
                # ── Page 1: open sign-in and enter email ──────────────────
                Step.open(self.LOGIN_URL),
                Step.wait(self.WAIT_AFTER_OPEN),

                Step.type_text(username, label="type email"),
                Step.press("tab"),      # move focus to the Next button
                Step.press("enter"),    # click Next

                # ── Page 2: enter password ────────────────────────────────
                Step.wait(self.WAIT_BETWEEN_PAGES),

                Step.type_text(password, label="type password"),
                Step.press("enter"),    # submit
            ],
        )


# ===========================================================================
# GitHub login helper
# ===========================================================================

class GitHubLoginHelper(BaseLoginHelper):
    """
    Login helper for GitHub.

    GitHub's sign-in is a single-page form:
      Field 1 – Username or email address
      Field 2 – Password
      Button  – Sign in

    The Tab key moves between the two input fields.
    """

    NAME    = "GitHub"
    DOMAINS = ["github.com"]

    WAIT_AFTER_OPEN: float = 2.0

    LOGIN_URL = "https://github.com/login"

    def get_flow(self, username: str, password: str) -> LoginFlow:
        return LoginFlow(
            name=self.NAME,
            url=self.LOGIN_URL,
            steps=[
                Step.open(self.LOGIN_URL),
                Step.wait(self.WAIT_AFTER_OPEN),

                Step.type_text(username, label="type username"),
                Step.press("tab"),                   # move to password field

                Step.type_text(password, label="type password"),
                Step.press("enter"),                 # submit the form
            ],
        )


# ===========================================================================
# Registry
# ===========================================================================

class LoginHelperRegistry:
    """
    Stores all available helpers and resolves the right one for a URL.

    Usage (manual registration)
    ---------------------------
        registry = LoginHelperRegistry()
        registry.register_helper(GoogleLoginHelper())
        registry.register_helper(GitHubLoginHelper())

        helper = registry.find("https://github.com/login")

    Usage (factory — recommended)
    ------------------------------
        registry = LoginHelperRegistry.default()
        helper   = registry.find(entry.website)
    """

    def __init__(self) -> None:
        self._helpers: List[BaseLoginHelper] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_helper(self, helper: BaseLoginHelper) -> "LoginHelperRegistry":
        """Register a helper instance. Returns self for chaining."""
        self._helpers.append(helper)
        return self

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def find(self, url_or_domain: str) -> Optional[BaseLoginHelper]:
        """
        Return the first helper whose DOMAINS match *url_or_domain*,
        or None if no helper is registered for that site.
        """
        for helper in self._helpers:
            if helper.matches(url_or_domain):
                return helper
        return None

    def list_helpers(self) -> List[BaseLoginHelper]:
        """Return all registered helpers (copy)."""
        return list(self._helpers)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def default(cls) -> "LoginHelperRegistry":
        """
        Return a registry pre-loaded with all built-in helpers.

        When you add a new helper class, add it here as well.
        """
        registry = cls()
        registry.register_helper(GoogleLoginHelper())
        registry.register_helper(GitHubLoginHelper())
        return registry


# ===========================================================================
# Convenience top-level function  (mirrors existing auto_fill pattern)
# ===========================================================================

def auto_login(
    website: str,
    username: str,
    password: str,
    registry:  Optional[LoginHelperRegistry] = None,
    executor:  Optional[BaseExecutor]        = None,
) -> LoginResult:
    """
    One-call integration point for password_manager.py.

    Parameters
    ----------
    website  – value of PasswordEntry.website
    username – value of PasswordEntry.username
    password – value of PasswordEntry.password
    registry – defaults to LoginHelperRegistry.default()
    executor – defaults to LoginExecutor() (real browser automation)

    Returns
    -------
    LoginResult with .success and .message

    Example (inside PasswordManager._auto_fill)
    -------------------------------------------
        from login_helper import auto_login

        entry  = self.model.get_password(entry_id)
        result = auto_login(entry.website, entry.username, entry.password)

        if result.success:
            messagebox.showinfo("Success", result.message)
        else:
            messagebox.showerror("Error", result.message)
    """
    if registry is None:
        registry = LoginHelperRegistry.default()

    helper = registry.find(website)

    if helper is None:
        return LoginResult(
            success=False,
            message=(
                f"No login helper registered for {website!r}.\n"
                "The built-in helpers cover: Google/Gmail and GitHub.\n"
                "You can add a custom helper by subclassing BaseLoginHelper."
            ),
        )

    return helper.login(username, password, executor)


# ===========================================================================
# Quick manual smoke-test  (run this file directly to verify)
# ===========================================================================

if __name__ == "__main__":  # pragma: no cover
    print("=" * 60)
    print("login_helper.py  —  smoke test (FakeExecutor)")
    print("=" * 60)

    fake     = FakeExecutor()
    registry = LoginHelperRegistry.default()

    test_cases = [
        ("https://gmail.com",          "alice@gmail.com", "hunter2"),
        ("https://github.com/login",   "alice",           "gh_token_abc"),
        ("https://unknown-site.com",   "alice",           "pw"),
    ]

    for website, username, password in test_cases:
        result = auto_login(website, username, password, registry, fake)
        status = "✓" if result.success else "✗"
        print(f"\n{status} {website}")
        print(f"  message : {result.message}")
        if result.success:
            print(f"  steps   : {len(fake.executed)}")
            print(f"  typed   : {fake.typed_values()}")
        fake.reset()

    print("\n" + "=" * 60)
    print("All helpers registered:")
    for h in registry.list_helpers():
        print(f"  {h}")
