#!/usr/bin/env python3
"""Shared browser-backed authentication helpers for Atlassian requests."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
import stat
from urllib.parse import urlparse, urlunparse

import requests
from playwright.sync_api import Error, TimeoutError, sync_playwright

ServiceName = Literal["jira", "confluence"]

_LOGIN_LOCK = threading.Lock()
_USERNAME_SELECTORS = [
    'input[name="identifier"]',
    'input[name="username"]',
    'input[name="email"]',
    'input[type="email"]',
    'input[id*="user"]',
    'input[id*="email"]',
    'input[autocomplete="username"]',
    'input[type="text"]',
]


def _env_truthy(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off", ""}


def browser_auth_enabled() -> bool:
    return _env_truthy("ATLASSIAN_BROWSER_AUTH_ENABLED", True)


@dataclass(frozen=True)
class BrowserAuthConfig:
    jira_url: str
    confluence_url: str
    username: str | None
    profile_dir: Path
    storage_state: Path
    channel: str
    login_timeout_seconds: int
    jira_login_url: str
    confluence_login_url: str
    user_agent: str

    @classmethod
    def from_env(cls) -> "BrowserAuthConfig":
        jira_url = os.environ["JIRA_URL"].rstrip("/")
        confluence_url = os.environ["CONFLUENCE_URL"].rstrip("/")
        base_dir = Path(__file__).resolve().parent
        home = Path.home()

        profile_dir = Path(
            os.environ.get(
                "ATLASSIAN_BROWSER_PROFILE_DIR",
                str(base_dir / ".atlassian-browser-profile"),
            )
        ).expanduser().resolve()
        storage_state = Path(
            os.environ.get(
                "ATLASSIAN_STORAGE_STATE",
                str(base_dir / ".atlassian-browser-state.json"),
            )
        ).expanduser().resolve()

        for label, path in [("ATLASSIAN_BROWSER_PROFILE_DIR", profile_dir), ("ATLASSIAN_STORAGE_STATE", storage_state)]:
            if not (str(path).startswith(str(base_dir)) or str(path).startswith(str(home))):
                raise ValueError(
                    f"{label} resolves to '{path}' which is outside the project "
                    f"directory and user home. Refusing to use it."
                )

        return cls(
            jira_url=jira_url,
            confluence_url=confluence_url,
            username=os.environ.get("ATLASSIAN_USERNAME"),
            profile_dir=profile_dir,
            storage_state=storage_state,
            channel=os.environ.get("ATLASSIAN_BROWSER_CHANNEL", "chromium"),
            login_timeout_seconds=int(
                os.environ.get("ATLASSIAN_LOGIN_TIMEOUT_SECONDS", "300")
            ),
            jira_login_url=os.environ.get(
                "ATLASSIAN_JIRA_LOGIN_URL", f"{jira_url}/secure/Dashboard.jspa"
            ),
            confluence_login_url=os.environ.get(
                "ATLASSIAN_CONFLUENCE_LOGIN_URL", confluence_url
            ),
            user_agent=os.environ.get(
                "ATLASSIAN_BROWSER_USER_AGENT",
                (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/136.0.0.0 Safari/537.36"
                ),
            ),
        )

    def service_base(self, service: ServiceName) -> str:
        return self.jira_url if service == "jira" else self.confluence_url

    def login_target(self, service: ServiceName) -> str:
        return self.jira_login_url if service == "jira" else self.confluence_login_url

    @staticmethod
    def redact_url(url: str) -> str:
        """Strip query and fragment from URLs to avoid logging SAML tokens."""
        parsed = urlparse(url)
        if parsed.query or parsed.fragment:
            return urlunparse(parsed._replace(query="<redacted>", fragment=""))
        return url

    def is_allowed_url(self, url: str) -> bool:
        """Reject URLs that don't belong to configured Jira/Confluence instances."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        for base in (self.jira_url, self.confluence_url, self.jira_login_url, self.confluence_login_url):
            base_parsed = urlparse(base)
            if parsed.hostname == base_parsed.hostname:
                return True
        return False


def _wait_for_any_selector(
    page, selectors: list[str], timeout_ms: int = 1800
) -> str | None:
    try:
        page.locator(", ".join(selectors)).first.wait_for(
            state="visible",
            timeout=timeout_ms,
        )
    except TimeoutError:
        return None
    except Error:
        return None

    for selector in selectors:
        try:
            if page.locator(selector).first.is_visible():
                return selector
        except Error:
            continue
    return None


def _best_effort_prefill(page, username: str | None) -> None:
    if not username:
        return
    selector = _wait_for_any_selector(page, _USERNAME_SELECTORS)
    if not selector:
        return
    try:
        page.locator(selector).first.fill(username)
        print(
            f"[atlassian-browser-auth] Prefilled username into {selector}",
            file=sys.stderr,
            flush=True,
        )
    except Error as exc:
        print(
            f"[atlassian-browser-auth] Could not prefill username: {exc}",
            file=sys.stderr,
            flush=True,
        )


def interactive_login(
    service: ServiceName = "jira",
    url: str | None = None,
    config: BrowserAuthConfig | None = None,
) -> dict[str, Any]:
    cfg = config or BrowserAuthConfig.from_env()
    cfg.profile_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    cfg.profile_dir.chmod(stat.S_IRWXU)
    cfg.storage_state.parent.mkdir(parents=True, exist_ok=True)
    target_url = url or cfg.login_target(service)

    if url is not None and not cfg.is_allowed_url(url):
        raise ValueError(
            f"Refusing to open URL '{url}' — it does not match any configured "
            f"Atlassian host ({cfg.jira_url}, {cfg.confluence_url}). "
            "This restriction prevents phishing via MCP tool calls."
        )

    with _LOGIN_LOCK:
        print(
            f"[atlassian-browser-auth] Opening browser for {service} login at {target_url}",
            file=sys.stderr,
            flush=True,
        )
        print(
            "[atlassian-browser-auth] Complete SSO / MFA in the browser window. "
            "The request will resume automatically once the page lands on Jira or Confluence.",
            file=sys.stderr,
            flush=True,
        )

        deadline = time.time() + cfg.login_timeout_seconds
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                user_data_dir=str(cfg.profile_dir),
                channel=cfg.channel,
                headless=False,
                viewport={"width": 1440, "height": 960},
            )
            page = context.pages[0] if context.pages else context.new_page()
            page.goto(target_url, wait_until="domcontentloaded")
            _best_effort_prefill(page, cfg.username)

            last_url = page.url
            while time.time() < deadline:
                current_url = page.url
                if current_url != last_url:
                    print(
                        f"[atlassian-browser-auth] Browser now at: {BrowserAuthConfig.redact_url(current_url)}",
                        file=sys.stderr,
                        flush=True,
                    )
                    last_url = current_url

                if current_url.startswith((cfg.jira_url, cfg.confluence_url)):
                    context.storage_state(path=str(cfg.storage_state))
                    cfg.storage_state.chmod(stat.S_IRUSR | stat.S_IWUSR)
                    context.close()
                    return {
                        "status": "ok",
                        "service": service,
                        "final_url": current_url,
                        "storage_state": str(cfg.storage_state),
                    }
                time.sleep(1)

            current_url = page.url
            context.close()
            raise RuntimeError(
                "Timed out waiting for Atlassian login to complete. "
                f"Last page: {BrowserAuthConfig.redact_url(current_url)}"
            )


def _load_storage_state(path: Path) -> dict[str, Any]:
    try:
        file_stat = path.stat()
        if file_stat.st_uid != os.getuid():
            raise RuntimeError(
                f"Storage state file '{path}' is owned by uid {file_stat.st_uid}, "
                f"not the current user (uid {os.getuid()}). Possible tampering."
            )
        if file_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH):
            print(
                f"[atlassian-browser-auth] WARNING: '{path}' is readable by "
                "group/others. Tightening permissions to 600.",
                file=sys.stderr,
                flush=True,
            )
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Browser storage state does not exist yet: {path}"
        ) from exc


def _cookie_matches_base_url(cookie: dict[str, Any], base_url: str) -> bool:
    hostname = urlparse(base_url).hostname or ""
    domain = (cookie.get("domain") or "").lstrip(".")
    if not domain:
        return False
    # Exact hostname match only — reject broad domain cookies (e.g. ".epam.com")
    # to prevent leaking SSO IdP cookies with Jira API requests.
    return hostname == domain


def _apply_storage_state_cookies(
    session: requests.Session,
    storage_state: dict[str, Any],
    base_url: str,
) -> None:
    session.cookies.clear()
    for cookie in storage_state.get("cookies", []):
        if not _cookie_matches_base_url(cookie, base_url):
            continue
        rest: dict[str, Any] = {}
        if cookie.get("httpOnly") is not None:
            rest["HttpOnly"] = cookie.get("httpOnly")
        if cookie.get("sameSite"):
            rest["SameSite"] = cookie.get("sameSite")
        expires = cookie.get("expires")
        session.cookies.set(
            name=cookie["name"],
            value=cookie["value"],
            domain=cookie.get("domain"),
            path=cookie.get("path", "/"),
            secure=bool(cookie.get("secure")),
            expires=None
            if expires in (None, -1, 0)
            else int(float(expires)),
            rest=rest,
        )


def _load_sso_markers() -> tuple[str, ...]:
    """Load SSO detection markers from env or use sensible defaults."""
    custom = os.environ.get("ATLASSIAN_SSO_MARKERS")
    if custom:
        parsed = tuple(m.strip() for m in custom.split(",") if m.strip())
        if parsed:
            return parsed
    return (
        "oauth2/authorize",
        "The page has timed out",
        "Sign in with your account",
        "saml2/idp/SSOService",
        "/adfs/ls",
        "login.microsoftonline.com",
        "accounts.google.com/o/saml2",
        "auth.pingone.com",
        "login.okta.com",
    )


def looks_like_sso_response(response: requests.Response) -> bool:
    final_url = response.url or ""
    content_type = response.headers.get("Content-Type", "")
    body_sample = response.text[:2000] if "text/" in content_type else ""
    markers = _load_sso_markers()
    url_markers = [m for m in markers if "/" in m or "." in m]
    if any(marker in final_url for marker in url_markers):
        return True
    if any(
        any(marker in prior.url for marker in url_markers)
        for prior in response.history
    ):
        return True
    return "text/html" in content_type and any(marker in body_sample for marker in markers)


class BrowserCookieSession(requests.Session):
    """Requests session that refreshes itself through the Playwright browser profile."""

    def __init__(
        self,
        service: ServiceName,
        base_url: str,
        config: BrowserAuthConfig | None = None,
    ) -> None:
        super().__init__()
        self.service = service
        self.base_url = base_url.rstrip("/")
        self.browser_config = config or BrowserAuthConfig.from_env()
        self.trust_env = False
        self.max_redirects = 5
        self.headers.update({"User-Agent": self.browser_config.user_agent})
        self._browser_retry_on_auth = True
        try:
            self.refresh_cookies()
        except Exception as exc:
            raise RuntimeError(
                f"[atlassian-browser-auth] Could not load browser cookies for {service}. "
                "Refusing to proceed without authentication. Run atlassian_login first "
                "or check your storage state file."
            ) from exc

    def refresh_cookies(self) -> None:
        if not self.browser_config.storage_state.exists():
            if not sys.stdin.isatty() and not os.environ.get("DISPLAY"):
                return
            interactive_login(self.service, config=self.browser_config)
        if not self.browser_config.storage_state.exists():
            return
        storage_state = _load_storage_state(self.browser_config.storage_state)
        _apply_storage_state_cookies(self, storage_state, self.base_url)

    def request(self, method: str, url: str, *args: Any, **kwargs: Any) -> requests.Response:
        response = super().request(method, url, *args, **kwargs)
        if self._browser_retry_on_auth and looks_like_sso_response(response):
            response.close()
            self._browser_retry_on_auth = False
            try:
                interactive_login(self.service, config=self.browser_config)
                self.refresh_cookies()
                return super().request(method, url, *args, **kwargs)
            finally:
                self._browser_retry_on_auth = True
        return response


def create_browser_session(
    service: ServiceName,
    base_url: str,
    config: BrowserAuthConfig | None = None,
) -> BrowserCookieSession:
    return BrowserCookieSession(service=service, base_url=base_url, config=config)
