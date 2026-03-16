from __future__ import annotations

import json
from typing import Optional
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app import config


PROVIDERS = {
    "google": {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scope": "openid email profile",
    },
    "github": {
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "emails_url": "https://api.github.com/user/emails",
        "scope": "read:user user:email",
    },
}


def build_authorization_url(provider: str, state: Optional[str] = None) -> str:
    provider = provider.lower()
    if provider not in PROVIDERS:
        raise RuntimeError("Unsupported provider")
    client_id = config.get_oauth_client_id(provider)
    redirect_uri = config.get_oauth_redirect_uri(provider)
    if not client_id or not redirect_uri:
        raise RuntimeError("OAuth provider not configured")
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": PROVIDERS[provider]["scope"],
    }
    if state:
        params["state"] = state
    return f"{PROVIDERS[provider]['auth_url']}?{urlencode(params)}"


def _exchange_code(provider: str, code: str) -> dict:
    client_id = config.get_oauth_client_id(provider)
    client_secret = config.get_oauth_client_secret(provider)
    redirect_uri = config.get_oauth_redirect_uri(provider)
    if not client_id or not client_secret or not redirect_uri:
        raise RuntimeError("OAuth provider not configured")
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if provider == "google":
        data["grant_type"] = "authorization_code"
    request = Request(
        PROVIDERS[provider]["token_url"],
        data=urlencode(data).encode("utf-8"),
        headers={"Accept": "application/json"},
    )
    with urlopen(request, timeout=15) as response:
        raw = response.read().decode("utf-8")
    return json.loads(raw or "{}")


def fetch_profile(provider: str, code: str) -> dict:
    provider = provider.lower()
    if provider not in PROVIDERS:
        raise RuntimeError("Unsupported provider")
    token_payload = _exchange_code(provider, code)
    access_token = token_payload.get("access_token")
    if not access_token:
        raise RuntimeError("OAuth token exchange failed")

    user_request = Request(
        PROVIDERS[provider]["userinfo_url"],
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
    )
    with urlopen(user_request, timeout=15) as response:
        user_raw = response.read().decode("utf-8")
    user_info = json.loads(user_raw or "{}")

    email = user_info.get("email")
    provider_user_id = str(user_info.get("sub") or user_info.get("id") or "")
    name = user_info.get("name") or user_info.get("login") or ""

    if provider == "github" and not email:
        emails_url = PROVIDERS[provider]["emails_url"]
        emails_request = Request(
            emails_url,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        with urlopen(emails_request, timeout=15) as response:
            emails_raw = response.read().decode("utf-8")
        emails = json.loads(emails_raw or "[]")
        for entry in emails:
            if entry.get("primary"):
                email = entry.get("email")
                break
        if not email and emails:
            email = emails[0].get("email")

    return {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "email": email,
        "name": name,
    }
