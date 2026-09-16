

import os
import base64
import hashlib
import hmac
import secrets
import html
import re
import json
import time
import textwrap
import sqlite3
from datetime import datetime
from io import BytesIO, StringIO
from urllib.parse import urlparse, urlunparse

import numpy as np
import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI

# Optional Word export dependency. Excel export uses pandas/openpyxl.
try:
    from docx import Document
    from docx.shared import Inches, Pt
    WORD_EXPORT_AVAILABLE = True
except Exception:
    Document = None
    Inches = None
    Pt = None
    WORD_EXPORT_AVAILABLE = False


# ============================================================
# ENVIRONMENT
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"), override=True)

def _get_secret(name, default=""):
    """Read Streamlit Cloud Secrets first, then local environment variables."""
    try:
        value = st.secrets.get(name, None)
        if value is not None:
            return str(value).strip()
    except Exception:
        pass
    return os.getenv(name, default).strip()


DHIS2_URL = _get_secret(
    "DHIS2_URL",
    "https://dhis2.nutritionintl.org"
).rstrip("/")

# Read credentials through the same secure helper.
# Local: .env beside this file.
# Streamlit Cloud: App settings -> Secrets.
# Never hard-code passwords or API keys in source code.
# ============================================================
# OPENAI CONFIGURATION — MAIN NEXUS DANIP APP
# ============================================================
# OpenAI is NOT part of DHIS2 authentication.
# Keep the OpenAI secret under [OPENAI] in Streamlit Secrets.
try:
    OPENAI_API_KEY = str(
        st.secrets["OPENAI"]["OPENAI_API_KEY"]
    ).strip()
    OPENAI_MODEL = str(
        st.secrets["OPENAI"].get("OPENAI_MODEL", "gpt-5")
    ).strip()
except Exception:
    # Local fallback for .env development.
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5").strip()


# ============================================================
# PAGE
# ============================================================

st.set_page_config(
    page_title="NEXUS DANIP AI Data Intelligence",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# SECURE DHIS2 OAUTH2 AUTHENTICATION
# ============================================================
# Authentication is completely separate from OpenAI.
# DHIS2 OAuth credentials belong in [DANIP_DHIS2].
# OpenAI credentials belong in [OPENAI] and are used only by
# the main NEXUS DANIP AI dashboard.
# ============================================================

def _dhis2_secret(key, default=""):
    try:
        section = st.secrets.get("DANIP_DHIS2", {})
        value = section.get(key, None)
        if value is not None:
            return str(value).strip()
    except Exception:
        pass
    return os.getenv(key, default).strip()


DANIP_DHIS2_BASE_URL = _dhis2_secret(
    "BASE_URL",
    "https://dhis2.nutritionintl.org",
).rstrip("/")

DANIP_OAUTH_CLIENT_ID = _dhis2_secret("CLIENT_ID")
DANIP_OAUTH_CLIENT_SECRET = _dhis2_secret("CLIENT_SECRET")
DANIP_OAUTH_REDIRECT_URI = _dhis2_secret("REDIRECT_URI")
DANIP_OAUTH_STATE_SECRET = _dhis2_secret("STATE_SECRET")

DANIP_OAUTH_AUTHORIZE_URL = _dhis2_secret(
    "AUTHORIZE_URL",
    f"{DANIP_DHIS2_BASE_URL}/uaa/oauth/authorize",
)

DANIP_OAUTH_TOKEN_URL = _dhis2_secret(
    "TOKEN_URL",
    f"{DANIP_DHIS2_BASE_URL}/uaa/oauth/token",
)

DANIP_OAUTH_ME_URL = _dhis2_secret(
    "ME_URL",
    f"{DANIP_DHIS2_BASE_URL}/api/me",
)


if "danip_authenticated" not in st.session_state:
    st.session_state["danip_authenticated"] = False

if "danip_user" not in st.session_state:
    st.session_state["danip_user"] = {}

if "danip_access_token" not in st.session_state:
    st.session_state["danip_access_token"] = ""

if "danip_refresh_token" not in st.session_state:
    st.session_state["danip_refresh_token"] = ""


def _oauth_b64url(data):
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _create_oauth_state():
    if not DANIP_OAUTH_STATE_SECRET:
        return ""

    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(32)
    payload = f"{timestamp}.{nonce}"

    signature = hmac.new(
        DANIP_OAUTH_STATE_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    return (
        f"{_oauth_b64url(payload.encode('utf-8'))}."
        f"{_oauth_b64url(signature)}"
    )


def _verify_oauth_state(state, max_age_seconds=600):
    if not state or not DANIP_OAUTH_STATE_SECRET:
        return False

    try:
        encoded_payload, encoded_signature = state.split(".", 1)

        payload = base64.urlsafe_b64decode(
            encoded_payload + "=" * (-len(encoded_payload) % 4)
        ).decode("utf-8")

        signature = base64.urlsafe_b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4)
        )

        expected = hmac.new(
            DANIP_OAUTH_STATE_SECRET.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(signature, expected):
            return False

        timestamp_text, nonce = payload.split(".", 1)
        if not nonce:
            return False

        timestamp = int(timestamp_text)

        if abs(int(time.time()) - timestamp) > max_age_seconds:
            return False

        return True

    except Exception:
        return False


def _oauth_configuration_errors():
    errors = []

    if not DANIP_OAUTH_CLIENT_ID:
        errors.append("DANIP_DHIS2.CLIENT_ID")

    if not DANIP_OAUTH_CLIENT_SECRET:
        errors.append("DANIP_DHIS2.CLIENT_SECRET")

    if not DANIP_OAUTH_REDIRECT_URI:
        errors.append("DANIP_DHIS2.REDIRECT_URI")

    if not DANIP_OAUTH_STATE_SECRET:
        errors.append("DANIP_DHIS2.STATE_SECRET")

    return errors


def _build_dhis2_authorization_url():
    state = _create_oauth_state()

    if not state:
        return ""

    params = {
        "client_id": DANIP_OAUTH_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": DANIP_OAUTH_REDIRECT_URI,
        "scope": "ALL",
        "state": state,
    }

    return DANIP_OAUTH_AUTHORIZE_URL + "?" + urlencode(params)


def _exchange_dhis2_code(code):
    response = requests.post(
        DANIP_OAUTH_TOKEN_URL,
        auth=(
            DANIP_OAUTH_CLIENT_ID,
            DANIP_OAUTH_CLIENT_SECRET,
        ),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DANIP_OAUTH_REDIRECT_URI,
        },
        headers={
            "Accept": "application/json",
        },
        timeout=30,
    )

    if not response.ok:
        detail = ""
        try:
            body = response.json()
            detail = body.get("error_description") or body.get("error") or ""
        except Exception:
            detail = ""

        if detail:
            raise RuntimeError(
                f"DHIS2 OAuth error: {detail}"
            )

        raise RuntimeError(
            f"DHIS2 token endpoint returned HTTP {response.status_code}."
        )

    return response.json()


def _get_dhis2_authenticated_user(access_token):
    response = requests.get(
        DANIP_OAUTH_ME_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def _clear_oauth_query_params():
    try:
        st.query_params.clear()
    except Exception:
        pass


def _process_dhis2_oauth_callback():
    params = st.query_params

    code = params.get("code")
    state = params.get("state")
    error = params.get("error")
    error_description = params.get("error_description")

    if error:
        st.error("DHIS2 authentication was not completed.")
        if error_description:
            st.caption(str(error_description))
        _clear_oauth_query_params()
        return False

    if not code:
        return False

    if not _verify_oauth_state(state or ""):
        st.error(
            "The DHIS2 authentication response could not be verified."
        )
        st.caption("The OAuth state was invalid or expired.")
        _clear_oauth_query_params()
        return False

    try:
        token_data = _exchange_dhis2_code(code)
        access_token = token_data.get("access_token")

        if not access_token:
            raise RuntimeError(
                "DHIS2 did not return an access token."
            )

        user_data = _get_dhis2_authenticated_user(access_token)

        st.session_state["danip_authenticated"] = True
        st.session_state["danip_user"] = user_data
        st.session_state["danip_access_token"] = access_token
        st.session_state["danip_refresh_token"] = (
            token_data.get("refresh_token", "")
        )

        _clear_oauth_query_params()
        return True

    except requests.HTTPError as exc:
        status = (
            exc.response.status_code
            if exc.response is not None
            else "unknown"
        )

        st.error("DHIS2 OAuth authentication failed.")
        st.caption(f"DHIS2 returned HTTP {status}.")
        _clear_oauth_query_params()
        return False

    except requests.RequestException:
        st.error(
            "NEXUS DANIP could not connect to the DHIS2 "
            "authentication service."
        )
        st.caption(
            "Check the DHIS2 server URL and network connection."
        )
        _clear_oauth_query_params()
        return False

    except RuntimeError as exc:
        st.error("DHIS2 OAuth authentication failed.")
        st.caption(str(exc))
        _clear_oauth_query_params()
        return False

    except Exception:
        st.error(
            "NEXUS DANIP could not complete DHIS2 authentication."
        )
        st.caption("Check the OAuth configuration and application logs.")
        _clear_oauth_query_params()
        return False


def _logout_dhis2():
    st.session_state["danip_authenticated"] = False
    st.session_state["danip_user"] = {}
    st.session_state["danip_access_token"] = ""
    st.session_state["danip_refresh_token"] = ""
    _clear_oauth_query_params()
    st.rerun()


def _render_dhis2_login():
    st.markdown(
        """
        <style>
        .nexus-auth-shell {
            max-width: 520px;
            margin: 5vh auto 0 auto;
        }

        .nexus-auth-card {
            background: #ffffff;
            border: 1px solid #dbe2ea;
            border-radius: 18px;
            padding: 28px;
            box-shadow: 0 12px 35px rgba(15,23,42,.10);
        }

        .nexus-auth-title {
            color: #17374b;
            text-align: center;
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 4px;
        }

        .nexus-auth-subtitle {
            color: #64748b;
            text-align: center;
            font-size: 12px;
            margin-bottom: 22px;
        }

        .nexus-auth-security {
            background: #1d1f27;
            color: #ffffff;
            border-radius: 10px;
            padding: 15px 16px;
            font-size: 11px;
            line-height: 1.6;
            margin-bottom: 14px;
        }

        .nexus-auth-provider {
            background: #edf6fb;
            border: 1px solid #c9dce8;
            color: #17374b;
            border-radius: 10px;
            padding: 12px 14px;
            font-size: 10px;
            line-height: 1.6;
            margin-bottom: 16px;
        }

        .nexus-auth-footer {
            text-align: center;
            color: #8292a1;
            font-size: 9px;
            margin-top: 18px;
        }
        </style>

        <div class="nexus-auth-shell">
            <div class="nexus-auth-card">
                <div class="nexus-auth-title">NEXUS DANIP</div>
                <div class="nexus-auth-subtitle">
                    Data + M&amp;E Intelligence Platform
                </div>

                <div class="nexus-auth-security">
                    <b>🔐 Authorized access only</b><br>
                    Sign in using your existing DHIS2 account.
                    Your DHIS2 username and password are entered on
                    the official DHIS2 authentication page and are not
                    collected by NEXUS DANIP.
                </div>

                <div class="nexus-auth-provider">
                    <b>Authentication provider:</b>
                    Datalytics for Nutrition International Program (DANIP)<br>
                    <b>DHIS2 server:</b> dhis2.nutritionintl.org
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    errors = _oauth_configuration_errors()

    if errors:
        st.error("DHIS2 authentication is not configured yet.")
        st.write("Missing configuration:")
        for item in errors:
            st.code(item)
        st.info(
            "Configure the DANIP_DHIS2 values in Streamlit Secrets "
            "and restart the application."
        )
        return

    authorization_url = _build_dhis2_authorization_url()

    if not authorization_url:
        st.error("OAuth state security is not configured.")
        return

    st.link_button(
        "🔐 Sign in with DHIS2",
        authorization_url,
        use_container_width=True,
    )

    st.markdown(
        '<div class="nexus-auth-footer">'
        'You will be redirected to the official DHIS2 login page.'
        '</div>',
        unsafe_allow_html=True,
    )


# ============================================================
# PROCESS AUTHENTICATION BEFORE THE MAIN DASHBOARD
# ============================================================

if not st.session_state["danip_authenticated"]:
    if _process_dhis2_oauth_callback():
        st.rerun()

    _render_dhis2_login()
    st.stop()


# ============================================================
# AUTHENTICATED SESSION CONTEXT
# ============================================================

DANIP_ACCESS_TOKEN = st.session_state.get(
    "danip_access_token",
    "",
)

DANIP_AUTHENTICATED_USER = st.session_state.get(
    "danip_user",
    {},
)

DANIP_AUTHENTICATED_USERNAME = (
    DANIP_AUTHENTICATED_USER.get("username")
    or DANIP_AUTHENTICATED_USER.get("userCredentials", {}).get("username")
    or DANIP_AUTHENTICATED_USER.get("displayName")
    or DANIP_AUTHENTICATED_USER.get("name")
    or "Authenticated DHIS2 user"
)

# Authentication status is intentionally displayed in the existing
# dashboard sidebar without exposing the OAuth access token.
with st.sidebar:
    st.markdown(
        f"""
        <div style="
            background:#eef6f2;
            border:1px solid #b9d8c8;
            border-radius:10px;
            padding:10px;
            color:#174b34;
            font-size:11px;
            font-weight:700;
            margin-bottom:10px;">
            🔓 DHIS2 authenticated<br>
            User: {html.escape(str(DANIP_AUTHENTICATED_USERNAME))}
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button(
        "🔒 Sign Out",
        use_container_width=True,
        key="nexus_dhis2_signout",
    ):
        _logout_dhis2()



# ============================================================
# CSS
# ============================================================

st.markdown(
    """
    <style>
    html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"] {
        background: #ffffff !important;
        color: #1f2937 !important;
    }

    [data-testid="stHeader"] {
        background: #ffffff !important;
    }

    .block-container {
        max-width: 1500px;
        padding: 1.1rem 2rem 3rem 2rem;
    }

    .app-hero {
        padding: 1.2rem 1.35rem;
        border-radius: 18px;
        border: 1px solid rgba(148,163,184,.18);
        background: #ffffff;
        box-shadow: 0 1px 4px rgba(15,23,42,.06);
        margin-bottom: 1rem;
    }

    .app-title {
        font-size: clamp(1.6rem, 3vw, 2.35rem);
        font-weight: 800;
        letter-spacing: -.03em;
        margin: 0;
    }

    .app-subtitle {
        color: #64748b;
        margin-top: .45rem;
        font-size: .95rem;
        line-height: 1.5;
    }

    .status-row {
        display: flex;
        flex-wrap: wrap;
        gap: .45rem;
        marg
