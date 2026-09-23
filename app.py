

import os
import base64
import hashlib
import hmac
import secrets
import html
import re
import json
import time
import threading
import http.server
import socketserver
import textwrap
import sqlite3
from datetime import datetime
from io import BytesIO, StringIO
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs, unquote

import numpy as np
import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI
from ai_public_website_builder import render_ai_public_website_builder
from my_reports_monitoring import render_my_reports_monitoring

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


# ============================================================
# DHIS2 AUTHENTICATION SWITCH
# ============================================================
# False = temporarily disable the DHIS2 login / OAuth gate.
# True  = restore the normal DHIS2 OAuth login.
# Keep the OAuth functions and secrets in place so authentication
# can be restored later by changing only this value.
# ============================================================

ENABLE_DHIS2_AUTHENTICATION = False


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

if ENABLE_DHIS2_AUTHENTICATION:

    if not st.session_state["danip_authenticated"]:
        if _process_dhis2_oauth_callback():
            st.rerun()

        _render_dhis2_login()
        st.stop()


# ============================================================
# DEVELOPMENT MODE WHEN DHIS2 AUTHENTICATION IS DISABLED
# ============================================================

if not ENABLE_DHIS2_AUTHENTICATION:
    st.session_state["danip_authenticated"] = True

    if not st.session_state.get("danip_user"):
        st.session_state["danip_user"] = {
            "username": "Development mode",
            "displayName": "Development mode",
        }


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

    if ENABLE_DHIS2_AUTHENTICATION:
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

    else:
        st.markdown(
            """
            <div style="
                background:#fff7ed;
                border:1px solid #fed7aa;
                border-radius:10px;
                padding:10px;
                color:#9a3412;
                font-size:11px;
                font-weight:700;
                margin-bottom:10px;">
                ⚠️ DHIS2 authentication disabled<br>
                Development mode
            </div>
            """,
            unsafe_allow_html=True,
        )



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
        margin-top: .75rem;
    }

    .status-pill {
        display: inline-block;
        border-radius: 999px;
        padding: .3rem .65rem;
        font-size: .75rem;
        font-weight: 700;
        border: 1px solid rgba(148,163,184,.18);
        background: rgba(30,41,59,.7);
    }

    .status-ok { color: #86efac; }
    .status-info { color: #93c5fd; }

    .section-card {
        border: 1px solid rgba(148,163,184,.16);
        border-radius: 15px;
        padding: 1rem 1.05rem;
        background: #ffffff;
        margin-bottom: .75rem;
    }

    .section-kicker {
        color: #60a5fa;
        font-size: .72rem;
        font-weight: 800;
        letter-spacing: .08em;
        text-transform: uppercase;
    }

    .section-title {
        font-size: 1.08rem;
        font-weight: 750;
        margin: .15rem 0 .2rem 0;
    }

    .section-help {
        color: #94a3b8;
        font-size: .82rem;
        line-height: 1.45;
    }

    div[data-testid="stMetric"] {
        border: 1px solid rgba(148,163,184,.16);
        border-radius: 14px;
        padding: .6rem .75rem;
        background: #ffffff;
        min-height: 88px;
    }

    .ai-result {
        padding: 1.2rem 1.25rem;
        border-radius: 15px;
        border: 1px solid rgba(96,165,250,.2);
        background: #ffffff;
        line-height: 1.7;
    }

    [data-testid="stSidebar"] {
        background: #ffffff !important;
        border-right: 1px solid #e5e7eb;
    }

    [data-testid="stDataFrame"] {
        background: #ffffff !important;
    }

    .auto-analysis-card {
        border: 1px solid #dbeafe;
        background: linear-gradient(135deg, #ffffff 0%, #f8fbff 100%);
        box-shadow: 0 2px 8px rgba(37, 99, 235, .05);
    }

    .auto-analysis-card .section-kicker {
        color: #2563eb !important;
    }


    .guided-panel {
        border: 1px solid #e5e7eb;
        border-radius: 16px;
        padding: 1rem;
        background: #ffffff;
        margin-bottom: 1rem;
    }

    .comparison-note {
        border-left: 4px solid #2563eb;
        padding: .75rem 1rem;
        background: #eff6ff;
        border-radius: 8px;
        margin: .75rem 0;
    }


    /* =========================================================
       KPI / METRIC CARDS
       Fix invisible text on white background.
       ========================================================= */

    [data-testid="stMetric"] {
        background: #ffffff !important;
        border: 1px solid #e2e8f0 !important;
        border-radius: 12px !important;
        padding: 14px 16px !important;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04) !important;
    }

    [data-testid="stMetric"] label,
    [data-testid="stMetric"] [data-testid="stMetricLabel"],
    [data-testid="stMetric"] [data-testid="stMetricValue"],
    [data-testid="stMetric"] [data-testid="stMetricDelta"],
    [data-testid="stMetric"] div,
    [data-testid="stMetric"] span {
        color: #1f2937 !important;
        -webkit-text-fill-color: #1f2937 !important;
        opacity: 1 !important;
    }

    [data-testid="stMetric"] [data-testid="stMetricLabel"] {
        color: #64748b !important;
        -webkit-text-fill-color: #64748b !important;
        font-size: 0.82rem !important;
        font-weight: 600 !important;
    }

    [data-testid="stMetric"] [data-testid="stMetricValue"] {
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
        font-size: 1.65rem !important;
        font-weight: 700 !important;
        line-height: 1.2 !important;
    }

    [data-testid="stMetric"] [data-testid="stMetricDelta"] {
        color: #475569 !important;
        -webkit-text-fill-color: #475569 !important;
    }

    /* Generic metric markup fallback for Streamlit versions */
    div[data-testid="stMetricLabel"] p,
    div[data-testid="stMetricValue"] div,
    div[data-testid="stMetricValue"] {
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
        opacity: 1 !important;
    }

    div[data-testid="stMetricLabel"] p {
        color: #64748b !important;
        -webkit-text-fill-color: #64748b !important;
    }

    .empty-state {
        border: 1px dashed rgba(148,163,184,.28);
        border-radius: 15px;
        padding: 1.35rem;
        text-align: center;
        color: #94a3b8;
        margin-top: .75rem;
    }

    .stButton > button,
    .stDownloadButton > button {
        border-radius: 10px;
        font-weight: 700;
        min-height: 42px;
    }

    /* =========================================================
       FORM CONTROLS — FORCE LIGHT/WHITE INPUTS
       ========================================================= */

    textarea,
    input,
    [data-baseweb="textarea"] textarea,
    [data-baseweb="input"] input {
        background: #ffffff !important;
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
        caret-color: #111827 !important;
        border: 1px solid #cbd5e1 !important;
        border-radius: 10px !important;
        opacity: 1 !important;
    }

    textarea::placeholder,
    input::placeholder {
        color: #64748b !important;
        -webkit-text-fill-color: #64748b !important;
        opacity: 1 !important;
    }

    [data-testid="stTextArea"] textarea {
        background: #ffffff !important;
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
    }

    [data-testid="stSelectbox"] [data-baseweb="select"] > div,
    [data-testid="stMultiSelect"] [data-baseweb="select"] > div {
        background: #ffffff !important;
        color: #111827 !important;
        border-color: #cbd5e1 !important;
    }

    [data-testid="stSelectbox"] input,
    [data-testid="stMultiSelect"] input {
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
    }

    [data-baseweb="select"] span,
    [data-baseweb="select"] div {
        color: #111827 !important;
    }

    [data-baseweb="popover"],
    [role="listbox"] {
        background: #ffffff !important;
        color: #111827 !important;
    }

    [role="option"] {
        color: #111827 !important;
        background: #ffffff !important;
    }

    [role="option"]:hover {
        background: #f1f5f9 !important;
    }

    [data-testid="stBaseButton-secondary"] {
        background: #ffffff !important;
        color: #1f2937 !important;
        -webkit-text-fill-color: #1f2937 !important;
        border: 1px solid #cbd5e1 !important;
    }

    [data-testid="stBaseButton-secondary"]:hover {
        background: #f8fafc !important;
        color: #111827 !important;
    }

    [data-testid="stBaseButton-primary"] {
        color: #ffffff !important;
        -webkit-text-fill-color: #ffffff !important;
    }

    .stCaption,
    [data-testid="stCaptionContainer"] {
        color: #64748b !important;
    }

    @media (max-width: 900px) {
        .block-container {
            padding: .8rem .75rem 2rem .75rem;
        }

        .app-hero {
            padding: 1rem;
            border-radius: 14px;
        }

        div[data-testid="stMetric"] {
            min-height: 76px;
        }
    }

    @media (max-width: 640px) {
        .block-container {
            padding: .6rem .45rem 1.5rem .45rem;
        }

        .app-subtitle {
            font-size: .86rem;
        }

        .stButton > button,
        .stDownloadButton > button {
            width: 100%;
        }

        .status-pill {
            width: 100%;
            text-align: center;
        }
    }
    
    .section-card,
    .guided-panel,
    .section-title,
    .section-help,
    .section-kicker {
        color: #1f2937 !important;
        -webkit-text-fill-color: #1f2937 !important;
    }

    .section-help,
    .section-kicker {
        color: #64748b !important;
        -webkit-text-fill-color: #64748b !important;
    }

    h1, h2, h3, h4, h5, h6,
    p, label, [data-testid="stMarkdownContainer"] {
        color: #1f2937 !important;
        -webkit-text-fill-color: #1f2937 !important;
    }

    [data-testid="stAlert"] {
        color: #1f2937 !important;
    }

    /* =========================================================
       REQUESTED VISUALIZATIONS — CLEAN WHITE / BLACK TEXT
       ========================================================= */

    .requested-viz-card {
        background: #ffffff !important;
        border: 1px solid #e2e8f0 !important;
        border-radius: 12px !important;
        padding: 1rem !important;
        margin: .75rem 0 1rem 0 !important;
        box-shadow: 0 1px 3px rgba(15, 23, 42, .04) !important;
    }

    .requested-viz-card,
    .requested-viz-card * {
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
    }

    .viz-data-table-wrap {
        width: 100%;
        overflow-x: auto;
        margin-top: .8rem;
        border: 1px solid #dbe2ea;
        border-radius: 9px;
        background: #ffffff !important;
    }

    .viz-data-table {
        width: 100%;
        border-collapse: collapse;
        background: #ffffff !important;
        color: #111827 !important;
        font-size: .84rem;
    }

    .viz-data-table th {
        background: #ffffff !important;
        color: #111827 !important;
        font-weight: 800 !important;
        text-align: left;
        padding: .62rem .65rem;
        border-bottom: 1px solid #cbd5e1;
        white-space: nowrap;
    }

    .viz-data-table td {
        background: #ffffff !important;
        color: #111827 !important;
        padding: .55rem .65rem;
        border-bottom: 1px solid #e5e7eb;
        vertical-align: top;
    }

    .viz-data-table tr:last-child td {
        border-bottom: none;
    }

    .viz-data-table .total-row td {
        font-weight: 800 !important;
        border-top: 1px solid #cbd5e1;
    }

    .viz-notes {
        margin-top: .7rem;
        color: #334155 !important;
        font-size: .78rem;
        line-height: 1.5;
    }

    /* =========================================================
       DHIS2 DATA QUALITY — MANAGER / AUDITOR TABLES
       ========================================================= */

    .dq-audit-shell {
        background: #ffffff !important;
        border: 1px solid #d7dee8 !important;
        border-radius: 12px !important;
        padding: 0 !important;
        overflow: hidden !important;
        box-shadow: 0 2px 8px rgba(15, 23, 42, .05) !important;
        margin: .5rem 0 1rem 0 !important;
    }

    .dq-audit-toolbar {
        background: #ffffff !important;
        border-bottom: 1px solid #dbe2ea !important;
        padding: .85rem 1rem !important;
    }

    .dq-audit-toolbar,
    .dq-audit-toolbar * {
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
    }

    .dq-audit-title {
        font-size: 1rem !important;
        font-weight: 800 !important;
        color: #111827 !important;
        margin: 0 !important;
    }

    .dq-audit-subtitle {
        font-size: .78rem !important;
        color: #475569 !important;
        margin-top: .25rem !important;
        line-height: 1.45 !important;
    }

    .dq-table-wrap {
        width: 100% !important;
        overflow-x: auto !important;
        background: #ffffff !important;
    }

    .dq-table {
        width: 100% !important;
        min-width: 1050px !important;
        border-collapse: separate !important;
        border-spacing: 0 !important;
        background: #ffffff !important;
        color: #111827 !important;
        font-size: .80rem !important;
    }

    .dq-table th {
        position: sticky !important;
        top: 0 !important;
        z-index: 2 !important;
        background: #ffffff !important;
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
        font-weight: 800 !important;
        text-align: left !important;
        padding: .72rem .70rem !important;
        border-bottom: 2px solid #cbd5e1 !important;
        border-right: 1px solid #eef2f7 !important;
        white-space: nowrap !important;
    }

    .dq-table td {
        background: #ffffff !important;
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
        padding: .70rem .70rem !important;
        border-bottom: 1px solid #e5e7eb !important;
        border-right: 1px solid #f1f5f9 !important;
        vertical-align: top !important;
        line-height: 1.4 !important;
    }

    .dq-table tbody tr:hover td {
        background: #f8fafc !important;
        color: #111827 !important;
    }

    .dq-domain {
        font-weight: 800 !important;
        white-space: nowrap !important;
    }

    .dq-metric {
        font-weight: 700 !important;
    }

    .dq-result {
        font-weight: 800 !important;
        white-space: nowrap !important;
    }

    .dq-badge {
        display: inline-block !important;
        border-radius: 999px !important;
        padding: .20rem .52rem !important;
        font-size: .68rem !important;
        font-weight: 900 !important;
        letter-spacing: .03em !important;
        border: 1px solid #cbd5e1 !important;
        background: #ffffff !important;
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
        white-space: nowrap !important;
    }

    .dq-badge-pass {
        border-color: #86efac !important;
        background: #f0fdf4 !important;
        color: #166534 !important;
        -webkit-text-fill-color: #166534 !important;
    }

    .dq-badge-review {
        border-color: #fbbf24 !important;
        background: #fffbeb !important;
        color: #92400e !important;
        -webkit-text-fill-color: #92400e !important;
    }

    .dq-badge-fail {
        border-color: #fca5a5 !important;
        background: #fef2f2 !important;
        color: #991b1b !important;
        -webkit-text-fill-color: #991b1b !important;
    }

    .dq-badge-info {
        border-color: #93c5fd !important;
        background: #eff6ff !important;
        color: #1e40af !important;
        -webkit-text-fill-color: #1e40af !important;
    }

    .dq-priority-high {
        border-color: #fca5a5 !important;
        background: #fef2f2 !important;
        color: #991b1b !important;
        -webkit-text-fill-color: #991b1b !important;
    }

    .dq-priority-medium {
        border-color: #fcd34d !important;
        background: #fffbeb !important;
        color: #92400e !important;
        -webkit-text-fill-color: #92400e !important;
    }

    .dq-priority-low {
        border-color: #cbd5e1 !important;
        background: #f8fafc !important;
        color: #334155 !important;
        -webkit-text-fill-color: #334155 !important;
    }

    .dq-action {
        font-weight: 650 !important;
        color: #1f2937 !important;
        -webkit-text-fill-color: #1f2937 !important;
    }

    .dq-audit-summary {
        display: grid !important;
        grid-template-columns: repeat(4, minmax(0, 1fr)) !important;
        gap: .65rem !important;
        margin: .65rem 0 .9rem 0 !important;
    }

    .dq-summary-card {
        background: #ffffff !important;
        border: 1px solid #dbe2ea !important;
        border-radius: 10px !important;
        padding: .72rem .8rem !important;
    }

    .dq-summary-label {
        color: #64748b !important;
        -webkit-text-fill-color: #64748b !important;
        font-size: .70rem !important;
        font-weight: 800 !important;
        text-transform: uppercase !important;
        letter-spacing: .05em !important;
    }

    .dq-summary-value {
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
        font-size: 1.25rem !important;
        font-weight: 850 !important;
        margin-top: .18rem !important;
    }

    .dq-score-excellent { border-left: 4px solid #16a34a !important; }
    .dq-score-good { border-left: 4px solid #2563eb !important; }
    .dq-score-review { border-left: 4px solid #d97706 !important; }
    .dq-score-poor { border-left: 4px solid #dc2626 !important; }

    /* =========================================================
       AI DATA QUALITY INTERPRETATION
       ========================================================= */

    .dq-ai-quality-card {
        background: #ffffff !important;
        border: 1px solid #dbe2ea !important;
        border-left: 4px solid #2563eb !important;
        border-radius: 12px !important;
        padding: 1rem 1.05rem !important;
        margin: .75rem 0 1rem 0 !important;
        box-shadow: 0 2px 8px rgba(15, 23, 42, .04) !important;
    }

    .dq-ai-quality-card,
    .dq-ai-quality-card * {
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
    }

    .dq-ai-quality-kicker {
        color: #2563eb !important;
        -webkit-text-fill-color: #2563eb !important;
        font-size: .70rem !important;
        font-weight: 900 !important;
        letter-spacing: .08em !important;
        text-transform: uppercase !important;
        margin-bottom: .25rem !important;
    }

    .dq-ai-quality-title {
        font-size: 1.05rem !important;
        font-weight: 850 !important;
        margin: 0 0 .35rem 0 !important;
    }

    .dq-ai-quality-body {
        font-size: .86rem !important;
        line-height: 1.65 !important;
        color: #334155 !important;
        -webkit-text-fill-color: #334155 !important;
    }

    .dq-ai-quality-body h1,
    .dq-ai-quality-body h2,
    .dq-ai-quality-body h3,
    .dq-ai-quality-body h4,
    .dq-ai-quality-body strong {
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
    }

    .dq-ai-quality-body ul,
    .dq-ai-quality-body ol {
        margin-top: .35rem !important;
        margin-bottom: .55rem !important;
    }

    .dq-ai-quality-body li {
        margin-bottom: .2rem !important;
    }

    .dq-ai-quality-meta {
        display: flex !important;
        flex-wrap: wrap !important;
        gap: .45rem !important;
        margin-top: .75rem !important;
    }

    .dq-ai-quality-chip {
        display: inline-block !important;
        padding: .25rem .55rem !important;
        border: 1px solid #dbe2ea !important;
        border-radius: 999px !important;
        background: #f8fafc !important;
        color: #334155 !important;
        -webkit-text-fill-color: #334155 !important;
        font-size: .70rem !important;
        font-weight: 800 !important;
    }

    .dq-ai-quality-disclaimer {
        margin-top: .7rem !important;
        padding-top: .65rem !important;
        border-top: 1px solid #e5e7eb !important;
        font-size: .73rem !important;
        line-height: 1.45 !important;
        color: #64748b !important;
        -webkit-text-fill-color: #64748b !important;
    }

    .dq-audit-note {
        margin: .65rem 0 .9rem 0 !important;
        padding: .75rem .9rem !important;
        border: 1px solid #dbe2ea !important;
        border-left: 4px solid #2563eb !important;
        border-radius: 8px !important;
        background: #ffffff !important;
        color: #1f2937 !important;
        -webkit-text-fill-color: #1f2937 !important;
        font-size: .80rem !important;
        line-height: 1.5 !important;
    }

    .dq-detail-table {
        min-width: 1150px !important;
    }

    @media (max-width: 800px) {
        .dq-audit-summary {
            grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
        }
    }

    @media (max-width: 480px) {
        .dq-audit-summary {
            grid-template-columns: 1fr !important;
        }
    }

    @media (max-width: 640px) {
        .requested-viz-card {
            padding: .7rem !important;
        }

        .viz-data-table {
            min-width: 620px;
        }
    }



    /* =========================================================
       M&E PROGRAMME MANAGER INTERPRETATION
       ========================================================= */
    .me-programme-card {
        background: #ffffff !important;
        border: 1px solid #dbeafe !important;
        border-left: 4px solid #2563eb !important;
        border-radius: 12px !important;
        padding: 1rem 1.1rem !important;
        margin: .5rem 0 1rem 0 !important;
        box-shadow: 0 1px 3px rgba(15,23,42,.04) !important;
    }
    .me-programme-kicker {
        color: #2563eb !important;
        font-size: .72rem !important;
        font-weight: 800 !important;
        letter-spacing: .08em !important;
    }
    .me-programme-title {
        color: #111827 !important;
        font-size: 1.05rem !important;
        font-weight: 800 !important;
        margin-top: .2rem !important;
    }
    .me-programme-meta {
        color: #475569 !important;
        font-size: .8rem !important;
        margin-top: .35rem !important;
    }
    .me-ai-badge {
        display: inline-block;
        padding: .28rem .58rem;
        border-radius: 999px;
        background: #eff6ff !important;
        color: #1d4ed8 !important;
        border: 1px solid #bfdbfe !important;
        font-size: .7rem;
        font-weight: 800;
        margin: .5rem 0;
    }
    .me-programme-result {
        background: #ffffff !important;
        color: #111827 !important;
        border: 1px solid #dbe2ea !important;
        border-radius: 12px !important;
        padding: 1rem 1.15rem !important;
        line-height: 1.65 !important;
    }
    .me-programme-result * {
        color: #111827 !important;
    }

    /* =========================================================
       ANALYSIS CHATBOT — ISOLATED MODULE
       Does not modify existing dashboard classes.
       ========================================================= */
    .danip-analysis-chat {
        border: 1px solid #1e3a8a;
        border-radius: 16px;
        background: linear-gradient(135deg, #0b1f3a 0%, #123a68 55%, #0a2748 100%);
        padding: 1rem 1.05rem;
        margin: 1.1rem 0 1rem 0;
        box-shadow: 0 2px 8px rgba(15, 23, 42, .04);
    }

    .danip-analysis-chat .chat-kicker {
        color: #93c5fd !important;
        -webkit-text-fill-color: #2563eb !important;
        font-size: .70rem;
        font-weight: 900;
        letter-spacing: .08em;
        text-transform: uppercase;
        margin-bottom: .2rem;
    }

    .danip-analysis-chat .chat-title {
        color: #ffffff !important;
        -webkit-text-fill-color: #ffffff !important;
        font-size: 1.12rem;
        font-weight: 850;
        margin-bottom: .25rem;
    }

    .danip-analysis-chat .chat-help {
        color: #dbeafe !important;
        -webkit-text-fill-color: #dbeafe !important;
        font-size: .82rem;
        line-height: 1.5;
        margin-bottom: .7rem;
    }

    .danip-chat-source {
        display: inline-block;
        border: 1px solid #dbeafe;
        background: #eff6ff;
        color: #1d4ed8 !important;
        -webkit-text-fill-color: #1d4ed8 !important;
        border-radius: 999px;
        padding: .25rem .55rem;
        font-size: .68rem;
        font-weight: 800;
        max-width: 100%;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .danip-chat-answer {
        border: 1px solid #dbe2ea;
        border-left: 4px solid #2563eb;
        border-radius: 10px;
        background: #ffffff;
        padding: .85rem 1rem;
        margin: .55rem 0 .75rem 0;
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
        line-height: 1.65;
    }

    .danip-chat-answer * {
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
    }

    .danip-chat-note {
        color: #64748b !important;
        -webkit-text-fill-color: #64748b !important;
        font-size: .72rem;
        margin-top: .35rem;
    }

    /* Professional dark-blue chat composer */
    [data-testid="stChatInput"] {
        background: #0b1f3a !important;
        border: 1px solid #1d4ed8 !important;
        border-radius: 12px !important;
    }

    [data-testid="stChatInput"] textarea {
        color: #111827 !important;
        background: #ffffff !important;
        caret-color: #111827 !important;
    }

    [data-testid="stChatInput"] textarea::placeholder {
        color: #475569 !important;
        opacity: 1 !important;
    }

    [data-testid="stChatInput"] button {
        background: #1d4ed8 !important;
        color: #ffffff !important;
    }


    @media (max-width: 640px) {
        .danip-analysis-chat {
            padding: .75rem;
            border-radius: 13px;
        }
    }

</style>
    """,
    unsafe_allow_html=True,
)



# ============================================================
# PREMIUM UI THEME — NEXUS AI
# UI ONLY: does not modify data, AI, DHIS2 or analysis logic.
# ============================================================

st.markdown(
    """
    <style>
    /* ---------- Canvas ---------- */
    [data-testid="stAppViewContainer"] {
        background:
            radial-gradient(circle at 88% 0%, rgba(109,93,252,.07), transparent 28%),
            radial-gradient(circle at 8% 5%, rgba(49,94,251,.05), transparent 25%),
            #f7f8fb !important;
    }
    [data-testid="stHeader"] {
        background: rgba(247,248,251,.88) !important;
        backdrop-filter: blur(12px);
    }
    .block-container {
        max-width: none !important;
        width: 100% !important;
        padding-top: 1.15rem !important;
        padding-bottom: 4rem !important;
    }

    /* ---------- Luxury hero ---------- */
    .app-hero {
        position: relative !important;
        overflow: hidden !important;
        border: 1px solid rgba(255,255,255,.7) !important;
        border-radius: 26px !important;
        padding: 1.8rem 1.9rem 1.55rem !important;
        background: linear-gradient(135deg, #0a1020 0%, #17233a 52%, #29436f 100%) !important;
        box-shadow: 0 20px 50px rgba(16,24,40,.16) !important;
        margin-bottom: 1.35rem !important;
    }
    .app-hero::before {
        content: "";
        position: absolute;
        width: 360px;
        height: 360px;
        right: -90px;
        top: -190px;
        border-radius: 50%;
        background: rgba(109,93,252,.25);
        filter: blur(8px);
    }
    .app-hero::after {
        content: "";
        position: absolute;
        width: 220px;
        height: 220px;
        right: 160px;
        bottom: -170px;
        border-radius: 50%;
        background: rgba(49,94,251,.18);
    }
    .app-title, .app-subtitle, .status-row { position: relative; z-index: 1; }
    .app-title {
        color: #fff !important;
        -webkit-text-fill-color: #fff !important;
        font-size: clamp(2rem, 3.7vw, 3.05rem) !important;
        font-weight: 850 !important;
        letter-spacing: -.05em !important;
        line-height: 1.02 !important;
    }
    .app-subtitle {
        color: #cbd5e1 !important;
        -webkit-text-fill-color: #cbd5e1 !important;
        max-width: 930px !important;
        font-size: .96rem !important;
        line-height: 1.65 !important;
        margin-top: .7rem !important;
    }
    .status-row { gap: .55rem !important; margin-top: 1.05rem !important; }
    .status-pill {
        background: rgba(255,255,255,.085) !important;
        border: 1px solid rgba(255,255,255,.14) !important;
        color: #e5e7eb !important;
        -webkit-text-fill-color: #e5e7eb !important;
        padding: .4rem .74rem !important;
        backdrop-filter: blur(10px);
    }
    .status-ok { color: #b7f7d0 !important; -webkit-text-fill-color: #b7f7d0 !important; }
    .status-info { color: #dbe5ff !important; -webkit-text-fill-color: #dbe5ff !important; }

    /* ---------- Sidebar ---------- */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0a1020 0%, #111827 100%) !important;
        border-right: 1px solid rgba(255,255,255,.08) !important;
    }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"],
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] span {
        color: #e5e7eb !important;
        -webkit-text-fill-color: #e5e7eb !important;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] {
        background: rgba(255,255,255,.045) !important;
        border: 1px solid rgba(255,255,255,.09) !important;
        border-radius: 14px !important;
    }
    [data-testid="stSidebar"] [data-testid="stExpander"] * {
        color: #e5e7eb !important;
        -webkit-text-fill-color: #e5e7eb !important;
    }
    [data-testid="stSidebar"] .stButton > button {
        border: 1px solid rgba(255,255,255,.12) !important;
        background: rgba(255,255,255,.07) !important;
        color: #fff !important;
    }

    /* ---------- Content cards ---------- */
    .section-card, .guided-panel, .requested-viz-card, .dq-audit-shell,
    .me-programme-card, .dq-ai-quality-card {
        border-radius: 17px !important;
        box-shadow: 0 6px 22px rgba(16,24,40,.045) !important;
    }
    .section-card {
        background: rgba(255,255,255,.94) !important;
        border-color: #e7eaf0 !important;
    }
    .section-kicker {
        color: #5b5bd6 !important;
        -webkit-text-fill-color: #5b5bd6 !important;
        letter-spacing: .12em !important;
    }
    .section-title { letter-spacing: -.015em !important; }

    /* ---------- Metrics ---------- */
    [data-testid="stMetric"] {
        border: 1px solid #e6e9ef !important;
        border-radius: 15px !important;
        background: #fff !important;
        box-shadow: 0 5px 16px rgba(16,24,40,.04) !important;
        transition: transform .18s ease, box-shadow .18s ease;
    }
    [data-testid="stMetric"]:hover {
        transform: translateY(-2px);
        box-shadow: 0 9px 24px rgba(16,24,40,.075) !important;
    }

    /* ---------- Inputs ---------- */
    textarea, input, [data-baseweb="input"] input, [data-baseweb="textarea"] textarea,
    [data-baseweb="select"] > div {
        border-radius: 11px !important;
    }
    textarea:focus, input:focus {
        border-color: #6d5dfc !important;
        box-shadow: 0 0 0 2px rgba(109,93,252,.12) !important;
    }
    .stButton > button, .stDownloadButton > button {
        border-radius: 11px !important;
        min-height: 42px !important;
        font-weight: 750 !important;
        transition: transform .15s ease, box-shadow .15s ease;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 6px 18px rgba(16,24,40,.09) !important;
    }

   

    /* ---------- Data tables ---------- */
    [data-testid="stDataFrame"] {
        border: 1px solid #e5e7eb !important;
        border-radius: 14px !important;
        overflow: hidden !important;
        box-shadow: 0 5px 18px rgba(16,24,40,.04) !important;
    }

    /* ---------- Small screens ---------- */
    @media (max-width: 700px) {
        .app-hero { padding: 1.25rem !important; border-radius: 19px !important; }
        .app-title { font-size: 2rem !important; }
        .app-subtitle { font-size: .88rem !important; }
    }
    
    </style>
    """,
    unsafe_allow_html=True,
)
# =========================================================
# RESPONSIVE CHATBOT COMPOSER
# ONLY CHATBOT — DO NOT CHANGE OTHER UI
# =========================================================

st.markdown(
    """
    <style>

    /* =====================================================
       CHAT INPUT OUTER POSITION
       ===================================================== */

    [data-testid="stChatInput"] {
        width: min(100%, 950px) !important;
        max-width: 950px !important;

        margin-left: auto !important;
        margin-right: auto !important;

        box-sizing: border-box !important;

        background: #ffffff !important;

        border: 1px solid #cbd5e1 !important;

        border-radius: 16px !important;

        padding: 4px !important;

        box-shadow:
            0 4px 18px rgba(15, 23, 42, 0.10) !important;

        transition:
            border-color .2s ease,
            box-shadow .2s ease !important;
    }


    /* =====================================================
       FOCUS
       ===================================================== */

    [data-testid="stChatInput"]:focus-within {
        border-color: #2563eb !important;

        box-shadow:
            0 0 0 3px rgba(37, 99, 235, .10),
            0 6px 20px rgba(15, 23, 42, .12) !important;
    }


    /* =====================================================
       INTERNAL FORM
       ===================================================== */

    [data-testid="stChatInput"] form {
        width: 100% !important;
        max-width: 100% !important;

        display: flex !important;
        align-items: center !important;

        box-sizing: border-box !important;
    }


    /* =====================================================
       TEXT AREA
       ===================================================== */

    [data-testid="stChatInput"] textarea {
        width: 100% !important;

        min-height: 44px !important;
        max-height: 130px !important;

        box-sizing: border-box !important;

        border: none !important;
        outline: none !important;

        resize: none !important;

        background: transparent !important;

        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;

        font-size: 14px !important;
        line-height: 1.5 !important;

        padding:
            10px 48px 10px 14px !important;
    }


    /* =====================================================
       PLACEHOLDER
       ===================================================== */

    [data-testid="stChatInput"] textarea::placeholder {
        color: #64748b !important;
        -webkit-text-fill-color: #64748b !important;

        opacity: 1 !important;
    }


    /* =====================================================
       SEND BUTTON
       ===================================================== */

    [data-testid="stChatInput"] button {
        width: 38px !important;
        height: 38px !important;

        min-width: 38px !important;
        min-height: 38px !important;

        max-width: 38px !important;
        max-height: 38px !important;

        flex-shrink: 0 !important;

        border-radius: 10px !important;

        background: #2563eb !important;

        border: none !important;

        color: #ffffff !important;

        margin-right: 2px !important;

        transition:
            background .15s ease,
            transform .15s ease,
            box-shadow .15s ease !important;
    }


    [data-testid="stChatInput"] button:hover {
        background: #1d4ed8 !important;

        transform: translateY(-1px) !important;

        box-shadow:
            0 4px 12px rgba(37, 99, 235, .25) !important;
    }


    [data-testid="stChatInput"] button:focus {
        outline: none !important;
    }


    [data-testid="stChatInput"] button svg {
        color: #ffffff !important;

        fill: currentColor !important;
    }


    /* =====================================================
       CHAT MESSAGES
       ===================================================== */

    [data-testid="stChatMessage"] {
        width: min(100%, 950px) !important;
        max-width: 950px !important;

        margin-left: auto !important;
        margin-right: auto !important;

        box-sizing: border-box !important;
    }


    /* =====================================================
       CHAT RESPONSE
       ===================================================== */

    .danip-chat-answer {
        width: 100% !important;
        max-width: 100% !important;

        box-sizing: border-box !important;

        overflow-wrap: anywhere !important;
    }


    /* =====================================================
       TABLET
       ===================================================== */

    @media (max-width: 1000px) {

        [data-testid="stChatInput"] {
            width: calc(100% - 30px) !important;
            max-width: none !important;
        }

        [data-testid="stChatMessage"] {
            width: calc(100% - 30px) !important;
            max-width: none !important;
        }
    }


    /* =====================================================
       MOBILE
       ===================================================== */

    @media (max-width: 640px) {

        [data-testid="stChatInput"] {
            width: calc(100% - 16px) !important;

            margin-left: auto !important;
            margin-right: auto !important;

            border-radius: 13px !important;

            padding: 3px !important;
        }


        [data-testid="stChatInput"] textarea {
            min-height: 40px !important;

            max-height: 115px !important;

            font-size: 13px !important;

            padding:
                8px 44px 8px 11px !important;
        }


        [data-testid="stChatInput"] button {
            width: 34px !important;
            height: 34px !important;

            min-width: 34px !important;
            min-height: 34px !important;

            max-width: 34px !important;
            max-height: 34px !important;

            border-radius: 9px !important;
        }


        [data-testid="stChatMessage"] {
            width: calc(100% - 16px) !important;

            max-width: none !important;
        }
    }


    /* =====================================================
       SMALL PHONE
       ===================================================== */

    @media (max-width: 400px) {

        [data-testid="stChatInput"] {
            width: calc(100% - 10px) !important;

            border-radius: 11px !important;
        }


        [data-testid="stChatInput"] textarea {
            font-size: 12px !important;

            padding:
                7px 40px 7px 9px !important;
        }


        [data-testid="stChatInput"] button {
            width: 31px !important;
            height: 31px !important;

            min-width: 31px !important;
            min-height: 31px !important;

            max-width: 31px !important;
            max-height: 31px !important;
        }
    }

    </style>
    """,
    unsafe_allow_html=True,
)
# =========================================================
# GLOBAL TEXT HOVER COLOR
# Hover text color: #9d2130
#
# UI ONLY
# Does not change:
# - Data
# - AI
# - DHIS2
# - API
# - Charts
# - Calculations
# =========================================================

st.markdown(
    """
    <style>

    /* =====================================================
       GLOBAL TEXT HOVER COLOR
       ===================================================== */

    /* Headings */
    h1:hover,
    h2:hover,
    h3:hover,
    h4:hover,
    h5:hover,
    h6:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* Paragraph text */
    p:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* Strong / bold text */
    strong:hover,
    b:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* Italic text */
    em:hover,
    i:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* Labels */
    label:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* Markdown text */
    [data-testid="stMarkdownContainer"] p:hover,
    [data-testid="stMarkdownContainer"] span:hover,
    [data-testid="stMarkdownContainer"] strong:hover,
    [data-testid="stMarkdownContainer"] em:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       LINKS
       ===================================================== */

    a:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    [data-testid="stMarkdownContainer"] a:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;

        text-decoration-color: #9d2130 !important;
    }


    /* =====================================================
       SIDEBAR TEXT
       ===================================================== */

    [data-testid="stSidebar"] p:hover,
    [data-testid="stSidebar"] span:hover,
    [data-testid="stSidebar"] label:hover,
    [data-testid="stSidebar"] strong:hover,
    [data-testid="stSidebar"] b:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* Sidebar markdown */
    [data-testid="stSidebar"]
    [data-testid="stMarkdownContainer"]
    p:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       TABS
       ===================================================== */

    [data-baseweb="tab"]:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    [data-baseweb="tab"] p:hover,
    [data-baseweb="tab"] span:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       EXPANDERS
       ===================================================== */

    [data-testid="stExpander"] summary:hover,
    [data-testid="stExpander"] summary:hover span,
    [data-testid="stExpander"] summary:hover p {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       SELECTBOX / MULTISELECT
       ===================================================== */

    [data-testid="stSelectbox"] label:hover,
    [data-testid="stMultiSelect"] label:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    [data-testid="stSelectbox"] [data-baseweb="select"]:hover,
    [data-testid="stMultiSelect"] [data-baseweb="select"]:hover {
        color: #9d2130 !important;
    }


    /* Dropdown options */
    [role="option"]:hover,
    [role="option"]:hover span,
    [role="option"]:hover div {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       RADIO BUTTONS
       ===================================================== */

    [data-testid="stRadio"] label:hover,
    [data-testid="stRadio"] label:hover span,
    [data-testid="stRadio"] label:hover p {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       CHECKBOXES
       ===================================================== */

    [data-testid="stCheckbox"] label:hover,
    [data-testid="stCheckbox"] label:hover span,
    [data-testid="stCheckbox"] label:hover p {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       SLIDER LABELS
       ===================================================== */

    [data-testid="stSlider"] label:hover,
    [data-testid="stSlider"] span:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       METRIC TEXT
       ===================================================== */

    [data-testid="stMetricLabel"]:hover,
    [data-testid="stMetricValue"]:hover,
    [data-testid="stMetricDelta"]:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    [data-testid="stMetric"] label:hover,
    [data-testid="stMetric"] div:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       BUTTON TEXT
       ===================================================== */

    .stButton > button:hover,
    .stDownloadButton > button:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    .stButton > button:hover *,
    .stDownloadButton > button:hover * {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       CAPTION / SMALL TEXT
       ===================================================== */

    [data-testid="stCaptionContainer"]:hover,
    [data-testid="stCaptionContainer"] p:hover,
    .stCaption:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       ALERT TEXT
       ===================================================== */

    [data-testid="stAlert"] p:hover,
    [data-testid="stAlert"] span:hover,
    [data-testid="stAlert"] strong:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       CHAT TEXT
       Included so chatbot follows same global hover color
       ===================================================== */

    .danip-chat-answer p:hover,
    .danip-chat-answer span:hover,
    .danip-chat-answer strong:hover,
    .danip-chat-answer a:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       CUSTOM DASHBOARD TEXT CLASSES
       ===================================================== */

    .app-title:hover,
    .app-subtitle:hover,
    .section-kicker:hover,
    .section-title:hover,
    .section-help:hover,
    .comparison-note:hover,
    .empty-state:hover,
    .viz-notes:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* Children inside custom text elements */
    .app-title:hover *,
    .app-subtitle:hover *,
    .section-kicker:hover *,
    .section-title:hover *,
    .section-help:hover *,
    .comparison-note:hover *,
    .empty-state:hover *,
    .viz-notes:hover * {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       DQ DASHBOARD
       ===================================================== */

    .dq-audit-title:hover,
    .dq-audit-subtitle:hover,
    .dq-domain:hover,
    .dq-metric:hover,
    .dq-result:hover,
    .dq-action:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    .dq-table td:hover,
    .dq-table td:hover * {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       M&E PROGRAMME MANAGER
       ===================================================== */

    .me-programme-kicker:hover,
    .me-programme-title:hover,
    .me-programme-meta:hover,
    .me-programme-result:hover {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    .me-programme-result:hover * {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       REQUESTED VISUALIZATION
       ===================================================== */

    .requested-viz-card:hover,
    .requested-viz-card:hover * {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       DATA TABLE TEXT
       ===================================================== */

    .viz-data-table td:hover,
    .viz-data-table td:hover *,
    .viz-data-table th:hover,
    .viz-data-table th:hover * {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       STATUS PILLS
       ===================================================== */

    .status-pill:hover,
    .status-pill:hover * {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       GENERAL MARKDOWN LINKS / TEXT
       ===================================================== */

    [data-testid="stMarkdownContainer"] li:hover,
    [data-testid="stMarkdownContainer"] li:hover *,
    [data-testid="stMarkdownContainer"] blockquote:hover,
    [data-testid="stMarkdownContainer"] blockquote:hover * {
        color: #9d2130 !important;
        -webkit-text-fill-color: #9d2130 !important;
    }


    /* =====================================================
       DO NOT CHANGE INPUT TEXT WHILE TYPING
       ===================================================== */

    textarea:hover,
    input:hover,
    textarea:focus,
    input:focus {
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
    }


    /* =====================================================
       DO NOT CHANGE CHAT INPUT WHILE TYPING
       ===================================================== */

    [data-testid="stChatInput"] textarea:hover,
    [data-testid="stChatInput"] textarea:focus {
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
    }


    </style>
    """,
    unsafe_allow_html=True,
)
# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
    <div class="app-hero">
        <div class="app-title">NEXUS DANIP AI Data Analyst</div>
        <div class="app-subtitle">
            A premium evidence-first workspace for DHIS2, tabular and API data.
            Ask questions in natural language, explore performance, compare indicators,
            assess data quality and turn evidence into decision-ready intelligence.
        </div>
        <div class="status-row">
            <span class="status-pill status-ok">● Complete Data Processing</span>
            <span class="status-pill status-info">● User-Driven Analysis</span>
            <span class="status-pill status-info">● Data Quality First</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# CONFIGURATION STATUS
# ============================================================

missing = []

# DHIS2 URL is required for DHIS2 data access.
if not DHIS2_URL:
    missing.append("DHIS2_URL")

# OAuth is required only when the DHIS2 authentication gate is enabled.
if ENABLE_DHIS2_AUTHENTICATION and not DANIP_ACCESS_TOKEN:
    missing.append("DHIS2 OAuth session")

# OpenAI is optional. DHIS2 and Power BI functionality remain available.
openai_missing = not OPENAI_API_KEY

if missing:
    st.warning(
        "⚙️ Configuration is incomplete. "
        "The interface is still available."
    )

    with st.expander("Configuration details", expanded=False):
        st.write("Missing configuration:")
        for item in missing:
            st.code(item)

        st.info(
            "Configure the missing values in .env or Streamlit Secrets."
        )
elif openai_missing:
    st.info(
        "🤖 AI interpretation is currently disabled because "
        "OPENAI_API_KEY is not configured. "
        "DHIS2 data access and Power BI analytics remain available."
    )

# ============================================================
# OPENAI CLIENT
# ============================================================

client = None

if OPENAI_API_KEY:
    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
    except Exception as e:
        st.error(
            "OpenAI client could not be initialized. "
            "Check OPENAI_API_KEY."
        )
        with st.expander("Technical details", expanded=False):
            st.code(str(e))
else:
    client = None

# ============================================================
# OPENAI CONFIGURATION SAFETY
# ============================================================

if OPENAI_API_KEY and OPENAI_API_KEY.startswith("sk-"):
    # The key is intentionally not printed anywhere in the application.
    pass

# ============================================================
# DHIS2 SESSION
# ============================================================

session = requests.Session()

# Use the authenticated DHIS2 OAuth token for all protected API requests.
DANIP_ACCESS_TOKEN = st.session_state.get(
    "danip_access_token",
    "",
)

session.headers.update({
    "Authorization": f"Bearer {DANIP_ACCESS_TOKEN}",
    "User-Agent": "DANIP-DHIS2-AI/2.0",
})


# ============================================================
# HELPERS
# ============================================================

def show_ai_error(error):
    message = str(error)

    if "credit_balance_exhausted" in message or "insufficient_quota" in message:
        st.warning(
            "💳 AI credits are currently unavailable. "
            "The data-quality and deterministic analysis pipeline can still "
            "process the loaded data, but AI interpretation requires API access."
        )
    elif "invalid_api_key" in message or "incorrect api key" in message.lower() or "401" in message:
        st.error(
            "🔑 OpenAI rejected the API key. The chatbot's AI/web-research "
            "features cannot authenticate until OPENAI_API_KEY is corrected."
        )
        st.info(
            "Update OPENAI_API_KEY in Streamlit Cloud → App settings → Secrets "
            "or in the local .env file. Restart Streamlit after changing it."
        )
    elif "429" in message:
        st.warning("⏳ The AI service is temporarily rate-limited.")
    else:
        st.error("🤖 AI analysis could not be completed.")

    with st.expander("Technical details"):
        st.code(message)


def _safe_json_value(value):
    if value is None:
        return None

    try:
        if pd.isna(value):
            return None
    except Exception:
        pass

    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass

    return value


def safe_json_dumps(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        default=_safe_json_value,
    )


# ============================================================
# DHIS2 REQUEST
# ============================================================

def dhis2_get(url, accept="application/json", timeout=180):
    try:
        response = session.get(
            url,
            headers={"Accept": accept},
            timeout=timeout,
        )
    except requests.exceptions.RequestException as e:
        raise Exception(f"Unable to connect to DHIS2:\n\n{e}")

    if response.status_code != 200:
        raise Exception(
            f"DHIS2 returned HTTP {response.status_code}\n\n"
            f"URL:\n{response.url}\n\n"
            f"Server response:\n{response.text[:5000]}"
        )

    return response


def identify_url_type(url):
    lower = url.lower()

    if "/api/analytics" in lower:
        return "analytics"
    if "dhis-web-data-visualizer" in lower:
        return "visualization"
    if "/api/visualizations/" in lower:
        return "visualization_api"
    if "/api/events" in lower:
        return "events"
    if "/api/tracker" in lower:
        return "tracker"
    if "/api/datavaluesets" in lower:
        return "data_value_sets"
    if "/api/" in lower:
        return "api"

    return "unknown"


def get_extension(url):
    path = urlparse(url).path.lower()

    if path.endswith(".xlsx"):
        return "xlsx"
    if path.endswith(".xls"):
        return "xls"
    if path.endswith(".csv"):
        return "csv"
    if path.endswith(".json"):
        return "json"

    return ""


def change_extension(url, new_extension):
    parsed = urlparse(url)

    path = re.sub(
        r"\.(xls|xlsx|csv|json)$",
        "",
        parsed.path,
        flags=re.IGNORECASE,
    )

    path += "." + new_extension

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def get_csv_from_analytics_url(url):
    csv_url = change_extension(url, "csv")

    response = session.get(
        csv_url,
        headers={"Accept": "application/csv"},
        timeout=180,
    )

    if response.status_code == 200:
        return pd.read_csv(StringIO(response.text))

    return None


def read_xls_response(response):
    try:
        return pd.read_excel(
            BytesIO(response.content),
            engine="xlrd",
        )
    except Exception as e:
        raise Exception(
            "DHIS2 returned Excel data, but Python could not read the XLS file.\n\n"
            f"{e}"
        )


def read_xlsx_response(response):
    try:
        return pd.read_excel(
            BytesIO(response.content),
            engine="openpyxl",
        )
    except Exception as e:
        raise Exception(
            "DHIS2 returned Excel data, but Python could not read the XLSX file.\n\n"
            f"{e}"
        )


def read_csv_response(response):
    try:
        return pd.read_csv(StringIO(response.text))
    except Exception as e:
        raise Exception(
            "DANIP returned CSV data, but Python could not read it.\n\n"
            f"{e}"
        )


def read_json_response(response):
    try:
        return response.json()
    except Exception as e:
        raise Exception(
            "DANIP returned JSON data, but it could not be parsed.\n\n"
            f"{e}"
        )


def get_analytics_data(url):
    extension = get_extension(url)

    if extension in ["xls", "xlsx", "csv", ""]:
        try:
            csv_df = get_csv_from_analytics_url(url)
            if csv_df is not None and not csv_df.empty:
                return csv_df
        except Exception:
            pass

    if extension == "xlsx":
        return read_xlsx_response(
            dhis2_get(
                url,
                accept="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        )

    if extension == "xls":
        return read_xls_response(
            dhis2_get(
                url,
                accept="application/vnd.ms-excel",
            )
        )

    if extension == "csv":
        return read_csv_response(
            dhis2_get(
                url,
                accept="application/csv",
            )
        )

    return read_json_response(
        dhis2_get(url, accept="application/json")
    )


def get_direct_api_data(url):
    extension = get_extension(url)

    if "/api/analytics" in url.lower():
        return get_analytics_data(url)

    if extension == "xlsx":
        return read_xlsx_response(
            dhis2_get(
                url,
                accept="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        )

    if extension == "xls":
        return read_xls_response(
            dhis2_get(
                url,
                accept="application/vnd.ms-excel",
            )
        )

    if extension == "csv":
        return read_csv_response(
            dhis2_get(url, accept="application/csv")
        )

    return read_json_response(
        dhis2_get(url, accept="application/json")
    )


# ============================================================
# VISUALIZATION
# ============================================================

def extract_visualization_uid(url):
    patterns = [
        r"dhis-web-data-visualizer/#/([A-Za-z0-9]{11})",
        r"/api/visualizations/([A-Za-z0-9]{11})",
        r"^([A-Za-z0-9]{11})$",
    ]

    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)

    return None


def get_visualization(uid):
    response = dhis2_get(
        f"{DHIS2_URL}/api/visualizations/{uid}"
    )
    return response.json()


# ============================================================
# JSON -> DATAFRAME
# ============================================================

def json_to_dataframe(data):
    if isinstance(data, list):
        return pd.DataFrame(data)

    if not isinstance(data, dict):
        return pd.DataFrame()

    headers = data.get("headers")
    rows = data.get("rows")

    if headers and rows:
        columns = []

        for header in headers:
            if isinstance(header, dict):
                column = (
                    header.get("column")
                    or header.get("name")
                    or header.get("value")
                    or "Unknown"
                )
            else:
                column = str(header)

            columns.append(column)

        return pd.DataFrame(rows, columns=columns)

    for key in ["data", "rows", "items", "records", "events"]:
        value = data.get(key)

        if isinstance(value, list):
            return pd.DataFrame(value)

    return pd.DataFrame()


def normalize_dataframe(data):
    if isinstance(data, pd.DataFrame):
        df = data.copy()
    else:
        df = json_to_dataframe(data)

    if df.empty:
        return df

    df = df.dropna(how="all")
    df = df.dropna(axis=1, how="all")

    df.columns = [
        str(column).strip()
        for column in df.columns
    ]

    return df


# ============================================================
# DATA TYPES / STATISTICS
# ============================================================

def get_numeric_columns(df):
    numeric_columns = []

    for column in df.columns:
        converted = pd.to_numeric(
            df[column],
            errors="coerce",
        )

        if converted.notna().sum() >= 1:
            numeric_columns.append(column)

    return numeric_columns


def convert_numeric_columns(df):
    df = df.copy()
    numeric_columns = get_numeric_columns(df)

    for column in numeric_columns:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce",
        )

    return df, numeric_columns


def calculate_statistics(df):
    """Complete deterministic statistical profile using ALL loaded rows."""
    numeric_df, numeric_columns = convert_numeric_columns(df)
    result = {
        "records": int(len(df)),
        "columns": int(len(df.columns)),
        "column_names": [str(x) for x in df.columns],
        "numeric_columns": numeric_columns,
        "missing_values": {},
        "numeric_summary": {},
    }

    result["missing_values"] = {
        str(k): int(v) for k, v in df.isna().sum().to_dict().items()
    }

    for column in numeric_columns:
        values = numeric_df[column].dropna()
        if values.empty:
            continue

        q1 = values.quantile(0.25)
        q3 = values.quantile(0.75)
        iqr = q3 - q1
        outlier_count = 0 if iqr == 0 else int(
            ((values < q1 - 1.5 * iqr) | (values > q3 + 1.5 * iqr)).sum()
        )
        mean_value = values.mean()
        std_value = values.std()
        variance_value = values.var()

        result["numeric_summary"][column] = {
            "count": int(values.count()),
            "missing": int(numeric_df[column].isna().sum()),
            "minimum": float(values.min()),
            "Q1": float(q1),
            "average": float(mean_value),
            "median": float(values.median()),
            "Q3": float(q3),
            "maximum": float(values.max()),
            "range": float(values.max() - values.min()),
            "standard_deviation": float(std_value) if pd.notna(std_value) else None,
            "variance": float(variance_value) if pd.notna(variance_value) else None,
            "IQR": float(iqr),
            "total": float(values.sum()),
            "zero_count": int((values == 0).sum()),
            "negative_count": int((values < 0).sum()),
            "outlier_count": outlier_count,
            "coefficient_of_variation": (
                float(std_value / mean_value * 100)
                if mean_value != 0 and pd.notna(std_value) else None
            ),
        }

    return result


# ============================================================
# DATA QUALITY - DHIS2 QUALITY MATRIX
# ============================================================

def find_period_column(df):
    candidates = [
        "pe", "period", "periodname", "period name",
        "period code", "periodcode", "date", "event date"
    ]
    for candidate in candidates:
        for column in df.columns:
            if str(column).strip().lower() == candidate:
                return column
    for column in df.columns:
        if "period" in str(column).lower() or "event date" in str(column).lower():
            return column
    return None


def find_ou_column(df):
    for column in df.columns:
        name = str(column).strip().lower()
        if (
            name in {"ou", "orgunit", "organisation", "organization"}
            or "organisation unit" in name
            or "organization unit" in name
            or "organisationunit" in name
            or "organizationunit" in name
            or "org unit" in name
            or "orgunit" in name
            or "facility" in name
        ):
            return column
    return None


def find_indicator_like_columns(df):
    cols = []
    for c in df.columns:
        n = str(c).lower()
        if any(k in n for k in ["indicator", "numerator", "denominator", "coverage", "rate", "percent", "%"]):
            cols.append(c)
    return cols


def _quality_issue(priority, domain, issue, column="", count=0,
                   percentage=None, impact="", recommendation=""):
    item = {
        "Priority": priority,
        "Domain": domain,
        "Issue": issue,
        "Column": str(column) if column else "",
        "Count": int(count) if count is not None else 0,
        "Impact": impact,
        "Recommendation": recommendation,
    }
    if percentage is not None:
        item["Percentage"] = round(float(percentage), 2)
    return item


def _priority_from_pct(pct, high=20, medium=5):
    if pct >= high:
        return "HIGH"
    if pct >= medium:
        return "MEDIUM"
    return "LOW"


def build_quality_matrix(df):
    """Return a DHIS2-oriented quality matrix and detailed issues.

    Domains covered:
      Completeness, Uniqueness, Validity, Consistency, Timeliness,
      Integrity, Plausibility/Outliers and Zero/Negative checks.
    """
    issues = []
    matrix = []
    n = len(df)
    numeric_df, numeric_columns = convert_numeric_columns(df)

    def add_matrix(domain, metric, value, status, detail, priority="LOW"):
        matrix.append({
            "Domain": domain,
            "Metric": metric,
            "Result": value,
            "Status": status,
            "Priority": priority,
            "Details": detail,
        })

    # ---------------- COMPLETENESS ----------------
    missing_total = int(df.isna().sum().sum())
    total_cells = max(n * max(len(df.columns), 1), 1)
    missing_pct = missing_total / total_cells * 100
    comp_status = "PASS" if missing_total == 0 else "REVIEW" if missing_pct < 20 else "FAIL"
    comp_priority = "LOW" if missing_total == 0 else _priority_from_pct(missing_pct)
    add_matrix("Completeness", "Missing cells", f"{missing_total:,}", comp_status,
               f"{missing_pct:.2f}% of all cells are missing.", comp_priority)

    for column in df.columns:
        count = int(df[column].isna().sum())
        if count:
            pct = count / n * 100 if n else 0
            priority = _priority_from_pct(pct)
            issues.append(_quality_issue(
                priority, "Completeness", "Missing values", column, count, pct,
                "Missing observations can reduce completeness and affect calculations.",
                "Review source forms, mandatory fields and data-entry completeness."
            ))

    # ---------------- UNIQUENESS ----------------
    duplicate_rows = int(df.duplicated(keep=False).sum())
    dup_pct = duplicate_rows / n * 100 if n else 0
    add_matrix("Uniqueness", "Duplicate rows", f"{duplicate_rows:,}",
               "PASS" if duplicate_rows == 0 else "FAIL",
               f"{dup_pct:.2f}% of rows are part of an exact duplicate group.",
               "LOW" if duplicate_rows == 0 else "HIGH")
    if duplicate_rows:
        issues.append(_quality_issue(
            "HIGH", "Uniqueness", "Duplicate rows", "All columns", duplicate_rows, dup_pct,
            "Duplicates may inflate DHIS2 totals and rankings.",
            "Investigate duplicate import, repeated submission or extraction logic."
        ))

    # Natural-key duplicates: OU + period + indicator columns where available.
    ou = find_ou_column(df)
    period = find_period_column(df)
    indicator_cols = find_indicator_like_columns(df)
    key_cols = []
    if ou: key_cols.append(ou)
    if period: key_cols.append(period)
    if len(indicator_cols) == 1: key_cols.append(indicator_cols[0])
    if len(key_cols) >= 2:
        keyed = df[key_cols].astype("string")
        natural_dup = int(keyed.duplicated(keep=False).sum())
        add_matrix("Uniqueness", "DHIS2 natural-key duplicates", f"{natural_dup:,}",
                   "PASS" if natural_dup == 0 else "REVIEW",
                   "Key: " + ", ".join(map(str, key_cols)),
                   "LOW" if natural_dup == 0 else "HIGH")
        if natural_dup:
            issues.append(_quality_issue(
                "HIGH", "Uniqueness", "Possible OU-period-indicator duplicates",
                ", ".join(map(str, key_cols)), natural_dup,
                natural_dup / n * 100 if n else 0,
                "Multiple records can cause double counting for the same reporting grain.",
                "Check dataset/reporting period, OU and indicator uniqueness."
            ))

    # ---------------- VALIDITY ----------------
    parse_failures = 0
    for column in numeric_columns:
        original_nonblank = df[column].notna().sum()
        converted_nonnull = numeric_df[column].notna().sum()
        # get_numeric_columns only selects columns with >=1 numeric parse, so count mixed strings
        if original_nonblank > converted_nonnull:
            bad = int(original_nonblank - converted_nonnull)
            parse_failures += bad
            issues.append(_quality_issue(
                "MEDIUM", "Validity", "Non-numeric values in numeric-like field", column, bad,
                bad / n * 100 if n else 0,
                "Text values can be excluded from numeric analysis.",
                "Standardize numeric values and remove labels such as N/A or text suffixes."
            ))
    add_matrix("Validity", "Numeric parsing", f"{parse_failures:,} invalid numeric cells",
               "PASS" if parse_failures == 0 else "REVIEW",
               "Numeric fields were tested using strict numeric conversion.",
               "LOW" if parse_failures == 0 else "MEDIUM")

    # Negative values
    negative_total = 0
    for column in numeric_columns:
        count = int((numeric_df[column] < 0).sum())
        negative_total += count
        if count:
            issues.append(_quality_issue(
                "HIGH", "Validity", "Negative value", column, count,
                count / n * 100 if n else 0,
                "Negative values may be invalid for counts, coverage or service-delivery indicators.",
                "Review whether negative values are structurally valid or data-entry errors."
            ))
    add_matrix("Validity", "Negative numeric values", f"{negative_total:,}",
               "PASS" if negative_total == 0 else "FAIL",
               "Negative observations were checked across numeric fields.",
               "LOW" if negative_total == 0 else "HIGH")

    # Percentage/rate plausibility
    pct_cols = []
    for column in numeric_columns:
        name = str(column).lower()
        if any(k in name for k in ["percent", "%", "percentage", "coverage", "rate", "proportion"]):
            pct_cols.append(column)
    pct_over_100 = 0
    for column in pct_cols:
        values = numeric_df[column].dropna()
        count = int((values > 100).sum())
        pct_over_100 += count
        if count:
            issues.append(_quality_issue(
                "HIGH", "Plausibility", "Percentage/rate above 100", column, count,
                count / n * 100 if n else 0,
                "Values above 100 may indicate numerator/denominator, aggregation or data-entry problems.",
                "Verify indicator definition, denominator and aggregation method."
            ))
    add_matrix("Plausibility", "Percentage/rate > 100", f"{pct_over_100:,}",
               "PASS" if pct_over_100 == 0 else "FAIL",
               f"Detected {len(pct_cols)} percentage/rate-like columns.",
               "LOW" if pct_over_100 == 0 else "HIGH")

    # ---------------- ZERO / COMPLETENESS BEHAVIOUR ----------------
    zero_cells = 0
    zero_heavy_cols = 0
    for column in numeric_columns:
        values = numeric_df[column].dropna()
        if values.empty:
            continue
        count = int((values == 0).sum())
        zero_cells += count
        zero_pct = count / len(values) * 100
        if zero_pct >= 50:
            zero_heavy_cols += 1
            issues.append(_quality_issue(
                "MEDIUM", "Plausibility", "High zero concentration", column, count, zero_pct,
                "A high proportion of zeros may represent true zero performance or systematic non-reporting.",
                "Confirm whether zero is a valid reported value or should be distinguished from missing."
            ))
    add_matrix("Plausibility", "Zero concentration", f"{zero_cells:,} zero values",
               "PASS" if zero_heavy_cols == 0 else "REVIEW",
               f"{zero_heavy_cols} numeric fields have >=50% zero among observed values.",
               "LOW" if zero_heavy_cols == 0 else "MEDIUM")

    # ---------------- OUTLIERS ----------------
    outlier_total = 0
    for column in numeric_columns:
        values = numeric_df[column].dropna()
        if len(values) < 5:
            continue
        q1 = values.quantile(0.25)
        q3 = values.quantile(0.75)
        iqr = q3 - q1
        if iqr == 0:
            continue
        low = q1 - 1.5 * iqr
        high = q3 + 1.5 * iqr
        count = int(((values < low) | (values > high)).sum())
        outlier_total += count
        if count:
            issues.append(_quality_issue(
                "LOW", "Plausibility", "Statistical outlier (IQR)", column, count,
                count / len(values) * 100,
                "Outliers are not automatically errors, but may warrant review.",
                "Check source records and contextual programme changes before removing values."
            ))
    add_matrix("Plausibility", "IQR outliers", f"{outlier_total:,}",
               "PASS" if outlier_total == 0 else "REVIEW",
               "IQR rule used only where at least five observed values exist.",
               "LOW")

    # ---------------- PERIOD / TIMELINESS ----------------
    future_periods = 0
    period_gaps = 0
    if period:
        p = df[period].astype("string")
        parsed = pd.to_datetime(p, errors="coerce")
        if parsed.notna().sum() == 0:
            # DHIS2 YYYYMM/quarter codes are handled separately.
            cleaned = p.str.extract(r"(20\d{2})[\-/]?(\d{1,2})", expand=True)
            if not cleaned.empty:
                years = pd.to_numeric(cleaned[0], errors="coerce")
                months = pd.to_numeric(cleaned[1], errors="coerce")
                parsed = pd.to_datetime(
                    dict(year=years, month=months.clip(1,12), day=1),
                    errors="coerce"
                )
        if parsed.notna().any():
            future_periods = int((parsed > pd.Timestamp.today()).sum())
            add_matrix("Timeliness", "Future reporting periods", f"{future_periods:,}",
                       "PASS" if future_periods == 0 else "FAIL",
                       f"Using detected period column: {period}",
                       "LOW" if future_periods == 0 else "HIGH")
            if future_periods:
                issues.append(_quality_issue(
                    "HIGH", "Timeliness", "Future reporting period", period, future_periods,
                    future_periods / n * 100 if n else 0,
                    "Future records can distort current reporting and trend analysis.",
                    "Verify period selection and reporting calendar."
                ))
        else:
            add_matrix("Timeliness", "Period parseability", "Not determinable", "REVIEW",
                       f"Period column detected as {period}, but values were not parseable as dates.", "MEDIUM")
    else:
        add_matrix("Timeliness", "Period availability", "No period column detected", "REVIEW",
                   "Trend and reporting-period validation cannot be fully performed.", "MEDIUM")

    # ---------------- ORGANISATION UNIT ----------------
    if ou:
        missing_ou = int(df[ou].isna().sum())
        blank_ou = int((df[ou].astype("string").str.strip() == "").sum())
        ou_problem = missing_ou + blank_ou
        add_matrix("Integrity", "Organisation unit completeness", f"{ou_problem:,}",
                   "PASS" if ou_problem == 0 else "FAIL",
                   f"Detected organisation-unit field: {ou}",
                   "LOW" if ou_problem == 0 else "HIGH")
        if ou_problem:
            issues.append(_quality_issue(
                "HIGH", "Integrity", "Missing/blank organisation unit", ou, ou_problem,
                ou_problem / n * 100 if n else 0,
                "Records cannot be reliably attributed to a DHIS2 organisation unit.",
                "Review OU mapping and source extract completeness."
            ))
    else:
        add_matrix("Integrity", "Organisation unit field", "Not detected", "REVIEW",
                   "No standard OU field was detected in the returned data.", "MEDIUM")

    # ---------------- NUMERATOR / DENOMINATOR ----------------
    numerator_cols = [c for c in df.columns if re.search(r"(^|[_\s-])num(erator)?($|[_\s-])", str(c), re.I)]
    denominator_cols = [c for c in df.columns if re.search(r"(^|[_\s-])den(ominator)?($|[_\s-])", str(c), re.I)]
    ratio_issues = 0
    if numerator_cols and denominator_cols:
        pairs = min(len(numerator_cols), len(denominator_cols))
        for num_col, den_col in zip(numerator_cols[:pairs], denominator_cols[:pairs]):
            num = pd.to_numeric(df[num_col], errors="coerce")
            den = pd.to_numeric(df[den_col], errors="coerce")
            invalid_den = int((den <= 0).sum())
            num_gt_den = int(((num > den) & den.notna() & num.notna() & (den > 0)).sum())
            ratio_issues += num_gt_den
            if invalid_den:
                issues.append(_quality_issue(
                    "MEDIUM", "Consistency", "Non-positive denominator", den_col, invalid_den,
                    invalid_den / n * 100 if n else 0,
                    "Rates cannot be reliably calculated when denominators are zero or negative.",
                    "Validate denominator definition and source reporting."
                ))
            if num_gt_den:
                issues.append(_quality_issue(
                    "HIGH", "Consistency", "Numerator greater than denominator",
                    f"{num_col} / {den_col}", num_gt_den,
                    num_gt_den / n * 100 if n else 0,
                    "A numerator above its denominator produces a rate above 100%.",
                    "Check indicator formula, data aggregation and reporting grain."
                ))
        add_matrix("Consistency", "Numerator > denominator", f"{ratio_issues:,}",
                   "PASS" if ratio_issues == 0 else "FAIL",
                   f"Detected {len(numerator_cols)} numerator and {len(denominator_cols)} denominator fields.",
                   "LOW" if ratio_issues == 0 else "HIGH")
    else:
        add_matrix("Consistency", "Numerator/denominator validation", "Not available", "INFO",
                   "No explicit numerator/denominator column pair was detected.", "LOW")

    # ---------------- STRUCTURAL / CARDINALITY ----------------
    high_cardinality = []
    for c in df.columns:
        unique = int(df[c].nunique(dropna=True))
        if n and unique / n > 0.95 and n >= 20:
            high_cardinality.append(str(c))
    add_matrix("Integrity", "High-cardinality fields", str(len(high_cardinality)),
               "INFO",
               ", ".join(high_cardinality[:10]) if high_cardinality else "No suspicious high-cardinality fields detected.",
               "LOW")

    # Sort issues
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    issues.sort(key=lambda x: (order.get(x.get("Priority"), 9), x.get("Domain", "")))

    # Quality score: weighted issue prevalence, capped 0-100.
    weights = {"HIGH": 5, "MEDIUM": 2, "LOW": 0.5}
    penalty = sum(weights.get(i.get("Priority"), 0) for i in issues)
    denominator = max(len(df.columns) * 2 + len(df) / 1000, 1)
    score = max(0.0, min(100.0, 100 - (penalty / denominator * 100)))

    summary = {
        "score": round(score, 1),
        "rating": "Excellent" if score >= 90 else "Good" if score >= 75 else "Needs review" if score >= 50 else "Poor",
        "rows": n,
        "columns": len(df.columns),
        "issues": len(issues),
        "matrix": matrix,
    }
    return issues, matrix, summary



def build_indicator_quality_matrix(df, indicator):
    """
    DHIS2-oriented, indicator-level data-quality assessment.

    The existing overall quality engine remains unchanged. This focused engine
    applies the same audit philosophy to the indicator selected by the user:
    completeness, uniqueness, validity/correctness, plausibility, timeliness,
    integrity and consistency. It never edits source values.
    """
    indicator = str(indicator)
    if indicator not in df.columns:
        return [], [], {
            "score": 0.0,
            "rating": "Unavailable",
            "rows": len(df),
            "columns": len(df.columns),
            "issues": 0,
            "indicator": indicator,
            "matrix": [],
        }

    n = len(df)
    issues = []
    matrix = []

    def add_matrix(domain, metric, value, status, detail, priority="LOW"):
        matrix.append({
            "Domain": domain,
            "Metric": metric,
            "Result": value,
            "Status": status,
            "Priority": priority,
            "Details": detail,
        })

    def pct(count, denominator=None):
        denominator = n if denominator is None else denominator
        return (count / denominator * 100) if denominator else 0.0

    # Selected indicator values only.
    raw = df[indicator]
    text_values = raw.astype("string")
    blank_mask = raw.isna() | text_values.str.strip().eq("")
    missing = int(blank_mask.sum())
    nonblank = raw[~blank_mask]
    numeric = pd.to_numeric(nonblank, errors="coerce")
    parse_failures = int(numeric.isna().sum())
    valid_numeric = numeric.dropna()

    # ------------------------------------------------------------
    # 1. COMPLETENESS — data-element level
    # ------------------------------------------------------------
    missing_pct = pct(missing)
    comp_status = "PASS" if missing == 0 else "REVIEW" if missing_pct < 20 else "FAIL"
    comp_priority = "LOW" if missing == 0 else _priority_from_pct(missing_pct)

    add_matrix(
        "Completeness",
        "Indicator missing values",
        f"{missing:,}",
        comp_status,
        f"{missing_pct:.2f}% of records have no value for the selected indicator.",
        comp_priority,
    )

    if missing:
        issues.append(_quality_issue(
            comp_priority,
            "Completeness",
            "Missing indicator values",
            indicator,
            missing,
            missing_pct,
            "Missing indicator values reduce data-element completeness and can bias trends, comparisons or aggregates.",
            "Review reporting completeness by organisation unit and period; verify whether blanks represent non-reporting or a legitimate absence of service.",
        ))

    # ------------------------------------------------------------
    # 2. UNIQUENESS — OU + period reporting grain
    # ------------------------------------------------------------
    ou_col = find_ou_column(df)
    period_col = find_period_column(df)

    if ou_col and period_col:
        key = df[[ou_col, period_col]].astype("string")
        duplicate_key_rows = int(key.duplicated(keep=False).sum())
        dup_pct = pct(duplicate_key_rows)
        add_matrix(
            "Uniqueness",
            "OU-period duplicate records",
            f"{duplicate_key_rows:,}",
            "PASS" if duplicate_key_rows == 0 else "FAIL",
            f"Reporting grain assessed using {ou_col} + {period_col} for {indicator}.",
            "LOW" if duplicate_key_rows == 0 else "HIGH",
        )
        if duplicate_key_rows:
            issues.append(_quality_issue(
                "HIGH",
                "Uniqueness",
                "Possible repeated OU-period records",
                f"{indicator} | {ou_col} + {period_col}",
                duplicate_key_rows,
                dup_pct,
                "Repeated reporting records can double-count an indicator when records are aggregated.",
                "Check extraction grain, duplicate submissions and whether multiple category/disaggregation dimensions were flattened into the returned data.",
            ))
    else:
        add_matrix(
            "Uniqueness",
            "OU-period uniqueness",
            "Not determinable",
            "INFO",
            "A standard organisation-unit and period pair was not available for this indicator.",
            "LOW",
        )

    # ------------------------------------------------------------
    # 3. VALIDITY / CORRECTNESS — numeric conversion and negatives
    # ------------------------------------------------------------
    add_matrix(
        "Validity",
        "Numeric parsing",
        f"{parse_failures:,} invalid numeric cells",
        "PASS" if parse_failures == 0 else "REVIEW",
        "The selected indicator was tested using strict numeric conversion.",
        "LOW" if parse_failures == 0 else "MEDIUM",
    )
    if parse_failures:
        issues.append(_quality_issue(
            "MEDIUM",
            "Validity",
            "Non-numeric values in numeric indicator",
            indicator,
            parse_failures,
            pct(parse_failures, max(len(nonblank), 1)),
            "Non-numeric entries can be excluded from calculations or create inconsistent reporting.",
            "Standardize numeric values and investigate text labels such as N/A, unknown or suppressed values.",
        ))

    negative_count = int((valid_numeric < 0).sum())
    add_matrix(
        "Validity",
        "Negative indicator values",
        f"{negative_count:,}",
        "PASS" if negative_count == 0 else "FAIL",
        "Negative observations were checked for the selected indicator.",
        "LOW" if negative_count == 0 else "HIGH",
    )
    if negative_count:
        issues.append(_quality_issue(
            "HIGH",
            "Validity",
            "Negative indicator values",
            indicator,
            negative_count,
            pct(negative_count, max(len(valid_numeric), 1)),
            "Negative values are generally implausible for service counts and many health programme indicators.",
            "Validate against the indicator definition and source register; do not delete values without documented verification.",
        ))

    # ------------------------------------------------------------
    # 4. PLAUSIBILITY — indicator type, zeros and outliers
    # ------------------------------------------------------------
    name_lower = indicator.lower()
    percentage_like = any(
        token in name_lower
        for token in ["percent", "%", "percentage", "coverage", "rate", "proportion"]
    )

    if percentage_like:
        over_100 = int((valid_numeric > 100).sum())
        add_matrix(
            "Plausibility",
            "Percentage/rate > 100",
            f"{over_100:,}",
            "PASS" if over_100 == 0 else "FAIL",
            "The selected indicator appears to be a percentage/rate/coverage measure; values above 100 were checked.",
            "LOW" if over_100 == 0 else "HIGH",
        )
        if over_100:
            issues.append(_quality_issue(
                "HIGH",
                "Plausibility",
                "Percentage/rate above 100",
                indicator,
                over_100,
                pct(over_100, max(len(valid_numeric), 1)),
                "Values above 100 may indicate numerator/denominator, aggregation, definition or data-entry problems.",
                "Verify indicator definition, numerator, denominator, aggregation method and reporting grain.",
            ))
    else:
        add_matrix(
            "Plausibility",
            "Percentage/rate > 100",
            "Not applicable",
            "INFO",
            "The selected indicator was not identified as a percentage/rate/coverage field by its name.",
            "LOW",
        )

    zero_count = int((valid_numeric == 0).sum())
    zero_pct = pct(zero_count, max(len(valid_numeric), 1))
    zero_heavy = zero_pct >= 50 and len(valid_numeric) > 0
    add_matrix(
        "Plausibility",
        "Zero concentration",
        f"{zero_count:,} zero values",
        "REVIEW" if zero_heavy else "PASS",
        f"{zero_pct:.2f}% of observed values are zero.",
        "MEDIUM" if zero_heavy else "LOW",
    )
    if zero_heavy:
        issues.append(_quality_issue(
            "MEDIUM",
            "Plausibility",
            "High zero concentration",
            indicator,
            zero_count,
            zero_pct,
            "A high concentration of zeros may represent true zero service delivery or systematic non-reporting.",
            "Confirm the indicator definition and distinguish valid zero activity from blank/non-reporting records.",
        ))

    outlier_count = 0
    if len(valid_numeric) >= 5:
        q1 = valid_numeric.quantile(0.25)
        q3 = valid_numeric.quantile(0.75)
        iqr = q3 - q1
        if iqr != 0:
            low = q1 - 1.5 * iqr
            high = q3 + 1.5 * iqr
            outlier_count = int(((valid_numeric < low) | (valid_numeric > high)).sum())

    add_matrix(
        "Plausibility",
        "IQR outliers",
        f"{outlier_count:,}",
        "REVIEW" if outlier_count else "PASS",
        "Statistical outlier screening was applied where at least five observed numeric values were available.",
        "LOW" if not outlier_count else "LOW",
    )
    if outlier_count:
        issues.append(_quality_issue(
            "LOW",
            "Plausibility",
            "Statistical outlier (IQR)",
            indicator,
            outlier_count,
            pct(outlier_count, max(len(valid_numeric), 1)),
            "Outliers may indicate data-entry problems, unusual service activity or genuine programme events.",
            "Validate flagged values against source records and programme context before deciding whether they are erroneous.",
        ))

    # ------------------------------------------------------------
    # 5. TIMELINESS — only assess when a period/date exists
    # ------------------------------------------------------------
    if period_col:
        period_values = df[period_col].astype("string")
        parsed = pd.to_datetime(period_values, errors="coerce")

        if parsed.notna().sum() == 0:
            extracted = period_values.str.extract(r"(20\d{2})[\-/]?(\d{1,2})", expand=True)
            if not extracted.empty:
                years = pd.to_numeric(extracted[0], errors="coerce")
                months = pd.to_numeric(extracted[1], errors="coerce")
                parsed = pd.to_datetime(
                    dict(year=years, month=months.clip(1, 12), day=1),
                    errors="coerce",
                )

        if parsed.notna().any():
            future_count = int((parsed > pd.Timestamp.today()).sum())
            add_matrix(
                "Timeliness",
                "Future reporting periods",
                f"{future_count:,}",
                "PASS" if future_count == 0 else "FAIL",
                f"Indicator periods assessed using detected period column: {period_col}.",
                "LOW" if future_count == 0 else "HIGH",
            )
            if future_count:
                issues.append(_quality_issue(
                    "HIGH",
                    "Timeliness",
                    "Future reporting period",
                    f"{indicator} | {period_col}",
                    future_count,
                    pct(future_count),
                    "Future-dated observations can distort current reporting and trend interpretation.",
                    "Verify period selection, reporting calendar and extraction filters.",
                ))
        else:
            add_matrix(
                "Timeliness",
                "Period parseability",
                "Not determinable",
                "INFO",
                f"Period field {period_col} was detected but could not be parsed reliably.",
                "LOW",
            )
    else:
        add_matrix(
            "Timeliness",
            "Reporting period",
            "Not detected",
            "INFO",
            "No standard period/date field was detected for the selected indicator.",
            "LOW",
        )

    # ------------------------------------------------------------
    # 6. INTEGRITY — organisation unit availability
    # ------------------------------------------------------------
    if ou_col:
        ou_missing = int(df[ou_col].isna().sum() + df[ou_col].astype("string").str.strip().eq("").sum())
        # Avoid double counting rows that are both NA and empty.
        ou_missing = int((df[ou_col].isna() | df[ou_col].astype("string").str.strip().eq("")).sum())
        add_matrix(
            "Integrity",
            "Organisation unit field",
            f"{ou_missing:,} missing",
            "PASS" if ou_missing == 0 else "REVIEW",
            f"Organisation unit field detected as {ou_col}.",
            "LOW" if ou_missing == 0 else "MEDIUM",
        )
        if ou_missing:
            issues.append(_quality_issue(
                "MEDIUM",
                "Integrity",
                "Missing organisation unit",
                ou_col,
                ou_missing,
                pct(ou_missing),
                "Missing organisation units prevent reliable geographic attribution and comparison.",
                "Validate OU mapping and confirm that the extraction includes the intended reporting hierarchy.",
            ))
    else:
        add_matrix(
            "Integrity",
            "Organisation unit field",
            "Not detected",
            "REVIEW",
            "No standard organisation-unit field was detected for the selected indicator.",
            "MEDIUM",
        )
        issues.append(_quality_issue(
            "MEDIUM",
            "Integrity",
            "Organisation unit not available",
            indicator,
            0,
            0,
            "Without an organisation-unit field, OU-level completeness, duplication and comparison cannot be fully assessed.",
            "Include a DHIS2 organisation-unit identifier/name in the extraction when OU-level audit is required.",
        ))

    # ------------------------------------------------------------
    # 7. CONSISTENCY — explicit numerator/denominator fields
    # ------------------------------------------------------------
    numerator_cols = [
        c for c in df.columns
        if re.search(r"(^|[_\s-])num(erator)?($|[_\s-])", str(c), re.I)
    ]
    denominator_cols = [
        c for c in df.columns
        if re.search(r"(^|[_\s-])den(ominator)?($|[_\s-])", str(c), re.I)
    ]

    # Prefer pairs whose names share a meaningful base with the selected indicator.
    def _base_name(value):
        s = re.sub(r"[^a-z0-9]+", " ", str(value).lower())
        s = re.sub(r"\b(numerator|denominator|num|den)\b", " ", s)
        return " ".join(s.split())

    selected_base = _base_name(indicator)
    candidate_pairs = []
    for num_col in numerator_cols:
        for den_col in denominator_cols:
            score = 1 if selected_base and (
                selected_base in _base_name(num_col) or
                selected_base in _base_name(den_col)
            ) else 0
            candidate_pairs.append((score, num_col, den_col))

    candidate_pairs.sort(reverse=True, key=lambda x: x[0])
    pair = candidate_pairs[0][1:] if candidate_pairs else None

    if pair:
        num_col, den_col = pair
        num = pd.to_numeric(df[num_col], errors="coerce")
        den = pd.to_numeric(df[den_col], errors="coerce")
        invalid_den = int((den <= 0).sum())
        num_gt_den = int(
            ((num > den) & den.notna() & num.notna() & (den > 0)).sum()
        )
        total_consistency_issues = invalid_den + num_gt_den

        status = "PASS" if total_consistency_issues == 0 else "FAIL"
        priority = "LOW" if total_consistency_issues == 0 else "HIGH"
        add_matrix(
            "Consistency",
            "Numerator / denominator validation",
            f"{total_consistency_issues:,}",
            status,
            f"Pair assessed: {num_col} / {den_col}.",
            priority,
        )
        if invalid_den:
            issues.append(_quality_issue(
                "MEDIUM",
                "Consistency",
                "Non-positive denominator",
                den_col,
                invalid_den,
                pct(invalid_den),
                "A zero or negative denominator prevents a valid rate calculation.",
                "Validate denominator definition, reporting coverage and source values.",
            ))
        if num_gt_den:
            issues.append(_quality_issue(
                "HIGH",
                "Consistency",
                "Numerator greater than denominator",
                f"{num_col} / {den_col}",
                num_gt_den,
                pct(num_gt_den),
                "A numerator above its denominator produces an impossible rate above 100% for a conventional coverage ratio.",
                "Check indicator formula, aggregation and reporting grain.",
            ))
    else:
        add_matrix(
            "Consistency",
            "Numerator / denominator validation",
            "Not available",
            "INFO",
            "No explicit numerator/denominator pair relevant to the selected indicator was detected.",
            "LOW",
        )

    # ------------------------------------------------------------
    # Score: use the same priority-weighted philosophy as the
    # existing engine, but normalize to the selected indicator.
    # ------------------------------------------------------------
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    issues.sort(key=lambda x: (order.get(str(x.get("Priority", "")).upper(), 9), x.get("Domain", "")))

    weights = {"HIGH": 5, "MEDIUM": 2, "LOW": 0.5}
    penalty = sum(weights.get(str(i.get("Priority", "")).upper(), 0) for i in issues)

    # Indicator-level score is normalized against the number of controls,
    # not the width of the complete dataset.
    denominator = max(len(matrix) * 2, 1)
    score = max(0.0, min(100.0, 100 - (penalty / denominator * 100)))

    summary = {
        "score": round(score, 1),
        "rating": (
            "Excellent" if score >= 90
            else "Good" if score >= 75
            else "Needs review" if score >= 50
            else "Poor"
        ),
        "rows": n,
        "columns": 1,
        "issues": len(issues),
        "indicator": indicator,
        "matrix": matrix,
    }
    return issues, matrix, summary

def check_data_quality(df):
    """Backward-compatible wrapper used by the rest of the app."""
    issues, _, _ = build_quality_matrix(df)
    return issues



def build_local_quality_interpretation(quality_issues, quality_matrix, quality_summary):
    """Create an evidence-only audit interpretation when AI API is unavailable.

    This fallback never invents findings or changes deterministic results.
    It makes the dashboard useful even when OpenAI quota/rate limits are reached.
    """
    score = float((quality_summary or {}).get("score", 0))
    rating = str((quality_summary or {}).get("rating", "Unknown"))
    rows = int((quality_summary or {}).get("rows", 0))
    high = [i for i in (quality_issues or []) if str(i.get("Priority", "")).upper() == "HIGH"]
    medium = [i for i in (quality_issues or []) if str(i.get("Priority", "")).upper() == "MEDIUM"]

    if score >= 90:
        verdict = "The dataset demonstrates strong overall quality based on the implemented controls and is suitable for routine analysis."
    elif score >= 75:
        verdict = "The dataset is generally suitable for routine analysis, with targeted quality checks recommended for the findings listed below."
    elif score >= 50:
        verdict = "The dataset requires review before high-stakes reporting. Routine analysis may proceed only with appropriate caution and documented limitations."
    else:
        verdict = "The dataset requires remediation before it should be used for high-stakes reporting or management decisions."

    lines = [
        "## Overall Quality Verdict",
        f"**Quality score:** {score:.1f}/100  \n**Rating:** {rating}  \n**Records assessed:** {rows:,}",
        verdict,
        "",
        "## Quality Dimension Interpretation",
    ]

    for item in quality_matrix or []:
        domain = str(item.get("Domain", "Unknown"))
        metric = str(item.get("Metric", "Control"))
        result = str(item.get("Result", ""))
        status = str(item.get("Status", "INFO")).upper()
        priority = str(item.get("Priority", "LOW")).upper()
        detail = str(item.get("Details", "")).strip()
        if status == "PASS":
            interpretation = "No material issue was detected by this implemented control."
        elif status == "INFO":
            interpretation = "The control was informational or could not be fully assessed from the available fields; this is a limitation, not automatically a data-quality failure."
        elif status == "REVIEW":
            interpretation = "This result warrants targeted verification before relying on the affected data for important reporting."
        else:
            interpretation = "This result indicates a material quality exception that should be investigated before high-stakes use."
        lines.append(f"### {domain} — {metric}")
        lines.append(f"**Result:** {result} | **Status:** {status} | **Priority:** {priority}")
        if detail:
            lines.append(f"**Evidence:** {detail}")
        lines.append(interpretation)

    lines.append("")
    lines.append("## Priority Risks")
    if high or medium:
        for item in high + medium:
            issue = str(item.get("Issue", "Quality issue"))
            domain = str(item.get("Domain", ""))
            column = str(item.get("Column", ""))
            count = item.get("Count", 0)
            impact = str(item.get("Impact", "")).strip()
            where = f" — {column}" if column else ""
            lines.append(f"- **{item.get('Priority', 'MEDIUM')} | {domain}: {issue}{where}** — {count:,} affected observation(s). {impact}")
    else:
        lines.append("No HIGH or MEDIUM priority findings were identified by the implemented controls.")

    lines.extend([
        "",
        "## Audit Interpretation",
        "The interpretation below is limited to the evidence produced by the deterministic quality engine. Findings may affect reporting reliability, indicator calculations, trends, organisation-unit comparisons or management decisions only where the affected field/control is relevant to those outputs.",
        "",
        "## Recommended Data Quality Actions",
    ])

    actions = []
    for item in high + medium:
        rec = str(item.get("Recommendation", "")).strip()
        if rec and rec not in actions:
            actions.append(rec)
    if actions:
        for idx, action in enumerate(actions[:8], 1):
            lines.append(f"{idx}. {action}")
    else:
        lines.append("1. Retain the quality assessment as audit evidence and continue routine monitoring.")

    confidence = "High" if not high else "Medium"
    reason = (
        "The interpretation is based entirely on deterministic quality controls and supplied evidence."
        if not high else
        "The interpretation is evidence-based, but HIGH-priority findings require source-level verification."
    )
    lines.extend([
        "",
        "## Data Quality Confidence",
        f"**{confidence} confidence.** {reason}",
    ])
    return "\n\n".join(lines)



def ask_ai_quality_interpretation(df, quality_issues, quality_matrix, quality_summary):
    """Generate an AI interpretation of the deterministic DHIS2 quality matrix.

    Important design rule:
    - No row-level records are sent to the model.
    - The deterministic quality engine remains authoritative for counts/statuses.
    - AI explains the evidence, prioritises risks and proposes management actions.
    """
    if client is None:
        return {
            "status": "FALLBACK",
            "source": "LOCAL_RULES",
            "text": build_local_quality_interpretation(quality_issues, quality_matrix, quality_summary),
        }

    # Only quality evidence is sent to the model; never send the actual rows.
    compact_matrix = []
    for item in quality_matrix or []:
        compact_matrix.append({
            "domain": str(item.get("Domain", "")),
            "metric": str(item.get("Metric", "")),
            "result": str(item.get("Result", "")),
            "status": str(item.get("Status", "")),
            "priority": str(item.get("Priority", "")),
            "details": str(item.get("Details", "")),
        })

    compact_issues = []
    for item in (quality_issues or [])[:100]:
        compact_issues.append({
            "priority": str(item.get("Priority", "")),
            "domain": str(item.get("Domain", "")),
            "issue": str(item.get("Issue", "")),
            "column": str(item.get("Column", "")),
            "count": item.get("Count", 0),
            "percentage": item.get("Percentage", None),
            "impact": str(item.get("Impact", "")),
            "recommendation": str(item.get("Recommendation", "")),
        })

    evidence = {
        "dataset_rows": int(len(df)),
        "dataset_columns": int(len(df.columns)),
        "quality_summary": quality_summary or {},
        "quality_dimensions": compact_matrix,
        "priority_findings": compact_issues,
    }

    prompt = f"""
You are the DANIP-NI AI Data Quality Auditor.

Your task is to interpret a deterministic DHIS2 data-quality assessment for
data managers, MEL managers, data-quality auditors and programme leads.

IMPORTANT:
- The Python quality engine is authoritative for all counts, statuses and scores.
- Do not change, recalculate, cap or reinterpret the supplied numerical results.
- Do not invent findings.
- Do not claim causation.
- Do not silently treat zero as missing.
- Do not recommend deleting observations simply because they are outliers.
- Distinguish a data-quality problem from a legitimate programme result.
- Explain what the finding means operationally for DHIS2 reporting.
- Prioritise HIGH issues first, then MEDIUM, then LOW.
- If a dimension is PASS, explicitly say that no material issue was detected by
  the implemented control.
- If a dimension is INFO because a field/control could not be detected, explain
  the limitation rather than calling it a failure.
- Recommendations must be practical for data managers and auditors.
- Use only the evidence below.

DATA QUALITY EVIDENCE
{safe_json_dumps(evidence)}

Return a concise professional audit interpretation using exactly these sections:

## Overall Quality Verdict
State the quality score/rating and whether the dataset is suitable for
routine analysis, suitable with caution, or requires remediation before
high-stakes reporting. Base this only on the supplied evidence.

## Quality Dimension Interpretation
Interpret each quality domain present in the matrix:
Completeness, Uniqueness, Validity, Plausibility, Timeliness, Integrity,
Consistency, or any other supplied domain.

For each important non-PASS result explain:
1. what was detected,
2. why it matters,
3. what a data manager should verify.

## Priority Risks
List the most important HIGH and MEDIUM findings, ordered by urgency.
If none exist, state that clearly.

## Audit Interpretation
Explain the implications for:
- DHIS2 reporting reliability
- indicator calculations
- trend analysis
- organisation-unit comparisons
- management decisions

Only discuss implications supported by the evidence.

## Recommended Data Quality Actions
Give practical actions in priority order:
1. immediate remediation,
2. validation/reconciliation,
3. preventive controls,
4. audit documentation.

## Data Quality Confidence
Give High, Medium or Low confidence and one short reason.

Keep the answer professional, concise and useful to a data-quality auditor.
"""

    try:
        response = client.responses.create(
            model=OPENAI_MODEL,
            input=prompt,
        )
        return {
            "status": "SUCCESS",
            "text": response.output_text or "No AI interpretation was returned.",
        }
    except Exception as e:
        # Graceful degradation: quota/rate-limit/API errors must never break the
        # data-quality dashboard. Return an evidence-only interpretation instead.
        message = str(e).lower()
        quota_error = any(token in message for token in (
            "insufficient_quota", "exceeded your current quota", "429",
            "rate limit", "rate_limit", "quota"
        ))
        return {
            "status": "FALLBACK",
            "source": "LOCAL_RULES",
            "api_error": "quota" if quota_error else "unavailable",
            "text": build_local_quality_interpretation(quality_issues, quality_matrix, quality_summary),
        }


def render_ai_quality_interpretation(df, quality_issues, quality_matrix, quality_summary):
    """Render an optional AI interpretation without changing the existing matrix UI."""
    st.markdown("### 🤖 AI Quality Interpretation")
    st.caption(
        "AI interprets the deterministic DHIS2 Quality Dimensions. "
        "The underlying score, findings and statuses remain controlled by the quality engine."
    )

    score = float(quality_summary.get("score", 0))
    rating = str(quality_summary.get("rating", "Unknown"))
    high = sum(str(i.get("Priority", "")).upper() == "HIGH" for i in quality_issues)
    medium = sum(str(i.get("Priority", "")).upper() == "MEDIUM" for i in quality_issues)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("AI audit evidence", f"{len(quality_matrix):,} controls")
    with c2:
        st.metric("Priority risks", f"{high + medium:,}")
    with c3:
        st.metric("Quality rating", rating)

    if "dq_ai_interpretation" not in st.session_state:
        st.session_state["dq_ai_interpretation"] = None

    if st.button(
        "🤖 Generate AI Quality Interpretation",
        key="generate_dq_ai_interpretation",
        use_container_width=True,
    ):
        with st.spinner("🤖 AI is interpreting the DHIS2 quality evidence..."):
            st.session_state["dq_ai_interpretation"] = ask_ai_quality_interpretation(
                df=df,
                quality_issues=quality_issues,
                quality_matrix=quality_matrix,
                quality_summary=quality_summary,
            )

    result = st.session_state.get("dq_ai_interpretation")

    if result:
        if result.get("status") in ("SUCCESS", "FALLBACK"):
            body = result.get("text", "")
            source = result.get("source", "OPENAI")
            st.markdown(
                f"""
                <div class="dq-ai-quality-card">
                    <div class="dq-ai-quality-kicker">AI DATA QUALITY AUDITOR</div>
                    <div class="dq-ai-quality-title">
                        Quality interpretation for {len(df):,} loaded records
                    </div>
                    <div class="dq-ai-quality-body">
                        {body}
                    </div>
                    <div class="dq-ai-quality-meta">
                        <span class="dq-ai-quality-chip">Score: {score:.1f}/100</span>
                        <span class="dq-ai-quality-chip">Rating: {html.escape(rating)}</span>
                        <span class="dq-ai-quality-chip">Controls: {len(quality_matrix):,}</span>
                        <span class="dq-ai-quality-chip">High: {high:,}</span>
                        <span class="dq-ai-quality-chip">Medium: {medium:,}</span>
                        <span class="dq-ai-quality-chip">Source: {html.escape('AI' if source == 'OPENAI' else 'Evidence-only fallback')}</span>
                    </div>
                    <div class="dq-ai-quality-disclaimer">
                        Numerical results, control statuses and quality findings
                        remain based on the deterministic Python quality engine.
                        {'The AI service was unavailable for this run, so the dashboard generated an evidence-only audit interpretation from the same verified controls. No quality calculation was changed.' if source != 'OPENAI' else 'AI provides interpretation and prioritisation only.'}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.warning(result.get("text", "AI quality interpretation is unavailable."))



def render_quality_dashboard(
    df,
    quality_issues,
    quality_matrix,
    quality_summary,
    selected_indicators=None,
):
    """
    Manager/auditor-focused DHIS2 quality control register.

    UI is intentionally unchanged. When the user has confirmed one or more
    indicators, the same register is rendered separately for each selected
    indicator using an indicator-level DHIS2-oriented assessment. When no
    indicator is selected, the existing complete-dataset assessment is shown.
    """
    st.subheader("📐 DHIS2 Quality Dimensions")

    selected_indicators = [
        str(c) for c in (selected_indicators or [])
        if str(c) in df.columns
    ]

    # ------------------------------------------------------------
    # Build indicator-specific assessments only after user selection.
    # ------------------------------------------------------------
    indicator_assessments = []
    if selected_indicators:
        for indicator in selected_indicators:
            ind_issues, ind_matrix, ind_summary = build_indicator_quality_matrix(
                df, indicator
            )
            indicator_assessments.append(
                {
                    "indicator": indicator,
                    "issues": ind_issues,
                    "matrix": ind_matrix,
                    "summary": ind_summary,
                }
            )

        # Combined evidence is used for the existing summary cards and
        # optional AI interpretation, without changing their interface.
        combined_issues = []
        combined_matrix = []
        scores = []

        for assessment in indicator_assessments:
            indicator = assessment["indicator"]
            scores.append(float(assessment["summary"].get("score", 0)))

            for item in assessment["issues"]:
                item_copy = dict(item)
                item_copy["Column"] = (
                    f"{indicator} | {item_copy.get('Column', '')}"
                    if item_copy.get("Column")
                    else indicator
                )
                combined_issues.append(item_copy)

            for item in assessment["matrix"]:
                item_copy = dict(item)
                # Keep the existing table columns unchanged. The indicator
                # context is placed in the audit-detail text rather than
                # introducing a new visible column.
                detail = str(item_copy.get("Details", ""))
                item_copy["Details"] = (
                    f"Indicator: {indicator}. {detail}"
                )
                combined_matrix.append(item_copy)

        combined_score = round(float(np.mean(scores)), 1) if scores else 0.0
        combined_rating = (
            "Excellent" if combined_score >= 90
            else "Good" if combined_score >= 75
            else "Needs review" if combined_score >= 50
            else "Poor"
        )

        quality_issues_for_dashboard = combined_issues
        quality_matrix_for_dashboard = combined_matrix
        quality_summary_for_dashboard = {
            "score": combined_score,
            "rating": combined_rating,
            "rows": len(df),
            "columns": len(selected_indicators),
            "issues": len(combined_issues),
            "matrix": combined_matrix,
            "selected_indicators": selected_indicators,
        }
    else:
        indicator_assessments = []
        quality_issues_for_dashboard = quality_issues
        quality_matrix_for_dashboard = quality_matrix
        quality_summary_for_dashboard = quality_summary

    score = float(quality_summary_for_dashboard.get("score", 0))
    rating = str(quality_summary_for_dashboard.get("rating", "Unknown"))
    high_count = sum(
        str(i.get("Priority", "")).upper() == "HIGH"
        for i in quality_issues_for_dashboard
    )
    medium_count = sum(
        str(i.get("Priority", "")).upper() == "MEDIUM"
        for i in quality_issues_for_dashboard
    )
    low_count = sum(
        str(i.get("Priority", "")).upper() == "LOW"
        for i in quality_issues_for_dashboard
    )
    matrix_df = pd.DataFrame(quality_matrix_for_dashboard)

    rating_class = (
        "dq-score-excellent" if score >= 90 else
        "dq-score-good" if score >= 75 else
        "dq-score-review" if score >= 50 else "dq-score-poor"
    )

    st.markdown(
        f"""
        <div class="dq-audit-summary">
            <div class="dq-summary-card {rating_class}">
                <div class="dq-summary-label">Quality score</div>
                <div class="dq-summary-value">{score:.1f}/100</div>
            </div>
            <div class="dq-summary-card">
                <div class="dq-summary-label">Overall rating</div>
                <div class="dq-summary-value">{html.escape(rating)}</div>
            </div>
            <div class="dq-summary-card">
                <div class="dq-summary-label">Control findings</div>
                <div class="dq-summary-value">{len(quality_issues_for_dashboard):,}</div>
            </div>
            <div class="dq-summary-card">
                <div class="dq-summary-label">High priority</div>
                <div class="dq-summary-value">{high_count:,}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    scope_text = (
        f"selected indicator(s): <strong>{html.escape(', '.join(selected_indicators))}</strong>"
        if selected_indicators
        else f"<strong>{len(df):,}</strong> loaded records across <strong>{len(df.columns):,}</strong> fields"
    )

    st.markdown(
        f"""
        <div class="dq-audit-note">
            <strong>Audit view:</strong> This register evaluates {scope_text}.
            <strong>FAIL</strong> findings require remediation,
            <strong>REVIEW</strong> findings require validation,
            and <strong>INFO</strong> findings document control limitations.
            Source values are not silently deleted or corrected.
        </div>
        """,
        unsafe_allow_html=True,
    )

    def status_badge(status):
        value = str(status or "INFO").upper()
        cls = {
            "PASS": "dq-badge-pass",
            "REVIEW": "dq-badge-review",
            "FAIL": "dq-badge-fail",
            "INFO": "dq-badge-info",
        }.get(value, "dq-badge-info")
        return f'<span class="dq-badge {cls}">{html.escape(value)}</span>'

    def priority_badge(priority):
        value = str(priority or "LOW").upper()
        cls = {
            "HIGH": "dq-priority-high",
            "MEDIUM": "dq-priority-medium",
            "LOW": "dq-priority-low",
        }.get(value, "dq-priority-low")
        return f'<span class="dq-badge {cls}">{html.escape(value)}</span>'

    def audit_action(row):
        status = str(row.get("Status", "")).upper()
        metric = str(row.get("Metric", "")).lower()

        if status == "FAIL":
            return "Remediate and re-run the control before reporting."
        if status == "REVIEW":
            if "missing" in metric or "completeness" in metric:
                return "Validate source completeness and mandatory fields."
            if "duplicate" in metric:
                return "Investigate reporting grain and duplicate submissions."
            if "outlier" in metric:
                return "Validate against source records and programme context."
            if "zero" in metric:
                return "Confirm zero is valid and not non-reporting."
            return "Investigate evidence and document the management decision."
        if status == "INFO":
            return "Document limitation and confirm whether additional fields are required."
        return "No corrective action required; retain as audit evidence."

    # ------------------------------------------------------------
    # SAME REGISTER UI — rendered once per selected indicator.
    # ------------------------------------------------------------
    if indicator_assessments:
        st.markdown(
            "### 📐 DHIS2 Quality Dimensions"
        )
        st.caption(
            "Indicator-level assessment aligned with DHIS2 data-quality practice: "
            "data-element completeness, correctness/validity, consistency, timeliness, "
            "plausibility and organisation-unit integrity."
        )

        for assessment in indicator_assessments:
            indicator = assessment["indicator"]
            matrix_df = pd.DataFrame(assessment["matrix"])

            if matrix_df.empty:
                continue

            rows = []
            for _, row in matrix_df.iterrows():
                rows.append(
                    f"""
                    <tr>
                        <td class="dq-domain">{html.escape(str(row.get("Domain", "")))}</td>
                        <td class="dq-metric">{html.escape(str(row.get("Metric", "")))}</td>
                        <td class="dq-result">{html.escape(str(row.get("Result", "")))}</td>
                        <td>{status_badge(row.get("Status", ""))}</td>
                        <td>{priority_badge(row.get("Priority", ""))}</td>
                        <td>{html.escape(str(row.get("Details", "")))}</td>
                        <td class="dq-action">{html.escape(audit_action(row))}</td>
                    </tr>
                    """
                )

            quality_register_html = f"""
            <div class="dq-audit-shell">
                <div class="dq-audit-toolbar">
                    <div class="dq-audit-title">DHIS2 Quality Control Register</div>
                    <div class="dq-audit-subtitle">
                        Indicator: <strong>{html.escape(indicator)}</strong>
                        · Indicator-level assessment for the selected user analysis.
                    </div>
                </div>
                <div class="dq-table-wrap">
                    <table class="dq-table">
                        <thead>
                            <tr>
                                <th>Quality domain</th>
                                <th>Control / metric</th>
                                <th>Result</th>
                                <th>Status</th>
                                <th>Priority</th>
                                <th>Audit evidence / details</th>
                                <th>Management action</th>
                            </tr>
                        </thead>
                        <tbody>{''.join(rows)}</tbody>
                    </table>
                </div>
            </div>
            """
            st.html(textwrap.dedent(quality_register_html))

            ind_issues = assessment["issues"]
            ind_summary = assessment["summary"]

            if ind_issues:
                detail_rows = []
                for row in ind_issues:
                    priority = str(row.get("Priority", "LOW")).upper()
                    percentage = row.get("Percentage", "")
                    if percentage != "":
                        try:
                            percentage = f"{float(percentage):.2f}%"
                        except Exception:
                            percentage = str(percentage)

                    detail_rows.append(
                        f"""
                        <tr>
                            <td>{priority_badge(priority)}</td>
                            <td class="dq-domain">{html.escape(str(row.get("Domain", "")))}</td>
                            <td class="dq-metric">{html.escape(str(row.get("Issue", "")))}</td>
                            <td>{html.escape(str(row.get("Column", indicator)))}</td>
                            <td class="dq-result">{html.escape(str(row.get("Count", "")))}</td>
                            <td>{html.escape(str(percentage))}</td>
                            <td>{html.escape(str(row.get("Impact", "")))}</td>
                            <td class="dq-action">{html.escape(str(row.get("Recommendation", "")))}</td>
                        </tr>
                        """
                    )

                issue_register_html = f"""
                <div class="dq-audit-shell">
                    <div class="dq-audit-toolbar">
                        <div class="dq-audit-title">Data Quality Issue Register</div>
                        <div class="dq-audit-subtitle">
                            Indicator: <strong>{html.escape(indicator)}</strong>
                            · Findings are prioritised for investigation, remediation and audit follow-up.
                        </div>
                    </div>
                    <div class="dq-table-wrap">
                        <table class="dq-table dq-detail-table">
                            <thead>
                                <tr>
                                    <th>Priority</th>
                                    <th>Domain</th>
                                    <th>Issue</th>
                                    <th>Field / column</th>
                                    <th>Count</th>
                                    <th>%</th>
                                    <th>Impact</th>
                                    <th>Recommended action</th>
                                </tr>
                            </thead>
                            <tbody>{''.join(detail_rows)}</tbody>
                        </table>
                    </div>
                </div>
                """
                st.html(textwrap.dedent(issue_register_html))

                if any(
                    str(i.get("Priority", "")).upper() == "HIGH"
                    for i in ind_issues
                ):
                    st.error(
                        f"High-priority quality issues were identified for {indicator}. "
                        "Review and resolve these findings before using the indicator "
                        "for high-stakes management decisions or formal reporting."
                    )
            else:
                st.success(
                    f"All implemented indicator-level DHIS2 quality checks passed for {indicator}."
                )

    elif not matrix_df.empty:
        # --------------------------------------------------------
        # Existing complete-dataset register — unchanged behavior.
        # --------------------------------------------------------
        st.markdown("### 📐 DHIS2 Quality Dimensions")
        st.caption(
            "Advanced quality-control register designed for data managers, MEL teams and data-quality auditors."
        )

        rows = []
        for _, row in matrix_df.iterrows():
            rows.append(
                f"""
                <tr>
                    <td class="dq-domain">{html.escape(str(row.get("Domain", "")))}</td>
                    <td class="dq-metric">{html.escape(str(row.get("Metric", "")))}</td>
                    <td class="dq-result">{html.escape(str(row.get("Result", "")))}</td>
                    <td>{status_badge(row.get("Status", ""))}</td>
                    <td>{priority_badge(row.get("Priority", ""))}</td>
                    <td>{html.escape(str(row.get("Details", "")))}</td>
                    <td class="dq-action">{html.escape(audit_action(row))}</td>
                </tr>
                """
            )

        quality_register_html = f"""
        <div class="dq-audit-shell">
            <div class="dq-audit-toolbar">
                <div class="dq-audit-title">DHIS2 Quality Control Register</div>
                <div class="dq-audit-subtitle">
                    Evidence-based assessment of completeness, uniqueness, validity,
                    plausibility, timeliness, integrity and consistency.
                </div>
            </div>
            <div class="dq-table-wrap">
                <table class="dq-table">
                    <thead>
                        <tr>
                            <th>Quality domain</th>
                            <th>Control / metric</th>
                            <th>Result</th>
                            <th>Status</th>
                            <th>Priority</th>
                            <th>Audit evidence / details</th>
                            <th>Management action</th>
                        </tr>
                    </thead>
                    <tbody>{''.join(rows)}</tbody>
                </table>
            </div>
        </div>
        """
        st.html(textwrap.dedent(quality_register_html))

    # ------------------------------------------------------------
    # Detailed findings for the displayed scope.
    # ------------------------------------------------------------
    if quality_issues_for_dashboard and not indicator_assessments:
        st.markdown("### 🔍 Detailed Quality Findings")
        st.caption(
            "Prioritised issue register for investigation, remediation and audit follow-up."
        )
        issues_df = pd.DataFrame(quality_issues_for_dashboard).copy()
        detail_rows = []

        for _, row in issues_df.iterrows():
            priority = str(row.get("Priority", "LOW")).upper()
            percentage = row.get("Percentage", "")
            if percentage != "":
                try:
                    percentage = f"{float(percentage):.2f}%"
                except Exception:
                    percentage = str(percentage)

            detail_rows.append(
                f"""
                <tr>
                    <td>{priority_badge(priority)}</td>
                    <td class="dq-domain">{html.escape(str(row.get("Domain", "")))}</td>
                    <td class="dq-metric">{html.escape(str(row.get("Issue", "")))}</td>
                    <td>{html.escape(str(row.get("Column", "")))}</td>
                    <td class="dq-result">{html.escape(str(row.get("Count", "")))}</td>
                    <td>{html.escape(str(percentage))}</td>
                    <td>{html.escape(str(row.get("Impact", "")))}</td>
                    <td class="dq-action">{html.escape(str(row.get("Recommendation", "")))}</td>
                </tr>
                """
            )

        issue_register_html = f"""
        <div class="dq-audit-shell">
            <div class="dq-audit-toolbar">
                <div class="dq-audit-title">Data Quality Issue Register</div>
                <div class="dq-audit-subtitle">
                    Findings are prioritised for investigation, remediation and audit follow-up.
                </div>
            </div>
            <div class="dq-table-wrap">
                <table class="dq-table dq-detail-table">
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Domain</th>
                            <th>Issue</th>
                            <th>Field / column</th>
                            <th>Count</th>
                            <th>%</th>
                            <th>Impact</th>
                            <th>Recommended action</th>
                        </tr>
                    </thead>
                    <tbody>{''.join(detail_rows)}</tbody>
                </table>
            </div>
        </div>
        """
        st.html(textwrap.dedent(issue_register_html))

        if high_count:
            st.error(
                "High-priority quality issues may materially affect the requested analysis. "
                "Review and resolve these findings before using results for management decisions or formal reporting."
            )
    elif not indicator_assessments and not quality_issues_for_dashboard:
        st.success(
            "All implemented DHIS2 quality checks passed for the returned dataset."
        )

    with st.expander("📚 Quality methodology", expanded=False):
        st.markdown("""
        **DHIS2 alignment** — The assessment follows the DHIS2 data-quality approach by
        considering completeness, correctness/validity, consistency and timeliness, with
        additional integrity and plausibility controls useful for routine audit.

        **Completeness** — selected data-element missingness; this does not replace
        DHIS2 reporting-rate completeness when expected reports are available.

        **Uniqueness** — organisation-unit/period reporting grain where those fields exist.

        **Validity / correctness** — numeric parsing and negative-value checks.

        **Consistency** — numerator/denominator validation when explicit related fields
        can be identified.

        **Timeliness** — future reporting periods and period parseability.

        **Integrity** — organisation-unit availability for geographic attribution.

        **Plausibility** — percentage/rate limits, zero concentration and statistical
        outlier screening.

        **Important:** outliers and zeros are flagged for review; they are not
        automatically deleted or converted to missing values.
        """)

    # Existing AI quality interpretation UI remains unchanged. It receives the
    # selected-indicator evidence when a user has selected indicators.
    render_ai_quality_interpretation(
        df=df,
        quality_issues=quality_issues_for_dashboard,
        quality_matrix=quality_matrix_for_dashboard,
        quality_summary=quality_summary_for_dashboard,
    )

# ============================================================
# GUIDED ANALYSIS CONFIGURATION
# ============================================================
# AI ANALYSIS PLANNER
# ============================================================
# AGGREGATION
# ============================================================

def aggregate_series(series, aggregation):
    """Apply the user's selected aggregation deterministically."""
    aggregation = str(aggregation or "sum").strip().lower()

    if aggregation in {"mean", "average"}:
        return series.mean()

    if aggregation == "median":
        return series.median()

    if aggregation in {"min", "minimum"}:
        return series.min()

    if aggregation in {"max", "maximum"}:
        return series.max()

    if aggregation == "count":
        return series.count()

    return series.sum()


def resolve_analysis_aggregation(analysis_type, selected_aggregation):
    """Return ONLY the aggregation selected by the user.

    Analysis Type and Aggregation are independent controls.  The selected
    aggregation is the mathematical operation used inside every X-axis group.
    """
    value = str(selected_aggregation or "sum").strip().lower()

    aliases = {
        "sum": "sum",
        "total": "sum",
        "average": "mean",
        "avg": "mean",
        "mean": "mean",
        "median": "median",
        "minimum": "min",
        "minimum value": "min",
        "min": "min",
        "maximum": "max",
        "maximum value": "max",
        "max": "max",
        "count": "count",
        "number of records": "count",
    }

    return aliases.get(value, "sum")


def aggregation_display_name(aggregation):
    """Return a clear user-facing name for the actual aggregation."""
    names = {
        "sum": "Sum",
        "mean": "Average",
        "median": "Median",
        "min": "Minimum",
        "max": "Maximum",
        "count": "Count",
    }
    return names.get(str(aggregation).strip().lower(), str(aggregation).title())


def aggregation_group_diagnostic(df, x_column, y_columns, aggregation):
    """
    Explain when different aggregation choices legitimately produce the same
    result because every X-axis category contains only one valid observation.

    This is especially important for DHIS2 extracts where the selected
    indicator may already be at the reporting grain (for example, one value
    per period). In that situation Sum == Average == Median == Minimum ==
    Maximum, while Count == 1.
    """
    if not x_column or x_column not in df.columns or not y_columns:
        return None

    try:
        observations = []
        for y in y_columns:
            if y not in df.columns:
                continue

            temp = pd.DataFrame({
                "__x__": df[x_column],
                "__value__": pd.to_numeric(df[y], errors="coerce"),
            }).dropna(subset=["__x__", "__value__"])

            if temp.empty:
                continue

            group_sizes = temp.groupby("__x__", dropna=False)["__value__"].count()

            if not group_sizes.empty:
                observations.append({
                    "indicator": y,
                    "groups": int(group_sizes.size),
                    "max_observations_per_group": int(group_sizes.max()),
                    "repeated_groups": int((group_sizes > 1).sum()),
                })

        if not observations:
            return None

        # Only show the diagnostic when all selected indicators have at most
        # one valid observation in every X-axis category.
        if all(x["max_observations_per_group"] <= 1 for x in observations):
            return (
                "Aggregation note: each selected X-axis category has only "
                "one valid observation. Therefore Sum, Average, Median, "
                "Minimum and Maximum are mathematically identical for this "
                "view; Count will return 1 per category. To see differences "
                "between aggregations, use an X-axis with repeated records "
                "(for example Organisation Unit when multiple periods exist)."
            )

    except Exception:
        return None

    return None


def apply_analysis_operation(result_df, analysis_type, x_column, value_column="value"):
    """
    Apply analysis-type operations AFTER the selected aggregation.

    Aggregation determines the value represented by each X-axis group.
    Analysis Type adds a secondary analytical operation without replacing
    the user's aggregation.
    """
    analysis = str(analysis_type or "statistical").strip().lower()

    if result_df is None or result_df.empty or value_column not in result_df.columns:
        return result_df

    result_df = result_df.copy()
    result_df[value_column] = pd.to_numeric(
        result_df[value_column],
        errors="coerce",
    )

    if analysis == "percentage":
        total = result_df[value_column].sum(skipna=True)
        if total != 0 and pd.notna(total):
            result_df[value_column] = (
                result_df[value_column] / total * 100.0
            )
        else:
            result_df[value_column] = 0.0
        return result_df

    if analysis in {"difference", "change"} and x_column and len(result_df) >= 2:
        valid = result_df.dropna(subset=[value_column]).copy()

        if len(valid) >= 2:
            first = float(valid[value_column].iloc[0])
            last = float(valid[value_column].iloc[-1])

            if analysis == "change":
                change_value = last - first
            else:
                change_value = float(
                    valid[value_column].max()
                    - valid[value_column].min()
                )

            result_df["analysis_result"] = change_value

    if analysis == "ranking" and value_column in result_df.columns:
        # Ranking is applied to the already aggregated values.
        result_df = result_df.sort_values(
            value_column,
            ascending=False,
            kind="stable",
        ).reset_index(drop=True)

    return result_df


# ============================================================
# APPLY FILTERS
# ============================================================

def apply_plan_filters(
    work,
    filters,
):
    applied = []

    for filter_item in filters or []:

        if not isinstance(
            filter_item,
            dict,
        ):
            continue

        column = filter_item.get(
            "column"
        )

        operator = filter_item.get(
            "operator",
            "equals",
        )

        value = filter_item.get(
            "value"
        )

        if column not in work.columns:
            continue

        before = len(work)

        series = work[column]

        if operator == "equals":

            work = work[
                series.astype(str)
                .str.lower()
                ==
                str(value).lower()
            ]

        elif operator == "not_equals":

            work = work[
                series.astype(str)
                .str.lower()
                !=
                str(value).lower()
            ]

        elif operator == "contains":

            work = work[
                series.astype(str)
                .str.contains(
                    str(value),
                    case=False,
                    na=False,
                )
            ]

        elif operator == "starts_with":

            work = work[
                series.astype(str)
                .str.lower()
                .str.startswith(
                    str(value).lower()
                )
            ]

        elif operator == "ends_with":

            work = work[
                series.astype(str)
                .str.lower()
                .str.endswith(
                    str(value).lower()
                )
            ]

        else:
            continue

        applied.append({
            "column": column,
            "operator": operator,
            "value": value,
            "rows_before": int(before),
            "rows_after": int(len(work)),
        })

    return work, applied


# ============================================================
# REQUEST-SPECIFIC CALCULATION ENGINE
# ============================================================


def build_multi_indicator_comparison_evidence(df, chart_plan):
    """
    Build an explicit comparison matrix for multiple indicators.

    This is supplementary evidence for the AI narrative. It never replaces
    the main requested-analysis calculation.
    """
    indicators = [
        c for c in (chart_plan.get("y_columns") or [])
        if c in df.columns
    ]
    x_column = chart_plan.get("x_column")

    if len(indicators) < 2:
        return {
            "comparison_mode": False,
            "message": "Fewer than two indicators were selected."
        }

    work = df.copy()

    for col in indicators:
        work[col] = pd.to_numeric(work[col], errors="coerce")

    group_cols = [x_column] if x_column and x_column in work.columns else []

    if group_cols:
        grouped = (
            work.groupby(group_cols, dropna=False)[indicators]
            .agg(chart_plan.get("aggregation", "sum"))
            .reset_index()
        )
    else:
        grouped = pd.DataFrame(
            [work[indicators].agg(chart_plan.get("aggregation", "sum"))]
        )

    summary = {}
    for indicator in indicators:
        values = pd.to_numeric(grouped[indicator], errors="coerce").dropna()
        if values.empty:
            summary[indicator] = {
                "value_count": 0,
                "mean": None,
                "min": None,
                "max": None,
                "total": None,
            }
        else:
            summary[indicator] = {
                "value_count": int(values.count()),
                "mean": float(values.mean()),
                "min": float(values.min()),
                "max": float(values.max()),
                "total": float(values.sum()),
            }

    return {
        "comparison_mode": True,
        "x_column": x_column,
        "indicators": indicators,
        "aggregation": chart_plan.get("aggregation", "sum"),
        "rows_compared": int(len(grouped)),
        "indicator_summary": summary,
        "comparison_data": grouped.head(500).to_dict(orient="records"),
    }


def build_requested_analysis_evidence(
    df,
    user_question,
    chart_plan,
):
    """
    THIS IS THE CORE FIX.

    Python executes the requested analysis against ALL rows.
    GPT does not have to guess or calculate from a sample.
    """

    evidence = {
        "status": "SUCCESS",
        "user_request": user_question,
        "analysis_population": "ALL_ROWS",
        "source_rows": int(len(df)),
        "columns_used": [],
        "filters_applied": [],
        "result": {},
    }

    if not chart_plan:
        return {
            "status": "NO_ANALYSIS_PLAN",
            "message": "No analysis plan was produced.",
        }

    try:
        work = df.copy()

        x_column = chart_plan.get(
            "x_column"
        )

        y_columns = list(
            chart_plan.get(
                "y_columns",
                [],
            )
        )

        indicator_columns = list(
            chart_plan.get(
                "indicator_columns",
                [],
            )
        )

        # Combine indicator and Y fields
        requested_numeric = []

        for col in (
            indicator_columns
            + y_columns
        ):
            if (
                col in work.columns
                and col not in requested_numeric
            ):
                requested_numeric.append(col)

        group_column = chart_plan.get(
            "group_column"
        )

        dimension_column = chart_plan.get(
            "dimension_column"
        )

        if (
            not x_column
            and dimension_column
            and dimension_column in work.columns
        ):
            x_column = dimension_column

        selected_aggregation = chart_plan.get(
            "aggregation",
            "sum",
        )

        analysis_type = chart_plan.get(
            "analysis_type",
            "custom",
        )

        # IMPORTANT: Total and Average have explicit mathematical meaning.
        # All other analysis types continue to respect the Aggregation control.
        aggregation = resolve_analysis_aggregation(
            analysis_type,
            selected_aggregation,
        )

        ranking_limit = chart_plan.get(
            "ranking_limit"
        )

        # ----------------------------------------------------
        # Validate requested fields
        # ----------------------------------------------------

        missing_columns = []

        for col in (
            [x_column, group_column]
            + requested_numeric
        ):
            if (
                col
                and col not in work.columns
            ):
                missing_columns.append(col)

        if missing_columns:
            return {
                "status": "ERROR",
                "error": (
                    "Requested columns do not exist: "
                    + ", ".join(
                        map(
                            str,
                            missing_columns,
                        )
                    )
                ),
            }

        evidence["columns_used"] = [
            c
            for c in (
                [x_column, group_column]
                + requested_numeric
            )
            if c
        ]

        # ----------------------------------------------------
        # Convert numeric fields
        # ----------------------------------------------------

        for column in requested_numeric:
            work[column] = pd.to_numeric(
                work[column],
                errors="coerce",
            )

        # ----------------------------------------------------
        # Filters
        # ----------------------------------------------------

        work, applied_filters = apply_plan_filters(
            work,
            chart_plan.get(
                "filters",
                [],
            ),
        )

        evidence["filters_applied"] = applied_filters

        # ----------------------------------------------------
        # DEFAULT STATISTICAL ANALYSIS
        # ----------------------------------------------------
        if analysis_type == "statistical":
            statistical_summary = {}
            for column in requested_numeric:
                values = work[column].dropna()
                if values.empty:
                    continue

                q1 = values.quantile(0.25)
                q3 = values.quantile(0.75)
                iqr = q3 - q1
                outlier_count = 0 if iqr == 0 else int(
                    ((values < q1 - 1.5 * iqr) | (values > q3 + 1.5 * iqr)).sum()
                )
                mean_value = values.mean()
                std_value = values.std()

                statistical_summary[column] = {
                    "count": int(values.count()),
                    "missing": int(work[column].isna().sum()),
                    "sum": float(values.sum()),
                    "mean": float(mean_value),
                    "median": float(values.median()),
                    "minimum": float(values.min()),
                    "maximum": float(values.max()),
                    "range": float(values.max() - values.min()),
                    "standard_deviation": float(std_value) if pd.notna(std_value) else None,
                    "variance": float(values.var()) if pd.notna(values.var()) else None,
                    "Q1": float(q1),
                    "Q3": float(q3),
                    "IQR": float(iqr),
                    "zero_count": int((values == 0).sum()),
                    "negative_count": int((values < 0).sum()),
                    "outlier_count": outlier_count,
                }

            evidence["result"] = {
                "analysis_type": "statistical",
                "rows_after_filters": int(len(work)),
                "data": statistical_summary,
            }
            return evidence

        # ----------------------------------------------------
        # Remove missing X
        # ----------------------------------------------------

        if x_column:
            work = work.dropna(
                subset=[x_column]
            )

        # ----------------------------------------------------
        # No explicit numeric field
        # ----------------------------------------------------

        if not requested_numeric:

            evidence["result"] = {
                "rows_after_filters": int(len(work)),
                "analysis_type": analysis_type,
                "message": (
                    "The request did not resolve to a "
                    "numeric indicator. The AI should interpret "
                    "the available dimensions and explain "
                    "any missing requested measure."
                ),
            }

            return evidence

        # ----------------------------------------------------
        # Determine grouping
        # ----------------------------------------------------

        group_columns = []

        if x_column:
            group_columns.append(
                x_column
            )

        if (
            group_column
            and group_column not in group_columns
        ):
            group_columns.append(
                group_column
            )

        # If no grouping but user asks for total/average
        if not group_columns:

            overall = []

            for y in requested_numeric:

                valid = work[y].dropna()

                if valid.empty:
                    value = None
                else:
                    value = aggregate_series(
                        valid,
                        aggregation,
                    )

                overall.append({
                    "indicator": y,
                    "value": _safe_json_value(
                        value
                    ),
                    "valid_observations": int(
                        valid.notna().sum()
                    ),
                })

            evidence["result"] = {
                "analysis_type": analysis_type,
                "aggregation": aggregation,
                "rows_after_filters": int(len(work)),
                "data": overall,
            }

            return evidence

        # ----------------------------------------------------
        # Grouped calculation
        # ----------------------------------------------------

        result_frames = []

        for y in requested_numeric:

            temp = work[
                group_columns + [y]
            ].copy()

            # Missing numeric values are NOT zero.
            temp = temp.dropna(
                subset=[y]
            )

            if temp.empty:
                continue

            grouped = (
                temp
                .groupby(
                    group_columns,
                    dropna=False,
                )[y]
                .agg(
                    aggregation
                )
                .reset_index()
            )

            grouped["indicator"] = y
            grouped["value"] = grouped[y]

            grouped["valid_observations"] = (
                temp
                .groupby(
                    group_columns,
                    dropna=False,
                )[y]
                .count()
                .values
            )

            result_frames.append(
                grouped[
                    group_columns
                    + [
                        "indicator",
                        "value",
                        "valid_observations",
                    ]
                ]
            )

        if not result_frames:

            return {
                "status": "NO_DATA",
                "error": (
                    "No valid observations were available "
                    "for the requested calculation."
                ),
            }

        result_df = pd.concat(
            result_frames,
            ignore_index=True,
        )

        # Apply the selected analysis operation after aggregation.
        result_df = apply_analysis_operation(
            result_df,
            analysis_type,
            x_column,
            value_column="value",
        )

        # ----------------------------------------------------
        # Ranking
        # ----------------------------------------------------

        if (
            analysis_type == "ranking"
            and ranking_limit
            and "value" in result_df.columns
        ):
            result_df = (
                result_df
                .sort_values(
                    "value",
                    ascending=False,
                )
                .head(
                    int(ranking_limit)
                )
            )

        # ----------------------------------------------------
        # Change / difference when two groups exist
        # ----------------------------------------------------

        comparison_summary = None

        if (
            analysis_type
            in {
                "comparison",
                "difference",
                "change",
            }
            and x_column
            and len(requested_numeric) == 1
        ):
            y = requested_numeric[0]

            values = result_df[
                [x_column, "value"]
            ].dropna()

            if len(values) >= 2:
                comparison_summary = {
                    "lowest": safe_json_dumps(
                        values.loc[
                            values["value"].idxmin()
                        ].to_dict()
                    ),
                    "highest": safe_json_dumps(
                        values.loc[
                            values["value"].idxmax()
                        ].to_dict()
                    ),
                }

        # ----------------------------------------------------
        # Exact evidence
        # ----------------------------------------------------

        clean_records = []

        for record in result_df.to_dict(
            orient="records"
        ):
            clean_records.append({
                str(k): _safe_json_value(v)
                for k, v in record.items()
            })

        evidence["result"] = {
            "analysis_type": analysis_type,
            "aggregation": aggregation,
            "rows_after_filters": int(len(work)),
            "rows_used_in_calculation": int(
                len(result_df)
            ),
            "grouping": group_columns,
            "data": clean_records,
            "comparison_summary": comparison_summary,
        }

        return evidence

    except Exception as e:
        return {
            "status": "ERROR",
            "error": str(e),
        }


# ============================================================
# CHART DATAFRAME
# ============================================================

def build_chart_data_dataframe(
    df,
    plan,
):
    chart_type = plan.get(
        "chart_type"
    )

    x_column = plan.get(
        "x_column"
    )

    y_columns = plan.get(
        "y_columns",
        [],
    )

    group_column = plan.get(
        "group_column"
    )

    selected_aggregation = plan.get(
        "aggregation",
        "sum",
    )

    analysis_type = plan.get(
        "analysis_type",
        "statistical",
    )

    # IMPORTANT: the Aggregation widget is the single source of truth for
    # the grouped chart values. Analysis Type must never silently replace it.
    aggregation = resolve_analysis_aggregation(
        analysis_type,
        selected_aggregation,
    )
    # IMPORTANT: never use analysis_type as a fallback mathematical operation.
    # The user's Aggregation control is the sole source of truth.
    if aggregation not in {"sum", "mean", "median", "min", "max", "count"}:
        aggregation = "sum"

    if chart_type == "none":
        return None, None

    if (
        not x_column
        or not y_columns
    ):
        return (
            None,
            "The requested chart needs "
            "a valid X and Y field.",
        )

    if x_column not in df.columns:
        return (
            None,
            f"X column '{x_column}' is not available.",
        )

    for y in y_columns:
        if y not in df.columns:
            return (
                None,
                f"Y column '{y}' is not available.",
            )

    work = df.copy()

    for y in y_columns:
        work[y] = pd.to_numeric(
            work[y],
            errors="coerce",
        )

    work = work.dropna(
        subset=[x_column]
    )

    # Scatter: use the selected aggregation when possible. If X is numeric,
    # keep row-level observations because grouping a continuous X would
    # destroy the meaning of the scatter plot.
    if chart_type == "scatter":

        y = y_columns[0]
        temp = work[[x_column, y]].dropna(subset=[x_column, y]).copy()

        x_numeric = pd.to_numeric(temp[x_column], errors="coerce")
        if x_numeric.notna().all():
            temp[x_column] = x_numeric
            return temp[[x_column, y]], None

        grouped = (
            temp.groupby(x_column, dropna=False)[y]
            .agg(aggregation)
            .reset_index()
        )
        return grouped[[x_column, y]], None

    group_cols = [x_column]

    if (
        group_column
        and group_column != x_column
    ):
        group_cols.append(
            group_column
        )

    pieces = []

    for y in y_columns:

        temp = work[
            group_cols + [y]
        ].copy()

        temp = temp.dropna(
            subset=[y]
        )

        if temp.empty:
            continue

        grouped = (
            temp
            .groupby(
                group_cols,
                dropna=False,
            )[y]
            .agg(
                aggregation
            )
            .reset_index()
        )

        grouped["__series__"] = y
        grouped["__value__"] = grouped[y]

        pieces.append(
            grouped[
                group_cols
                + [
                    "__series__",
                    "__value__",
                ]
            ]
        )

    if not pieces:
        return (
            None,
            "No usable numeric values were available.",
        )

    chart = pd.concat(
        pieces,
        ignore_index=True,
    )

    if not group_column:

        wide = chart.pivot_table(
            index=x_column,
            columns="__series__",
            values="__value__",
            aggfunc="first",
        ).reset_index()

        wide.columns.name = None

        return wide, None

    return chart, None


# ============================================================
# CHART RENDERING
# ============================================================

def _format_viz_value(value):
    """Format chart/table values consistently."""
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass

    if isinstance(value, (int, np.integer)):
        return f"{int(value):,}"

    if isinstance(value, (float, np.floating)):
        if np.isfinite(value):
            if float(value).is_integer():
                return f"{int(value):,}"
            return f"{float(value):,.2f}".rstrip("0").rstrip(".")

    return str(value)


def _render_visualization_data_table(chart_df, plan, x_column, y_columns):
    """
    Render the exact aggregated data used by the visualization.
    Uses HTML so the table is always white with black text.
    """
    if chart_df is None or chart_df.empty or not x_column:
        return

    aggregation = str(plan.get("aggregation", "sum")).lower()

    if "__series__" in chart_df.columns and "__value__" in chart_df.columns:
        table_df = chart_df.pivot_table(
            index=x_column,
            columns="__series__",
            values="__value__",
            aggfunc="first",
        ).reset_index()
        table_df.columns.name = None
    else:
        cols = [x_column] + [c for c in y_columns if c in chart_df.columns]
        table_df = chart_df[cols].copy()

    if table_df.empty:
        return

    max_rows = 100
    truncated = len(table_df) > max_rows
    display_df = table_df.head(max_rows).copy()

    headers = list(display_df.columns)
    header_html = "".join(
        f"<th>{html.escape(str(col))}</th>" for col in headers
    )

    rows_html = []
    for _, row in display_df.iterrows():
        cells = "".join(
            f"<td>{html.escape(_format_viz_value(row[col]))}</td>"
            for col in headers
        )
        rows_html.append(f"<tr>{cells}</tr>")

    summary_cells = ["<td><strong>Total</strong></td>"]

    for col in headers[1:]:
        numeric = pd.to_numeric(table_df[col], errors="coerce").dropna()

        if numeric.empty:
            summary_value = ""
        elif aggregation == "mean":
            summary_value = _format_viz_value(numeric.mean())
        elif aggregation == "median":
            summary_value = _format_viz_value(numeric.median())
        elif aggregation == "min":
            summary_value = _format_viz_value(numeric.min())
        elif aggregation == "max":
            summary_value = _format_viz_value(numeric.max())
        elif aggregation == "count":
            summary_value = _format_viz_value(numeric.count())
        else:
            summary_value = _format_viz_value(numeric.sum())

        summary_cells.append(
            f"<td><strong>{html.escape(summary_value)}</strong></td>"
        )

    total_row = f'<tr class="total-row">{"".join(summary_cells)}</tr>'

    extra_note = (
        f"<br>• Showing first {max_rows:,} grouped rows of "
        f"{len(table_df):,}."
        if truncated
        else ""
    )

    st.markdown(
        f"""
        <div class="viz-data-table-wrap">
            <table class="viz-data-table">
                <thead><tr>{header_html}</tr></thead>
                <tbody>
                    {''.join(rows_html)}
                    {total_row}
                </tbody>
            </table>
        </div>
        <div class="viz-notes">
            <strong>Notes:</strong><br>
            • All values are calculated using the complete loaded dataset.<br>
            • X-axis: {html.escape(str(x_column))} |
              Aggregation: {html.escape(str(plan.get("aggregation", "sum")).title())}
            {extra_note}
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_single_chart(df, plan, title=None):
    """Render one requested chart with a clean white background and black text."""
    chart_type = str(plan.get("chart_type", "none")).strip().lower()

    if chart_type == "none":
        return False

    chart_df, error = build_chart_data_dataframe(df, plan)

    if error:
        st.warning(error)
        return False

    if chart_df is None or chart_df.empty:
        st.warning("No usable data is available for this visualization.")
        return False

    title = title or plan.get("title") or "Requested Visualization"
    x = plan.get("x_column")
    ys = [c for c in plan.get("y_columns", []) if c in chart_df.columns]

    try:
        import plotly.express as px

        if chart_type in {"bar", "line"}:

            if "__series__" in chart_df.columns and "__value__" in chart_df.columns:

                plot_df = chart_df[
                    [x, "__series__", "__value__"]
                ].copy()

                plot_df["__value__"] = pd.to_numeric(
                    plot_df["__value__"],
                    errors="coerce",
                )

                plot_df = plot_df.dropna(
                    subset=[x, "__value__"]
                )

                if plot_df.empty:
                    st.warning(
                        "The selected indicator has no numeric values to graph."
                    )
                    return False

                if chart_type == "bar":
                    fig = px.bar(
                        plot_df,
                        x=x,
                        y="__value__",
                        color="__series__",
                        barmode="group",
                        title=title,
                        text="__value__",
                        labels={
                            x: str(x),
                            "__value__": "Value",
                            "__series__": "Indicator",
                        },
                    )

                    fig.update_traces(
                        texttemplate="%{text:,.0f}",
                        textposition="outside",
                        cliponaxis=False,
                    )

                else:
                    fig = px.line(
                        plot_df,
                        x=x,
                        y="__value__",
                        color="__series__",
                        markers=True,
                        title=title,
                        text="__value__",
                        labels={
                            x: str(x),
                            "__value__": "Value",
                            "__series__": "Indicator",
                        },
                    )

                    fig.update_traces(
                        texttemplate="%{text:,.0f}",
                        textposition="top center",
                    )

            else:

                if not x or not ys:
                    st.warning(
                        "A valid X-axis and numeric indicator are required."
                    )
                    return False

                plot_df = chart_df[
                    [x] + ys
                ].copy()

                for col in ys:
                    plot_df[col] = pd.to_numeric(
                        plot_df[col],
                        errors="coerce",
                    )

                plot_df = plot_df.dropna(
                    subset=[x]
                )

                if chart_type == "bar":
                    fig = px.bar(
                        plot_df,
                        x=x,
                        y=ys,
                        barmode="group",
                        title=title,
                    )

                    fig.update_traces(
                        texttemplate="%{y:,.0f}",
                        textposition="outside",
                        cliponaxis=False,
                    )

                else:
                    fig = px.line(
                        plot_df,
                        x=x,
                        y=ys,
                        markers=True,
                        title=title,
                    )

        elif chart_type == "pie":

            if not x or not ys:
                st.warning(
                    "Pie chart requires an X-axis and one numeric indicator."
                )
                return False

            y = ys[0]

            plot_df = chart_df[
                [x, y]
            ].copy()

            plot_df[y] = pd.to_numeric(
                plot_df[y],
                errors="coerce",
            )

            plot_df = plot_df.dropna(
                subset=[x, y]
            )

            if plot_df.empty:
                st.warning(
                    "The selected indicator has no numeric values to graph."
                )
                return False

            fig = px.pie(
                plot_df,
                names=x,
                values=y,
                title=title,
            )

            fig.update_traces(
                textinfo="label+value",
                textfont=dict(
                    color="#111827",
                    size=12,
                ),
            )

        elif chart_type == "scatter":

            if not x or not ys:
                st.warning(
                    "Scatter chart requires an X-axis and one numeric indicator."
                )
                return False

            y = ys[0]

            plot_df = chart_df[
                [x, y]
            ].copy()

            plot_df[y] = pd.to_numeric(
                plot_df[y],
                errors="coerce",
            )

            plot_df = plot_df.dropna(
                subset=[x, y]
            )

            if plot_df.empty:
                st.warning(
                    "The selected indicator has no numeric values to graph."
                )
                return False

            fig = px.scatter(
                plot_df,
                x=x,
                y=y,
                title=title,
            )

        else:
            st.warning(
                f"Unsupported graph type: {chart_type}"
            )
            return False

        # =====================================================
        # FORCE WHITE BACKGROUND + BLACK TEXT EVERYWHERE
        # =====================================================

        black = "#111827"
        grid = "#e5e7eb"

        fig.update_layout(
            template="plotly_white",
            paper_bgcolor="#ffffff",
            plot_bgcolor="#ffffff",

            font=dict(
                family="Arial, Helvetica, sans-serif",
                color=black,
                size=12,
            ),

            title=dict(
                text=title,
                font=dict(
                    family="Arial, Helvetica, sans-serif",
                    color=black,
                    size=16,
                ),
                x=0,
                xanchor="left",
            ),

            legend=dict(
                title=dict(
                    text="Indicator",
                    font=dict(color=black),
                ),
                font=dict(color=black),
                bgcolor="#ffffff",
            ),

            margin=dict(
                l=60,
                r=30,
                t=70,
                b=65,
            ),

            hoverlabel=dict(
                bgcolor="#ffffff",
                bordercolor="#cbd5e1",
                font=dict(
                    color=black,
                    size=12,
                ),
            ),
        )

        fig.update_xaxes(
            title_font=dict(color=black),
            tickfont=dict(color=black),
            showgrid=True,
            gridcolor=grid,
            zeroline=False,
            linecolor=black,
        )

        fig.update_yaxes(
            title_font=dict(color=black),
            tickfont=dict(color=black),
            showgrid=True,
            gridcolor=grid,
            zeroline=True,
            zerolinecolor=black,
            linecolor=black,
        )

        for trace in fig.data:
            try:
                trace.textfont = dict(
                    color=black
                )
            except Exception:
                pass

        st.plotly_chart(
            fig,
            use_container_width=True,
            config={
                "displayModeBar": False,
                "responsive": True,
            },
        )

        # Exact data represented by this visualization.
        _render_visualization_data_table(
            chart_df,
            plan,
            x,
            ys,
        )

        return True

    except Exception:
        # Never expose Plotly/Streamlit's dark technical error block.
        st.warning(
            "The selected visualization could not be rendered. "
            "Please verify the selected X-axis and numeric indicator."
        )
        return False


def render_user_chart(
    df,
    plan,
    section_title=True,
    title_override=None,
):
    """Render a single requested visualization with clean output."""

    chart_type = str(
        plan.get("chart_type", "none")
    ).strip().lower()

    if chart_type == "none":
        return

    title = (
        title_override
        or plan.get("title")
        or "Requested Visualization"
    )

    if section_title:
        st.subheader(
            "📊 Requested Visualization"
        )

    effective_aggregation = resolve_analysis_aggregation(
        plan.get("analysis_type", "statistical"),
        plan.get("aggregation", "sum"),
    )

    st.caption(
        f"{title} • "
        f"Analysis: {str(plan.get('analysis_type', 'statistical')).title()} • "
        f"Aggregation: {aggregation_display_name(effective_aggregation)}"
    )

    diagnostic = aggregation_group_diagnostic(
        df,
        plan.get("x_column"),
        plan.get("y_columns", []),
        effective_aggregation,
    )
    if diagnostic:
        st.info("ℹ️ " + diagnostic)

    _render_single_chart(
        df,
        plan,
        title=title,
    )


def render_requested_visualizations(
    df,
    plan,
):
    """
    Render exactly the graph types selected by the user.

    The user's X-axis, indicators and aggregation remain
    the source of truth.
    """

    if not plan or not plan.get(
        "chart_requested"
    ):
        return

    x = plan.get("x_column")

    ys = [
        c
        for c in plan.get(
            "y_columns",
            [],
        )
        if c in df.columns
    ]

    chart_types = list(
        plan.get(
            "chart_types",
            [],
        )
        or []
    )

    if not chart_types:

        legacy_chart = plan.get(
            "chart_type"
        )

        if (
            legacy_chart
            and legacy_chart != "none"
        ):
            chart_types = [
                legacy_chart
            ]

    if (
        not x
        or not ys
        or x not in df.columns
        or not chart_types
    ):
        return

    st.subheader(
        "📊 Requested Visualizations"
    )

    st.caption(
        "Showing only the graph types selected by the user. "
        "All selected visualizations use the same X-axis, "
        "indicators and aggregation."
    )

    effective_aggregation = resolve_analysis_aggregation(
        plan.get("analysis_type", "statistical"),
        plan.get("aggregation", "sum"),
    )
    st.caption(
        f"Calculation: {str(plan.get('analysis_type', 'statistical')).title()} "
        f"analysis using {aggregation_display_name(effective_aggregation)} aggregation."
    )

    label_by_type = {
        "bar": "Bar",
        "line": "Line",
        "pie": "Pie",
        "scatter": "Scatter",
    }

    seen = set()
    selected_types = []

    chart_aliases = {
        "Grouped Bar": "bar",
        "grouped bar": "bar",
        "Bar": "bar",
        "bar": "bar",
        "Line": "line",
        "line": "line",
        "Pie": "pie",
        "pie": "pie",
        "Scatter": "scatter",
        "scatter": "scatter",
    }

    for chart_type in chart_types:

        normalized = chart_aliases.get(
            str(chart_type).strip(),
            str(chart_type).strip().lower(),
        )

        if (
            normalized in {
                "bar",
                "line",
                "pie",
                "scatter",
            }
            and normalized not in seen
        ):
            seen.add(
                normalized
            )
            selected_types.append(
                normalized
            )

    for index, chart_type in enumerate(
        selected_types,
        start=1,
    ):

        chart = dict(plan)

        chart["chart_type"] = chart_type
        chart["chart_requested"] = True
        chart["y_columns"] = ys

        if chart_type == "bar":
            chart["group_column"] = None

        if chart_type == "scatter":

            chart["y_columns"] = ys[:1]

            if len(ys) > 1:
                st.info(
                    "💡 Scatter uses the first selected indicator "
                    "because a scatter plot requires one Y measure."
                )

        if chart_type == "pie":

            chart["y_columns"] = ys[:1]

            if len(ys) > 1:
                st.info(
                    "🥧 Pie uses the first selected indicator "
                    "because a pie chart represents one measure at a time."
                )

        chart["title"] = (
            f"{label_by_type.get(chart_type, chart_type.title())} — "
            f"{plan.get('title') or 'Requested Analysis'}"
        )

        st.markdown(
            f"### {index}. "
            f"{label_by_type.get(chart_type, chart_type.title())}"
        )

        render_user_chart(
            df=df,
            plan=chart,
            section_title=False,
            title_override=chart.get("title"),
        )


# ============================================================
# AI DATA PREPARATION
# ============================================================
# ============================================================

def prepare_ai_data(
    df,
    chart_plan=None,
    requested_evidence=None,
):
    """
    Prepare a compact, deterministic evidence package for the AI.

    IMPORTANT:
    - Python performs the calculations.
    - AI receives evidence rather than calculating from a sample.
    - The complete dataframe remains available locally.
    - Only a compact preview is sent to the AI to avoid huge prompts.
    """

    if not isinstance(df, pd.DataFrame):
        raise TypeError("prepare_ai_data expects a pandas DataFrame.")

    working = df.copy()

    # --------------------------------------------------------
    # Column metadata
    # --------------------------------------------------------
    column_metadata = []

    for column in working.columns:
        series = working[column]

        column_metadata.append({
            "column": str(column),
            "dtype": str(series.dtype),
            "non_null": int(series.notna().sum()),
            "missing": int(series.isna().sum()),
            "unique": int(series.nunique(dropna=True)),
        })

    # --------------------------------------------------------
    # Numeric evidence
    # --------------------------------------------------------
    numeric_columns = get_numeric_columns(working)
    numeric_evidence = {}

    for column in numeric_columns:
        values = pd.to_numeric(
            working[column],
            errors="coerce",
        ).dropna()

        if values.empty:
            continue

        q1 = values.quantile(0.25)
        q3 = values.quantile(0.75)
        iqr = q3 - q1

        if iqr != 0:
            outlier_count = int(
                (
                    (values < q1 - 1.5 * iqr)
                    | (values > q3 + 1.5 * iqr)
                ).sum()
            )
        else:
            outlier_count = 0

        mean_value = values.mean()

        numeric_evidence[str(column)] = {
            "count": int(values.count()),
            "missing": int(working[column].isna().sum()),
            "sum": float(values.sum()),
            "mean": float(mean_value),
            "median": float(values.median()),
            "minimum": float(values.min()),
            "maximum": float(values.max()),
            "range": float(values.max() - values.min()),
            "standard_deviation": (
                float(values.std())
                if pd.notna(values.std())
                else None
            ),
            "Q1": float(q1),
            "Q3": float(q3),
            "IQR": float(iqr),
            "zero_count": int((values == 0).sum()),
            "negative_count": int((values < 0).sum()),
            "outlier_count": outlier_count,
        }

    # --------------------------------------------------------
    # Key dimensions
    # --------------------------------------------------------
    period_column = find_period_column(working)
    ou_column = find_ou_column(working)

    dimension_evidence = {
        "period_column": (
            str(period_column)
            if period_column is not None
            else None
        ),
        "organisation_unit_column": (
            str(ou_column)
            if ou_column is not None
            else None
        ),
        "period_count": (
            int(working[period_column].nunique(dropna=True))
            if period_column is not None
            else 0
        ),
        "organisation_unit_count": (
            int(working[ou_column].nunique(dropna=True))
            if ou_column is not None
            else 0
        ),
    }

    # --------------------------------------------------------
    # Compact categorical/dimension summaries
    # --------------------------------------------------------
    categorical_evidence = {}

    for column in working.columns:
        if column in numeric_columns:
            continue

        series = working[column].dropna()

        if series.empty:
            continue

        unique_count = int(series.nunique())

        # Only summarize dimensions with manageable cardinality.
        if unique_count <= 50:
            counts = (
                series.astype(str)
                .value_counts()
                .head(25)
            )

            categorical_evidence[str(column)] = {
                "unique_values": unique_count,
                "top_values": [
                    {
                        "value": str(index),
                        "count": int(value),
                    }
                    for index, value in counts.items()
                ],
            }

    # --------------------------------------------------------
    # Compact data preview
    # --------------------------------------------------------
    # This is explicitly a preview only. Numerical conclusions
    # must come from deterministic evidence.
    preview_df = working.head(25).copy()

    preview_records = (
        preview_df
        .replace({np.nan: None})
        .to_dict(orient="records")
    )

    # --------------------------------------------------------
    # Requested-analysis evidence
    # --------------------------------------------------------
    requested_result = {}

    if isinstance(requested_evidence, dict):
        requested_result = requested_evidence.get(
            "result",
            {},
        )

    # --------------------------------------------------------
    # Automatic analysis evidence
    # --------------------------------------------------------
    automatic_analysis = {}

    if isinstance(requested_evidence, dict):
        automatic_analysis = requested_evidence.get(
            "automatic_analysis",
            {},
        )

    # --------------------------------------------------------
    # Final evidence package
    # --------------------------------------------------------
    full_data_evidence = {
        "dataset": {
            "rows": int(len(working)),
            "columns": int(len(working.columns)),
            "column_names": [
                str(column)
                for column in working.columns
            ],
        },

        "column_metadata": column_metadata,

        "numeric_columns": [
            str(column)
            for column in numeric_columns
        ],

        "numeric_statistics": numeric_evidence,

        "dimensions": dimension_evidence,

        "categorical_dimensions": categorical_evidence,

        "requested_analysis_result": requested_result,

        "automatic_analysis": automatic_analysis,

        "analysis_plan": chart_plan or {},

        "schema_preview": {
            "rows_in_preview": int(len(preview_df)),
            "records": preview_records,
        },
    }

    return {
        "full_data_evidence": full_data_evidence,
    }



# ============================================================
# AI INTERPRETATION
# ============================================================

def ask_ai(
    df,
    user_question,
    statistics,
    quality_issues,
    quality_matrix=None,
    quality_summary=None,
    chart_plan=None,
    requested_evidence=None,
    external_context=None,
):
    # AI is optional. Deterministic analysis and data-quality processing
    # can run without an OpenAI API key.
    if client is None:
        return (
            "## AI Interpretation\n\n"
            "AI interpretation is currently unavailable because "
            "`OPENAI_API_KEY` is not configured.\n\n"
            "The deterministic analysis, requested chart and DHIS2 "
            "data-quality assessment can still be generated. Add "
            "`OPENAI_API_KEY` to `.env` and restart the application "
            "to enable the AI narrative."
        )
    data_text = prepare_ai_data(
        df=df,
        chart_plan=chart_plan,
        requested_evidence=requested_evidence,
    )

    prompt = f"""
You are an expert DHIS2 data analyst, public-health
monitoring and evaluation specialist, nutrition programme
analyst, and data-quality specialist.

============================================================
PRIORITY 1 — DATA QUALITY
============================================================

Data quality has HIGH PRIORITY.

Before interpreting the result, assess:

1. Missing values
2. Duplicate records
3. Zero values
4. Negative values
5. Suspicious percentages
6. Missing organisation units
7. Missing periods
8. Any issue that affects the requested calculation

Classify relevant issues as HIGH, MEDIUM, or LOW.

Never hide an important quality problem.

BUT data quality must NOT replace the user's request.

============================================================
PRIORITY 2 — USER REQUEST
============================================================

The USER REQUEST defines the analysis.

If the user asks for a comparison, answer the comparison.

If the user asks for a ranking, rank all applicable rows.

If the user asks for a trend, analyse periods.

If the user asks for a total, calculate totals.

If the user asks for an average, analyse averages.

If the user asks for a percentage, analyse the percentage.

Do NOT automatically make a trend.

Do NOT automatically choose a different aggregation.

Do NOT answer a different question simply because
another analysis seems more interesting.

============================================================
PRIORITY 3 — COMPLETE DATA
============================================================

The dataset contains {len(df):,} rows.

All applicable rows have been processed locally.

The first 25 rows are ONLY a schema preview.

Never treat the top-row matrix as the complete dataset.

============================================================
EXTERNAL INDICATOR CONTEXT
============================================================

External context below comes from a separate web-research step limited to trusted UN/INGO/public-health domains. Use it only as contextual evidence. Do not use it to change the user's numerical results or definitions.

{safe_json_dumps(external_context or {})}

Clearly label external evidence in the report. Distinguish EXACT MATCH, RELATED MATCH and NO VERIFIED MATCH. Never imply that a related indicator is identical to the user's indicator.

============================================================
PRIORITY 4 — PYTHON CALCULATION
============================================================

Python has executed the requested calculation.

The REQUESTED_ANALYSIS_EVIDENCE is authoritative
for numerical results.

Do not reconstruct numerical results from a sample.

Do not invent values.

Do not silently change the aggregation.

============================================================
USER REQUEST
============================================================

{user_question}

============================================================
ANALYSIS PLAN
============================================================

{safe_json_dumps(chart_plan or {})}

============================================================
REQUESTED ANALYSIS EVIDENCE
============================================================

{safe_json_dumps(requested_evidence or {})}

============================================================
MULTI-INDICATOR COMPARISON EVIDENCE
============================================================

{safe_json_dumps((requested_evidence or {}).get("multi_indicator_comparison", {}))}

If multiple indicators were selected, use this evidence to produce
a detailed comparison and a professional narrative.

============================================================
DATA QUALITY MATRIX
============================================================

QUALITY SCORE / RATING:
{safe_json_dumps(quality_summary or {})}

QUALITY DIMENSIONS:
{safe_json_dumps(quality_matrix or [])}

DETAILED FINDINGS:
{safe_json_dumps(quality_issues)}

============================================================
FULL DATA PROFILE
============================================================

{safe_json_dumps(data_text["full_data_evidence"])}

============================================================
AUTOMATIC DANIP-NI REPORTING MODE
============================================================

The user did not provide a manual analysis configuration.

DANIP-NI is responsible for deciding which valid analyses are
supported by the actual dataset.

Do not ask the user to choose X, Y, aggregation or chart type.

The report must automatically synthesize:
- data quality
- complete-data profile
- indicator statistics
- organisation-unit rankings
- period analysis when available
- indicator comparisons
- important exceptions and outliers
- programme-monitoring interpretation
- practical recommendations
- confidence

Numerical values must come from the supplied deterministic evidence.

============================================================
RESPONSE FORMAT
============================================================

## User Request

Restate exactly what the user asked.

## Data Quality Priority

Identify the most important quality issue affecting
the requested analysis.

If none materially affects it, say so.

## Executive Summary

Answer the user's request directly.

Do not give a generic dataset summary.

If more than one indicator is selected, make the executive summary
a true comparison of the selected indicators rather than separate
descriptions of each one.

## Requested Analysis

Present the exact requested comparison,
ranking, calculation, trend, or interpretation.

Use the Python-calculated evidence.

If multiple indicators were selected, compare EVERY selected indicator.
Do not discuss only the first indicator.

For multi-indicator comparisons, explicitly describe:
- highest and lowest indicator
- absolute differences where available
- relative differences or percentage-point differences where valid
- which organisation units or periods drive the differences
- whether the indicators move in the same or opposite direction
- notable gaps, exceptions and outliers
- important changes over time when the X-axis is temporal
- any indicator that is consistently stronger or weaker
- whether apparent differences may be affected by data quality

Do not invent calculations that are not present in the evidence.

## Comparison Table / Structured Findings

When multiple indicators are selected, provide a concise comparison table
using the calculated evidence where possible.

## Narrative Interpretation

Write a professional programme-monitoring narrative that explains
what the comparison means in plain language.

The narrative should connect the numerical findings to the requested
DHIS2 reporting dimension without claiming causation.

## External Indicator Context

If verified external indicator evidence is available, summarize the matched UN/INGO/public-health definition or programme context here. Clearly label the organization and distinguish exact matches from related indicators. Do not use external sources to calculate or alter the user's data.

## Key Findings

Give findings directly relevant to the request.

## Data Quality Impact

Explain whether quality issues:

- do not affect the result
- partially affect the result
- substantially affect the result
- make the result unreliable

## Interpretation

Explain what the observed data shows.

Do not claim causation without evidence.

## Areas Requiring Attention

Identify important programme/data-management issues.

## Recommendations

Give practical evidence-based actions.

## Confidence

High, Medium, or Low, with a short reason.

FINAL RULE:
The answer must be driven by:

1. Data quality
2. User request
3. Request-specific calculation
4. Complete data

Never reverse this priority.
"""

    response = client.responses.create(
        model=OPENAI_MODEL,
        input=prompt,
    )

    return response.output_text


# ============================================================
# EXTERNAL INDICATOR CONTEXT / NARRATIVE ENGINE
# ============================================================

EXTERNAL_EVIDENCE_DOMAINS = [
    "who.int", "data.who.int", "data.unicef.org", "unicef.org",
    "un.org", "unstats.un.org", "worldbank.org", "wfp.org",
    "nutritionintl.org", "reliefweb.int", "savethechildren.net",
    "care.org", "rescue.org", "actionagainsthunger.org", "worldvision.org",
]


def _extract_response_urls(response):
    """Extract URLs from Responses API web-search annotations safely."""
    urls, seen = [], set()
    def walk(value):
        if value is None:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"url", "source_url"} and isinstance(item, str) and item.startswith("http"):
                    if item not in seen:
                        seen.add(item); urls.append(item)
                walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value: walk(item)
        else:
            for attr in ("annotations", "url", "output", "content"):
                try: item = getattr(value, attr, None)
                except Exception: item = None
                if attr == "url" and isinstance(item, str) and item.startswith("http"):
                    if item not in seen:
                        seen.add(item); urls.append(item)
                elif item is not None: walk(item)
    try: walk(response)
    except Exception: pass
    return urls[:20]


def _indicator_candidates(df, limit=15):
    """Return indicator-like numeric column names; never send row-level data."""
    names=[]
    for column in get_numeric_columns(df):
        name=str(column).strip(); low=name.lower()
        if not name or low in {"id","uid","code","value","count","year","month"}:
            continue
        if any(x in low for x in ["latitude","longitude","coordinate","geometry","timestamp"]):
            continue
        if name not in names: names.append(name)
    return names[:limit]


def build_data_quality_narrative(quality_summary, quality_issues):
    score=quality_summary.get("score", 0); rating=quality_summary.get("rating", "Unknown")
    high=sum(i.get("Priority")=="HIGH" for i in quality_issues)
    medium=sum(i.get("Priority")=="MEDIUM" for i in quality_issues)
    low=sum(i.get("Priority")=="LOW" for i in quality_issues)
    if not quality_issues:
        return (f"The dataset currently has a quality score of {score}/100 ({rating}). "
                "No implemented high-, medium-, or low-priority data-quality findings were detected. "
                "DANIP-NI can proceed with interpretation while keeping observed evidence separate from external context.")
    top=[]
    for issue in quality_issues[:5]:
        suffix=f" in {issue.get('Column')}" if issue.get("Column") else ""
        top.append(f"{issue.get('Domain','Quality')}: {issue.get('Issue','Issue')}{suffix} ({issue.get('Count',0):,})")
    return (f"The dataset has a quality score of {score}/100 ({rating}) with {high} high-, {medium} medium-, "
            f"and {low} low-priority findings. The most important findings are " + "; ".join(top) + ". "
            "DANIP-NI uses these checks to qualify interpretation rather than silently removing observations "
            "or changing the user's requested calculation.")


def research_indicator_context(df, quality_summary=None, quality_issues=None):
    """Find verified UN/INGO context for matching indicators using Responses web search."""
    if client is None:
        return {"status":"DISABLED","message":"External indicator context requires OPENAI_API_KEY.","indicators":[],"sources":[],"narrative":""}
    indicators=_indicator_candidates(df)
    if not indicators:
        return {"status":"NO_INDICATORS","message":"No suitable numeric indicator names were detected for external matching.","indicators":[],"sources":[],"narrative":""}
    quality_text=build_data_quality_narrative(quality_summary or {}, quality_issues or [])
    prompt=f"""
You are DANIP-NI's external indicator evidence researcher.

Enrich the programme-monitoring report with carefully verified context from authoritative UN agencies,
INGOs and major public-health institutions.

INDICATORS DETECTED IN USER DATA:
{safe_json_dumps(indicators)}

DATA-QUALITY CONTEXT:
{quality_text}

Rules:
- Search each indicator or a close standardized name.
- Prefer WHO, UNICEF, UN agencies, World Bank, WFP, Nutrition International, Save the Children, CARE,
  IRC, World Vision, Action Against Hunger and ReliefWeb.
- EXACT MATCH requires materially the same indicator meaning, population and numerator/denominator or definition.
- RELATED MATCH means conceptually close but definition/population/denominator differs. Never call it the same indicator.
- If no credible match exists, say NO VERIFIED MATCH.
- Never invent definitions, targets, thresholds, prevalence, coverage or recommendations.
- Never use external sources to change, cap, recalculate or replace user data.
- Use external evidence only for definition, programme relevance and contextual narrative.
- Clearly separate USER DATA findings from EXTERNAL CONTEXT.

For every indicator provide: indicator, match status, matched title, organization, supported definition,
programme relevance, source URL, date when available, confidence.
Then write a concise External Context Narrative using only verified matches.

Trusted domains: {", ".join(EXTERNAL_EVIDENCE_DOMAINS)}
"""
    try:
        response=client.responses.create(
            model=OPENAI_MODEL,
            tools=[{"type":"web_search","search_context_size":"high"}],
            input=prompt,
        )
        return {"status":"SUCCESS","indicators":indicators,"sources":_extract_response_urls(response),"narrative":response.output_text or ""}
    except Exception as e:
        return {"status":"ERROR","message":str(e),"indicators":indicators,"sources":[],"narrative":""}


def render_ai_methodology_and_external_context(df, quality_summary, quality_issues, external_context):
    st.markdown("""
    <div class="section-card auto-analysis-card">
      <div class="section-kicker">NEXUS INTELLIGENCE LAYER</div>
      <div class="section-title">🧠 How NEXUS AI is working with your data</div>
      <div class="section-help">Python calculates deterministic evidence from the complete dataset. AI interprets that evidence, while verified UN/INGO/public-health sources provide indicator context without changing the user's calculations.</div>
    </div>
    """, unsafe_allow_html=True)
    a1,a2,a3,a4=st.columns(4)
    with a1: st.metric("Rows analysed", f"{len(df):,}")
    with a2: st.metric("Data quality", f"{quality_summary.get('score',0)}/100")
    with a3: st.metric("Quality findings", f"{len(quality_issues):,}")
    with a4: st.metric("External context", "Available" if external_context.get("status")=="SUCCESS" else "Limited")
    with st.expander("🔍 1. Data-quality narration", expanded=True):
        st.markdown(build_data_quality_narrative(quality_summary, quality_issues))
        st.caption("Quality checks qualify the interpretation. The AI does not silently delete outliers, convert zeros to missing, or change the requested aggregation.")
    with st.expander("🤖 2. How the AI works", expanded=False):
        st.markdown("""
**Step 1 — Complete-data processing:** all returned rows are loaded locally.

**Step 2 — Deterministic evidence:** Python calculates totals, averages, distributions, trends, rankings, missingness, duplicates, validity, numerator/denominator consistency and other quality checks.

**Step 3 — User intent:** confirmed X-axis, indicators, graph, analysis type and aggregation control the requested analysis.

**Step 4 — AI interpretation:** the model receives calculated evidence and is instructed not to invent or recalculate values.

**Step 5 — External context:** matching indicators are researched against trusted UN/INGO/public-health sources.

**Step 6 — Separation:** external context is labelled separately and never replaces the user's values.
        """)
    with st.expander("🌍 3. External indicator context & programme narrative", expanded=True):
        if external_context.get("status")=="SUCCESS":
            st.markdown(external_context.get("narrative") or "No external narrative was returned.")
            for url in external_context.get("sources",[])[:12]: st.markdown(f"- {url}")
            st.caption("External context is contextual evidence only. A similar indicator is not treated as an exact match unless its definition is materially aligned.")
        elif external_context.get("status")=="DISABLED":
            st.info("External indicator research is disabled until OPENAI_API_KEY is configured.")
        else:
            st.info(external_context.get("message","No verified external indicator context was found."))


# ============================================================
# EXCEL REPORT
# ============================================================

def create_excel_report(
    df,
    statistics,
    quality_issues,
    quality_matrix,
    quality_summary,
    ai_result,
    requested_evidence,
):
    from openpyxl import Workbook
    from openpyxl.styles import Font
    from openpyxl.utils.dataframe import dataframe_to_rows

    workbook = Workbook()

    # Data
    ws_data = workbook.active
    ws_data.title = "DHIS2 Data"

    for row in dataframe_to_rows(
        df,
        index=False,
        header=True,
    ):
        ws_data.append(row)

    for cell in ws_data[1]:
        cell.font = Font(bold=True)

    # Summary
    ws_summary = workbook.create_sheet(
        "Summary"
    )

    ws_summary.append([
        "Metric",
        "Value",
    ])

    ws_summary["A1"].font = Font(
        bold=True
    )
    ws_summary["B1"].font = Font(
        bold=True
    )

    ws_summary.append([
        "Records",
        statistics["records"],
    ])

    ws_summary.append([
        "Columns",
        statistics["columns"],
    ])

    ws_summary.append([
        "Numeric Fields",
        len(
            statistics["numeric_columns"]
        ),
    ])

    ws_summary.append([
        "Quality Issues",
        len(quality_issues),
    ])

    # Quality matrix
    ws_matrix = workbook.create_sheet("Quality Matrix")
    ws_matrix.append(["Metric", "Value"])
    ws_matrix.append(["Quality Score", quality_summary.get("score")])
    ws_matrix.append(["Rating", quality_summary.get("rating")])
    ws_matrix.append(["Rows", quality_summary.get("rows")])
    ws_matrix.append(["Columns", quality_summary.get("columns")])
    ws_matrix.append(["Issues", quality_summary.get("issues")])

    matrix_df = pd.DataFrame(quality_matrix)
    if not matrix_df.empty:
        ws_matrix.append([])
        for row in dataframe_to_rows(matrix_df, index=False, header=True):
            ws_matrix.append(row)

    # Quality details
    ws_quality = workbook.create_sheet(
        "Data Quality"
    )

    if quality_issues:

        quality_df = pd.DataFrame(
            quality_issues
        )

        for row in dataframe_to_rows(
            quality_df,
            index=False,
            header=True,
        ):
            ws_quality.append(row)

    else:
        ws_quality.append([
            "No basic quality issues detected."
        ])

    # Requested calculation
    ws_request = workbook.create_sheet(
        "Requested Analysis"
    )

    request_json = safe_json_dumps(
        requested_evidence
    )

    for i, line in enumerate(
        request_json.splitlines(),
        start=1,
    ):
        ws_request.cell(
            row=i,
            column=1,
            value=line,
        )

    # External indicator context
    ws_external = workbook.create_sheet("External Context")
    external_context = requested_evidence.get("external_indicator_context", {}) if isinstance(requested_evidence, dict) else {}
    ws_external["A1"] = "External Indicator Context"
    ws_external["A1"].font = Font(bold=True)
    ws_external["A3"] = "Status"
    ws_external["B3"] = external_context.get("status", "")
    ws_external["A4"] = "Narrative"
    ws_external["B4"] = external_context.get("narrative", "")
    for idx, url in enumerate(external_context.get("sources", [])[:20], start=6):
        ws_external.cell(row=idx, column=1, value="Source")
        ws_external.cell(row=idx, column=2, value=url)

    # AI
    ws_ai = workbook.create_sheet(
        "AI Interpretation"
    )

    ws_ai["A1"] = (
        "DHIS2 AI Interpretation"
    )

    ws_ai["A1"].font = Font(
        bold=True
    )

    for index, line in enumerate(
        ai_result.splitlines(),
        start=3,
    ):
        ws_ai.cell(
            row=index,
            column=1,
            value=line,
        )

    output = BytesIO()
    workbook.save(output)
    output.seek(0)

    return output



# ============================================================
# ANALYSIS CHATBOT — QUESTIONS AGAINST THE CURRENT DATASET
# ============================================================

def _chat_json_safe(value):
    """Convert pandas/numpy values into JSON-safe Python values."""
    if value is None:
        return None

    try:
        if pd.isna(value):
            return None
    except Exception:
        pass

    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass

    return value


def _chat_dimension_candidates(df):
    """
    Identify useful dimensions for conversational analysis without changing
    the existing analysis pipeline.
    """
    preferred_tokens = (
        "country", "nation", "region", "province", "state", "district",
        "zone", "woreda", "facility", "organisation", "organization",
        "orgunit", "org unit", "ou", "period", "month", "year", "date",
        "quarter", "sex", "gender", "age", "category", "indicator",
    )

    candidates = []

    for column in df.columns:
        series = df[column]
        if pd.api.types.is_numeric_dtype(series):
            continue

        name = str(column).strip().lower()
        unique_count = int(series.nunique(dropna=True))

        if unique_count == 0 or unique_count > 200:
            continue

        score = sum(1 for token in preferred_tokens if token in name)

        # The active chart X-axis is especially useful to the chatbot.
        if str(column) == str(
            st.session_state.get("analysis_chat_x_column", "")
        ):
            score += 20

        if score > 0:
            candidates.append((score, unique_count, column))

    candidates.sort(
        key=lambda item: (-item[0], item[1], str(item[2]).lower())
    )

    # Avoid a very large prompt while retaining the most useful dimensions.
    return [item[2] for item in candidates[:6]]


def _build_chat_group_evidence(df, dimensions, indicators):
    """
    Calculate compact, deterministic summaries for common user questions
    such as highest/lowest country, trend by period, total by OU, etc.
    """
    evidence = {}

    work = df.copy()

    valid_indicators = []
    for column in indicators:
        if column in work.columns:
            numeric = pd.to_numeric(work[column], errors="coerce")
            if numeric.notna().any():
                work[column] = numeric
                valid_indicators.append(column)

    if not valid_indicators:
        return evidence

    for dimension in dimensions:
        if dimension not in work.columns:
            continue

        try:
            grouped = work.groupby(
                dimension,
                dropna=False,
            )[valid_indicators].agg(
                ["sum", "mean", "max", "count"]
            ).reset_index()
        except Exception:
            continue

        # Flatten MultiIndex columns.
        flattened = []
        for column in grouped.columns:
            if isinstance(column, tuple):
                parts = [str(x) for x in column if str(x) != ""]
                flattened.append("_".join(parts))
            else:
                flattened.append(str(column))
        grouped.columns = flattened

        records = grouped.replace(
            {np.nan: None}
        ).to_dict(orient="records")

        # Keep exact deterministic ranking/trend evidence compact.
        dimension_block = {
            "unique_values": int(work[dimension].nunique(dropna=True)),
            "indicator_summaries": {},
        }

        for indicator in valid_indicators:
            sum_col = f"{indicator}_sum"
            mean_col = f"{indicator}_mean"
            max_col = f"{indicator}_max"
            count_col = f"{indicator}_count"

            if sum_col not in grouped.columns:
                continue

            temp = grouped[
                [dimension, sum_col, mean_col, max_col, count_col]
            ].copy()

            temp[sum_col] = pd.to_numeric(
                temp[sum_col], errors="coerce"
            )
            temp[mean_col] = pd.to_numeric(
                temp[mean_col], errors="coerce"
            )

            temp = temp.dropna(subset=[sum_col])

            if temp.empty:
                continue

            # For periods, provide chronological-looking latest records where
            # possible; for other dimensions provide highest/lowest rankings.
            name_lower = str(dimension).lower()
            if any(token in name_lower for token in ["period", "date", "month", "year", "quarter"]):
                # Prefer parsed date ordering for trend questions; fall back to
                # the source ordering when the period values are not parseable.
                sort_values = pd.to_datetime(
                    temp[dimension].astype(str),
                    errors="coerce",
                )
                if sort_values.notna().any():
                    temp = temp.assign(_chat_sort=sort_values).sort_values(
                        "_chat_sort"
                    ).drop(columns=["_chat_sort"])
                else:
                    temp = temp.sort_values(
                        dimension,
                        kind="stable",
                    )
                latest = temp.tail(15)
                ranked = latest
            else:
                ranked = temp.sort_values(
                    sum_col,
                    ascending=False,
                ).head(10)

            lowest = temp.sort_values(
                sum_col,
                ascending=True,
            ).head(10)

            dimension_block["indicator_summaries"][str(indicator)] = {
                "highest_by_sum": ranked.replace(
                    {np.nan: None}
                ).to_dict(orient="records"),
                "lowest_by_sum": lowest.replace(
                    {np.nan: None}
                ).to_dict(orient="records"),
                "records": int(len(temp)),
            }

        if dimension_block["indicator_summaries"]:
            evidence[str(dimension)] = dimension_block

    return evidence



def _chat_normalize_text(value):
    """Normalize text for indicator/question matching."""
    value = str(value or "").lower()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def _chat_indicator_candidates(question, df, chart_plan=None, limit=3):
    """
    Identify the indicators most relevant to the user's question.

    Priority:
      1. Explicitly selected dashboard indicators.
      2. Exact/near-exact indicator-name matches.
      3. Semantic token overlap with column names.
    """
    if not isinstance(df, pd.DataFrame) or df.empty:
        return []

    selected = []
    if isinstance(chart_plan, dict):
        for col in (
            chart_plan.get("indicator_columns", [])
            + chart_plan.get("y_columns", [])
        ):
            if col in df.columns and col not in selected:
                selected.append(col)

    q = _chat_normalize_text(question)
    q_tokens = set(q.split())

    scored = []
    for col in df.columns:
        if col not in get_numeric_columns(df):
            continue

        name = _chat_normalize_text(col)
        name_tokens = set(name.split())

        score = 0.0
        if name and name in q:
            score += 100
        if q and q in name:
            score += 90

        overlap = len(q_tokens & name_tokens)
        score += overlap * 8

        # Strong M&E terms that usually identify the indicator itself.
        for token in (
            "indicator", "coverage", "rate", "percent", "percentage",
            "number", "women", "pregnant", "children", "attending",
            "received", "screened", "treated", "supplementation",
            "anc", "vas", "wifa", "zinc", "mnhn",
        ):
            if token in q_tokens and token in name_tokens:
                score += 5

        if col in selected:
            score += 25

        if score > 0:
            scored.append((score, str(col)))

    scored.sort(key=lambda x: (-x[0], x[1].lower()))

    result = [name for _, name in scored[:limit]]

    # If the user asks about "this indicator", use the active selection.
    if not result and selected:
        result = selected[:limit]

    return result


def _chat_infer_indicator_context(indicator):
    """
    Give ChatGPT a cautious M&E interpretation from the indicator label.

    This is NOT treated as an official indicator definition. The prompt
    explicitly tells the model to distinguish label-based inference from
    authoritative metadata.
    """
    name = str(indicator)
    n = _chat_normalize_text(name)

    if any(x in n for x in ["percentage", "percent", "coverage", "rate", "proportion"]):
        indicator_type = "coverage/rate/proportion indicator"
    elif any(x in n for x in ["number", "women", "pregnant", "children", "clients", "cases", "#"]):
        indicator_type = "count/output indicator"
    else:
        indicator_type = "numeric programme indicator"

    focus = []
    if any(x in n for x in ["anc", "antenatal", "pregnant", "pregnancy"]):
        focus.append("maternal/antenatal care access or service utilisation")
    if any(x in n for x in ["first 12 weeks", "12 weeks", "early", "timely", "first trimester"]):
        focus.append("timeliness of early service initiation")
    if any(x in n for x in ["vas", "vitamin a"]):
        focus.append("vitamin A supplementation")
    if any(x in n for x in ["wifa", "iron", "folic"]):
        focus.append("women's iron/folic-acid supplementation")
    if any(x in n for x in ["zinc", "diarr"]):
        focus.append("zinc treatment/service delivery")
    if any(x in n for x in ["mnhn", "maternal", "newborn"]):
        focus.append("maternal/newborn health service delivery")

    if not focus:
        focus.append("the programme result represented by the indicator label")

    return {
        "indicator": name,
        "type": indicator_type,
        "label_based_m_and_e_focus": focus,
        "definition_status": (
            "Label-based interpretation only. An official DHIS2 indicator "
            "definition should be used when numerator, denominator, "
            "calculation formula or metadata are available."
        ),
    }


def _chat_find_num_den_context(df, indicator):
    """Find plausible numerator/denominator fields related to one indicator."""
    num_cols = [
        c for c in df.columns
        if re.search(r"(^|[_\s-])num(erator)?($|[_\s-])", str(c), re.I)
    ]
    den_cols = [
        c for c in df.columns
        if re.search(r"(^|[_\s-])den(ominator)?($|[_\s-])", str(c), re.I)
    ]

    def base(v):
        s = _chat_normalize_text(v)
        return re.sub(r"\b(numerator|denominator|num|den)\b", " ", s).strip()

    selected_base = base(indicator)
    pairs = []

    for num in num_cols:
        for den in den_cols:
            score = 0
            nb = base(num)
            db = base(den)

            if selected_base and (
                selected_base in nb or selected_base in db
                or nb in selected_base or db in selected_base
            ):
                score += 10

            # Shared tokens are useful when columns are long DHIS2 labels.
            score += len(set(nb.split()) & set(db.split()))

            pairs.append((score, num, den))

    pairs.sort(key=lambda x: (-x[0], str(x[1]).lower(), str(x[2]).lower()))

    if not pairs:
        return []

    result = []
    for score, num, den in pairs[:3]:
        result.append({
            "numerator": str(num),
            "denominator": str(den),
            "relevance_score": score,
        })
    return result


def build_chat_mne_indicator_context(df, indicators, quality_issues=None):
    """
    Build the M&E context used by the chatbot.

    It combines:
      - indicator label and cautious label-based meaning,
      - deterministic statistics,
      - focused DHIS2 indicator-level quality assessment,
      - numerator/denominator fields when available.

    No values are changed.
    """
    context = []

    if not isinstance(df, pd.DataFrame):
        return context

    for indicator in indicators:
        if indicator not in df.columns:
            continue

        numeric = pd.to_numeric(df[indicator], errors="coerce")
        valid = numeric.dropna()

        item = _chat_infer_indicator_context(indicator)

        if not valid.empty:
            item["observed_data"] = {
                "records_with_numeric_value": int(valid.count()),
                "missing_values": int(numeric.isna().sum()),
                "total": float(valid.sum()),
                "average": float(valid.mean()),
                "median": float(valid.median()),
                "minimum": float(valid.min()),
                "maximum": float(valid.max()),
                "zero_count": int((valid == 0).sum()),
            }
        else:
            item["observed_data"] = {
                "records_with_numeric_value": 0,
                "missing_values": int(numeric.isna().sum()),
            }

        # Focused indicator-level DQ is more useful than sending the entire
        # dataset-level matrix to ChatGPT.
        try:
            ind_issues, ind_matrix, ind_summary = build_indicator_quality_matrix(
                df, indicator
            )
            item["indicator_quality"] = {
                "summary": ind_summary,
                "issues": ind_issues[:12],
                "matrix": ind_matrix[:12],
            }
        except Exception as exc:
            item["indicator_quality"] = {
                "error": str(exc),
            }

        item["numerator_denominator_candidates"] = _chat_find_num_den_context(
            df, indicator
        )

        context.append(item)

    return context


def _chat_local_mne_answer(
    question,
    df,
    indicators,
    chart_plan=None,
    quality_issues=None,
):
    """Deterministic M&E assistant used whenever AI is unavailable."""
    if not isinstance(df, pd.DataFrame) or df.empty:
        return "No dataset is currently loaded. Please load the DHIS2 data first."

    # Prefer the user's selected indicator(s). If the question names another
    # indicator, _chat_indicator_candidates() will already have selected it.
    if not indicators:
        if isinstance(chart_plan, dict):
            indicators = [
                c for c in (chart_plan.get("y_columns") or [])
                if c in df.columns
            ][:3]
        if not indicators:
            indicators = get_numeric_columns(df)[:3]

    if not indicators:
        return (
            "I could not identify a numeric indicator in the current dataset. "
            "Please select an indicator in User-Requested Analysis."
        )

    q = _chat_normalize_text(question)

    # Build indicator-specific evidence for every selected indicator.
    profiles = []
    for indicator in indicators[:3]:
        if indicator not in df.columns:
            continue

        values = pd.to_numeric(df[indicator], errors="coerce")
        valid = values.dropna()
        context = _chat_infer_indicator_context(indicator)

        try:
            _, ind_matrix, ind_summary = build_indicator_quality_matrix(
                df, indicator
            )
        except Exception:
            ind_matrix, ind_summary = [], {}

        profile = {
            "indicator": str(indicator),
            "type": context.get("type", "indicator"),
            "focus": context.get("label_based_m_and_e_focus", []),
            "observations": int(valid.count()),
            "missing": int(values.isna().sum()),
            "total": float(valid.sum()) if not valid.empty else None,
            "average": float(valid.mean()) if not valid.empty else None,
            "median": float(valid.median()) if not valid.empty else None,
            "minimum": float(valid.min()) if not valid.empty else None,
            "maximum": float(valid.max()) if not valid.empty else None,
            "quality_score": float(ind_summary.get("score", 0)) if ind_summary else None,
            "quality_rating": str(ind_summary.get("rating", "Unknown")) if ind_summary else "Unknown",
            "quality_matrix": ind_matrix[:12] if isinstance(ind_matrix, list) else [],
        }

        # Add period/OU extrema where possible.
        x_column = chart_plan.get("x_column") if isinstance(chart_plan, dict) else None
        if x_column in df.columns and not valid.empty:
            tmp = pd.DataFrame({
                "__x": df[x_column].astype(str),
                "__v": values,
            }).dropna(subset=["__v"])
            if not tmp.empty:
                hi = tmp.loc[tmp["__v"].idxmax()]
                lo = tmp.loc[tmp["__v"].idxmin()]
                profile["highest_category"] = str(hi["__x"])
                profile["lowest_category"] = str(lo["__x"])

                # Trend is descriptive only and follows the displayed order.
                if len(tmp) >= 2:
                    first = float(tmp["__v"].iloc[0])
                    last = float(tmp["__v"].iloc[-1])
                    profile["first_value"] = first
                    profile["last_value"] = last
                    profile["change"] = last - first
                    profile["change_pct"] = (
                        (last - first) / abs(first) * 100
                        if first != 0 else None
                    )

        profiles.append(profile)

    if not profiles:
        return "I could not calculate evidence for the selected indicator(s)."

    primary = profiles[0]
    name = primary["indicator"]
    name_lower = name.lower()
    focus = "; ".join(primary.get("focus") or [])

    # ---------------------------------------------------------
    # Indicator meaning / M&E significance
    # ---------------------------------------------------------
    meaning_terms = (
        "what does", "what is", "meaning", "mean", "interpret",
        "definition", "measure", "measures", "why is", "why this",
        "importance", "important", "m&e", "program relevance",
        "programme relevance", "what does this indicator tell",
    )
    if any(t in q for t in meaning_terms):
        if any(x in name_lower for x in ["within", "first 12 weeks", "early"]):
            mne_role = (
                "This indicator is relevant to monitoring timely access to "
                "early service utilisation. For an M&E team, it can help "
                "track whether the programme is reaching the intended "
                "population within the expected service window."
            )
        elif any(x in name_lower for x in ["coverage", "rate", "percent", "%", "proportion"]):
            mne_role = (
                "This appears to be a coverage/rate indicator. Its programme "
                "meaning depends on the numerator, denominator, target and "
                "reporting grain, so the observed percentage should not be "
                "judged without those elements."
            )
        elif any(x in name_lower for x in ["number of", "# of", "count", "women", "children", "people"]):
            mne_role = (
                "This appears to be a service/output volume indicator. It can "
                "help monitor the amount of service or reach recorded by the "
                "programme, but a higher count is not automatically better "
                "without considering the eligible population, target and "
                "reporting completeness."
            )
        else:
            mne_role = (
                "The indicator's M&E meaning should be confirmed against the "
                "official DHIS2 indicator metadata. The current interpretation "
                "is based on the indicator label and observed data only."
            )

        observed = (
            f"The current dataset contains **{primary['observations']:,}** valid "
            f"observations. The average is **{primary['average']:,.2f}**, "
            f"minimum **{primary['minimum']:,.2f}**, and maximum "
            f"**{primary['maximum']:,.2f}**."
            if primary["average"] is not None else
            "No valid numeric observations are available for this indicator."
        )

        quality = (
            f"Indicator-level quality is **{primary['quality_rating']}** "
            f"({primary['quality_score']:.1f}/100)."
            if primary["quality_score"] is not None else
            "Indicator-level quality could not be scored."
        )

        return f"""
## Indicator / Direct Answer

**{name}** is being interpreted as a **{primary['type']}** indicator based on its label.

## M&E Interpretation

{mne_role}

The label-based M&E focus is: **{focus or 'programme performance monitoring'}**.

The official indicator definition, numerator, denominator, target and calculation formula should be confirmed from DHIS2 metadata where available. They are not inferred as official definitions by this assistant.

## Current Evidence

{observed}

## Programme-Management Implication

Use this indicator to monitor the level, trend and distribution of reported performance. Investigate material differences between reporting periods or organisation units and compare the observed result with the approved programme target before making a performance judgement.

## Data Quality Note

{quality}
"""

    # ---------------------------------------------------------
    # Total / average / median / min / max / count
    # ---------------------------------------------------------
    if primary["average"] is not None:
        if any(t in q for t in ["total", "sum", "altogether", "overall total"]):
            return (
                f"## Direct Answer\n\n**{name} total:** "
                f"**{primary['total']:,.2f}** across {primary['observations']:,} "
                f"valid observations.\n\n## M&E Interpretation\n\n"
                f"This represents the total recorded volume in the loaded dataset. "
                f"For programme interpretation, consider reporting completeness, "
                f"population size and the approved target before treating a higher "
                f"total as better performance."
            )

        if any(t in q for t in ["average", "mean"]):
            return (
                f"## Direct Answer\n\n**{name} average:** "
                f"**{primary['average']:,.2f}**.\n\n"
                f"This is the mean across {primary['observations']:,} valid observations. "
                f"Use it to describe the typical observed level; compare it with "
                f"the programme target or benchmark before judging performance."
            )

        if "median" in q:
            return (
                f"## Direct Answer\n\n**{name} median:** "
                f"**{primary['median']:,.2f}**.\n\n"
                f"The median represents the middle observed value and can be useful "
                f"when unusually high or low observations may influence the mean."
            )

        if any(t in q for t in ["highest", "maximum", "max", "top"]):
            category = primary.get("highest_category")
            suffix = f" in **{category}**" if category else ""
            return (
                f"## Direct Answer\n\n**{name} highest observed value:** "
                f"**{primary['maximum']:,.2f}**{suffix}.\n\n"
                f"## M&E Interpretation\n\n"
                f"The highest observed value identifies where reported performance "
                f"is greatest in the current dataset. It should not automatically "
                f"be classified as best performance without the relevant target, "
                f"denominator and reporting context."
            )

        if any(t in q for t in ["lowest", "minimum", "min", "bottom"]):
            category = primary.get("lowest_category")
            suffix = f" in **{category}**" if category else ""
            return (
                f"## Direct Answer\n\n**{name} lowest observed value:** "
                f"**{primary['minimum']:,.2f}**{suffix}.\n\n"
                f"## M&E Interpretation\n\n"
                f"The lowest observed value identifies an area or period that may "
                f"warrant programme review. Verify reporting completeness and the "
                f"underlying source before interpreting it as a performance gap."
            )

        if any(t in q for t in ["how many", "count", "number of records", "observations"]):
            return (
                f"## Direct Answer\n\n**{name}:** "
                f"**{primary['observations']:,} valid observations**.\n\n"
                f"Missing values: **{primary['missing']:,}**."
            )

    # ---------------------------------------------------------
    # Trend
    # ---------------------------------------------------------
    if any(t in q for t in ["trend", "improving", "increase", "decrease", "changed"]):
        if primary.get("change") is not None:
            change = primary["change"]
            pct = primary.get("change_pct")
            direction = "increased" if change > 0 else "decreased" if change < 0 else "remained unchanged"
            pct_text = f" ({pct:+.1f}%)" if pct is not None else ""
            return (
                f"## Direct Answer\n\n**{name}** {direction} from the first to the last "
                f"displayed observation by **{abs(change):,.2f}**{pct_text}.\n\n"
                f"## M&E Interpretation\n\n"
                f"This is a descriptive change in the loaded reporting sequence. "
                f"It should be assessed against the programme target, expected "
                f"direction and data-quality findings before being classified as "
                f"improvement or deterioration."
            )
        return (
            f"There are not enough ordered observations for **{name}** to establish "
            f"a trend from the current dataset."
        )

    # ---------------------------------------------------------
    # Data quality
    # ---------------------------------------------------------
    if any(t in q for t in ["data quality", "dqa", "quality", "reliable", "missing", "complete"]):
        score = primary.get("quality_score")
        rating = primary.get("quality_rating", "Unknown")
        missing = primary.get("missing", 0)
        return f"""
## Data Quality Assessment — {name}

**Indicator quality rating:** {rating}

**Quality score:** {score:.1f}/100

**Valid observations:** {primary['observations']:,}

**Missing observations:** {missing:,}

## M&E Interpretation

The result should be interpreted together with completeness, validity, plausibility, timeliness and consistency findings. A numerical result should not be treated as fully reliable simply because a value exists.

## Programme Management Attention

Prioritise any HIGH or MEDIUM DQA finding linked to this indicator and verify the result with the responsible reporting unit/source register before high-stakes decisions.
"""

    # ---------------------------------------------------------
    # Multi-indicator comparison
    # ---------------------------------------------------------
    if len(profiles) > 1 and any(t in q for t in ["compare", "comparison", "difference", "which indicator", "better"]):
        lines = ["## Indicator Comparison", ""]
        for p in profiles:
            lines.append(
                f"- **{p['indicator']}** — average: "
                f"{p['average']:,.2f}; minimum: {p['minimum']:,.2f}; "
                f"maximum: {p['maximum']:,.2f}."
            )
        lines.extend([
            "",
            "## M&E Interpretation",
            "",
            "The indicators should only be compared directly when they have compatible units, definitions and denominators. A larger numeric value does not automatically indicate better programme performance.",
        ])
        return "\n".join(lines)

    # ---------------------------------------------------------
    # Generic indicator-specific response
    # ---------------------------------------------------------
    return f"""
## Direct Answer

I identified **{name}** as the primary indicator for this question.

## M&E Interpretation

This indicator is treated as a **{primary['type']}** indicator based on its label, with the M&E focus of **{focus or 'programme performance monitoring'}**.

## Current Evidence

Average: **{primary['average']:,.2f}**  
Minimum: **{primary['minimum']:,.2f}**  
Maximum: **{primary['maximum']:,.2f}**  
Valid observations: **{primary['observations']:,}**

## Programme-Management Implication

Review the level, trend and geographic/reporting-unit differences against the approved programme target or benchmark. Do not infer causality from the descriptive result alone.

## Data Quality Note

Indicator-level quality: **{primary['quality_rating']} ({primary['quality_score']:.1f}/100)**.
"""



# ============================================================
# CHAT PERFORMANCE INTELLIGENCE
# ============================================================

def _chat_performance_intent(question):
    """Detect a request to assess indicators against programme targets."""
    q = _chat_normalize_text(question)
    performance_terms = (
        "performance", "below target", "under target", "underperform",
        "off target", "missed target", "not meeting target",
        "below the target", "which indicators are below",
        "which indicator is below", "target achievement",
        "target performance", "achievement against target",
    )
    return any(term in q for term in performance_terms)


def _chat_normalize_name(value):
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _chat_find_indicator_column(df):
    """Find a row-level indicator/name field when the dataset is long-form."""
    patterns = [
        r"^indicator$", r"indicator name", r"indicator",
        r"data element", r"dataelement", r"dx",
        r"measure", r"metric"
    ]
    return _meal_col(df, patterns) if "_meal_col" in globals() else None


def _chat_match_indicator_column(df, indicator_name):
    """Match a Results Framework indicator name to a loaded dataframe column."""
    target = _chat_normalize_name(indicator_name)
    if not target:
        return None

    exact = {}
    for c in df.columns:
        exact[_chat_normalize_name(c)] = c

    if target in exact:
        return exact[target]

    # Conservative containment match; avoid arbitrary fuzzy matches.
    candidates = []
    for c in df.columns:
        nc = _chat_normalize_name(c)
        if not nc:
            continue
        if target in nc or nc in target:
            candidates.append((abs(len(nc) - len(target)), c))

    if candidates:
        candidates.sort(key=lambda x: x[0])
        return candidates[0][1]

    return None


def _chat_performance_from_results_framework(df):
    """
    Build indicator-level target-vs-actual performance using the persistent
    Results Framework when available. This is the preferred path because it
    gives the chatbot an explicit indicator target.
    """
    try:
        rf = _meal_persistent_df("meal_results_framework")
    except Exception:
        rf = pd.DataFrame()

    if not isinstance(rf, pd.DataFrame) or rf.empty:
        return pd.DataFrame()

    rows = []
    for _, rec in rf.iterrows():
        indicator = str(rec.get("Indicator", "")).strip()
        if not indicator:
            continue

        target = pd.to_numeric(pd.Series([rec.get("Target", "")]), errors="coerce").iloc[0]
        if pd.isna(target):
            continue

        actual_col = _chat_match_indicator_column(df, indicator)
        if not actual_col:
            continue

        values = pd.to_numeric(df[actual_col], errors="coerce").dropna()
        if values.empty:
            continue

        # Counts/volumes are normally additive; percentages/rates are better
        # represented by their observed mean when the target is <= 100.
        if float(target) <= 100:
            actual = float(values.mean())
        else:
            actual = float(values.sum())

        direction = str(rec.get("Direction", "") or "Higher is better").strip()
        direction_lower = direction.lower()

        if "lower" in direction_lower:
            gap = float(target) - actual
            achievement = (target / actual * 100) if actual != 0 else None
            below_target = actual > float(target)
            status = "Above target" if not below_target else "Below target"
        else:
            gap = actual - float(target)
            achievement = (actual / target * 100) if target != 0 else None
            below_target = actual < float(target)
            status = "Below target" if below_target else "At/above target"

        rows.append({
            "Indicator": indicator,
            "Data field": str(actual_col),
            "Target": float(target),
            "Actual": actual,
            "Achievement %": achievement,
            "Gap": gap,
            "Direction": direction or "Higher is better",
            "Status": status,
            "Valid observations": int(values.count()),
            "Missing observations": int(df[actual_col].isna().sum()),
        })

    return pd.DataFrame(rows)


def _chat_performance_from_long_data(df):
    """
    Build indicator-level target-vs-actual performance when Target and Actual
    exist as columns in a long-form dataset.
    """
    target_col = _meal_col(df, [
        r"^target$", r"annual target", r"monthly target",
        r"quarter target", r"planned", r"goal"
    ])
    actual_col = _meal_col(df, [
        r"^actual$", r"achievement", r"result",
        r"reported value", r"actual value", r"^value$"
    ], exclude=[target_col] if target_col else [])

    indicator_col = _chat_find_indicator_column(df)

    if not target_col or not actual_col or not indicator_col:
        return pd.DataFrame()

    work = df[[indicator_col, target_col, actual_col]].copy()
    work[target_col] = pd.to_numeric(work[target_col], errors="coerce")
    work[actual_col] = pd.to_numeric(work[actual_col], errors="coerce")
    work = work.dropna(subset=[indicator_col, target_col, actual_col])

    if work.empty:
        return pd.DataFrame()

    rows = []
    for indicator, grp in work.groupby(indicator_col, dropna=False):
        target_values = grp[target_col].dropna()
        actual_values = grp[actual_col].dropna()
        if target_values.empty or actual_values.empty:
            continue

        # If target values are percentages/rates, use mean. For volume targets,
        # aggregate the rows. This preserves the reporting grain.
        target_value = (
            float(target_values.mean())
            if float(target_values.max()) <= 100
            else float(target_values.sum())
        )
        actual_value = (
            float(actual_values.mean())
            if target_value <= 100
            else float(actual_values.sum())
        )

        achievement = (
            actual_value / target_value * 100
            if target_value != 0 else None
        )
        gap = actual_value - target_value
        below = actual_value < target_value

        rows.append({
            "Indicator": str(indicator),
            "Data field": str(actual_col),
            "Target": target_value,
            "Actual": actual_value,
            "Achievement %": achievement,
            "Gap": gap,
            "Direction": "Higher is better",
            "Status": "Below target" if below else "At/above target",
            "Valid observations": int(actual_values.count()),
            "Missing observations": int(grp[actual_col].isna().sum()),
        })

    return pd.DataFrame(rows)


def _chat_performance_report_data(df, quality_issues=None):
    """
    Deterministic performance engine for chatbot requests such as:
    'Performance: Which indicators are below target and why?'

    Returns the full performance table, below-target subset and evidence-based
    explanations. It never claims causality from descriptive dashboard data.
    """
    result = _chat_performance_from_results_framework(df)

    if result.empty:
        result = _chat_performance_from_long_data(df)

    if result.empty:
        # Fall back to the existing target/actual engine. This is still useful
        # for datasets where the reporting grain is one record per observation.
        try:
            performance, meta = build_meal_performance(df)
        except Exception:
            performance, meta = pd.DataFrame(), {}

        if not performance.empty:
            result = performance.copy()
            result.insert(0, "Indicator", [
                f"Performance record {i + 1}"
                for i in range(len(result))
            ])
            result["Valid observations"] = 1
            result["Missing observations"] = 0
            result["Direction"] = "Higher is better"

    if result.empty:
        return {
            "status": "NOT_AVAILABLE",
            "all": pd.DataFrame(),
            "below": pd.DataFrame(),
            "report": (
                "## Performance Report\n\n"
                "The loaded dataset does not contain enough information to "
                "identify indicators below target. A target and actual value "
                "could not be reliably matched to an indicator.\n\n"
                "**Required evidence:** an indicator name plus target and "
                "actual/result values, or a configured Results Framework "
                "target that matches a loaded indicator field."
            ),
        }

    result["Achievement %"] = pd.to_numeric(result["Achievement %"], errors="coerce")
    result["Target"] = pd.to_numeric(result["Target"], errors="coerce")
    result["Actual"] = pd.to_numeric(result["Actual"], errors="coerce")
    result["Gap"] = pd.to_numeric(result["Gap"], errors="coerce")

    below_mask = result["Status"].astype(str).str.contains(
        "Below target", case=False, na=False
    )
    below = result.loc[below_mask].copy()

    # Build evidence-based explanations for "why".
    quality_text = []
    for issue in (quality_issues or []):
        if isinstance(issue, dict):
            quality_text.append(
                " ".join(str(issue.get(k, "")) for k in (
                    "Priority", "Domain", "Issue", "Column",
                    "Impact", "Recommendation"
                ))
            )
    quality_blob = " ".join(quality_text).lower()

    explanation_rows = []
    for _, row in below.iterrows():
        indicator = str(row.get("Indicator", "Indicator"))
        data_field = str(row.get("Data field", ""))
        reasons = []

        if int(row.get("Missing observations", 0) or 0) > 0:
            reasons.append(
                f"{int(row['Missing observations']):,} missing observations "
                "could reduce the reported result."
            )

        if data_field and data_field.lower() in quality_blob:
            reasons.append(
                "The data-quality findings include an issue linked to the "
                "indicator/data field."
            )

        # Do not invent a programme cause. Give management hypotheses to verify.
        if not reasons:
            reasons.append(
                "The dashboard demonstrates a target gap, but it does not "
                "contain enough causal evidence to say why the gap occurred."
            )

        reasons.append(
            "Verify reporting completeness, service delivery volume, "
            "target assumptions, denominator/eligibility definitions and "
            "local implementation constraints with the responsible team."
        )

        explanation_rows.append({
            "Indicator": indicator,
            "Why / evidence": " ".join(reasons),
        })

    if explanation_rows:
        reasons_df = pd.DataFrame(explanation_rows)
        below = below.merge(reasons_df, on="Indicator", how="left")
    else:
        below["Why / evidence"] = "No indicators are below target."

    # Management report text.
    report_lines = [
        "## 📊 Performance Report — Indicators Below Target",
        "",
        f"**Indicators assessed:** {len(result):,}",
        f"**Indicators below target:** {len(below):,}",
        "",
    ]

    if below.empty:
        report_lines.extend([
            "### Overall finding",
            "",
            "No indicator in the available target-versus-actual evidence is "
            "below target.",
            "",
            "### Management interpretation",
            "",
            "Continue routine monitoring and verify that targets, reporting "
            "completeness and indicator definitions remain appropriate.",
        ])
    else:
        report_lines.extend([
            "### Indicators below target",
            "",
        ])
        for _, row in below.iterrows():
            ach = row.get("Achievement %")
            ach_text = f"{float(ach):.1f}%" if pd.notna(ach) else "not available"
            report_lines.append(
                f"- **{row['Indicator']}** — target **{row['Target']:,.2f}**, "
                f"actual **{row['Actual']:,.2f}**, achievement **{ach_text}**, "
                f"gap **{row['Gap']:,.2f}**."
            )

        report_lines.extend([
            "",
            "### Why / evidence",
            "",
        ])
        for _, row in below.iterrows():
            report_lines.append(
                f"- **{row['Indicator']}:** {row['Why / evidence']}"
            )

        report_lines.extend([
            "",
            "### Programme-management interpretation",
            "",
            "The available data confirms a performance gap, but descriptive "
            "dashboard data alone cannot establish programme causality. "
            "Management should review the affected reporting units and periods, "
            "data completeness, denominator/eligibility rules, service delivery "
            "constraints and whether the approved target remains realistic.",
            "",
            "### Recommended actions",
            "",
            "1. Validate the target and indicator definition against the approved "
            "Results Framework/DHIS2 metadata.",
            "2. Drill down by organisation unit and reporting period to locate "
            "where the gap is concentrated.",
            "3. Check data-quality findings before making high-stakes decisions.",
            "4. Confirm operational explanations with programme and reporting "
            "teams, then record the agreed corrective action.",
        ])

    return {
        "status": "SUCCESS",
        "all": result,
        "below": below,
        "report": "\n".join(report_lines),
    }


def render_chat_performance_visual(report_data):
    """Render a guaranteed performance graph for a target-gap chat request."""
    if not isinstance(report_data, dict):
        return

    below = report_data.get("below")
    if not isinstance(below, pd.DataFrame) or below.empty:
        return

    try:
        import plotly.express as px

        plot_df = below[["Indicator", "Achievement %"]].copy()
        plot_df["Achievement %"] = pd.to_numeric(
            plot_df["Achievement %"], errors="coerce"
        )
        plot_df = plot_df.dropna(subset=["Achievement %"])

        if plot_df.empty:
            return

        plot_df = plot_df.sort_values("Achievement %", ascending=True)

        fig = px.bar(
            plot_df,
            x="Achievement %",
            y="Indicator",
            orientation="h",
            title="Indicators Below Target — Achievement vs 100% Target",
            text="Achievement %",
        )
        fig.add_vline(
            x=100,
            line_dash="dash",
            annotation_text="Target = 100%",
            annotation_position="top",
        )
        fig.update_traces(
            texttemplate="%{text:.1f}%",
            textposition="outside",
        )
        fig.update_layout(
            template="plotly_white",
            paper_bgcolor="#ffffff",
            plot_bgcolor="#ffffff",
            font=dict(
                family="Arial, Helvetica, sans-serif",
                color="#111827",
            ),
            margin=dict(l=20, r=50, t=70, b=50),
            xaxis_title="Achievement (%)",
            yaxis_title="Indicator",
        )
        fig.update_xaxes(
            showgrid=True,
            gridcolor="#e5e7eb",
            zeroline=False,
            range=[0, max(110, float(plot_df["Achievement %"].max()) * 1.12)],
        )
        fig.update_yaxes(
            automargin=True,
        )

        st.markdown("### 📈 Performance Gap Graph")
        st.plotly_chart(
            fig,
            use_container_width=True,
            config={"displayModeBar": False, "responsive": True},
        )
        st.caption(
            "The dashed 100% line represents full target achievement. "
            "Only indicators identified as below target are plotted."
        )
    except Exception as exc:
        st.warning(f"Performance graph could not be rendered: {exc}")


def build_analysis_chat_evidence(
    df,
    source_url,
    chart_plan=None,
    quality_issues=None,
    quality_matrix=None,
    quality_summary=None,
    question="",
):
    """
    Build a compact deterministic evidence package for the chatbot.

    The previous implementation sent a broad evidence object to OpenAI. This
    version first identifies the relevant indicator(s), then sends only the
    M&E context and evidence needed for that question. This reduces API
    failures and makes indicator-specific M&E answers much more reliable.
    """
    if not isinstance(df, pd.DataFrame):
        return {}

    numeric_columns = get_numeric_columns(df)
    indicators = _chat_indicator_candidates(
        question,
        df,
        chart_plan=chart_plan,
        limit=3,
    )

    if not indicators:
        indicators = [
            c for c in (
                (chart_plan or {}).get("y_columns", [])
                if isinstance(chart_plan, dict) else []
            )
            if c in df.columns
        ][:3]

    if not indicators:
        indicators = numeric_columns[:3]

    if isinstance(chart_plan, dict):
        st.session_state["analysis_chat_x_column"] = chart_plan.get(
            "x_column", ""
        )

    dimensions = _chat_dimension_candidates(df)

    # Keep grouped evidence restricted to the relevant indicators.
    grouped_evidence = _build_chat_group_evidence(
        df,
        dimensions,
        indicators,
    )

    # Complete deterministic profile only for relevant indicators.
    indicator_context = build_chat_mne_indicator_context(
        df,
        indicators,
        quality_issues=quality_issues,
    )

    selected = []
    if isinstance(chart_plan, dict):
        for column in (
            chart_plan.get("indicator_columns", [])
            + chart_plan.get("y_columns", [])
        ):
            if column in df.columns and column not in selected:
                selected.append(column)

    current_analysis = {
        "x_column": (chart_plan or {}).get("x_column") if isinstance(chart_plan, dict) else None,
        "y_columns": (chart_plan or {}).get("y_columns", []) if isinstance(chart_plan, dict) else [],
        "aggregation": (chart_plan or {}).get("aggregation") if isinstance(chart_plan, dict) else None,
        "chart_types": (chart_plan or {}).get("chart_labels") if isinstance(chart_plan, dict) else [],
    }

    return {
        "source_url": str(source_url or ""),
        "dataset": {
            "rows": int(len(df)),
            "columns": int(len(df.columns)),
            "column_names": [str(c) for c in df.columns],
        },
        "current_analysis": current_analysis,
        "relevant_indicators": indicators,
        "indicator_m_and_e_context": indicator_context,
        "quality_summary": quality_summary or {},
        "quality_issues": (quality_issues or [])[:15],
        "quality_matrix": (quality_matrix or [])[:15],
        "grouped_evidence": grouped_evidence,
    }



def _chat_report_intent(question):
    """Detect requests to generate a report from the currently loaded API/DHIS2 data."""
    q = _chat_normalize_text(question)
    report_terms = (
        "write report", "generate report", "create report", "prepare report",
        "make a report", "give me a report", "produce a report",
        "analysis report", "m and e report", "m&e report",
        "programme report", "program report", "indicator report",
        "report on this indicator", "report on these indicators",
        "summarize this indicator", "summarise this indicator",
        "write a summary", "prepare a summary",
    )
    return any(term in q for term in report_terms)


def _chat_external_research_requested(question):
    """Detect questions that explicitly ask for external/UN/WHO evidence."""
    q = str(question or "").lower().strip()
    triggers = [
        "un report", "un reports", "un publication", "un publications",
        "un agency", "un agencies", "un guideline", "un guidelines",
        "un recommendation", "un recommendations", "un evidence",
        "un data", "un statistics", "un study", "un studies",
        "who report", "who reports", "who guideline", "who guidelines",
        "who recommendation", "who recommendations", "who evidence",
        "unicef", "unfpa", "who ", "world health organization",
        "united nations", "dhis2 guidance", "dhis2 guideline",
        "global guideline", "international guideline", "international report",
        "latest report", "recent report", "current report", "published report",
        "according to un", "according to the un", "according to who",
        "according to unicef", "according to unfpa", "according to dhis2",
        "external evidence", "external research", "research this indicator",
        "find a report", "find reports", "find a study", "find studies",
        "literature", "research evidence", "published evidence",
    ]
    return any(t in q for t in triggers)


UN_EVIDENCE_DOMAINS = [
    "un.org", "unstats.un.org", "who.int", "data.who.int",
    "unicef.org", "data.unicef.org", "unfpa.org", "data.unfpa.org",
    "undp.org", "wfp.org", "fao.org", "worldbank.org",
    "dhis2.org", "docs.dhis2.org", "nutritionintl.org",
]


def research_chat_external_question(
    question,
    indicators=None,
    current_evidence=None,
):
    """
    DANIP-NI external evidence research engine.

    IMPORTANT:
    - Used only for explicit external/UN/WHO/report/guideline/study questions.
    - Dashboard values are context only and NEVER replace external evidence.
    - Numerical dashboard/M&E calculations remain deterministic and local.
    - Uses the OpenAI Responses API built-in web_search tool.
    """

    if client is None:
        return {
            "status": "DISABLED",
            "source": "UN_WHO_EXTERNAL_RESEARCH",
            "text": (
                "External research is unavailable because OPENAI_API_KEY "
                "is not configured."
            ),
            "sources": [],
        }

    question = str(question or "").strip()
    if not question:
        return {
            "status": "ERROR",
            "source": "UN_WHO_EXTERNAL_RESEARCH",
            "text": "No external research question was provided.",
            "sources": [],
        }

    indicators = indicators or []

    indicator_text = "\n".join(
        f"- {str(indicator)}" for indicator in indicators[:5]
    ) or "- No dashboard indicator was confidently identified."

    prompt = f"""
You are the DANIP-NI External Evidence Research Assistant.

The user explicitly requested external evidence.
You MUST use web search for this request.
Do NOT answer this request from the dashboard data.

USER QUESTION:
{question}

CURRENT DASHBOARD INDICATOR NAMES (CONTEXT ONLY):
{indicator_text}

RESEARCH PRIORITY:
1. United Nations official publications and agencies
2. WHO
3. UNICEF
4. UNFPA
5. UN Statistics
6. World Bank where relevant
7. DHIS2 official documentation where relevant
8. Nutrition International where relevant

For maternal health / antenatal care questions, prioritize WHO, UNICEF,
UNFPA and United Nations sources.

If the question concerns pregnant women attending ANC-1 within the first
12 weeks of pregnancy, search equivalent concepts including:
- antenatal care in the first trimester
- first antenatal care contact before 12 weeks
- early antenatal care
- ANC1 first trimester
- first antenatal care visit within 12 weeks
- early initiation of antenatal care
- antenatal care before 12 weeks

MATCHING RULES:

EXACT MATCH means the external source supports substantially the same:
- population
- indicator concept
- timing
- measurement definition
- numerator/denominator where available

RELATED MATCH means the source is conceptually relevant but differs in
population, timing, definition, numerator, denominator or measurement.

Never describe a RELATED MATCH as an EXACT MATCH.

If no exact source can be verified, explicitly state:
"No verified exact UN report found."
Then provide only clearly labelled related official evidence.

DO NOT:
- use dashboard values as external evidence
- invent statistics
- invent targets
- invent indicator definitions
- invent publication titles
- invent URLs
- change or cap dashboard values
- recalculate or replace dashboard values
- claim that a related indicator is identical to the dashboard indicator
- claim programme causality from descriptive evidence

SOURCE RULE:
Prefer official domains such as:
- un.org
- who.int
- data.who.int
- unicef.org
- data.unicef.org
- unfpa.org
- data.unfpa.org
- unstats.un.org
- worldbank.org
- dhis2.org
- docs.dhis2.org
- nutritionintl.org

ANSWER FORMAT:

## 🌐 External Evidence

State clearly that the answer is based on external web research.

## UN / WHO Evidence

For each important source provide:

**Organization:**
**Report / publication:**
**Year/date:**
**Match:** EXACT MATCH or RELATED MATCH
**Relevant evidence:**
**Why it is relevant:**

## 📌 Indicator Definition

Give the externally supported definition when available.
If the exact dashboard definition cannot be verified, say so explicitly.

## 🧭 M&E Relevance

Explain the relevance to monitoring, programme performance,
service utilisation, programme management and indicator interpretation.
Do not invent programme targets.

## 🔗 Sources

Provide the official source URLs returned by web search.
If no credible source is found, say so explicitly.
"""

    # ------------------------------------------------------------
    # Use the current Responses API web_search tool first.
    # Keep the first attempt deliberately simple. This avoids failures
    # caused by unsupported filter syntax in older OpenAI SDK versions.
    # ------------------------------------------------------------
    # OpenAI currently exposes the stable Responses API web-search tool as
    # ``web_search``. Keep the older ``web_search_preview`` as a compatibility
    # fallback for environments whose SDK/API endpoint still exposes only the
    # preview tool.
    search_attempts = [
        (
            "web_search",
            {
                "type": "web_search",
                "search_context_size": "high",
            },
        ),
        (
            "web_search_preview",
            {
                "type": "web_search_preview",
                "search_context_size": "high",
            },
        ),
    ]

    api_errors = []

    for attempt_name, search_tool in search_attempts:
        try:
            response = client.responses.create(
                model=OPENAI_MODEL,
                tools=[search_tool],
                tool_choice="required",
                input=prompt,
            )

            answer = (
                getattr(response, "output_text", None) or ""
            ).strip()

            if not answer:
                api_errors.append(
                    f"{attempt_name}: empty response"
                )
                continue

            # ----------------------------------------------------
            # Extract URLs from the Responses API output.
            # The answer itself is still returned even if URL
            # extraction is not supported by the installed SDK.
            # ----------------------------------------------------
            urls = []

            try:
                output_items = getattr(response, "output", []) or []

                for item in output_items:
                    item_type = getattr(item, "type", "")

                    if item_type == "web_search_call":
                        action = getattr(item, "action", None)
                        if action is not None:
                            for src in (
                                getattr(action, "sources", []) or []
                            ):
                                url = getattr(src, "url", None)
                                if url and url not in urls:
                                    urls.append(url)

                    content_items = getattr(item, "content", []) or []

                    for content_item in content_items:
                        annotations = getattr(
                            content_item,
                            "annotations",
                            [],
                        ) or []

                        for annotation in annotations:
                            url = getattr(annotation, "url", None)
                            if url and url not in urls:
                                urls.append(url)

            except Exception as url_error:
                api_errors.append(
                    f"{attempt_name}: URL extraction warning: {url_error}"
                )

            return {
                "status": "SUCCESS",
                "source": "UN_WHO_EXTERNAL_RESEARCH",
                "text": answer,
                "sources": urls[:15],
                "search_method": attempt_name,
            }

        except Exception as exc:
            message = str(exc)
            api_errors.append(
                f"{attempt_name}: {message}"
            )

            lower = message.lower()

            # These failures will not be fixed by changing the search
            # tool syntax, so stop immediately.
            if any(
                token in lower
                for token in (
                    "invalid_api_key",
                    "incorrect api key",
                    "authentication",
                    "unauthorized",
                    "401",
                    "insufficient_quota",
                    "credit_balance_exhausted",
                    "429",
                    "rate limit",
                )
            ):
                break

    error_text = "\n\n".join(api_errors)[-6000:]

    return {
        "status": "ERROR",
        "source": "UN_WHO_EXTERNAL_RESEARCH",
        "text": (
            "### 🌐 External research could not be completed\n\n"
            "DANIP-NI detected this as an external UN/WHO research "
            "question, but the OpenAI web-search request failed.\n\n"
            "**Technical details:**\n"
            f"```text\n{error_text}\n```\n\n"
            "The dashboard data was NOT substituted for the requested "
            "external evidence."
        ),
        "sources": [],
        "error": error_text,
    }

def research_mne_external_context(question, indicators=None, danip_evidence=None, rag_context=None):
    """Automatically retrieve authoritative external M&E context for every analysis question.

    Dashboard/DHIS2 values remain the numerical source of truth. External web evidence is
    used only for indicator meaning, programme relevance, standards/guidance and context.
    """
    if client is None:
        return {
            "status": "DISABLED",
            "sources": [],
            "text": "No external source could be queried because OPENAI_API_KEY is not configured.",
        }

    indicators = indicators or []
    indicator_text = "\n".join(f"- {str(x)}" for x in indicators[:5]) or "- No specific indicator confidently identified."

    # The external layer receives the actual DANIP evidence and internal KM context.
    # This is critical for a true comparison: external search must know exactly what
    # DANIP measured before it decides whether an outside source is comparable.
    danip_payload = danip_evidence or {}
    km_payload = rag_context or {}

    prompt = f"""
You are the THIRD and final evidence layer in a strict three-level DANIP M&E search hierarchy.

SEARCH ORDER:
1. INTERNAL DANIP / DHIS2 — source of truth for observed programme values.
2. INTERNAL KM / ISG INDICATOR COMPENDIUM — source of truth for official internal definitions and metadata.
3. EXTERNAL AUTHORITATIVE SOURCES — UNICEF, WHO, UN, World Bank and similar sources.

The user explicitly requested external evidence or comparison. Use web search.
Your job is NOT to produce a generic external summary. Your job is to determine whether
a requested external source contains evidence that can actually be compared with the current DANIP result.

USER QUESTION:
{question}

DANIP INDICATORS IDENTIFIED:
{indicator_text}

LEVEL 1 — CURRENT DANIP / DHIS2 EVIDENCE:
{safe_json_dumps(danip_payload)}

LEVEL 2 — INTERNAL KM / ISG COMPENDIUM:
{_rag_context_text(km_payload) if km_payload else "No internal KM passage was retrieved."}

EXTERNAL SEARCH PRIORITY:
1. Explicitly requested organisation/source (for example UNICEF Ethiopia).
2. Requested country/geography.
3. Requested year/reporting period (for example 2026 / this year).
4. WHO / UNICEF / UN / UNFPA / World Bank authoritative sources.

COMPARABILITY TEST — REQUIRED:
Before reporting an external number, compare all of these:
- indicator concept/name
- population
- geography
- reporting period/year
- numerator and denominator, when applicable
- measurement unit
- coverage/count/rate definition

Classify the external evidence as:
- DIRECTLY COMPARABLE: materially aligned on the above dimensions.
- RELATED BUT NOT DIRECTLY COMPARABLE: relevant, but one or more dimensions differ.
- NO VERIFIED MATCH: no suitable authoritative evidence found.

IMPORTANT:
- Never invent an external number.
- Never estimate an external number from another indicator.
- Never treat IFA-or-MMS as MMS-only.
- Never treat a regional value as a national value.
- Never treat a target as an achieved result.
- Never change, cap, replace or recalculate the DANIP value.
- If no directly comparable value exists, explicitly return: NO DIRECTLY COMPARABLE EXTERNAL VALUE FOUND.
- If a related source exists, report its actual value and explain the mismatch.
- Include organisation, report/title, publication date/year, geography, value/unit, match status, comparison note and source URL.

Return concise structured evidence suitable for insertion into a DANIP answer.
"""

    api_errors = []

    # Primary current Responses API web-search tool.
    try:
        response = client.responses.create(
            model=OPENAI_MODEL,
            tools=[{
                "type": "web_search",
                "search_context_size": "high",
                "filters": {"allowed_domains": EXTERNAL_EVIDENCE_DOMAINS},
            }],
            input=prompt,
        )
        answer = (response.output_text or "").strip()
        urls = _extract_response_urls(response)
        if answer:
            return {"status":"SUCCESS","sources":urls[:12],"text":answer,"engine":"web_search"}
        api_errors.append("web_search returned no output text")
    except Exception as exc:
        api_errors.append("web_search: " + str(exc)[-1800:])

    # SDK compatibility fallback.
    try:
        response = client.responses.create(
            model=OPENAI_MODEL,
            tools=[{"type": "web_search_preview"}],
            input=prompt,
        )
        answer = (response.output_text or "").strip()
        urls = _extract_response_urls(response)
        if answer:
            return {"status":"SUCCESS","sources":urls[:12],"text":answer,"engine":"web_search_preview"}
        api_errors.append("web_search_preview returned no output text")
    except Exception as exc:
        api_errors.append("web_search_preview: " + str(exc)[-1800:])

    error_text = "\n\n".join(api_errors)[-5000:]
    return {
        "status":"ERROR",
        "sources":[],
        "text":"External evidence search could not be completed.\n\n" + error_text,
        "error":error_text,
    }


# ============================================================
# INDEPENDENT ISG INDICATOR COMPENDIUM RAG
# ============================================================
# RAG is intentionally independent from DHIS2/API loading.
# It supplies authoritative organizational indicator/M&E knowledge.
# DHIS2 remains the source of current numerical observations.
# ============================================================

RAG_SOURCE_NAME = "ISG Indicator Compendium"
RAG_GOOGLE_DOC_URL = (
    "https://docs.google.com/document/d/"
    "159IpWlCdgzCp1GOckjeux93_IrkFx7pf/edit"
)
RAG_KNOWLEDGE_FOLDER = os.path.join(BASE_DIR, "rag_knowledge")
RAG_SOURCES_FILE = os.path.join(RAG_KNOWLEDGE_FOLDER, "rag_sources.txt")
RAG_TOP_K = 8
RAG_CHUNK_WORDS = 220
RAG_CHUNK_OVERLAP = 40


def _rag_normalize(text):
    text = str(text or "")
    text = text.replace("\u00a0", " ")
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _rag_docx_text(path):
    """Extract paragraphs AND tables from a local Word compendium."""
    try:
        from docx import Document
        doc = Document(path)
        parts = []
        for p in doc.paragraphs:
            t = _rag_normalize(p.text)
            if t:
                parts.append(t)
        for table in doc.tables:
            for row in table.rows:
                cells = [_rag_normalize(c.text) for c in row.cells]
                cells = [c for c in cells if c]
                if cells:
                    parts.append(" | ".join(cells))
        return _rag_normalize("\n".join(parts))
    except Exception as exc:
        return f""


def _rag_google_doc_text(url):
    """Read a public Google Doc through its text export endpoint."""
    m = re.search(r"/document/d/([A-Za-z0-9_-]+)", str(url or ""))
    if not m:
        return ""
    doc_id = m.group(1)
    export_url = f"https://docs.google.com/document/d/{doc_id}/export?format=txt"
    try:
        r = requests.get(export_url, timeout=30, allow_redirects=True)
        if r.status_code == 200 and r.text.strip():
            return _rag_normalize(r.text)
    except Exception:
        pass
    return ""


def _rag_sources():
    """Return configured local files and direct Google Doc sources."""
    sources = []
    if os.path.isdir(RAG_KNOWLEDGE_FOLDER):
        for name in sorted(os.listdir(RAG_KNOWLEDGE_FOLDER)):
            if name == "rag_sources.txt":
                continue
            path = os.path.join(RAG_KNOWLEDGE_FOLDER, name)
            if os.path.isfile(path) and name.lower().endswith((
                ".txt", ".md", ".csv", ".tsv", ".docx", ".pdf"
            )):
                sources.append((name, path))
    # Direct authoritative source requested by the user. This is NOT a folder scan.
    sources.append((RAG_SOURCE_NAME, RAG_GOOGLE_DOC_URL))
    if os.path.isfile(RAG_SOURCES_FILE):
        try:
            for line in Path(RAG_SOURCES_FILE).read_text(encoding="utf-8").splitlines():
                line=line.strip()
                if line and not line.startswith("#") and line not in [x[1] for x in sources]:
                    if line.startswith("http"):
                        sources.append((RAG_SOURCE_NAME, line))
        except Exception:
            pass
    return sources


def _rag_file_text(path):
    lower = str(path).lower()
    try:
        if lower.endswith(".docx"):
            return _rag_docx_text(path)
        if lower.endswith(".pdf"):
            try:
                import pypdf
                reader = pypdf.PdfReader(path)
                return _rag_normalize("\n".join((p.extract_text() or "") for p in reader.pages))
            except Exception:
                return ""
        return _rag_normalize(Path(path).read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return ""


def _rag_chunk_text(text, source, chunk_words=RAG_CHUNK_WORDS, overlap=RAG_CHUNK_OVERLAP):
    words = _rag_normalize(text).split()
    if not words:
        return []
    chunks=[]
    step=max(1, chunk_words-overlap)
    for i in range(0, len(words), step):
        part=" ".join(words[i:i+chunk_words]).strip()
        if part:
            chunks.append({"source": source, "text": part})
        if i+chunk_words >= len(words):
            break
    return chunks


def _rag_load_knowledge():
    """Load and cache the indicator compendium and other local knowledge."""
    signature=[]
    for source, location in _rag_sources():
        if str(location).startswith("http"):
            signature.append((source, location))
        elif os.path.exists(location):
            try:
                signature.append((source, location, os.path.getmtime(location), os.path.getsize(location)))
            except Exception:
                signature.append((source, location))
    key=hashlib.sha256(repr(signature).encode()).hexdigest()
    cached=st.session_state.get("rag_knowledge_cache")
    if isinstance(cached, dict) and cached.get("key") == key:
        return cached.get("chunks", []), cached.get("warnings", [])

    chunks=[]; warnings=[]
    for source, location in _rag_sources():
        text=""
        if str(location).startswith("http"):
            text=_rag_google_doc_text(location)
            if not text:
                warnings.append(f"Could not retrieve {source} from the configured Google Doc URL.")
        else:
            text=_rag_file_text(location)
            if not text:
                warnings.append(f"Could not read local RAG source: {source}")
        chunks.extend(_rag_chunk_text(text, source))

    st.session_state["rag_knowledge_cache"]={"key":key,"chunks":chunks,"warnings":warnings}
    return chunks, warnings


def _rag_terms(text):
    return set(re.findall(r"[a-z0-9]{2,}", str(text or "").lower()))


def retrieve_rag_context(question, indicators=None, top_k=RAG_TOP_K):
    chunks, warnings = _rag_load_knowledge()
    q_terms=_rag_terms(question)
    extra=_rag_terms(" ".join(str(x) for x in (indicators or [])))
    q_terms |= extra
    if not chunks:
        return {"chunks":[],"warnings":warnings,"source_name":RAG_SOURCE_NAME}
    scored=[]
    for c in chunks:
        terms=_rag_terms(c["text"])
        overlap=len(q_terms & terms)
        exact=0
        qlow=str(question or "").lower()
        tlow=c["text"].lower()
        for phrase in re.findall(r"\b[a-z0-9][a-z0-9 #:%()\-/]{3,80}\b", qlow):
            phrase=phrase.strip()
            if len(phrase)>5 and phrase in tlow:
                exact += 8
        score=overlap + exact
        if score>0:
            scored.append((score,c))
    scored.sort(key=lambda x:x[0], reverse=True)
    return {
        "chunks":[c for _,c in scored[:top_k]],
        "warnings":warnings,
        "source_name":RAG_SOURCE_NAME,
    }


def _rag_context_text(result):
    parts=[]
    for i,c in enumerate((result or {}).get("chunks",[]),1):
        parts.append(f"[RAG {i} | {c.get('source','unknown')}]\n{c.get('text','')}")
    return "\n\n".join(parts)


# ============================================================
# STRUCTURED ISG RESULT-AREA RESPONSES
# ============================================================
# The compendium contains result-area tables.  For questions asking for the
# indicators within Impact Result 1000, return the source-defined list as a
# real table instead of asking the LLM to reconstruct a table from fragmented
# retrieval chunks.  This mapping is transcribed from the supplied ISG
# Indicator Compendium source and is only used for the exact result area.
# ============================================================

ISG_RESULT_AREA_INDICATORS = {
    "1000": [
        "# of cases of anaemia averted (sex- and age disaggregated where appropriate)",
        "# of deaths averted in girls and boys",
        "# of children born with higher IQ and improved ability to learn",
        "# of cases of LBW averted in newborn girls and boys",
        "# of stunting cases averted in girls and boys",
        "# of NTDs averted in newborn girls and boys",
        "# disability adjusted life years averted (DALY)",
        "# of children who receive ~ 1 additional year of schooling",
        "# of dollars of health care costs saved in countries by preventing disabilities and disease",
        "# of out-of-pocket expenses saved to individuals and families by preventing disabilities and disease",
        "# of economic losses averted due to disease prevented and lives saved",
        "# of health care and out-of-pocket costs saved",
    ]
}


def _chat_result_area_table(question, rag=None):
    """Return a source-grounded markdown table for a requested ISG result area."""
    q = str(question or "").lower()
    asks_for_indicators = any(term in q for term in (
        "indicator", "indicators", "within", "under", "listed", "list"
    ))
    asks_for_result = any(term in q for term in (
        "result area", "result statement", "impact result", "result 1000", "1000:"
    ))
    if not (asks_for_indicators and asks_for_result and "1000" in q):
        return ""

    rows = ISG_RESULT_AREA_INDICATORS.get("1000", [])
    if not rows:
        return ""

    lines = [
        "### Impact Result 1000 — Indicators",
        "",
        "| Indicator |",
        "|---|",
    ]
    lines.extend(f"| {item} |" for item in rows)
    lines.extend([
        "",
        "**Result statement:** 1000: Improved survival, health and wellbeing of women, newborns, children, and adolescent girls in low-and-middle-income countries.",
        "",
        f"*Source: {RAG_SOURCE_NAME}.*"
    ])
    return "\n".join(lines)


def _chat_danip_current_analysis_intent(question, df):
    """Return True when the user question can be answered from the loaded DANIP dataset.

    Matching is deliberately conservative: an explicit indicator code/name in the
    question, or a strong token overlap with a numeric DANIP indicator column,
    is enough to treat the request as DANIP analysis.
    """
    if not isinstance(df, pd.DataFrame) or df.empty:
        return False

    q = _chat_normalize_text(question)
    if not q:
        return False

    # Normalize punctuation so codes such as 1300(iii).02 and 1300 iii 02
    # can be matched consistently.
    q_compact = re.sub(r"\s+", "", q)
    q_tokens = set(q.split())

    for col in df.columns:
        col_text = str(col)
        name = _chat_normalize_text(col_text)
        if not name:
            continue

        name_compact = re.sub(r"\s+", "", name)

        # Exact indicator-name match.
        if name in q or q in name:
            return True

        # Explicit indicator-code match, e.g. 1300(iii).02.
        code_match = re.search(
            r"\b\d{3,4}\s*\(?[ivxIVX]{1,5}\)?\s*\.?\s*\d{1,3}\b",
            col_text,
        )
        if code_match:
            code = _chat_normalize_text(code_match.group(0))
            if code and (code in q or re.sub(r"\s+", "", code) in q_compact):
                return True

        # Strong token overlap for numeric indicator columns.
        if col not in get_numeric_columns(df):
            continue
        name_tokens = set(name.split())
        overlap = q_tokens & name_tokens
        if len(overlap) >= 3:
            return True
        if len(overlap) >= 2 and any(
            t in overlap for t in (
                "children", "women", "pregnant", "zinc", "ors", "diarrhoea",
                "diarrhea", "wifa", "vas", "mms", "received", "consumed",
                "coverage", "number", "additional",
            )
        ):
            return True

    return False


def _chat_requires_current_data(question):
    q=str(question or "").lower()
    terms=(
        "current", "latest", "reported", "value", "values", "performance",
        "trend", "compare", "comparison", "country", "countries", "period",
        "actual", "target", "achievement", "coverage rate", "dashboard",
        "dhis2", "api", "how many", "how much", "increase", "decrease",
        "highest", "lowest", "below target", "above target", "data quality",
        "data loaded", "report from the data", "using the data"
    )
    return any(t in q for t in terms)


def _chat_is_rag_or_me_knowledge(question):
    q=str(question or "").strip().lower()
    if not q:
        return False
    explicit=(
        "according to the compendium", "from the compendium", "indicator compendium",
        "from rag", "rag knowledge", "knowledge base", "official definition",
        "official indicator", "indicator definition", "indicator definitions",
        "numerator", "denominator", "formula", "result statement", "results framework",
        "what is an indicator", "what does this indicator mean", "define indicator",
        "m&e", "monitoring and evaluation", "monitoring and evaluation means",
        "data quality", "logframe", "results chain", "theory of change", "indicator framework"
    )
    knowledge_verbs=("define ","definition of ","explain ","what is ","what are ","describe ","meaning of ","how is it calculated")
    source_terms=("indicator","result","measure","vas","mnhn","wifa","usi","mms","nourish","m&e")
    if _chat_requires_current_data(q):
        # Current-data questions must never be routed to RAG-only merely because
        # they contain words such as "indicator" or "what is".
        current_phrases=("current","latest","reported","value","performance","trend","country","period","dhis2","dashboard","data")
        if any(x in q for x in current_phrases) and not any(x in q for x in ("according to the compendium","from the compendium","official definition","indicator definition","numerator","denominator","formula")):
            return False
    return any(x in q for x in explicit) or (any(v in q for v in knowledge_verbs) and any(t in q for t in source_terms))


def _chat_mixed_rag_analysis_intent(question):
    q=str(question or "").lower()
    knowledge=("according to the compendium","from the compendium","indicator definition","official definition","numerator","denominator","formula","guidance","target definition")
    analysis=("current","latest","reported","performance","trend","data","value","coverage","country","organisation","organization","period","dhis2","dashboard","actual")
    return any(k in q for k in knowledge) and any(a in q for a in analysis)


def _chat_compendium_table_request(question):
    """Detect requests where compendium content should be displayed as a table."""
    q = str(question or "").lower()
    return any(x in q for x in (
        "show the compendium", "show all compendium", "all compendium",
        "compendium table", "show as a table", "table format", "in table",
        "list the indicators", "list all indicators", "show the indicators",
        "indicators within", "indicators under", "indicators in", "indicator list",
        "result areas", "result area", "results framework", "all indicators",
    ))


def _chat_extract_compendium_indicator_rows(rag):
    """Extract source-defined coded indicator rows from retrieved compendium text.

    This is deliberately conservative: it only emits text that is visibly present
    in the retrieved source. It does not invent missing definitions or formulas.
    """
    context = _rag_context_text(rag)
    if not context:
        return []

    # Codes used in the supplied compendium include 1100, 1130c.(i),
    # 1210(i).01, 1210(i).15, 1200.(vi), etc.
    code_pat = re.compile(
        r"(?<![A-Za-z0-9])(\d{4}(?:[a-z])?(?:\([ivx]+\))?(?:\.(?:\d+|[a-z]+))?(?:\([ivx]+\))?)(?![A-Za-z0-9])",
        re.I,
    )

    rows = []
    seen = set()
    for block in re.split(r"\n\s*\n", context):
        clean = re.sub(r"\[RAG\s+\d+\s*\|[^\]]+\]\s*", "", block).strip()
        if not clean:
            continue
        matches = list(code_pat.finditer(clean))
        if not matches:
            continue
        for i, m in enumerate(matches):
            code = m.group(1)
            # Ignore dates/years and obvious non-indicator years.
            if code in {"2025", "2030"}:
                continue
            tail_end = matches[i + 1].start() if i + 1 < len(matches) else len(clean)
            fragment = clean[m.end():tail_end].strip(" :.-")
            fragment = re.sub(r"\s+", " ", fragment)
            if not fragment:
                continue
            # Remove table/section boilerplate that is not part of the indicator.
            fragment = re.sub(r"^(?:\(total\)\s*)", "", fragment, flags=re.I)
            fragment = fragment.strip()
            key = (code.lower(), fragment.lower())
            if key in seen:
                continue
            seen.add(key)
            rows.append((code, fragment))

    return rows


def _chat_compendium_table(question, rag):
    """Render retrieved ISG compendium material as a readable Markdown table."""
    # Keep the exact source-defined Impact Result 1000 table.
    structured = _chat_result_area_table(question, rag)
    if structured:
        return structured

    rows = _chat_extract_compendium_indicator_rows(rag)
    if not rows:
        return ""

    q = str(question or "").lower()
    # If a specific result code is requested, keep matching rows plus its parent.
    result_codes = re.findall(r"\b(\d{4})\b", q)
    if result_codes:
        wanted = set(result_codes)
        filtered = []
        for code, text in rows:
            base = re.match(r"(\d{4})", code)
            if base and base.group(1) in wanted:
                filtered.append((code, text))
        if filtered:
            rows = filtered

    lines = [
        "### ISG Indicator Compendium — Structured View",
        "",
        "| Indicator code | Indicator / compendium content |",
        "|---|---|",
    ]
    for code, text in rows:
        text = text.replace("|", "\\|")
        lines.append(f"| {code} | {text} |")
    lines.extend([
        "",
        f"*Source: {RAG_SOURCE_NAME}. The table contains only content retrieved from the compendium; no missing details have been inferred.*",
    ])
    return "\n".join(lines)



def _chat_parameter_table_prompt(question, context):
    """Return a compact two-column Parameter/Description answer matching the
    ISG Indicator Compendium layout supplied by the user."""
    return f"""
You are the ISG Indicator Compendium assistant.
Use ONLY the retrieved compendium text below.

OUTPUT FORMAT IS MANDATORY:
Return ONLY a Markdown table with exactly two columns:
| Parameter | Description |
|---|---|
| Intervention | ... |
| Indicator name | ... |
| PMF expected results statement | ... |
| Indicator code | ... |
| Rolls into | ... |
| Akin indicators | ... |
| Definition | ... |
| Purpose/ objective | ... |
| Relevance | ... |
| Measurement Unit | ... |
| Data Source | ... |
| Data Collection Frequency | ... |
| Baseline | ... |
| Target | ... |
| Calculation Method | ... |
| Interpretation | ... |
| Use/Application | ... |
| Data quality considerations | ... |
| Reporting and Dissemination | ... |
| References | ... |
| Version | ... |
| Date of update | ... |

RULES:
- Left column MUST contain the parameter/dimension name.
- Right column MUST contain the answer from the compendium.
- Do NOT output [RAG 1], [RAG 2], source chunks, citations, or raw retrieval text.
- Do NOT add a prose introduction or conclusion.
- Include only parameters supported by the retrieved source.
- Preserve the compendium terminology; do not invent or correct content.
- Keep each Description concise while preserving the key source meaning.
- If the user asks for a short/summary answer, include only the most relevant parameters.
- If multiple indicators are requested, create a separate two-column table for each indicator and put the indicator name as a Markdown heading above each table.
- If the user asks for an indicator list/result-area list rather than details, use the indicator-list table instead.

Question:
{question}

Retrieved compendium text:
{context}
"""


def _chat_is_indicator_detail_question(question):
    q = str(question or '').lower()
    detail_terms = (
        'definition', 'define', 'details', 'detail', 'parameters',
        'indicator information', 'indicator profile', 'how is it calculated',
        'calculation method', 'numerator', 'denominator', 'purpose',
        'relevance', 'data source', 'measurement unit', 'target',
        'interpretation', 'use/application', 'data quality', 'indicator code',
        'explain this indicator', 'about this indicator', 'what is this indicator',
    )
    # A pasted indicator name/code should also trigger detail mode.
    indicator_code = re.search(r'\b\d{4}[a-z]?(?:\([ivx]+\))?(?:\.\d+)?\b', q, re.I)
    indicator_terms = ('indicator', 'indicator name', 'code', 'result area', 'result')
    return bool(indicator_code or any(x in q for x in detail_terms)) and (
        any(x in q for x in indicator_terms) or bool(indicator_code)
    )


def _chat_parameter_table_answer(question, rag):
    """Format retrieved compendium evidence as the exact two-column layout.
    The model is used only to map source fields into the table; the UI renders
    the returned Markdown directly, so retrieval chunks never appear to users.
    """
    context = _rag_context_text(rag)
    if not context:
        return ''
    if client is None:
        return _chat_parameter_table_fallback(context)
    prompt = _chat_parameter_table_prompt(question, context)
    try:
        response = client.responses.create(model=OPENAI_MODEL, input=prompt)
        answer = (response.output_text or '').strip()
        # Require an actual two-column Markdown table and strip accidental prose.
        if '| Parameter | Description |' in answer and '|---|' in answer:
            lines = answer.splitlines()
            table_lines = []
            started = False
            for line in lines:
                if line.strip().startswith('| Parameter | Description |'):
                    started = True
                if started and line.strip().startswith('|'):
                    table_lines.append(line.strip())
            if len(table_lines) >= 2:
                return '\n'.join(table_lines)
    except Exception:
        pass
    return _chat_parameter_table_fallback(context)


def _chat_parameter_table_from_context(question, context):
    """Render one indicator in the original ISG Parameter / Description format."""
    context = str(context or "").strip()
    if not context:
        return ""

    labels = [
        "Intervention", "Indicator name", "PMF expected results statement",
        "Indicator code", "Rolls into", "Akin indicators", "Interventions",
        "Definition", "Recommended course public sector",
        "Recommended course private sector", "Purpose/ objective",
        "Purpose/objective", "Relevance", "Measurement Unit", "Data Source",
        "Supply chain method", "Data Collection Frequency", "Baseline",
        "Target", "Routine data/HMIS", "Calculation Method", "Interpretation",
        "Use/Application", "Data quality considerations",
        "Reporting and Dissemination", "References", "Version", "Date of update",
    ]

    clean = re.sub(r"\[RAG\s+\d+\s*\|[^\]]+\]\s*", "\n", context)
    clean = clean.replace("\r\n", "\n").replace("\r", "\n")
    clean = re.sub(r"[ \t]+", " ", clean)
    clean = re.sub(r"\n{3,}", "\n\n", clean).strip()

    code_match = re.search(
        r"\b(\d{3,4}\s*\(\s*[ivxIVX]+\s*\)\s*\.?\s*\d{1,2})\b",
        str(question or ""),
    )
    if not code_match:
        code_match = re.search(r"\b(\d{3,4}\s*\.\s*\d{1,2})\b", str(question or ""))

    def norm_code(value):
        return re.sub(r"[\s.]", "", str(value or "").lower())

    requested_code = norm_code(code_match.group(1)) if code_match else ""

    # Select the most relevant retrieved passage so adjacent indicators
    # (e.g. .01, .03, .04) are not merged into the requested indicator.
    passages = [p.strip() for p in re.split(r"\n\s*\n", clean) if p.strip()]
    selected = clean
    if requested_code:
        candidates = []
        for p in passages:
            if requested_code not in norm_code(p):
                continue
            score = 0
            if re.search(r"Parameter\s+Description", p, re.I): score += 6
            if re.search(r"\bIndicator name\b", p, re.I): score += 3
            if re.search(r"\bDefinition\b", p, re.I): score += 3
            candidates.append((score, len(p), p))
        if candidates:
            candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
            selected = candidates[0][2]

    pd_pos = re.search(r"Parameter\s+Description", selected, re.I)
    if pd_pos:
        selected = selected[pd_pos.end():].strip()

    # Detect labels even when the Word table was flattened onto one line.
    label_pattern = "|".join(
        re.escape(x) for x in sorted(set(labels), key=len, reverse=True)
    )
    marker = re.compile(
        rf"(?<![A-Za-z])(?P<label>{label_pattern})(?=(?:\s*:?\s+|$))",
        re.I,
    )
    matches = list(marker.finditer(selected))
    if not matches:
        return ""

    data = {}
    for i, m in enumerate(matches):
        raw_label = m.group("label")
        canonical = next(
            x for x in labels if x.lower() == raw_label.lower()
        )
        value_start = m.end()
        if value_start < len(selected) and selected[value_start] == ":":
            value_start += 1
        value_end = matches[i + 1].start() if i + 1 < len(matches) else len(selected)
        value = re.sub(r"\s+", " ", selected[value_start:value_end]).strip(" :;-")
        if not value:
            continue
        if canonical == "Purpose/objective":
            canonical = "Purpose/ objective"
        if canonical not in data:
            data[canonical] = value

    # The code may be represented with spaces in the compendium.
    if requested_code:
        if not any(requested_code in norm_code(v) for v in data.values()):
            # Accept a strong indicator-name match if the flattened source
            # separated the code from its Indicator name field.
            q = str(question or "").lower()
            q_words = set(re.findall(r"[a-z]{4,}", q))
            i_words = set(re.findall(r"[a-z]{4,}", data.get("Indicator name", "").lower()))
            if len(q_words & i_words) < 4:
                return ""

    ordered = [x for x in labels if x in data and data[x]]
    if not ordered:
        return ""

    out = ["| Parameter | Description |", "|---|---|"]
    for label in ordered:
        out.append(f"| {label} | {data[label].replace('|', r'\\|')} |")
    return "\n".join(out)


def _chat_parameter_table_answer(question, rag):
    """Original ISG compendium breakdown: one parameter per row."""
    context = _rag_context_text(rag)
    if not context:
        return ""
    return _chat_parameter_table_from_context(question, context)


def _chat_add_danip_interpretation(result, question, current_df, chart_plan=None, quality_issues=None):
    """Add ONLY the DANIP interpretation below the original compendium table."""
    if not result or not isinstance(current_df, pd.DataFrame) or current_df.empty:
        return result
    if not _chat_is_indicator_detail_question(question):
        return result

    indicators = _chat_indicator_candidates(question, current_df, chart_plan=chart_plan, limit=3)
    if not indicators and isinstance(chart_plan, dict):
        indicators = [c for c in (chart_plan.get("y_columns") or []) if c in current_df.columns][:3]
    if not indicators:
        return result

    try:
        interpretation = _chat_local_mne_answer(
            question=question,
            df=current_df,
            indicators=indicators,
            chart_plan=chart_plan,
            quality_issues=quality_issues,
        )
    except Exception:
        interpretation = ""

    if not interpretation:
        return result

    # Keep the compendium exactly as returned; append only a separate DANIP section.
    result["text"] = (
        result.get("text", "").rstrip()
        + "\n\n---\n\n## DANIP Interpretation\n\n"
        + str(interpretation).strip()
    )
    result["danip_interpretation"] = True
    return result


def _chat_rag_knowledge_answer(question, rag):
    # Indicator-detail questions use the same Parameter / Description structure
    # used by the ISG Indicator Compendium.
    if _chat_is_indicator_detail_question(question):
        parameter_table = _chat_parameter_table_answer(question, rag)
        if parameter_table:
            return {
                "status": "RAG_PARAMETER_TABLE",
                "source": "ISG_INDICATOR_COMPENDIUM",
                "text": parameter_table,
            }

    # For list/show/table requests, use deterministic source-grounded tables.
    # This prevents the LLM from turning the compendium back into prose.
    if _chat_compendium_table_request(question):
        table = _chat_compendium_table(question, rag)
        if table:
            return {
                "status": "RAG_TABLE",
                "source": "ISG_INDICATOR_COMPENDIUM",
                "text": table,
            }

    # Prefer a deterministic structured table for result-area questions.
    structured = _chat_result_area_table(question, rag)
    if structured:
        return {
            "status": "RAG_STRUCTURED",
            "source": "ISG_INDICATOR_COMPENDIUM",
            "text": structured,
        }

    context=_rag_context_text(rag)
    if not context:
        return {
            "status":"RAG_NOT_FOUND","source":"ISG_INDICATOR_COMPENDIUM",
            "text":f"I could not find supporting content in the **{RAG_SOURCE_NAME}** knowledge base for this question. I will not invent an official definition or formula."
        }
    if client is None:
        return {
            "status":"RAG_RETRIEVED","source":"ISG_INDICATOR_COMPENDIUM",
            "text":f"### Indicator / M&E knowledge\n\nBased on the **{RAG_SOURCE_NAME}**:\n\n{context}"
        }
    prompt=f"""
You are the authoritative ISG Indicator Compendium assistant.
Answer ONLY from the retrieved compendium passages below.
Do not use DHIS2 values, general model knowledge, web knowledge, or invented definitions.
Preserve official terminology. If the passages do not support a requested detail, say it was not found.
If the question asks to list, show, summarize, compare, or present multiple compendium items, ALWAYS use a Markdown table with clear column headers.
If the question asks for an indicator definition/details/profile, ALWAYS use the compendium's Parameter / Description structure, with one parameter per row. If multiple indicators are requested, use a separate Parameter / Description table for each indicator.
Question: {question}
Retrieved compendium passages:
{context}
"""
    try:
        response=client.responses.create(model=OPENAI_MODEL,input=prompt)
        answer=(response.output_text or "").strip()
        if answer:
            return {"status":"SUCCESS","source":"ISG_INDICATOR_COMPENDIUM","text":answer}
    except Exception:
        pass
    return {"status":"RAG_RETRIEVED","source":"ISG_INDICATOR_COMPENDIUM","text":f"### Indicator / M&E knowledge\n\n{context}"}


def _chat_external_status_block(external_context, explicit_external_request=False):
    """Build a visible, deterministic Level-3 external-RAG status block."""
    if not explicit_external_request:
        return "", "NOT_REQUESTED"

    ctx = external_context or {}
    status = str(ctx.get("status", "UNKNOWN")).upper()
    text = str(ctx.get("text", "") or "").strip()
    sources = ctx.get("sources", []) or []

    lower = text.lower()
    if status == "SUCCESS":
        if "no directly comparable external value found" in lower or "no verified match" in lower:
            label = "NOT FOUND — NO DIRECTLY COMPARABLE EXTERNAL DATA"
        elif "related but not directly comparable" in lower or "not directly comparable" in lower:
            label = "FOUND — RELATED BUT NOT DIRECTLY COMPARABLE"
        elif "directly comparable" in lower:
            label = "FOUND — DIRECTLY COMPARABLE"
        else:
            label = "FOUND — EXTERNAL EVIDENCE RETURNED"
    elif status == "DISABLED":
        label = "NOT AVAILABLE — EXTERNAL SEARCH DISABLED"
    elif status == "ERROR":
        label = "SEARCH ERROR — EXTERNAL SOURCE COULD NOT BE QUERIED"
    else:
        label = "NOT FOUND — NO VERIFIED EXTERNAL EVIDENCE"

    lines = [
        "## 🌐 External RAG Analysis",
        "",
        f"**Status: {label}**",
        "",
    ]

    if text:
        lines.append(text)
        lines.append("")
    else:
        if "NOT FOUND" in label:
            lines.append("No directly comparable external value was verified from the searched authoritative sources.")
        elif "SEARCH ERROR" in label:
            lines.append("The external search could not be completed. DANIP results were not replaced or altered.")
        else:
            lines.append("No external evidence was returned.")
        lines.append("")

    if sources:
        lines.append("**External sources:**")
        for url in sources[:12]:
            lines.append(f"- {url}")
        lines.append("")

    lines.append("External evidence is contextual only and never replaces DANIP/DHIS2 observed values.")
    return "\n".join(lines), label


def ask_analysis_chatbot(
    user_question,
    df=None,
    source_url="",
    chart_plan=None,
    quality_issues=None,
    quality_matrix=None,
    quality_summary=None,
):
    """Independent M&E/RAG chatbot with strict three-level search hierarchy.

    SEARCH HIERARCHY (highest to lowest priority):
      1) Internal DANIP / DHIS2 current evidence
      2) Internal KM / ISG Indicator Compendium
      3) External authoritative evidence (UNICEF, WHO, UN, etc.)

    DANIP is always the source of truth for observed programme values.
    Internal KM explains the indicator. External evidence is used only for
    contextual validation/comparison and never replaces DANIP values.
    """
    question=str(user_question or "").strip()
    if not question:
        return None

    current_df = df if isinstance(df,pd.DataFrame) and not df.empty else st.session_state.get("nexus_chat_df")
    current_source = str(source_url or st.session_state.get("nexus_chat_source_url", "") or "").strip()

    # 1. Intent routing. External requests MUST bypass the pure-RAG early return.
    # Otherwise an indicator question containing UNICEF can be answered by KM
    # before Level 3 external research is reached.
    rag_intent=_chat_is_rag_or_me_knowledge(question)
    mixed_intent=_chat_mixed_rag_analysis_intent(question)
    current_intent=_chat_requires_current_data(question)
    explicit_external_request = _chat_external_research_requested(question)

    if rag_intent and not explicit_external_request and not mixed_intent and not (current_intent and not any(x in question.lower() for x in ("compendium","official definition","indicator definition","numerator","denominator","formula"))):
        rag=retrieve_rag_context(question, indicators=[], top_k=(50 if _chat_compendium_table_request(question) else RAG_TOP_K))
        result=_chat_rag_knowledge_answer(question,rag)
        if isinstance(current_df, pd.DataFrame) and not current_df.empty:
            result=_chat_add_danip_interpretation(result, question, current_df, chart_plan=chart_plan, quality_issues=quality_issues)
        result["rag_warnings"]=rag.get("warnings",[])
        return result

    # 2. Current-data request with no dataset loaded.
    if current_df is None or current_df.empty:
        if mixed_intent or rag_intent:
            rag=retrieve_rag_context(question, indicators=[], top_k=(50 if _chat_compendium_table_request(question) else RAG_TOP_K))
            result=_chat_rag_knowledge_answer(question,rag)
            if result:
                note="\n\n**Current DHIS2 data:** Not loaded. The compendium/M&E part of the question was answered independently."
                result["text"]=(result.get("text","")+note)
                result["source"]="ISG_INDICATOR_COMPENDIUM"
                return result
        if current_intent:
            return {"status":"NO_DHIS2_DATA","source":"NO_DHIS2_DATA","text":"This question requires current DHIS2/API data, but no dataset is loaded yet. Please load the DHIS2/API data for the current value, trend, country or performance result. Indicator definitions and general M&E questions can be answered without the API."}
        # General M&E fallback — no API needed.
        rag=retrieve_rag_context(question, indicators=[], top_k=(50 if _chat_compendium_table_request(question) else RAG_TOP_K))
        if rag.get("chunks"):
            return _chat_rag_knowledge_answer(question,rag)
        return {"status":"NO_DHIS2_DATA","source":"M_AND_E_KNOWLEDGE","text":"The chatbot is ready without a DHIS2/API link. Ask an indicator-definition, results-framework, M&E or data-quality question, or load a dataset for current numerical analysis."}

    # Keep the latest loaded dataset available across Streamlit reruns.
    st.session_state["nexus_chat_df"]=current_df
    st.session_state["nexus_chat_source_url"]=current_source

    # 3. Performance target-gap mode remains deterministic.
    if _chat_performance_intent(question):
        performance_report=_chat_performance_report_data(df=current_df,quality_issues=quality_issues)
        return {"status":performance_report.get("status","SUCCESS"),"source":"CHAT_PERFORMANCE","text":performance_report.get("report",""),"performance_report":performance_report}

    indicators=_chat_indicator_candidates(question,current_df,chart_plan=chart_plan,limit=3)
    if not indicators and isinstance(chart_plan,dict):
        indicators=[c for c in (chart_plan.get("y_columns") or []) if c in current_df.columns][:3]

    # 4. THREE-LEVEL SEARCH HIERARCHY for DANIP analysis.
    #
    # The order is strict:
    #   1) Internal DANIP / DHIS2 current evidence FIRST
    #   2) Internal KM / ISG Indicator Compendium SECOND
    #   3) External authoritative evidence THIRD
    #
    # These are supporting research layers, not competing values. DANIP remains
    # the source of truth for observed programme results.
    rag_context={"chunks":[],"warnings":[]}
    report_intent=_chat_report_intent(question)
    danip_analysis_question = bool(
        current_df is not None
        and not current_df.empty
        and (
            _chat_danip_current_analysis_intent(question, current_df)
            or current_intent
            or mixed_intent
            or report_intent
            or _chat_is_indicator_detail_question(question)
        )
    )

    # LEVEL 1 — INTERNAL DANIP / DHIS2
    # The current dataframe and deterministic evidence have already been resolved
    # above. This is always the first and authoritative numerical layer.
    danip_source_context = {
        "status": "AVAILABLE",
        "source": "DANIP_DHIS2",
        "indicator_count": len(indicators),
    }

    # LEVEL 2 — INTERNAL KM / ISG INDICATOR COMPENDIUM
    # Search KM only after the DANIP indicator candidates have been identified,
    # so retrieval is anchored to the actual DANIP question/indicator.
    if danip_analysis_question or mixed_intent or report_intent:
        rag_context=retrieve_rag_context(
            question,
            indicators=indicators,
            top_k=(50 if report_intent else RAG_TOP_K),
        )

    # Build deterministic DANIP evidence BEFORE external search. The external layer
    # must receive this evidence so it can perform a real comparability check.
    evidence=build_analysis_chat_evidence(
        df=current_df,
        source_url=current_source,
        chart_plan=chart_plan,
        quality_issues=quality_issues,
        quality_matrix=quality_matrix,
        quality_summary=quality_summary,
        question=question,
    )

    # LEVEL 3 — EXTERNAL AUTHORITATIVE EVIDENCE
    # External research is performed after DANIP + KM. It can validate/contextualize
    # the interpretation or provide an explicit comparison requested by the user.
    # It must never replace, recalculate, cap, or override DANIP observations.
    external_context={
        "status":"NOT_REQUESTED",
        "sources":[],
        "text":"No external context retrieved."
    }
    # Level 3 is mandatory whenever the user explicitly names an external source.
    if danip_analysis_question or explicit_external_request:
        try:
            external_context=research_mne_external_context(
                question=question,
                indicators=indicators,
                danip_evidence=evidence,
                rag_context=rag_context,
            ) or external_context
        except Exception as exc:
            external_context={
                "status":"ERROR",
                "sources":[],
                "text":"External context unavailable; continue using DANIP and internal KM.",
            }

    # When the user explicitly names an external source/country/report (for example
    # "compare with UNICEF Ethiopia this year"), the external result is part of the
    # requested answer rather than hidden background context.
    external_comparison_instruction = ""
    if explicit_external_request:
        external_comparison_instruction = """

EXPLICIT EXTERNAL COMPARISON REQUEST:
The user explicitly requested an external source/report. Therefore, after presenting
the DANIP result, include a clearly labelled **External comparison** section.
- Identify the requested organization (e.g. UNICEF), country (e.g. Ethiopia), and
  reporting year/time period (e.g. this year) from the question.
- Compare DANIP with the external source ONLY if the external source provides a
  materially comparable indicator, population, geography and period.
- State the external reported value exactly as found; do not invent or estimate it.
- If the external source is not directly comparable, say **No directly comparable
  UNICEF Ethiopia value was verified** and explain why briefly.
- Include the external source name, report/title and URL when available.
- Never replace the DANIP value with the external value.
"""

    local_answer=_chat_local_mne_answer(
        question=question,
        df=current_df,
        indicators=indicators,
        chart_plan=chart_plan,
        quality_issues=quality_issues,
    )
    # Never return external research as the answer for a DANIP analytical
    # question. It is context for interpretation only.

    if client is None:
        return {"status":"FALLBACK","source":"LOCAL_M_AND_E","text":local_answer}

    history=st.session_state.get("analysis_chat_messages",[])
    recent_history=[{"role":x.get("role"),"content":x.get("content")} for x in history[-6:] if isinstance(x,dict)]
    rag_text=_rag_context_text(rag_context)
    rag_block=rag_text if rag_text else "No compendium passage was retrieved for this question. Do not invent official definitions."

    prompt=f"""
You are the DANIP-NI M&E Conversational Assistant.
You are a senior Monitoring, Evaluation and Learning advisor.

RESEARCH ARCHITECTURE — STRICT THREE-LEVEL SEARCH HIERARCHY:
1. INTERNAL DANIP / DHIS2 — FIRST: identify the current indicator, period, organisation/country and observed values. This is the ONLY source of truth for DANIP numerical results.
2. INTERNAL KM / ISG INDICATOR COMPENDIUM — SECOND: use it to explain the official indicator definition, result framework, measurement, calculation, interpretation and data-quality context.
3. EXTERNAL AUTHORITATIVE SOURCES — THIRD: use UNICEF, WHO, UN and other authoritative sources for contextual validation or an explicitly requested comparison.

The search order is DANIP -> Internal KM -> External. Never allow a lower-priority source to replace a higher-priority DANIP observation.

CRITICAL OUTPUT RULE:
The final answer for a DANIP analytical question must be presented as DANIP analytics.
Do NOT replace the DANIP result with internal KM or external statistics.
Do NOT display external research results, external benchmarks, external URLs or a separate external-evidence section UNLESS the user explicitly asks for an external comparison/source/report.
When the user explicitly asks for an external comparison, show the verified external evidence in a separate **External comparison** section after the DANIP analysis. The section MUST state the DANIP value alongside the external value, match status, and the reason for comparability/non-comparability.
Do NOT display the internal KM retrieval as the answer when the user is asking what the DANIP data show.
Internal KM and external evidence are background/context unless the user explicitly requests the external comparison.

RULES:
1. Never invent, change, cap or replace a DANIP number.
2. Use the exact DANIP indicator name, organisation, period and observed values.
3. Use internal KM to understand the indicator; never invent missing official metadata.
4. Use external evidence only as contextual support; never use it to alter the DANIP value.
5. If external research is unavailable, continue normally using DANIP evidence + internal KM + general M&E expertise.
6. Distinguish observed facts from interpretation and possible explanations; do not claim causality from descriptive data.
7. The answer should follow: DANIP RESULT -> OBSERVATION -> M&E INTERPRETATION -> DATA QUALITY -> PROGRAMME IMPLICATION.
8. If the indicator is absent from the compendium, continue using the exact DANIP indicator and general M&E expertise; clearly distinguish that from official compendium metadata.
9. If asked for a report, generate it from the DANIP evidence first and use KM/external research only to contextualize the interpretation.

REQUEST TYPE:
{"DETAILED NARRATIVE REPORT" if report_intent else "NORMAL CHAT QUESTION"}

USER QUESTION:
{question}

RECENT CHAT:
{safe_json_dumps(recent_history)}

LEVEL 1 — CURRENT DANIP / DHIS2:
{safe_json_dumps(danip_source_context)}

LEVEL 2 — INTERNAL KM / ISG INDICATOR COMPENDIUM:
{rag_block}

CURRENT DHIS2 SOURCE:
{current_source or 'Current DHIS2 source not explicitly named'}

CURRENT DHIS2 / DETERMINISTIC EVIDENCE:
{safe_json_dumps(evidence)}

EXTERNAL RESEARCH CONTEXT (LEVEL 3):
{safe_json_dumps(external_context)}
EXTERNAL SEARCH STATUS: {external_context.get("status", "UNKNOWN")}
EXTERNAL SEARCH ENGINE: {external_context.get("engine", "not available") or "not available"}
EXTERNAL SOURCE URLS: {safe_json_dumps(external_context.get("sources", []))}
{external_comparison_instruction}

EXTERNAL COMPARISON OUTPUT RULE:
If external comparison was explicitly requested, do not hide the external result in the narrative.
Use this format:
## External comparison
| Dimension | DANIP | External source | Assessment |
|---|---|---|---|
| Indicator | ... | ... | ... |
| Geography | ... | ... | ... |
| Period | ... | ... | ... |
| Value | ... | ... | DIRECTLY COMPARABLE / RELATED BUT NOT DIRECTLY COMPARABLE / NO VERIFIED MATCH |
Then explain the comparison in 1-3 sentences. If the external layer returned no directly comparable value, say exactly: **NO DIRECTLY COMPARABLE EXTERNAL VALUE FOUND.** Do not invent one.

USER-FACING ANSWER REQUIREMENT:
For ordinary DANIP analytical questions, present the current DANIP/DHIS2 findings and their M&E interpretation.
When explicit_external_request is TRUE, the **External comparison** section is REQUIRED after the DANIP analysis, even if the external result is NO VERIFIED MATCH or the search failed. Never silently hide Level-3 status.

If this is a REPORT REQUEST (for example, the user asks to generate, write,
prepare, create or produce a narrative report), DO NOT give a short answer.
Generate a detailed professional M&E narrative report using the selected/current
indicators and the deterministic DHIS2 evidence. The ISG Indicator Compendium
is supporting authoritative context when retrieved; it is not a prerequisite.
If an indicator is not found in the compendium, continue the report from the
DHIS2 evidence and explicitly note that compendium metadata was unavailable for
that indicator. Never stop or refuse the report because RAG returned no match.

For a REPORT REQUEST, use a CLEAR TABLE-FIRST FORMAT. Do not return a short prose summary.
Use the following structure exactly. Tables must be real Markdown tables with a header row and separator row.

## 1. Report Scope
| Dimension | Details |
|---|---|
| Indicators | ... |
| Reporting period | ... |
| Organisation/country | ... |
| Data source | ... |
| Analysis scope | ... |

## 2. Executive Summary
| Area | Finding | Management meaning |
|---|---|---|
| Overall result | ... | ... |
| Strongest indicator | ... | ... |
| Weakest indicator | ... | ... |
| Main variation | ... | ... |
| Main data-quality consideration | ... | ... |

## 3. Indicator-by-Indicator Analysis
Cover EVERY selected indicator in ONE complete table:
| Indicator | Current/observed result | Highest OU/period | Lowest OU/period | Variation | Data-quality note | Interpretation |
|---|---:|---|---|---|---|---|
Do not omit indicators because compendium metadata was not retrieved.

## 4. Comparative Analysis
| Comparison dimension | Indicator A | Indicator B | Indicator C | Interpretation |
|---|---|---|---|---|
Include all selected indicators. Add rows for level, difference, percentage-point difference where valid, trend, OU/period drivers, exceptions and data-quality effects.

## 5. Detailed M&E Narrative
After the tables, provide 3-6 substantive paragraphs explaining the observed patterns, programme-monitoring meaning and possible explanations. Do not claim causality.

## 6. Indicator Compendium Context
For EACH selected indicator with retrieved compendium evidence, create a separate table using the official Parameter / Description structure:
| Parameter | Description |
|---|---|
| Intervention | ... |
| Indicator name | ... |
| Indicator code | ... |
| PMF expected results statement | ... |
| Rolls into | ... |
| Akin indicators | ... |
| Definition | ... |
| Purpose/ objective | ... |
| Relevance | ... |
| Measurement Unit | ... |
| Data Source | ... |
| Data Collection Frequency | ... |
| Baseline | ... |
| Target | ... |
| Calculation Method | ... |
| Interpretation | ... |
| Use/Application | ... |
| Data quality considerations | ... |
| Reporting and Dissemination | ... |
| References | ... |
| Version | ... |
| Date of update | ... |
Only include parameters actually supported by the retrieved compendium. Never invent missing values. If no match exists, use:
| Parameter | Description |
|---|---|
| Compendium status | Not found in the ISG Indicator Compendium retrieval for this report |

## 7. Data Quality Assessment
| Quality dimension | Finding | Severity | Effect on analysis | Recommended action |
|---|---|---|---|---|

## 8. Programme Management Implications
| Finding | Programme implication | Management use |
|---|---|---|

## 9. Areas Requiring Attention
| Priority area | Evidence | Why it matters | Follow-up |
|---|---|---|---|

## 10. Recommendations
| # | Recommendation | Evidence/rationale | Responsible focus |
|---:|---|---|---|

## 11. Conclusion
Provide a substantive 1-3 paragraph conclusion after the tables.

## 12. Confidence and Limitations
| Item | Assessment |
|---|---|
| Confidence | High/Medium/Low with reason |
| Data limitations | ... |
| Compendium limitations | ... |
| Interpretation limitations | ... |

IMPORTANT TABLE RULES:
- Keep tables complete, readable and detailed; do not collapse them into prose.
- Use the exact indicator names from the evidence.
- Preserve calculated values from deterministic evidence.
- Do not invent values when evidence is unavailable; write "Not available in supplied evidence".
- The report must remain detailed, not shortened into 4-6 bullets.

For a NORMAL NON-REPORT QUESTION, remain concise and use sections where useful:
**Indicator / Direct answer**
**M&E interpretation**
**Current evidence**
**Programme-management implication**
**Data quality note**
"""

    errors=[]
    models=[OPENAI_MODEL]+[m for m in ("gpt-5-mini","gpt-4.1-mini") if m and m!=OPENAI_MODEL]
    for model in models:
        try:
            response=client.responses.create(model=model,input=prompt)
            answer=(response.output_text or "").strip()
            if answer:
                external_block, external_label = _chat_external_status_block(
                    external_context, explicit_external_request=explicit_external_request
                )
                if explicit_external_request and external_block and "## 🌐 External RAG Analysis" not in answer:
                    answer = answer.rstrip() + "\n\n---\n\n" + external_block
                return {
                    "status":"SUCCESS",
                    "source":"OPENAI_M_AND_E",
                    "model":model,
                    "text":answer,
                    "sources":external_context.get("sources", []) if explicit_external_request else [],
                    "external_status":external_context.get("status", "NOT_REQUESTED"),
                    "external_label":external_label,
                    "external_engine":external_context.get("engine", ""),
                }
        except Exception as exc:
            msg=str(exc); errors.append(f"{model}: {msg}")
            low=msg.lower()
            if any(t in low for t in ("insufficient_quota","credit_balance_exhausted","rate limit","429","invalid_api_key","401","authentication")):
                break
    external_block, external_label = _chat_external_status_block(
        external_context, explicit_external_request=explicit_external_request
    )
    fallback_text = local_answer
    if explicit_external_request and external_block and "## 🌐 External RAG Analysis" not in fallback_text:
        fallback_text = fallback_text.rstrip() + "\n\n---\n\n" + external_block
    return {
        "status":"FALLBACK",
        "source":"LOCAL_M_AND_E",
        "text":fallback_text,
        "error":" | ".join(errors)[-3000:],
        "sources":external_context.get("sources", []) if explicit_external_request else [],
        "external_status":external_context.get("status", "NOT_REQUESTED"),
        "external_label":external_label,
        "external_engine":external_context.get("engine", ""),
    }


def render_analysis_chatbot(
    df=None,
    source_url="",
    chart_plan=None,
    quality_issues=None,
    quality_matrix=None,
    quality_summary=None,
):
    """Render the chatbot independently of DHIS2/API availability."""
    if isinstance(df,pd.DataFrame) and not df.empty:
        st.session_state["nexus_chat_df"]=df
        st.session_state["nexus_chat_source_url"]=str(source_url or "")
    else:
        df=st.session_state.get("nexus_chat_df")
        source_url=st.session_state.get("nexus_chat_source_url",source_url)

    chat_source=str(source_url or "").strip()
    previous=st.session_state.get("analysis_chat_source_url")
    if previous != chat_source and chat_source:
        st.session_state["analysis_chat_messages"]=[]
        st.session_state["analysis_chat_source_url"]=chat_source
    if "analysis_chat_messages" not in st.session_state:
        st.session_state["analysis_chat_messages"]=[]

    st.markdown("""
    <div class="danip-analysis-chat">
      <div class="chat-kicker">NEXUS AI · INDEPENDENT M&E ASSISTANT</div>
      <div class="chat-title">💬 Ask an Indicator or M&E Question</div>
      <div class="chat-help">
        Indicator definitions, ISG Indicator Compendium questions and general M&E questions work
        <b>without a DHIS2/API link</b>. Current values, trends and performance use the loaded DHIS2 data.
      </div>
    </div>
    """,unsafe_allow_html=True)

    if chat_source:
        st.markdown(f'<span class="danip-chat-source">🔗 Current data source: {html.escape(chat_source)}</span>',unsafe_allow_html=True)
    else:
        st.markdown('<span class="danip-chat-source">📚 Knowledge source: ISG Indicator Compendium · No DHIS2 data loaded</span>',unsafe_allow_html=True)

    for message in st.session_state["analysis_chat_messages"]:
        with st.chat_message("user" if message.get("role")=="user" else "assistant"):
            # Render assistant content as native Streamlit Markdown.  This is
            # important because the ISG compendium responses intentionally use
            # Markdown tables (Parameter | Description). Wrapping the answer in
            # an HTML div would display the table syntax as plain text.
            st.markdown(message.get("content", ""))

    question=st.chat_input("Ask: What is VAS coverage? What is Impact Result 1000? What is the numerator?",key="analysis_chat_input")
    if not question:
        return
    question=question.strip()
    if not question:
        return
    st.session_state["analysis_chat_messages"].append({"role":"user","content":question})
    with st.chat_message("user"):
        st.markdown(question)
    with st.chat_message("assistant"):
        with st.spinner("🧠 Checking the indicator compendium and M&E evidence..."):
            try:
                result=ask_analysis_chatbot(user_question=question,df=df,source_url=chat_source,chart_plan=chart_plan,quality_issues=quality_issues,quality_matrix=quality_matrix,quality_summary=quality_summary)
            except Exception as exc:
                result={"status":"ERROR","source":"CHAT","text":f"The chatbot encountered an error: {str(exc)[-1200:]}"}
        answer=(result or {}).get("text","")
        st.markdown(answer)
        if (result or {}).get("source")=="ISG_INDICATOR_COMPENDIUM":
            st.caption("📚 Source: ISG Indicator Compendium (RAG)")
        elif (result or {}).get("source") in ("LOCAL_M_AND_E","OPENAI_M_AND_E"):
            base_caption = "📊 Current numerical evidence: DHIS2/API when loaded · 📚 Indicator knowledge: ISG Indicator Compendium when relevant"
            external_label = (result or {}).get("external_label", "")
            if external_label:
                base_caption += f" · 🌐 External RAG: {external_label}"
            st.caption(base_caption)
        elif (result or {}).get("source")=="NO_DHIS2_DATA":
            st.caption("ℹ️ No DHIS2/API data is loaded; this response is limited to knowledge/M&E content.")

    st.session_state["analysis_chat_messages"].append({"role":"assistant","content":answer})


# ============================================================
# DANIP M&E MANAGEMENT HUB — SEPARATE APPLICATION TAB
# ============================================================

ME_HUB_DB_PATH = os.path.join(BASE_DIR, "danip_me_management.db")


def _me_hub_conn():
    conn = sqlite3.connect(ME_HUB_DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _me_hub_init_db():
    conn = _me_hub_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS me_programs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_name TEXT NOT NULL,
        sponsor TEXT,
        department TEXT,
        status TEXT DEFAULT 'On Track',
        calendar_year INTEGER,
        budget REAL DEFAULT 0,
        actual REAL DEFAULT 0,
        eac REAL DEFAULT 0,
        progress REAL DEFAULT 0,
        start_date TEXT,
        finish_date TEXT,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS me_issues (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_name TEXT,
        issue TEXT NOT NULL,
        priority TEXT DEFAULT 'Medium',
        owner TEXT,
        status TEXT DEFAULT 'Open',
        due_date TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS me_risks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_name TEXT,
        risk TEXT NOT NULL,
        rating TEXT DEFAULT 'Medium',
        owner TEXT,
        mitigation TEXT,
        status TEXT DEFAULT 'Open',
        due_date TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS me_changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_name TEXT,
        change_request TEXT NOT NULL,
        impact TEXT DEFAULT 'Medium',
        owner TEXT,
        status TEXT DEFAULT 'Pending',
        requested_date TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS me_workplan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_name TEXT,
        activity TEXT NOT NULL,
        indicator TEXT,
        owner TEXT,
        due_date TEXT,
        status TEXT DEFAULT 'Planned',
        evidence_link TEXT,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS me_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_name TEXT,
        indicator TEXT,
        evidence_type TEXT,
        title TEXT NOT NULL,
        source_link TEXT,
        period TEXT,
        verification_status TEXT DEFAULT 'Pending',
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS me_monthly_finance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_name TEXT,
        month TEXT,
        forecast REAL DEFAULT 0,
        actual REAL DEFAULT 0,
        budget REAL DEFAULT 0,
        eac REAL DEFAULT 0
    );
    """)
    conn.commit()
    conn.close()


def _me_hub_df(table):
    conn = _me_hub_conn()
    try:
        return pd.read_sql_query(f"SELECT * FROM {table}", conn)
    finally:
        conn.close()


def _me_hub_insert(table, values):
    conn = _me_hub_conn()
    cols = list(values.keys())
    placeholders = ",".join(["?"] * len(cols))
    sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders})"
    conn.execute(sql, [values[c] for c in cols])
    conn.commit()
    conn.close()


def _me_hub_delete(table, row_id):
    conn = _me_hub_conn()
    conn.execute(f"DELETE FROM {table} WHERE id = ?", (int(row_id),))
    conn.commit()
    conn.close()


def _me_hub_update(table, row_id, values):
    conn = _me_hub_conn()
    assignments = ", ".join([f"{k} = ?" for k in values])
    conn.execute(
        f"UPDATE {table} SET {assignments} WHERE id = ?",
        [values[k] for k in values] + [int(row_id)],
    )
    conn.commit()
    conn.close()


def _me_hub_money(value):
    try:
        value = float(value or 0)
    except Exception:
        value = 0.0
    if abs(value) >= 1_000_000:
        return f"${value / 1_000_000:.2f}M"
    if abs(value) >= 1_000:
        return f"${value / 1_000:.1f}K"
    return f"${value:,.0f}"


def _me_hub_status_class(status):
    s = str(status or "").lower()
    if "on track" in s or "complete" in s or "closed" in s:
        return "🟢"
    if "watch" in s or "attention" in s or "progress" in s or "pending" in s:
        return "🟡"
    if "trouble" in s or "off track" in s or "overdue" in s or "high" in s:
        return "🔴"
    return "⚪"



def _me_hub_find_column(df, exact=(), contains=()):
    """Find the best matching column without changing the source dataframe."""
    if df is None or df.empty:
        return None
    lookup = {str(c).strip().lower(): c for c in df.columns}
    for name in exact:
        if str(name).strip().lower() in lookup:
            return lookup[str(name).strip().lower()]
    for c in df.columns:
        n = str(c).strip().lower()
        if any(token in n for token in contains):
            return c
    return None


def _me_hub_numeric_col(df, exact=(), contains=()):
    """Find a numeric column using semantic names and numeric-content validation."""
    col = _me_hub_find_column(df, exact=exact, contains=contains)
    if col is not None:
        return col
    for c in df.columns:
        n = str(c).strip().lower()
        if any(token in n for token in contains):
            values = pd.to_numeric(df[c], errors="coerce")
            if values.notna().sum() > 0:
                return c
    return None


def _me_hub_period_dates(series):
    """Parse common DHIS2 period/date formats for management charts."""
    raw = series.astype("string").str.strip()
    parsed = pd.to_datetime(raw, errors="coerce")

    # YYYYMM
    mask = parsed.isna() & raw.str.fullmatch(r"\d{6}", na=False)
    if mask.any():
        parsed.loc[mask] = pd.to_datetime(raw.loc[mask], format="%Y%m", errors="coerce")

    # YYYYMon, e.g. 2025Jan
    mask = parsed.isna() & raw.str.fullmatch(r"\d{4}[A-Za-z]{3}", na=False)
    if mask.any():
        parsed.loc[mask] = pd.to_datetime(raw.loc[mask], format="%Y%b", errors="coerce")

    # YYYY-Qn / YYYYnQn / YYYYQn
    for pattern in [r"(\d{4})[- ]?[Qq]([1-4])", r"(\d{4})[- ]?([1-4])[Qq]"]:
        mask = parsed.isna() & raw.str.fullmatch(pattern, na=False)
        if mask.any():
            extracted = raw.loc[mask].str.extract(pattern)
            for idx, (year, quarter) in extracted.iterrows():
                try:
                    month = (int(quarter) - 1) * 3 + 1
                    parsed.loc[idx] = pd.Timestamp(int(year), month, 1)
                except Exception:
                    pass

    return parsed


def _me_hub_status_from_progress(value):
    try:
        pct = float(value)
    except Exception:
        return "Unknown"
    if pct >= 90:
        return "On Track"
    if pct >= 75:
        return "Watch"
    return "Troubled"


def _me_hub_build_api_view(api_df):
    """Create a read-only management view from the SAME dataset loaded by the API tab.

    The function deliberately does not reinterpret arbitrary DHIS2 numeric columns as
    financial values. Budget/Actual/EAC are only populated when their column names make
    the financial meaning reasonably explicit.
    """
    if not isinstance(api_df, pd.DataFrame) or api_df.empty:
        return {
            "programs": pd.DataFrame(),
            "finance": pd.DataFrame(),
            "performance": pd.DataFrame(),
            "meta": {},
        }

    df = api_df.copy()

    program_col = _me_hub_find_column(
        df,
        exact=("program name", "programme name", "program", "programme", "project name", "project"),
        contains=("program name", "programme name", "project name"),
    )
    sponsor_col = _me_hub_find_column(df, exact=("sponsor",), contains=("sponsor", "donor", "funder"))
    dept_col = _me_hub_find_column(df, exact=("department", "dept"), contains=("department",))
    status_col = _me_hub_find_column(df, exact=("program status", "programme status", "status"), contains=("program status", "programme status"))
    period_col = find_period_column(df)
    ou_col = find_ou_column(df)

    target_col = _me_hub_numeric_col(
        df,
        exact=("target", "forecast", "annual target", "planned"),
        contains=("target", "forecast", "planned"),
    )
    actual_col = _me_hub_numeric_col(
        df,
        exact=("actual", "actual value", "achievement", "value"),
        contains=("actual", "achievement"),
    )
    budget_col = _me_hub_numeric_col(
        df,
        exact=("budget", "total budget", "approved budget", "budget amount"),
        contains=("budget",),
    )
    eac_col = _me_hub_numeric_col(
        df,
        exact=("eac", "estimate at completion", "estimated at completion"),
        contains=("eac", "estimate at completion"),
    )
    start_col = _me_hub_find_column(df, exact=("start date", "start"), contains=("start date",))
    finish_col = _me_hub_find_column(df, exact=("finish date", "end date", "finish"), contains=("finish date", "end date"))

    # If a generic 'value' column is found, it is valid for performance analysis but
    # must not be silently presented as financial actuals.
    financial_actual_col = _me_hub_numeric_col(
        df,
        exact=("actual", "actual amount", "actual cost", "actual expenditure", "actual spend"),
        contains=("actual cost", "actual expenditure", "actual spend", "expenditure", "spend"),
    )

    if program_col:
        program_series = df[program_col].astype("string").fillna("Unspecified").replace("", "Unspecified")
    else:
        # Do not use an OU as a fake programme. Keep the portfolio as one transparent
        # API-sourced programme when the source does not contain programme metadata.
        program_series = pd.Series("DANIP API Portfolio", index=df.index, dtype="string")

    df["__ME_PROGRAM__"] = program_series.astype(str)
    df["__ME_TARGET__"] = _me_hub_numeric_series(df[target_col]) if target_col else np.nan
    df["__ME_PERF_ACTUAL__"] = _me_hub_numeric_series(df[actual_col]) if actual_col else np.nan
    df["__ME_BUDGET__"] = pd.to_numeric(df[budget_col], errors="coerce") if budget_col else np.nan
    df["__ME_FIN_ACTUAL__"] = pd.to_numeric(df[financial_actual_col], errors="coerce") if financial_actual_col else np.nan
    df["__ME_EAC__"] = pd.to_numeric(df[eac_col], errors="coerce") if eac_col else np.nan

    if target_col and actual_col:
        df["__ME_PROGRESS__"] = np.where(
            df["__ME_TARGET__"] > 0,
            (df["__ME_PERF_ACTUAL__"] / df["__ME_TARGET__"]) * 100.0,
            np.nan,
        )
        # Keep the observed value for analysis; only the management status is classified.
        df["__ME_PROGRESS__"] = pd.to_numeric(df["__ME_PROGRESS__"], errors="coerce")
    else:
        df["__ME_PROGRESS__"] = np.nan

    if period_col:
        df["__ME_PERIOD_RAW__"] = df[period_col].astype("string")
        df["__ME_PERIOD_DATE__"] = _me_hub_period_dates(df[period_col])
    else:
        df["__ME_PERIOD_RAW__"] = ""
        df["__ME_PERIOD_DATE__"] = pd.NaT

    if status_col:
        df["__ME_STATUS__"] = df[status_col].astype("string").fillna("Unknown")
    else:
        df["__ME_STATUS__"] = df["__ME_PROGRESS__"].map(_me_hub_status_from_progress).fillna("Data Available")

    # Calendar year is derived from period first, then from an explicit year field.
    year_col = _me_hub_find_column(df, exact=("calendar year", "year"), contains=("calendar year",))
    if year_col:
        years = pd.to_numeric(df[year_col], errors="coerce")
    else:
        years = df["__ME_PERIOD_DATE__"].dt.year
    df["__ME_YEAR__"] = years

    records = []
    for name, g in df.groupby("__ME_PROGRAM__", dropna=False):
        valid_progress = g["__ME_PROGRESS__"].dropna()
        latest_date = g["__ME_PERIOD_DATE__"].dropna().max() if g["__ME_PERIOD_DATE__"].notna().any() else pd.NaT
        latest = g if pd.isna(latest_date) else g[g["__ME_PERIOD_DATE__"] == latest_date]
        latest_progress = latest["__ME_PROGRESS__"].dropna()
        progress = float(latest_progress.mean()) if not latest_progress.empty else (float(valid_progress.mean()) if not valid_progress.empty else np.nan)

        if status_col:
            latest_status = str(latest["__ME_STATUS__"].dropna().iloc[-1]) if not latest["__ME_STATUS__"].dropna().empty else "Unknown"
        else:
            latest_status = _me_hub_status_from_progress(progress) if pd.notna(progress) else "Data Available"

        sponsor = str(g[sponsor_col].dropna().iloc[-1]) if sponsor_col and not g[sponsor_col].dropna().empty else ""
        dept = str(g[dept_col].dropna().iloc[-1]) if dept_col and not g[dept_col].dropna().empty else ""
        start = str(g[start_col].dropna().iloc[0]) if start_col and not g[start_col].dropna().empty else ""
        finish = str(g[finish_col].dropna().iloc[-1]) if finish_col and not g[finish_col].dropna().empty else ""

        records.append({
            "program_name": str(name),
            "sponsor": sponsor,
            "department": dept,
            "status": latest_status,
            "calendar_year": int(latest["__ME_YEAR__"].dropna().iloc[-1]) if not latest["__ME_YEAR__"].dropna().empty else "",
            "budget": float(g["__ME_BUDGET__"].sum()) if budget_col else np.nan,
            "actual": float(g["__ME_FIN_ACTUAL__"].sum()) if financial_actual_col else np.nan,
            "eac": float(g["__ME_EAC__"].sum()) if eac_col else np.nan,
            "progress": round(progress, 2) if pd.notna(progress) else np.nan,
            "start_date": start,
            "finish_date": finish,
            "records": int(len(g)),
        })

    programs = pd.DataFrame(records)

    # Financial monthly view only when explicit finance columns exist.
    finance = pd.DataFrame()
    if period_col and any([target_col, financial_actual_col, budget_col, eac_col]):
        finance = df[["__ME_PERIOD_RAW__", "__ME_PERIOD_DATE__", "__ME_TARGET__", "__ME_FIN_ACTUAL__", "__ME_BUDGET__", "__ME_EAC__"]].copy()
        finance = finance.rename(columns={
            "__ME_PERIOD_RAW__": "month",
            "__ME_PERIOD_DATE__": "period_date",
            "__ME_TARGET__": "forecast",
            "__ME_FIN_ACTUAL__": "actual",
            "__ME_BUDGET__": "budget",
            "__ME_EAC__": "eac",
        })
        finance = finance.groupby(["month", "period_date"], dropna=False)[["forecast", "actual", "budget", "eac"]].sum(min_count=1).reset_index()
        finance = finance.sort_values(["period_date", "month"], na_position="last")

    performance = df[["__ME_PROGRAM__", "__ME_PERIOD_RAW__", "__ME_PERIOD_DATE__", "__ME_TARGET__", "__ME_PERF_ACTUAL__", "__ME_PROGRESS__", "__ME_STATUS__"]].copy()
    performance = performance.rename(columns={
        "__ME_PROGRAM__": "program_name",
        "__ME_PERIOD_RAW__": "period",
        "__ME_PERIOD_DATE__": "period_date",
        "__ME_TARGET__": "target",
        "__ME_PERF_ACTUAL__": "actual",
        "__ME_PROGRESS__": "progress",
        "__ME_STATUS__": "status",
    })

    meta = {
        "program_col": str(program_col) if program_col else None,
        "period_col": str(period_col) if period_col else None,
        "ou_col": str(ou_col) if ou_col else None,
        "target_col": str(target_col) if target_col else None,
        "actual_col": str(actual_col) if actual_col else None,
        "budget_col": str(budget_col) if budget_col else None,
        "financial_actual_col": str(financial_actual_col) if financial_actual_col else None,
        "eac_col": str(eac_col) if eac_col else None,
        "start_col": str(start_col) if start_col else None,
        "finish_col": str(finish_col) if finish_col else None,
        "rows": int(len(df)),
        "indicators": int(len(find_indicator_like_columns(df))),
        "organisation_units": int(df[ou_col].nunique(dropna=True)) if ou_col else 0,
        "periods": int(df[period_col].nunique(dropna=True)) if period_col else 0,
        "has_finance": bool(financial_actual_col or budget_col or eac_col),
        "has_performance": bool(target_col and actual_col),
    }
    return {"programs": programs, "finance": finance, "performance": performance, "meta": meta}


def _me_hub_responsive_css():
    st.markdown("""
    <style>
    :root{--mh-navy:#101827;--mh-navy2:#182235;--mh-blue:#2563eb;--mh-red:#a51e31;--mh-border:#e5e7eb;--mh-text:#172033;--mh-muted:#64748b;--mh-bg:#f4f7fb}
    /* Common Streamlit sidebar is shared by both top-level workspaces. */
    [data-testid="stSidebar"]{display:block!important}
    section[data-testid="stMain"]{width:100%!important}
    .block-container{max-width:none!important;width:100%!important;padding-top:.65rem!important;padding-bottom:2rem!important;padding-left:1.25rem!important;padding-right:1.25rem!important}
    .app-hero{width:100%!important;max-width:none!important;box-sizing:border-box!important}
    .mh-admin-top{height:52px;background:#fff;border:1px solid var(--mh-border);border-radius:10px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;margin-bottom:12px;box-shadow:0 2px 8px rgba(15,23,42,.04)}
    .mh-brand{display:flex;align-items:center;gap:9px;font-weight:800;color:var(--mh-text);font-size:.92rem}.mh-brand-mark{width:29px;height:29px;border-radius:7px;background:var(--mh-blue);color:#fff;display:flex;align-items:center;justify-content:center}.mh-top-right{font-size:.72rem;color:var(--mh-muted)}
    .mehub-statusbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:#f8fafc;border:1px solid #dbe4ef;border-radius:9px;padding:8px 12px;margin:8px 0 14px;color:#475569;font-size:.72rem}
    .mehub-status-dot{width:9px;height:9px;border-radius:50%;background:#16a34a;box-shadow:0 0 0 3px rgba(22,163,74,.12);flex:0 0 auto}
    .mehub-status-main{font-weight:750;color:#172033}
    .mehub-status-muted{color:#64748b}

    .mh-logo{height:82px;background:#fff;border:1px solid var(--mh-border);border-radius:10px;display:flex;align-items:center;justify-content:center;margin-bottom:12px;box-shadow:0 2px 8px rgba(15,23,42,.04)}.mh-logo-placeholder{width:80%;height:45px;border:1px dashed #d4dce7;border-radius:7px;display:flex;align-items:center;justify-content:center;color:#94a3b8;font-size:.65rem;letter-spacing:.08em;text-transform:uppercase}.mh-title-card{background:#fff;border:1px solid var(--mh-border);border-radius:10px;padding:14px 16px;margin-bottom:12px}.mh-kicker{font-size:.59rem;color:#4f46e5;letter-spacing:.12em;font-weight:800;text-transform:uppercase}.mh-title{font-size:1.18rem;font-weight:800;color:var(--mh-text);margin-top:4px}.mh-help{font-size:.7rem;color:var(--mh-muted);margin-top:3px}
    /* Dashboard cards */
    div[data-testid="stMetric"]{background:#fff!important;border:1px solid var(--mh-border)!important;border-radius:9px!important;box-shadow:0 2px 7px rgba(15,23,42,.035)!important;padding:.75rem .8rem!important;min-height:78px}.mh-main [data-testid="stMetricLabel"]{font-size:.67rem!important;color:#64748b!important}.mh-main [data-testid="stMetricValue"]{font-size:1.3rem!important;color:#172033!important;font-weight:800!important}
    [data-testid="stDataFrame"]{border-radius:8px;overflow:hidden}
    /* ============================================================
       TOP-LEVEL DANIP WORKSPACE NAVIGATION
       Admin-style full-width two-option bar.
       ============================================================ */
    [data-testid="stRadio"]{
        width:100%!important;
        margin:0 0 14px 0!important;
        padding:0!important;
        background:#17374b!important;
        border-bottom:3px solid #b03a2e!important;
        border-radius:0!important;
        overflow:hidden!important;
    }
    [data-testid="stRadio"] > label{display:none!important}
    [data-testid="stRadio"] > div{
        width:100%!important;
        display:flex!important;
        flex-direction:row!important;
        flex-wrap:nowrap!important;
        gap:0!important;
        margin:0!important;
        padding:0!important;
    }
    [data-testid="stRadio"] [role="radiogroup"]{
        width:100%!important;
        display:flex!important;
        flex-direction:row!important;
        gap:0!important;
        margin:0!important;
        padding:0!important;
    }
    [data-testid="stRadio"] [role="radio"]{
        flex:1 1 50%!important;
        min-width:0!important;
        min-height:48px!important;
        margin:0!important;
        padding:0!important;
        border:0!important;
        border-radius:0!important;
        background:#17374b!important;
        color:#ffffff!important;
        cursor:pointer!important;
        display:flex!important;
        align-items:center!important;
        justify-content:center!important;
        text-align:center!important;
        font-size:.78rem!important;
        font-weight:800!important;
        white-space:nowrap!important;
        transition:background .18s ease!important;
    }
    [data-testid="stRadio"] [role="radio"]:hover{background:#244e63!important}
    [data-testid="stRadio"] [role="radio"][aria-checked="true"]{
        background:#a51e31!important;
        color:#ffffff!important;
    }
    [data-testid="stRadio"] [role="radio"] > div:first-child{
        display:none!important;
    }
    [data-testid="stRadio"] [role="radio"] p,
    [data-testid="stRadio"] [role="radio"] span{
        color:#ffffff!important;
        -webkit-text-fill-color:#ffffff!important;
        font-weight:800!important;
        margin:0!important;
    }
    [data-testid="stRadio"] [role="radio"] [data-testid="stMarkdownContainer"]{
        display:flex!important;
        align-items:center!important;
        justify-content:center!important;
    }
    /* Force workspace selector text to white across Streamlit DOM variants. */
    [data-testid="stRadio"] [role="radio"] *,
    [data-testid="stRadio"] [role="radio"] label,
    [data-testid="stRadio"] [role="radio"] label *,
    [data-testid="stRadio"] [role="radio"] [data-testid="stMarkdownContainer"] *,
    [data-testid="stRadio"] [role="radio"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stRadio"] [role="radio"] [data-testid="stMarkdownContainer"] span{
        color:#ffffff!important;
        -webkit-text-fill-color:#ffffff!important;
        opacity:1!important;
        text-shadow:none!important;
    }
    [data-testid="stRadio"] [role="radio"][aria-checked="true"] *,
    [data-testid="stRadio"] [role="radio"][aria-checked="true"] label,
    [data-testid="stRadio"] [role="radio"][aria-checked="true"] label *{
        color:#ffffff!important;
        -webkit-text-fill-color:#ffffff!important;
        opacity:1!important;
    }
    /* Keep internal M&E tabs responsive without inheriting the top-level bar style. */
    [data-testid="stTabs"] [data-baseweb="tab-list"]{overflow-x:auto;flex-wrap:nowrap;gap:2px;scrollbar-width:thin}
    [data-testid="stTabs"] [data-baseweb="tab"]{white-space:nowrap;min-width:max-content;font-size:.73rem}
    @media(max-width:900px){.block-container{padding-left:.9rem!important;padding-right:.9rem!important}.mh-top-right{display:none}.mehub-statusbar{font-size:.68rem}}
    @media(max-width:680px){section[data-testid="stMain"] [data-testid="stTabs"]:first-of-type [data-baseweb="tab"]{height:44px!important;padding:0 8px!important;font-size:.68rem!important}}
    @media(max-width:430px){section[data-testid="stMain"] [data-testid="stTabs"]:first-of-type [data-baseweb="tab"]{font-size:.61rem!important;padding:0 5px!important}}
    @media(max-width:680px){.block-container{padding-left:.6rem!important;padding-right:.6rem!important}.mh-admin-top{height:46px}.mh-logo{height:64px}.mh-logo-placeholder{height:38px;width:92%}.mehub-statusbar{padding:8px 10px}}
    @media(max-width:520px){[data-testid="stHorizontalBlock"]{flex-wrap:wrap!important;gap:.4rem!important}[data-testid="stHorizontalBlock"]>[data-testid="column"]{min-width:100%!important;flex-basis:100%!important}}
    /* ---------- COMMON SIDEBAR SHARED BY AI + M&E ---------- */
    [data-testid="stSidebar"]{display:block!important;background:#17374b!important;background-color:#17374b!important;border-right:1px solid rgba(255,255,255,.10)!important}
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"], [data-testid="stSidebar"] label, [data-testid="stSidebar"] p, [data-testid="stSidebar"] span{color:#e5e7eb!important;-webkit-text-fill-color:#e5e7eb!important}
    [data-testid="stSidebar"] .stCaption, [data-testid="stSidebar"] small{color:#94a3b8!important;-webkit-text-fill-color:#94a3b8!important}
    .common-sidebar-brand{display:flex;align-items:center;gap:10px;padding:4px 2px 14px;border-bottom:1px solid rgba(255,255,255,.10);margin-bottom:12px;font-weight:800;color:#fff!important;-webkit-text-fill-color:#fff!important}
    .common-sidebar-mark{width:30px;height:30px;border-radius:8px;background:#2563eb;color:#fff!important;display:flex;align-items:center;justify-content:center;font-weight:900}
    .common-sidebar-section{font-size:.59rem!important;letter-spacing:.12em;text-transform:uppercase;font-weight:800;color:#94a3b8!important;-webkit-text-fill-color:#94a3b8!important;margin:13px 2px 6px}
    .common-sidebar-card{padding:9px 10px;border-radius:9px;background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.08);font-size:.68rem;line-height:1.5;color:#dbe5f1!important;-webkit-text-fill-color:#dbe5f1!important}
    .common-sidebar-card b{color:#fff!important;-webkit-text-fill-color:#fff!important}
    .common-sidebar-live{background:rgba(34,197,94,.09);border-color:rgba(34,197,94,.20)}
    </style>
    """, unsafe_allow_html=True)


def _me_hub_numeric_series(series):
    """Convert common DHIS2/API numeric representations to numbers safely."""
    if series is None:
        return pd.Series(dtype="float64")
    if pd.api.types.is_numeric_dtype(series):
        return pd.to_numeric(series, errors="coerce")
    cleaned = (
        series.astype("string")
        .str.strip()
        .str.replace(",", "", regex=False)
        .str.replace("%", "", regex=False)
        .str.replace(r"^\((.*)\)$", r"-\1", regex=True)
        .replace({"": pd.NA, "-": pd.NA, "—": pd.NA, "N/A": pd.NA, "NA": pd.NA})
    )
    return pd.to_numeric(cleaned, errors="coerce")


def _me_hub_find_indicator_dimension(df):
    """Find the DHIS2 long-format indicator dimension (usually dx)."""
    if not isinstance(df, pd.DataFrame) or df.empty:
        return None

    exact = {
        "dx", "indicator", "indicator id", "indicator_id",
        "data element", "data element id", "dataelement",
        "metric", "measure"
    }
    for c in df.columns:
        low = str(c).strip().lower()
        if low in exact:
            return c

    for c in df.columns:
        low = str(c).strip().lower()
        if re.search(r"(^|[\s_])dx($|[\s_])", low):
            return c

    return None


def _me_hub_find_indicator_value(df):
    """Find the numeric value field used by DHIS2 long-format responses."""
    if not isinstance(df, pd.DataFrame) or df.empty:
        return None

    exact = {
        "value", "values", "actual value", "result",
        "indicator value", "data value", "datavalue"
    }
    for c in df.columns:
        low = str(c).strip().lower()
        if low in exact:
            return c

    # Only use a generic numeric field as the value field when it is clearly
    # paired with an indicator dimension.
    for c in df.columns:
        low = str(c).strip().lower()
        if low in {"actual", "achievement"}:
            return c

    return None


def _me_hub_is_long_indicator_data(df):
    """Detect true DHIS2 long-format data without misclassifying wide data.

    The AI Public Website Builder treats numeric dataframe columns as the
    indicator universe. Therefore M&E must NOT pivot a normal wide dataframe
    merely because it happens to contain a column named ``indicator``. We only
    enter long mode when the table clearly has a dimension column (normally
    ``dx``) paired with a single value/measure column and there are no other
    numeric indicator columns.
    """
    if not isinstance(df, pd.DataFrame) or df.empty:
        return False

    indicator_col = _me_hub_find_indicator_dimension(df)
    value_col = _me_hub_find_indicator_value(df)
    if not indicator_col or not value_col or indicator_col == value_col:
        return False

    # ``dx`` is the canonical DHIS2 long-format indicator dimension.
    if str(indicator_col).strip().lower() == "dx":
        return True

    # For generic indicator/data-element columns, require a genuinely long
    # shape: one measure column and no other numeric columns.
    numeric_like = []
    for c in df.columns:
        if c == indicator_col:
            continue
        vals = _me_hub_numeric_series(df[c])
        if int(vals.notna().sum()) > 0:
            numeric_like.append(c)

    return len(numeric_like) == 1 and numeric_like[0] == value_col


def _me_hub_ai_style_indicator_columns(df):
    """Use the SAME indicator detection model as AI Public Website Builder.

    The AI Public Website Builder classifies every pandas numeric column as an
    indicator. This is intentionally simple and is the authoritative indicator
    model for the M&E Hub as well, so both workspaces see the same indicators.
    """
    if not isinstance(df, pd.DataFrame) or df.empty:
        return []

    indicators = []
    for col in df.columns:
        if str(col).startswith("__ME_"):
            continue
        if pd.api.types.is_numeric_dtype(df[col]):
            indicators.append(col)

    return sorted(
        indicators,
        key=lambda x: str(x).lower(),
    )


def _me_hub_expand_long_indicator_data(df):
    """Convert DHIS2 long indicator data (dx/value) into a wide M&E Hub view.

    This is deliberately local to the M&E Hub. The original API dataframe in
    session_state is never modified.

    Example:
        dx       value   pe       ou
        IND001   85      2026Q1   OU1
        IND002   72      2026Q1   OU1

    becomes:
        pe       ou       IND001   IND002
        2026Q1  OU1      85       72

    All indicator IDs returned by the source are retained, including indicators
    that have zero values. Metadata/dimension columns are preserved where they
    form the row grain.
    """
    if not isinstance(df, pd.DataFrame) or df.empty:
        return df.copy() if isinstance(df, pd.DataFrame) else df

    indicator_col = _me_hub_find_indicator_dimension(df)
    value_col = _me_hub_find_indicator_value(df)

    if not indicator_col or not value_col or indicator_col == value_col:
        return df.copy()

    work = df.copy()

    # Clean indicator identifiers/names without dropping them.
    work["__ME_INDICATOR_KEY__"] = (
        work[indicator_col]
        .astype("string")
        .fillna("")
        .str.strip()
    )
    work = work[work["__ME_INDICATOR_KEY__"] != ""].copy()

    if work.empty:
        return df.copy()

    work["__ME_INDICATOR_VALUE__"] = _me_hub_numeric_series(work[value_col])

    period_col = find_period_column(work)
    ou_col = find_ou_column(work)

    # Keep the normal DHIS2 dimensions at row level. Do not use arbitrary
    # descriptive columns as a pivot grain because that can split indicators.
    dimension_cols = []
    for c in [period_col, ou_col]:
        if c and c not in dimension_cols:
            dimension_cols.append(c)

    # Retain other common DHIS2 dimensions when they exist.
    dimension_aliases = {
        "pe", "period", "periodid", "periodcode",
        "ou", "organisationunit", "organisationunitid",
        "orgunit", "org unit", "level"
    }
    for c in work.columns:
        low = str(c).strip().lower()
        if c in {indicator_col, value_col,
                 "__ME_INDICATOR_KEY__", "__ME_INDICATOR_VALUE__"}:
            continue
        if low in dimension_aliases and c not in dimension_cols:
            dimension_cols.append(c)

    # If there is no obvious dimension, create one row per source table.
    if not dimension_cols:
        dimension_cols = ["__ME_SOURCE_ROW__"]
        work["__ME_SOURCE_ROW__"] = 0

    # Preserve the full indicator universe before pivoting. This prevents
    # indicators with all-null values in a particular slice from disappearing.
    indicator_universe = (
        work["__ME_INDICATOR_KEY__"]
        .dropna()
        .astype(str)
        .drop_duplicates()
        .tolist()
    )

    # Sum duplicate observations only when the source itself has repeated
    # records at the same dimension + indicator grain.
    wide = work.pivot_table(
        index=dimension_cols,
        columns="__ME_INDICATOR_KEY__",
        values="__ME_INDICATOR_VALUE__",
        aggfunc="sum",
        dropna=False,
    ).reset_index()

    wide.columns = [str(c) for c in wide.columns]
    wide.attrs = dict(getattr(df, "attrs", {}))
    wide.attrs["me_source_indicators"] = list(dict.fromkeys(
        list(wide.attrs.get("me_source_indicators", [])) + indicator_universe
    ))

    # Explicitly restore every indicator column from the source universe.
    # Reindexing guarantees the dropdown sees the complete indicator list.
    for indicator in indicator_universe:
        if indicator not in wide.columns:
            wide[indicator] = np.nan

    # Keep useful metadata that is constant within the pivot grain.
    used = set(dimension_cols + [indicator_col, value_col,
                                 "__ME_INDICATOR_KEY__",
                                 "__ME_INDICATOR_VALUE__"])
    metadata_candidates = [
        c for c in df.columns
        if c not in used and c not in wide.columns
    ]
    for col in metadata_candidates:
        try:
            nunique = (
                work.groupby(dimension_cols, dropna=False)[col]
                .nunique(dropna=True)
            )
            if not nunique.empty and nunique.max() <= 1:
                meta = (
                    work.groupby(dimension_cols, dropna=False)[col]
                    .first()
                    .reset_index()
                )
                wide = wide.merge(meta, on=dimension_cols, how="left")
        except Exception:
            continue

    if "__ME_SOURCE_ROW__" in wide.columns:
        wide = wide.drop(columns=["__ME_SOURCE_ROW__"], errors="ignore")

    # Put standard dimensions first, followed by every indicator.
    ordered = [c for c in dimension_cols if c in wide.columns]
    ordered += [
        c for c in indicator_universe
        if c in wide.columns and c not in ordered
    ]
    ordered += [c for c in wide.columns if c not in ordered]
    return wide[ordered]


def _me_hub_indicator_columns(df):
    """Return selectable indicator columns while excluding numeric metadata.

    Start with the AI Public Website Builder numeric-column model, then remove
    columns that are clearly structural metadata such as period IDs/codes,
    organisation-unit IDs, dates, row numbers and coordinates. This keeps real
    numeric indicators available without allowing fields such as ``periodid``
    or ``periodcode`` to appear in the Indicator selector.
    """
    if not isinstance(df, pd.DataFrame) or df.empty:
        return []

    candidates = _me_hub_ai_style_indicator_columns(df)
    period_col = find_period_column(df)
    ou_col = find_ou_column(df)

    # Exact structural columns that should never be treated as indicators.
    exact_metadata = {
        "id", "uid", "uuid", "code", "year", "month", "day",
        "quarter", "week", "period", "periodid", "periodcode",
        "period_id", "period_code", "ou", "ouid", "ou_id",
        "organisationunitid", "organisationunit_id",
        "organisation unit id", "orgunitid", "orgunit_id",
        "level", "rank", "index", "row", "rowid", "row_id",
        "serial", "sn", "latitude", "longitude", "lat", "lon",
        "startdate", "enddate", "start_date", "end_date",
    }

    # Common structural suffixes/patterns. Keep this deliberately narrow so
    # indicator names such as ``ANC coverage`` are not removed accidentally.
    metadata_suffixes = ("_id", "_code")
    metadata_contains = (
        "periodid", "periodcode", "organisationunitid",
        "organisationunit_id", "orgunitid", "orgunit_id",
    )

    excluded = {period_col, ou_col}
    out = []
    for col in candidates:
        low = str(col).strip().lower()
        compact = low.replace(" ", "").replace("-", "_")

        if col in excluded:
            continue
        if low in exact_metadata or compact in exact_metadata:
            continue
        if compact.endswith(metadata_suffixes):
            continue
        if any(token in compact for token in metadata_contains):
            continue

        # Pandas datetime columns are dimensions, not numeric indicators.
        try:
            if pd.api.types.is_datetime64_any_dtype(df[col]):
                continue
        except Exception:
            pass

        out.append(col)

    return out

def _me_hub_extract_source_indicators(source_url):
    """Extract the complete dx indicator universe from a DHIS2 analytics URL.

    DHIS2 analytics URLs can request indicators explicitly with one or more
    ``dimension=dx:...`` parameters. An indicator with no returned observation
    will not appear in the dataframe, so dataframe-only detection can never
    discover it. This helper reads the requested dx members directly from the
    source URL and keeps them available to the M&E Hub.
    """
    if not source_url:
        return []

    try:
        parsed = urlparse(str(source_url))
        query_items = parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return []

    indicators = []
    for key, values in query_items.items():
        if str(key).strip().lower() != "dimension":
            continue
        for raw_dimension in values:
            # A URL can contain dimension=dx:A;B or dimension=dx:A&dimension=dx:B.
            for part in str(raw_dimension).split(";"):
                part = unquote(part).strip()
                if not part:
                    continue
                if part.lower().startswith("dx:"):
                    members = part[3:]
                    for member in members.split(";"):
                        member = unquote(member).strip()
                        if member and member not in indicators:
                            indicators.append(member)

    return indicators


def _me_hub_add_source_indicator_universe(df, source_url=None):
    """Ensure every dx indicator requested by the source remains visible.

    This does not invent observations. Missing indicators are added as empty
    numeric columns so they remain selectable, while indicators already
    returned by the dataset keep their actual values.
    """
    if not isinstance(df, pd.DataFrame):
        return df

    out = df.copy()
    source_indicators = _me_hub_extract_source_indicators(source_url)
    if not source_indicators:
        return out

    existing = {str(c).strip() for c in out.columns}
    for indicator in source_indicators:
        if indicator not in existing:
            out[indicator] = np.nan
            existing.add(indicator)

    # Keep the requested indicator universe on the dataframe. This survives
    # normal pandas copies and lets the dropdown retain zero-observation items.
    out.attrs = dict(getattr(out, "attrs", {}))
    out.attrs["me_source_indicators"] = list(dict.fromkeys(
        list(out.attrs.get("me_source_indicators", [])) + source_indicators
    ))
    return out


def _me_hub_indicator_label(name):
    return " ".join(str(name).replace("_"," ").replace("-"," ").split()) or "Indicator"


def _me_hub_resolve_organisation_names(df, source_url=None):
    """Return a copy of the dataset with a human-readable DHIS2 organisation name column.

    DHIS2 analytics exports often return the organisation-unit UID in the ``ou``
    column.  The M&E Hub should never make the user work with those IDs.  When
    the values look like DHIS2 UIDs, this helper resolves them through the
    organisationUnits API using the same authenticated DHIS2 session already
    used by the main application.  If the source already contains names, they
    are preserved.
    """
    if not isinstance(df, pd.DataFrame) or df.empty:
        return df.copy() if isinstance(df, pd.DataFrame) else df

    out = df.copy()
    ou_col = find_ou_column(out)
    if not ou_col:
        return out

    raw = out[ou_col].astype("string")
    cleaned = raw.fillna("").str.strip()

    # DHIS2 UIDs are normally 11-character alphanumeric identifiers.
    uid_mask = cleaned.str.fullmatch(r"[A-Za-z0-9]{11}", na=False)
    uid_values = sorted(cleaned[uid_mask].dropna().unique().tolist())

    # If the source is already returning meaningful organisation names, do not
    # make an unnecessary metadata request.
    if not uid_values:
        out["__ME_ORG_NAME__"] = cleaned.replace("", "Organisation not specified")
        return out

    mapping = {}

    # Resolve against the same DHIS2 host used by the pasted API URL whenever
    # possible; otherwise fall back to the configured DHIS2 host.
    try:
        from urllib.parse import urlparse
        parsed = urlparse(str(source_url or ""))
        if parsed.scheme and parsed.netloc:
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        else:
            base_url = str(DHIS2_URL).rstrip("/")
    except Exception:
        base_url = str(DHIS2_URL).rstrip("/")

    # Query in batches so large OU selections do not create an oversized URL.
    for start in range(0, len(uid_values), 100):
        batch = uid_values[start:start + 100]
        try:
            response = session.get(
                f"{base_url}/api/organisationUnits.json",
                params={
                    "fields": "id,name,displayName,code",
                    "filter": "id:in:[" + ",".join(batch) + "]",
                    "paging": "false",
                },
                headers={"Accept": "application/json"},
                timeout=60,
            )
            if response.status_code == 200:
                payload = response.json()
                for item in payload.get("organisationUnits", []):
                    uid = str(item.get("id", "")).strip()
                    name = item.get("displayName") or item.get("name") or item.get("code") or uid
                    if uid:
                        mapping[uid] = str(name).strip()
        except Exception:
            # Keep the original UID as a last-resort fallback. The dashboard
            # remains usable even when the metadata endpoint is unavailable.
            continue

    def _display(value):
        value = "" if pd.isna(value) else str(value).strip()
        if not value:
            return "Organisation not specified"
        if value in mapping:
            return mapping[value]
        return value

    out["__ME_ORG_NAME__"] = raw.map(_display).astype("string")
    out["__ME_ORG_NAME__"] = out["__ME_ORG_NAME__"].replace("", "Organisation not specified")
    return out


def _me_hub_render_auto_indicator_dashboard(df, selected_period="All", selected_ou="All", selected_indicator="All"):
    """Automatically generate indicator charts from the currently loaded API data."""
    if not isinstance(df,pd.DataFrame) or df.empty:
        st.info("Load the API dataset in DANIP AI Data Analyst to populate the indicator dashboard automatically.")
        return
    period_col=find_period_column(df); ou_col=find_ou_column(df)
    indicator_cols=_me_hub_indicator_columns(df)
    work=df.copy()
    work["__ME_PERIOD_LABEL__"]=work[period_col].astype(str) if period_col else "All data"
    work["__ME_PERIOD_DATE__"]=_me_hub_period_dates(work[period_col]) if period_col else pd.NaT
    if "__ME_ORG_NAME__" in work.columns:
        work["__ME_OU_LABEL__"]=work["__ME_ORG_NAME__"].astype(str)
    else:
        work["__ME_OU_LABEL__"]=work[ou_col].astype(str) if ou_col else "All organisation units"
    if selected_period!="All": work=work[work["__ME_PERIOD_LABEL__"]==str(selected_period)]
    if selected_ou!="All": work=work[work["__ME_OU_LABEL__"]==str(selected_ou)]
    if work.empty:
        st.warning("No records match the selected filters."); return
    # The filter is a multi-select. ``All`` (or an empty selection) means all
    # valid indicator columns; otherwise keep exactly the indicators selected
    # by the user. A string is still accepted for backward compatibility.
    if isinstance(selected_indicator, (list, tuple, set)):
        selected_values = [str(x) for x in selected_indicator]
    elif selected_indicator is None:
        selected_values = []
    else:
        selected_values = [str(selected_indicator)]

    if selected_values and "All" not in selected_values:
        selected_lookup = set(selected_values)
        indicator_cols = [c for c in indicator_cols if str(c) in selected_lookup]
    if not indicator_cols:
        st.warning("No numeric indicator values were detected in the M&E view.")
        st.caption(
            "The AI workspace may still have the dataset. M&E accepts DHIS2 long format (dx/value), "
            "wide indicator columns, numeric strings, commas and percentage signs."
        )
        return
    # KPIs
    allvals=pd.concat([_me_hub_numeric_series(work[c]) for c in indicator_cols],ignore_index=True)
    kc=st.columns(5)
    kc[0].metric("Indicators",f"{len(indicator_cols):,}")
    kc[1].metric("Observations",f"{int(allvals.notna().sum()):,}")
    kc[2].metric("Organisation Units",f"{work['__ME_OU_LABEL__'].nunique():,}")
    kc[3].metric("Periods",f"{work['__ME_PERIOD_LABEL__'].nunique():,}")
    kc[4].metric("Average Value",f"{allvals.mean():,.2f}" if allvals.notna().any() else "—")
    try:
        import plotly.express as px
    except Exception:
        px=None
    # Summary / ranking
    rows=[]
    for c in indicator_cols:
        v=_me_hub_numeric_series(work[c]).dropna()
        rows.append({"indicator":_me_hub_indicator_label(c),"average":float(v.mean()) if not v.empty else np.nan,"total":float(v.sum()) if not v.empty else 0,"observations":int(v.size),"zero_values":int((v==0).sum()) if not v.empty else 0})
    summary=pd.DataFrame(rows).dropna(subset=["average"])
    if px and not summary.empty:
        fig=px.bar(summary.sort_values("average"),x="average",y="indicator",orientation="h",title="Average Value by Indicator")
        fig.update_layout(height=max(360,34*len(summary)),margin=dict(l=10,r=10,t=45,b=10))
        st.plotly_chart(fig,use_container_width=True)
    # Overall trend
    trend_rows=[]
    for c in indicator_cols:
        t=pd.DataFrame({"period":work["__ME_PERIOD_LABEL__"],"period_date":work["__ME_PERIOD_DATE__"],"indicator":_me_hub_indicator_label(c),"value":_me_hub_numeric_series(work[c])}).dropna(subset=["value"])
        if not t.empty: trend_rows.append(t)
    trend_all=pd.concat(trend_rows,ignore_index=True) if trend_rows else pd.DataFrame()
    if px and not trend_all.empty:
        if trend_all["period_date"].notna().any():
            t=trend_all.dropna(subset=["period_date"]).groupby(["period_date","indicator"],as_index=False)["value"].mean().sort_values("period_date")
            fig=px.line(t,x="period_date",y="value",color="indicator",markers=True,title="Indicator Trends Over Time")
            fig.update_layout(height=430,margin=dict(l=10,r=10,t=45,b=10),xaxis_title="Period",yaxis_title="Value")
        else:
            t=trend_all.groupby(["period","indicator"],as_index=False)["value"].mean()
            fig=px.line(t,x="period",y="value",color="indicator",markers=True,title="Indicator Values by Period")
            fig.update_layout(height=430,margin=dict(l=10,r=10,t=45,b=10))
        st.plotly_chart(fig,use_container_width=True)
    # Organisation-unit comparison, if available
    if px and ou_col and not trend_all.empty:
        ou_rows=[]
        for c in indicator_cols:
            t=pd.DataFrame({"ou":work["__ME_OU_LABEL__"],"value":_me_hub_numeric_series(work[c]),"indicator":_me_hub_indicator_label(c)}).dropna(subset=["value"])
            if not t.empty: ou_rows.append(t.groupby(["ou","indicator"],as_index=False)["value"].mean())
        if ou_rows:
            oo=pd.concat(ou_rows,ignore_index=True)
            top=summary.sort_values("average",ascending=False)["indicator"].head(12).tolist()
            oo=oo[oo["indicator"].isin(top)]
            fig=px.bar(oo,x="ou",y="value",color="indicator",barmode="group",title="Indicator Performance by Organisation Unit")
            fig.update_layout(height=430,margin=dict(l=10,r=10,t=45,b=10),xaxis_title="Organisation Unit",yaxis_title="Average Value")
            st.plotly_chart(fig,use_container_width=True)
    # Individual charts: one responsive chart for every populated indicator
    st.markdown("### 📈 Indicator-by-Indicator Analysis")
    st.caption(f"{len(indicator_cols):,} indicator chart(s) generated automatically. All charts respond to the Period and Organisation Unit filters above.")
    for i in range(0,len(indicator_cols),2):
        cc=st.columns(2)
        for j,c in enumerate(indicator_cols[i:i+2]):
            with cc[j]:
                title=_me_hub_indicator_label(c)
                vals=_me_hub_numeric_series(work[c])
                d=pd.DataFrame({"period":work["__ME_PERIOD_LABEL__"],"period_date":work["__ME_PERIOD_DATE__"],"ou":work["__ME_OU_LABEL__"],"value":vals}).dropna(subset=["value"])
                st.markdown(f"**{title}**")
                if d.empty:
                    st.info("No observations for this indicator in the selected filters."); continue
                if px and d["period_date"].notna().any():
                    g=d.dropna(subset=["period_date"]).groupby(["period_date","ou"],as_index=False)["value"].mean().sort_values("period_date")
                    fig=px.line(g,x="period_date",y="value",color="ou",markers=True)
                elif px:
                    g=d.groupby(["period","ou"],as_index=False)["value"].mean()
                    fig=px.bar(g,x="period",y="value",color="ou",barmode="group")
                else:
                    st.dataframe(d,use_container_width=True,hide_index=True); continue
                fig.update_layout(height=300,margin=dict(l=5,r=5,t=5,b=5),xaxis_title=None,yaxis_title="Value")
                st.plotly_chart(fig,use_container_width=True)
    st.markdown("### 📋 Indicator Summary")
    out=summary.copy(); out.columns=["Indicator","Average","Total","Observations","Zero Values"]
    out["Average"]=out["Average"].round(2); out["Total"]=out["Total"].round(2)
    st.dataframe(out,use_container_width=True,hide_index=True)

def render_danip_me_management_hub():
    """Separate responsive M&E Management Hub using the already-loaded API dataset when available."""
    _me_hub_init_db()
    _me_hub_responsive_css()

    # Existing manually maintained governance records remain available.
    manual_programs = _me_hub_df("me_programs")
    issues = _me_hub_df("me_issues")
    risks = _me_hub_df("me_risks")
    changes = _me_hub_df("me_changes")
    workplan = _me_hub_df("me_workplan")
    evidence = _me_hub_df("me_evidence")
    manual_finance = _me_hub_df("me_monthly_finance")

    # IMPORTANT: the Hub reuses the exact dataframe retrieved after the user pastes
    # the API URL in the DANIP AI tab. No second API URL is required.
    api_df = st.session_state.get("loaded_df")
    api_source_url = st.session_state.get("loaded_source_url") or st.session_state.get("last_analyzed_url")
    if isinstance(api_df, pd.DataFrame) and not api_df.empty:
        # Always expose organisation names in the M&E Hub filters/charts.
        # The original loaded dataframe remains untouched in session state.
        api_df = _me_hub_resolve_organisation_names(api_df, api_source_url)

        # IMPORTANT: use the AI Public Website Builder's indicator model.
        # It treats numeric dataframe columns as the indicator universe.
        # Only true DHIS2 long-format dx/value data is pivoted first. This
        # prevents the M&E Hub from changing a correctly shaped AI dataset
        # and accidentally replacing the real indicators with ``value`` or
        # metadata-derived columns.
        if _me_hub_is_long_indicator_data(api_df):
            api_df = _me_hub_expand_long_indicator_data(api_df)

        # For true long-format DHIS2 data, preserve every requested dx member
        # from the source URL, including members with no observations. For a
        # normal wide dataframe, the AI Public Website Builder's numeric-column
        # model is authoritative and we must NOT inject raw dx IDs as fake
        # indicator columns.
        if _me_hub_is_long_indicator_data(st.session_state.get("loaded_df")):
            api_df = _me_hub_add_source_indicator_universe(
                api_df,
                api_source_url,
            )

    api_view = _me_hub_build_api_view(api_df)
    api_programs = api_view["programs"]
    api_finance = api_view["finance"]
    performance = api_view["performance"]
    meta = api_view["meta"]

    # Data-quality results calculated by the main analysis page are also surfaced here.
    api_quality_issues = st.session_state.get("danip_api_quality_issues", [])
    api_quality_summary = st.session_state.get("danip_api_quality_summary", {})

    has_api = isinstance(api_df, pd.DataFrame) and not api_df.empty
    base_programs = api_programs.copy() if has_api and not api_programs.empty else manual_programs.copy()

    # M&E Hub header — compact because the common NEXUS banner is shared above both tabs.
    st.markdown("""<div class="mh-title-card" style="margin-top:.15rem"><div class="mh-kicker">DANIP · MONITORING, EVALUATION & LEARNING</div><div class="mh-title">🧭 DANIP M&E Management Hub</div><div class="mh-help">Automatic indicator monitoring from the same DHIS2/API dataset loaded by DANIP AI Data Analyst.</div></div>""", unsafe_allow_html=True)
    if has_api:
        st.markdown(
            f'<div class="mehub-source">🟢 <b>Live API dataset connected.</b> '
            f'{meta.get("rows", len(api_df)):,} records are being used automatically in this Hub.'
            + (f' Source: {html.escape(str(api_source_url))}' if api_source_url else '')
            + '</div>',
            unsafe_allow_html=True,
        )
    else:
        st.info("📡 Paste the API/Data URL in **🤖 DANIP AI Data Analyst**. Once the dataset loads, this Hub will populate automatically—no second URL is required.")

    # ---------------------------------------------------------
    # PRIMARY M&E FILTERS — period + organisation unit + indicator
    # ---------------------------------------------------------
    period_col = find_period_column(api_df) if has_api else None
    ou_col = find_ou_column(api_df) if has_api else None
    ou_display_col = "__ME_ORG_NAME__" if has_api and "__ME_ORG_NAME__" in api_df.columns else ou_col
    indicator_cols = _me_hub_indicator_columns(api_df) if has_api else []
    period_options = ["All"] + sorted(api_df[period_col].dropna().astype(str).unique().tolist()) if has_api and period_col else ["All"]
    ou_options = ["All"] + sorted(api_df[ou_display_col].dropna().astype(str).unique().tolist()) if has_api and ou_display_col else ["All"]
    indicator_options = ["All"] + [str(c) for c in indicator_cols] if has_api else ["All"]

    # Programme/governance metadata filters remain available when the source contains it.
    program_options = ["All"] + sorted(base_programs["program_name"].dropna().astype(str).unique().tolist()) if not base_programs.empty else ["All"]
    sponsor_options = ["All"] + sorted(base_programs["sponsor"].dropna().astype(str).replace("", np.nan).dropna().unique().tolist()) if not base_programs.empty else ["All"]
    dept_options = ["All"] + sorted(base_programs["department"].dropna().astype(str).replace("", np.nan).dropna().unique().tolist()) if not base_programs.empty else ["All"]
    status_options = ["All"] + sorted(base_programs["status"].dropna().astype(str).replace("", np.nan).dropna().unique().tolist()) if not base_programs.empty else ["All"]

    f1, f2, f3, f4, f5 = st.columns(5)
    with f1: f_period = st.selectbox("Period", period_options, key="mehub_period_filter")
    with f2: f_ou = st.selectbox("Organisation Unit Name", ou_options, key="mehub_ou_filter")
    with f3:
        # Streamlit may retain the old selectbox value after an app update.
        # Convert/remove that legacy state before creating the multiselect so
        # the widget always starts with a valid list value.
        _old_indicator_state = st.session_state.get("mehub_indicator_filter")
        if _old_indicator_state is not None and not isinstance(_old_indicator_state, list):
            st.session_state.pop("mehub_indicator_filter", None)
        f_indicator = st.multiselect(
            "Indicator(s)",
            indicator_options,
            default=["All"],
            key="mehub_indicator_filter",
            help="Select one or more indicators. Period, organisation-unit and other structural metadata fields are excluded automatically.",
        )
    with f4: f_program = st.selectbox("Program Name", program_options, key="mehub_program_filter")
    with f5: f_status = st.selectbox("Program Status", status_options, key="mehub_status_filter")
    g1, g2 = st.columns(2)
    with g1: f_sponsor = st.selectbox("Sponsor", sponsor_options, key="mehub_sponsor_filter")
    with g2: f_dept = st.selectbox("Department", dept_options, key="mehub_dept_filter")

    # ---------------------------------------------------------
    # LIVE DASHBOARD STATUS / CHANGE NOTIFICATION
    # ---------------------------------------------------------
    filter_signature = (f_period, f_ou, tuple(f_indicator), f_program, f_status, f_sponsor, f_dept)
    previous_signature = st.session_state.get("mehub_previous_filter_signature")
    if previous_signature is not None and previous_signature != filter_signature:
        st.toast("Dashboard updated — charts and indicators refreshed for the new selection.", icon="🔄")
    st.session_state["mehub_previous_filter_signature"] = filter_signature

    if has_api:
        status_text = (
            f"{meta.get('rows', len(api_df)):,} records • "
            f"{meta.get('indicators', len(indicator_cols)):,} indicators • "
            f"{meta.get('organisation_units', 0):,} organisation units • "
            f"{meta.get('periods', 0):,} periods"
        )
        st.markdown(
            f'<div class="mehub-statusbar"><span class="mehub-status-dot"></span>'
            f'<span class="mehub-status-main">Live dashboard ready</span>'
            f'<span class="mehub-status-muted">{html.escape(status_text)} · Filter changes automatically refresh all analysis.</span></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="mehub-statusbar"><span class="mehub-status-dot" style="background:#f59e0b"></span>'
            '<span class="mehub-status-main">Waiting for API data</span>'
            '<span class="mehub-status-muted">Load the dataset in DANIP AI Data Analyst to activate the M&E dashboard.</span></div>',
            unsafe_allow_html=True,
        )

    # ---------------------------------------------------------
    # AUTOMATIC INDICATOR DASHBOARD — PRIMARY VIEW
    # ---------------------------------------------------------
    if has_api:
        st.markdown("## 📊 M&E Indicator Dashboard")
        st.caption("The dashboard is generated directly from the indicators in the API dataset. Change Period, Organisation Unit or Indicator and every chart updates automatically.")
        _me_hub_render_auto_indicator_dashboard(api_df, f_period, f_ou, f_indicator)
    else:
        st.markdown("## 📊 M&E Indicator Dashboard")
        st.info("No API dataset is loaded. Paste the API/Data URL in DANIP AI Data Analyst and return here; the indicator dashboard will populate automatically.")

    # ---------------------------------------------------------
    # MANAGEMENT SUMMARY / GOVERNANCE FILTERS
    # ---------------------------------------------------------
    p = base_programs.copy()
    if not p.empty:
        if f_program != "All": p = p[p["program_name"].astype(str) == f_program]
        if f_sponsor != "All": p = p[p["sponsor"].astype(str) == f_sponsor]
        if f_dept != "All": p = p[p["department"].astype(str) == f_dept]
        if f_status != "All": p = p[p["status"].astype(str) == f_status]
    selected_names = set(p["program_name"].astype(str).tolist()) if not p.empty else set()
    fi_manual = issues[issues["program_name"].astype(str).isin(selected_names)] if selected_names else issues.iloc[0:0]
    fr = risks[risks["program_name"].astype(str).isin(selected_names)] if selected_names else risks.iloc[0:0]
    fc = changes[changes["program_name"].astype(str).isin(selected_names)] if selected_names else changes.iloc[0:0]
    # Filter the M&E workplan once at the management-summary level so it is
    # available both to the Workplan tab and the Management Priorities section.
    fw = workplan[workplan["program_name"].astype(str).isin(selected_names)] if selected_names else workplan.iloc[0:0]

    # Financial summary variables are deliberately calculated only from explicit
    # finance fields exposed by the API view. Never treat arbitrary DHIS2 indicator
    # values as budget/expenditure data.
    financial_available = isinstance(api_finance, pd.DataFrame) and not api_finance.empty and any(
        c in api_finance.columns for c in ["budget", "actual", "eac"]
    )
    if financial_available:
        total_budget = float(pd.to_numeric(api_finance.get("budget"), errors="coerce").sum()) if "budget" in api_finance.columns else 0.0
        total_fin_actual = float(pd.to_numeric(api_finance.get("actual"), errors="coerce").sum()) if "actual" in api_finance.columns else 0.0
        total_eac = float(pd.to_numeric(api_finance.get("eac"), errors="coerce").sum()) if "eac" in api_finance.columns else 0.0
    else:
        total_budget = total_fin_actual = total_eac = 0.0

    active_dq = int(len(api_quality_issues)) if has_api else 0
    active_manual_issues = int((fi_manual["status"].astype(str).str.lower().isin(["open", "in progress", "active"])).sum()) if not fi_manual.empty else 0
    active_issues = active_dq + active_manual_issues
    active_risks = int((fr["status"].astype(str).str.lower().isin(["open", "active", "monitoring"])).sum()) if not fr.empty else 0
    active_changes = int((fc["status"].astype(str).str.lower().isin(["pending", "open", "in review", "approved"])).sum()) if not fc.empty else 0
    progress = pd.to_numeric(p.get("progress", pd.Series(dtype=float)), errors="coerce").dropna() if not p.empty else pd.Series(dtype=float)
    k = st.columns(7)
    k[0].metric("Programs", len(p)); k[1].metric("Active Issues", active_issues); k[2].metric("Active Risks", active_risks); k[3].metric("Change Requests", active_changes)
    k[4].metric("M&E Records", f"{len(api_df):,}" if has_api else "0"); k[5].metric("On Track", int((progress >= 90).sum()) if not progress.empty else "—"); k[6].metric("Avg Progress", f"{progress.mean():.1f}%" if not progress.empty else "—")

    # ---------------------------------------------------------
    # MANAGEMENT WORKSPACES
    # ---------------------------------------------------------
    st.markdown("## M&E Management Workspaces")
    st.caption("The API-derived dashboard above is read-only. The registers below remain editable management records.")
    mt1, mt2, mt3, mt4, mt5, mt6 = st.tabs([
        "📋 Programs", "🚨 Issues & DQ", "⚠️ Risks", "🔄 Change Requests", "🗓️ M&E Workplan", "📁 Evidence"
    ])

    with mt1:
        st.markdown("### API Programme Portfolio")
        if has_api and not api_programs.empty:
            api_show = api_programs.copy()
            st.dataframe(api_show, use_container_width=True, hide_index=True)
            st.caption("Automatically populated from the same API dataset used by DANIP AI Data Analyst. This table is read-only.")
        else:
            st.info("No API-derived programme metadata is available yet.")

        st.markdown("### Manual Governance Register")
        with st.form("mehub_add_program", clear_on_submit=True):
            c1, c2, c3 = st.columns(3)
            with c1:
                pn = st.text_input("Program Name")
                sponsor = st.text_input("Sponsor")
                department = st.text_input("Department")
            with c2:
                status = st.selectbox("Program Status", ["On Track", "Watch", "Troubled", "Completed", "On Hold"])
                year = st.number_input("Calendar Year", min_value=2000, max_value=2100, value=datetime.now().year, step=1)
                budget = st.number_input("Budget", min_value=0.0, value=0.0, step=1000.0)
            with c3:
                actual = st.number_input("Actual", min_value=0.0, value=0.0, step=1000.0)
                eac = st.number_input("EAC", min_value=0.0, value=0.0, step=1000.0)
                progress = st.number_input("Progress %", min_value=0.0, max_value=100.0, value=0.0, step=1.0)
            c4, c5 = st.columns(2)
            with c4:
                start_date = st.date_input("Start Date")
            with c5:
                finish_date = st.date_input("Finish Date")
            notes = st.text_area("Notes")
            if st.form_submit_button("➕ Add Programme", use_container_width=True):
                if pn.strip():
                    _me_hub_insert("me_programs", {
                        "program_name": pn.strip(), "sponsor": sponsor.strip(), "department": department.strip(),
                        "status": status, "calendar_year": int(year), "budget": float(budget), "actual": float(actual),
                        "eac": float(eac), "progress": float(progress), "start_date": str(start_date), "finish_date": str(finish_date), "notes": notes.strip()
                    })
                    st.rerun()
                else:
                    st.error("Program Name is required.")
        if not manual_programs.empty:
            st.dataframe(manual_programs.drop(columns=["created_at"], errors="ignore"), use_container_width=True, hide_index=True)

    with mt2:
        st.markdown("### Data Quality & Issue Register")
        if has_api and api_quality_issues:
            st.markdown(f"**{len(api_quality_issues):,} DQ finding(s)** were detected by the main DANIP data-quality engine.")
            try:
                st.dataframe(pd.DataFrame(api_quality_issues), use_container_width=True, hide_index=True)
            except Exception:
                st.write(api_quality_issues)
        else:
            st.info("No API data-quality findings are available yet.")
        with st.form("mehub_add_issue", clear_on_submit=True):
            c1, c2 = st.columns(2)
            with c1:
                iprog = st.selectbox("Program", ["General"] + program_options[1:], key="mehub_iprog")
                issue = st.text_area("Issue")
                owner = st.text_input("Owner", key="mehub_i_owner")
            with c2:
                priority = st.selectbox("Priority", ["High", "Medium", "Low"])
                istatus = st.selectbox("Status", ["Open", "In Progress", "Resolved", "Closed"])
                due = st.date_input("Due Date", key="mehub_i_due")
            if st.form_submit_button("➕ Add Issue", use_container_width=True):
                if issue.strip():
                    _me_hub_insert("me_issues", {"program_name": iprog, "issue": issue.strip(), "priority": priority, "owner": owner.strip(), "status": istatus, "due_date": str(due)})
                    st.rerun()
                else:
                    st.error("Issue is required.")
        show = fi_manual if f_program != "All" else issues
        if not show.empty:
            st.dataframe(show.drop(columns=["created_at"], errors="ignore"), use_container_width=True, hide_index=True)

    with mt3:
        st.markdown("### Risk Register")
        with st.form("mehub_add_risk", clear_on_submit=True):
            c1, c2 = st.columns(2)
            with c1:
                rprog = st.selectbox("Program", ["General"] + program_options[1:], key="mehub_rprog")
                risk = st.text_area("Risk")
                owner = st.text_input("Owner", key="mehub_r_owner")
            with c2:
                rating = st.selectbox("Rating", ["High", "Medium", "Low"])
                rstatus = st.selectbox("Status", ["Open", "Monitoring", "Mitigated", "Closed"])
                rdue = st.date_input("Review Date", key="mehub_r_due")
            mitigation = st.text_area("Mitigation", key="mehub_r_mit")
            if st.form_submit_button("➕ Add Risk", use_container_width=True):
                if risk.strip():
                    _me_hub_insert("me_risks", {"program_name": rprog, "risk": risk.strip(), "rating": rating, "owner": owner.strip(), "mitigation": mitigation.strip(), "status": rstatus, "due_date": str(rdue)})
                    st.rerun()
                else:
                    st.error("Risk is required.")
        show = fr if f_program != "All" else risks
        st.dataframe(show.drop(columns=["created_at"], errors="ignore"), use_container_width=True, hide_index=True)

    with mt4:
        st.markdown("### Change Request Register")
        with st.form("mehub_add_change", clear_on_submit=True):
            c1, c2 = st.columns(2)
            with c1:
                cprog = st.selectbox("Program", ["General"] + program_options[1:], key="mehub_cprog")
                ctext = st.text_area("Change Request")
                cowner = st.text_input("Owner", key="mehub_c_owner")
            with c2:
                cimpact = st.selectbox("Impact", ["High", "Medium", "Low"])
                cstatus = st.selectbox("Status", ["Pending", "In Review", "Approved", "Rejected", "Closed"])
                cdate = st.date_input("Requested Date", key="mehub_c_date")
            if st.form_submit_button("➕ Add Change Request", use_container_width=True):
                if ctext.strip():
                    _me_hub_insert("me_changes", {"program_name": cprog, "change_request": ctext.strip(), "impact": cimpact, "owner": cowner.strip(), "status": cstatus, "requested_date": str(cdate)})
                    st.rerun()
                else:
                    st.error("Change Request is required.")
        show = fc if f_program != "All" else changes
        st.dataframe(show.drop(columns=["created_at"], errors="ignore"), use_container_width=True, hide_index=True)

    with mt5:
        st.markdown("### M&E Workplan & Reporting Calendar")
        with st.form("mehub_add_workplan", clear_on_submit=True):
            c1, c2 = st.columns(2)
            with c1:
                wprog = st.selectbox("Program", ["General"] + program_options[1:], key="mehub_wprog")
                wactivity = st.text_input("M&E Activity")
                windicator = st.text_input("Related Indicator")
                wowner = st.text_input("Responsible Person")
            with c2:
                wdue = st.date_input("Due Date", key="mehub_w_due")
                wstatus = st.selectbox("Status", ["Planned", "In Progress", "Completed", "Overdue", "Cancelled"])
                wevidence = st.text_input("Evidence / Link")
            wnotes = st.text_area("Notes", key="mehub_w_notes")
            if st.form_submit_button("➕ Add M&E Activity", use_container_width=True):
                if wactivity.strip():
                    _me_hub_insert("me_workplan", {"program_name": wprog, "activity": wactivity.strip(), "indicator": windicator.strip(), "owner": wowner.strip(), "due_date": str(wdue), "status": wstatus, "evidence_link": wevidence.strip(), "notes": wnotes.strip()})
                    st.rerun()
                else:
                    st.error("M&E Activity is required.")
        show = fw if f_program != "All" else workplan
        if not show.empty:
            wp = show.drop(columns=["created_at"], errors="ignore").copy()
            due = pd.to_datetime(wp["due_date"], errors="coerce")
            wp["Calendar Status"] = np.where(
                (due < pd.Timestamp.today()) & ~wp["status"].astype(str).str.lower().isin(["completed", "cancelled"]),
                "🔴 Overdue",
                wp["status"].map(_me_hub_status_class) + " " + wp["status"].astype(str),
            )
            st.dataframe(wp, use_container_width=True, hide_index=True)
        else:
            st.info("No M&E workplan activities yet.")

    with mt6:
        st.markdown("### Evidence & Verification Repository")
        with st.form("mehub_add_evidence", clear_on_submit=True):
            c1, c2 = st.columns(2)
            with c1:
                eprog = st.selectbox("Program", ["General"] + program_options[1:], key="mehub_eprog")
                eindicator = st.text_input("Indicator")
                etype = st.selectbox("Evidence Type", ["DHIS2", "DQA", "Survey", "Register", "Report", "Monitoring Visit", "Other"])
                etitle = st.text_input("Evidence Title")
            with c2:
                elink = st.text_input("Source / SharePoint Link")
                eperiod = st.text_input("Reporting Period")
                everify = st.selectbox("Verification Status", ["Pending", "Verified", "Needs Review", "Rejected"])
                enotes = st.text_area("Notes")
            if st.form_submit_button("➕ Add Evidence", use_container_width=True):
                if etitle.strip():
                    _me_hub_insert("me_evidence", {"program_name": eprog, "indicator": eindicator.strip(), "evidence_type": etype, "title": etitle.strip(), "source_link": elink.strip(), "period": eperiod.strip(), "verification_status": everify, "notes": enotes.strip()})
                    st.rerun()
                else:
                    st.error("Evidence Title is required.")
        show = evidence[evidence["program_name"].astype(str).isin(selected_names)] if selected_names else evidence.iloc[0:0]
        st.dataframe(show.drop(columns=["created_at"], errors="ignore"), use_container_width=True, hide_index=True)

    # ---------------------------------------------------------
    # MANAGEMENT PRIORITIES
    # ---------------------------------------------------------
    st.markdown("---")
    st.markdown("### 🧠 M&E Management Priorities")
    priority_messages = []
    if active_issues:
        priority_messages.append(f"**{active_issues} active issue(s)** require owner follow-up and closure evidence.")
    if active_risks:
        priority_messages.append(f"**{active_risks} active risk(s)** should remain under mitigation/review.")
    if active_changes:
        priority_messages.append(f"**{active_changes} change request(s)** need governance decision or status confirmation.")
    if not fw.empty:
        due = pd.to_datetime(fw["due_date"], errors="coerce")
        overdue = int(((due < pd.Timestamp.today()) & ~fw["status"].astype(str).str.lower().isin(["completed", "cancelled"])).sum())
        if overdue:
            priority_messages.append(f"**{overdue} M&E workplan item(s)** are overdue.")
    if financial_available and total_budget > 0 and total_eac > total_budget:
        priority_messages.append("**EAC is above approved budget** for the selected portfolio; review the variance and assumptions.")
    if api_quality_summary:
        try:
            dq_score = api_quality_summary.get("Overall Score", api_quality_summary.get("score", None))
            if dq_score is not None:
                priority_messages.append(f"**DQ score: {dq_score}** — consider data-quality evidence when interpreting programme performance.")
        except Exception:
            pass
    if priority_messages:
        for msg in priority_messages:
            st.warning(msg)
    elif has_api:
        st.success("No management exceptions are currently recorded for the selected API portfolio.")
    else:
        st.info("Load the API dataset to activate automatic M&E management analysis.")

    st.caption(
        "API-derived values are read from the same complete dataset loaded by DANIP AI Data Analyst. "
        "Financial fields are populated only when explicit budget/actual/EAC columns exist; arbitrary DHIS2 values are not relabelled as finance."
    )
    st.markdown('</div>', unsafe_allow_html=True)




def _nexus_sidebar_status(message, state="running", stage=None, detail=None):
    """Update the live sidebar monitor without changing the application's core logic."""
    now = datetime.now().strftime("%H:%M:%S")
    state = str(state or "running").lower()

    state_map = {
        "online": ("🟢", "SYSTEM ONLINE", "#16a34a"),
        "running": ("🔵", "PROCESSING", "#2563eb"),
        "success": ("🟢", "COMPLETED", "#16a34a"),
        "warning": ("🟠", "ATTENTION", "#d97706"),
        "error": ("🔴", "ERROR", "#dc2626"),
        "idle": ("⚪", "READY", "#64748b"),
    }
    icon, label, accent = state_map.get(state, state_map["running"])

    st.session_state["nexus_system_activity"] = str(message)
    st.session_state["nexus_system_state"] = state
    st.session_state["nexus_system_stage"] = str(stage or message)
    st.session_state["nexus_system_detail"] = str(detail or "")
    st.session_state["nexus_last_operation"] = str(message)
    st.session_state["nexus_operation_time"] = now

    history = st.session_state.setdefault("nexus_system_history", [])
    history.append({"time": now, "message": str(message), "state": state})
    st.session_state["nexus_system_history"] = history[-10:]

    placeholder = st.session_state.get("nexus_sidebar_live_placeholder")
    if placeholder is None:
        return

    loaded = st.session_state.get("loaded_df")
    has_data = isinstance(loaded, pd.DataFrame) and not loaded.empty
    records = len(loaded) if has_data else 0

    try:
        dq = st.session_state.get("danip_api_quality_summary") or {}
        dq_score = dq.get("score", dq.get("Overall Score", None))
    except Exception:
        dq_score = None

    ai_ready = bool(OPENAI_API_KEY)
    dhis_ready = bool(DANIP_ACCESS_TOKEN)

    def dot(ok, active=False, warning=False):
        if warning:
            return "🟠"
        if active:
            return "🔵"
        return "🟢" if ok else "⚪"

    pipeline = [
        (dot(True), "Application", "READY"),
        (dot(dhis_ready, active=(state == "running" and "DHIS2" in str(message))), "DHIS2 / API", "READY" if dhis_ready else "CONFIG"),
        (dot(has_data, active=(state == "running" and "data" in str(message).lower())), "Dataset", "LOADED" if has_data else "WAITING"),
        (dot(bool(dq_score is not None), active=(state == "running" and "quality" in str(message).lower())), "Data Quality", "ASSESSED" if dq_score is not None else "PENDING"),
        (dot(ai_ready, active=(state == "running" and ("AI" in str(message) or "interpret" in str(message).lower()))), "NEXUS AI", "READY" if ai_ready else "OPTIONAL"),
    ]

    pipeline_html = "".join(
        f'<div class="nexus-live-pipeline-row"><span>{i}</span><span>{html.escape(name)}</span><b>{html.escape(status)}</b></div>'
        for i, name, status in pipeline
    )

    detail_html = (
        f'<div class="nexus-live-detail">{html.escape(str(detail))}</div>'
        if detail else ""
    )

    with placeholder.container():
        st.markdown(
            f"""
            <div class="nexus-live-monitor" style="--nexus-accent:{accent};">
                <div class="nexus-live-head">
                    <div>
                        <div class="nexus-live-kicker">LIVE SYSTEM MONITOR</div>
                        <div class="nexus-live-title">{icon} {label}</div>
                    </div>
                    <div class="nexus-live-clock">{now}</div>
                </div>
                <div class="nexus-live-current">
                    <div class="nexus-live-pulse"></div>
                    <div>
                        <div class="nexus-live-activity">{html.escape(str(message))}</div>
                        {detail_html}
                    </div>
                </div>
                <div class="nexus-live-stage">CURRENT STAGE · {html.escape(str(stage or message))}</div>
                <div class="nexus-live-pipeline">{pipeline_html}</div>
                <div class="nexus-live-footer">
                    <span>{records:,} records in memory</span>
                    <span>{'AI enabled' if ai_ready else 'AI optional'}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_common_sidebar():
    """Render a responsive, readable common sidebar with a live system monitor."""
    with st.sidebar:
        live_placeholder = st.empty()
        st.session_state["nexus_sidebar_live_placeholder"] = live_placeholder

        defaults = {
            "nexus_system_history": [],
            "nexus_system_activity": "Waiting for user action",
            "nexus_system_state": "online",
            "nexus_system_stage": "System ready",
            "nexus_system_detail": "NEXUS is ready for the next operation.",
            "nexus_last_operation": "System initialized",
            "nexus_operation_time": datetime.now().strftime("%H:%M:%S"),
        }
        for key, value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = value

        _nexus_sidebar_status(
            st.session_state["nexus_system_activity"],
            st.session_state["nexus_system_state"],
            st.session_state["nexus_system_stage"],
            st.session_state["nexus_system_detail"],
        )

        # -----------------------------------------------------
        # BRAND
        # -----------------------------------------------------
        st.markdown(
            '<div class="common-sidebar-brand">'
            '<div class="common-sidebar-mark">D</div>'
            '<div class="common-sidebar-brand-text">'
            '<div class="common-sidebar-name">NEXUS DANIP</div>'
            '<div class="common-sidebar-subtitle">Data + M&amp;E Intelligence</div>'
            '</div></div>',
            unsafe_allow_html=True,
        )

        loaded = st.session_state.get("loaded_df")
        has_data = isinstance(loaded, pd.DataFrame) and not loaded.empty

        # -----------------------------------------------------
        # LIVE DATASET CARD
        # -----------------------------------------------------
        if has_data:
            st.markdown(
                f'<div class="common-sidebar-card common-sidebar-live">'
                f'<div class="sidebar-card-title"><span class="status-dot green"></span>Dataset available</div>'
                f'<div class="sidebar-card-text">{len(loaded):,} records are available to both DANIP workspaces.</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="common-sidebar-card common-sidebar-waiting">'
                '<div class="sidebar-card-title"><span class="status-dot orange"></span>Waiting for data</div>'
                '<div class="sidebar-card-text">Paste a DHIS2/API dataset URL in the AI workspace to begin.</div>'
                '</div>',
                unsafe_allow_html=True,
            )

        # -----------------------------------------------------
        # NAVIGATION
        # -----------------------------------------------------
        st.markdown('<div class="common-sidebar-section">WORKSPACES</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="sidebar-nav-card">'
            '<div class="sidebar-nav-item"><span class="sidebar-nav-icon">🤖</span>'
            '<div><b>DANIP AI Data Analyst</b><small>Analysis · DQ · charts · AI interpretation</small></div></div>'
            '<div class="sidebar-nav-item"><span class="sidebar-nav-icon">🧭</span>'
            '<div><b>DANIP M&amp;E Management Hub</b><small>Indicators · performance · trends · management</small></div></div>'
            '</div>',
            unsafe_allow_html=True,
        )

        # -----------------------------------------------------
        # DATASET STATUS
        # -----------------------------------------------------
        if has_data:
            try:
                period_col = find_period_column(loaded)
                ou_col = find_ou_column(loaded)
                indicator_cols = _me_hub_indicator_columns(loaded)
                periods = int(loaded[period_col].nunique(dropna=True)) if period_col else 0
                ous = int(loaded[ou_col].nunique(dropna=True)) if ou_col else 0

                st.markdown('<div class="common-sidebar-section">DATASET INTELLIGENCE</div>', unsafe_allow_html=True)
                st.markdown(
                    f'<div class="sidebar-metric-grid">'
                    f'<div class="sidebar-metric"><span>Records</span><b>{len(loaded):,}</b></div>'
                    f'<div class="sidebar-metric"><span>Indicators</span><b>{len(indicator_cols):,}</b></div>'
                    f'<div class="sidebar-metric"><span>Org units</span><b>{ous:,}</b></div>'
                    f'<div class="sidebar-metric"><span>Periods</span><b>{periods:,}</b></div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            except Exception:
                pass

        # -----------------------------------------------------
        # RECENT ACTIVITY
        # -----------------------------------------------------
        history = st.session_state.get("nexus_system_history", [])[-5:]
        st.markdown('<div class="common-sidebar-section">RECENT ACTIVITY</div>', unsafe_allow_html=True)

        if history:
            rows = []
            for item in reversed(history):
                state = str(item.get("state", "online")).lower()
                icon = {
                    "running": "🔵",
                    "success": "🟢",
                    "warning": "🟠",
                    "error": "🔴",
                    "online": "🟢",
                    "idle": "⚪",
                }.get(state, "⚪")
                rows.append(
                    '<div class="nexus-history-row">'
                    f'<span class="nexus-history-icon">{icon}</span>'
                    '<div class="nexus-history-content">'
                    f'<div class="nexus-history-message">{html.escape(str(item.get("message", "")))}</div>'
                    f'<div class="nexus-history-time">{html.escape(str(item.get("time", "")))}</div>'
                    '</div></div>'
                )
            st.markdown('<div class="nexus-history">' + "".join(rows) + '</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="sidebar-empty-activity">No activity yet — NEXUS is ready.</div>', unsafe_allow_html=True)

        # -----------------------------------------------------
        # WORKSPACE STATUS
        # -----------------------------------------------------
        st.markdown('<div class="common-sidebar-section">WORKSPACE STATUS</div>', unsafe_allow_html=True)
        current_workspace = st.session_state.get("danip_workspace_selector", "DANIP AI Data Analyst")
        short_workspace = str(current_workspace).replace("🤖 ", "").replace("🧭 ", "")
        st.markdown(
            f'<div class="sidebar-workspace-card">'
            f'<span class="status-dot blue"></span><div><b>{html.escape(short_workspace)}</b>'
            f'<small>Current workspace</small></div></div>',
            unsafe_allow_html=True,
        )

        # -----------------------------------------------------
        # SYSTEM CONTROL
        # -----------------------------------------------------
        st.markdown('<div class="common-sidebar-section">SYSTEM CONTROL</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="nexus-reset-card">'
            '<div class="nexus-reset-title">🔄 Start from the beginning</div>'
            '<div class="nexus-reset-text">'
            'Clear the current session, dataset selections, analysis state and temporary settings. '
            'Your persistent M&amp;E records remain stored in the application database.'
            '</div></div>',
            unsafe_allow_html=True,
        )

        st.markdown('<div class="nexus-reset-button">', unsafe_allow_html=True)
        reset_clicked = st.button(
            '🔄 Refresh & Start from Beginning',
            use_container_width=True,
            key='nexus_reset_application',
        )
        st.markdown('</div>', unsafe_allow_html=True)

        if reset_clicked:
            # Full application reset: clear the current workspace, dataset,
            # analysis state AND the pasted API/Data URL. Persistent MEAL
            # records in danip_meal.db are intentionally preserved.
            _auth_state = {
                "danip_authenticated": st.session_state.get("danip_authenticated", False),
                "danip_user": st.session_state.get("danip_user", {}),
                "danip_access_token": st.session_state.get("danip_access_token", ""),
                "danip_refresh_token": st.session_state.get("danip_refresh_token", ""),
            }
            st.session_state.clear()
            st.session_state.update(_auth_state)
            st.session_state["data_url_input"] = ""
            st.session_state["last_analyzed_url"] = ""
            st.session_state["loaded_source_url"] = ""
            st.session_state["data_loaded"] = False
            try:
                st.query_params.clear()
            except Exception:
                pass
            st.rerun()


# ============================================================
# SHARED EXCEL EXPORT HELPER
# ============================================================
# This helper is intentionally TOP-LEVEL because it is used by
# the Universal Power BI Analytics workspace as well as MEAL
# reporting/export workflows.
# ============================================================

def _meal_build_excel_bytes(sheets):
    """Build an editable multi-sheet Excel workbook from DataFrames."""
    output = BytesIO()

    try:
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            for name, frame in sheets.items():

                # Excel sheet names cannot contain: \ / * ? : [ ]
                safe_name = re.sub(
                    r"[\\/*?:\[\]]",
                    "-",
                    str(name),
                )[:31] or "Sheet"

                data = (
                    frame.copy()
                    if isinstance(frame, pd.DataFrame)
                    else pd.DataFrame(frame)
                )

                data.to_excel(
                    writer,
                    sheet_name=safe_name,
                    index=False,
                )

                ws = writer.book[safe_name]
                ws.freeze_panes = "A2"

                for col_cells in ws.columns:
                    max_len = 0
                    col_letter = col_cells[0].column_letter

                    for cell in col_cells[:200]:
                        value = (
                            ""
                            if cell.value is None
                            else str(cell.value)
                        )
                        max_len = max(max_len, len(value))

                    ws.column_dimensions[col_letter].width = min(
                        max(max_len + 2, 12),
                        45,
                    )

    except Exception as exc:
        raise RuntimeError(
            f"Excel export failed: {exc}"
        ) from exc

    return output.getvalue()


# ============================================================
# UNIVERSAL POWER BI API — EMBEDDED IN app.py
# ============================================================
# The API is intentionally part of this same application file.
# It exposes the current loaded dataset to Power BI Desktop.
# For Power BI Service/cloud refresh, deploy the application/API
# behind a public HTTPS endpoint.
# ============================================================

POWERBI_API_HOST = os.getenv("POWERBI_API_HOST", "0.0.0.0")
POWERBI_API_PORT = int(os.getenv("POWERBI_API_PORT", "8502"))

# Public Power BI API service.
# IMPORTANT: this must be a separate HTTPS API service, not the Streamlit UI URL.
POWERBI_API_BASE_URL = _get_secret("POWERBI_API_BASE_URL", "").rstrip("/")
POWERBI_API_KEY = _get_secret("POWERBI_API_KEY", "")
POWERBI_API_RUNTIME = {
    "api_key": None,
    "wide": [],
    "fact": [],
    "raw": [],
    "updated_at": None,
}
POWERBI_API_SERVER_STARTED = False
POWERBI_API_SERVER_LOCK = threading.Lock()


def _powerbi_json_default(value):
    if pd.isna(value):
        return None
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.bool_,)):
        return bool(value)
    if isinstance(value, (pd.Timestamp, datetime)):
        return value.isoformat()
    return str(value)


def _powerbi_json_records(frame):
    if not isinstance(frame, pd.DataFrame):
        return []
    clean = frame.copy()
    clean = clean.where(pd.notna(clean), None)
    return json.loads(clean.to_json(orient="records", date_format="iso"))


def _powerbi_find_column(df, exact_names=(), patterns=()):
    """Find a source column using exact normalized names first, then patterns."""
    normalized = {}
    for col in df.columns:
        key = re.sub(r"[^a-z0-9]+", "", str(col).lower())
        normalized[key] = col

    for name in exact_names:
        key = re.sub(r"[^a-z0-9]+", "", str(name).lower())
        if key in normalized:
            return normalized[key]

    for col in df.columns:
        name = re.sub(r"[^a-z0-9]+", " ", str(col).lower()).strip()
        if any(re.search(pattern, name) for pattern in patterns):
            return col
    return None


def _powerbi_prepare_tables(df):
    """Create screenshot-style Wide table plus normalized Fact and Raw tables."""
    data = df.copy()
    data.columns = [str(c).strip() for c in data.columns]

    period_id_col = _powerbi_find_column(
        data, exact_names=("periodid", "period_id"), patterns=(r"^period id$",)
    )
    period_name_col = _powerbi_find_column(
        data, exact_names=("periodname", "period_name"), patterns=(r"^period name$",)
    )
    period_code_col = _powerbi_find_column(
        data, exact_names=("periodcode", "period_code"), patterns=(r"^period code$", r"^pe$")
    )
    org_id_col = _powerbi_find_column(
        data,
        exact_names=("organisationunitid", "organisation_unit_id", "orgunitid", "ou"),
        patterns=(r"organisation unit id", r"org unit id", r"^ou$"),
    )
    org_name_col = _powerbi_find_column(
        data,
        exact_names=("organisationunitname", "organisation_unit_name", "orgunitname"),
        patterns=(r"organisation unit name", r"organisation", r"org unit name", r"facility"),
    )

    # If the source is already in DHIS2 Analytics wide format, preserve it.
    dimension_cols = [
        period_id_col,
        period_name_col,
        period_code_col,
        org_id_col,
        org_name_col,
    ]
    dimension_cols = [c for c in dimension_cols if c and c in data.columns]

    # Detect a genuine long-format DHIS2 dataset.
    dx_col = _powerbi_find_column(
        data, exact_names=("dx",), patterns=(r"^indicator$", r"data element", r"metric", r"measure")
    )
    value_col = _powerbi_find_column(
        data, exact_names=("value",), patterns=(r"^value$", r"actual", r"result")
    )

    if dx_col and value_col and dimension_cols:
        work = data.copy()
        work["__PBI_VALUE__"] = pd.to_numeric(work[value_col], errors="coerce")
        work["__PBI_INDICATOR__"] = work[dx_col].astype("string")

        wide = work.pivot_table(
            index=dimension_cols,
            columns="__PBI_INDICATOR__",
            values="__PBI_VALUE__",
            aggfunc="sum",
            dropna=False,
        ).reset_index()
        wide.columns = [str(c) for c in wide.columns]

        # Also retain any non-value metadata that can be safely represented.
        used = set(dimension_cols + [dx_col, value_col])
        extra_cols = [c for c in data.columns if c not in used]
        for col in extra_cols:
            if col not in wide.columns and col not in dimension_cols:
                # Do not duplicate arbitrary long-format rows into the wide grain.
                if data.groupby(dimension_cols, dropna=False)[col].nunique(dropna=True).max() <= 1:
                    meta = data.groupby(dimension_cols, dropna=False)[col].first().reset_index()
                    wide = wide.merge(meta, on=dimension_cols, how="left")
    else:
        wide = data.copy()

        # Collapse accidental duplicates to exactly one row per Period × Organisation.
        if dimension_cols and len(dimension_cols) >= 2:
            non_dimensions = [c for c in wide.columns if c not in dimension_cols]
            if wide.duplicated(subset=dimension_cols, keep=False).any():
                agg = {}
                for col in non_dimensions:
                    numeric = pd.to_numeric(wide[col], errors="coerce")
                    if numeric.notna().any():
                        wide[col] = numeric
                        agg[col] = "sum"
                    else:
                        agg[col] = "first"
                wide = wide.groupby(dimension_cols, dropna=False, as_index=False).agg(agg)

    # Standardize the five key fields to the screenshot naming convention.
    rename_map = {}
    if period_id_col and period_id_col != "periodid": rename_map[period_id_col] = "periodid"
    if period_name_col and period_name_col != "periodname": rename_map[period_name_col] = "periodname"
    if period_code_col and period_code_col != "periodcode": rename_map[period_code_col] = "periodcode"
    if org_id_col and org_id_col != "organisationunitid": rename_map[org_id_col] = "organisationunitid"
    if org_name_col and org_name_col != "organisationunitname": rename_map[org_name_col] = "organisationunitname"
    wide = wide.rename(columns=rename_map)

    preferred = [
        "periodid", "periodname", "periodcode",
        "organisationunitid", "organisationunitname",
    ]
    ordered = [c for c in preferred if c in wide.columns]
    ordered += [c for c in wide.columns if c not in ordered]
    wide = wide[ordered]

    # Normalized fact table for flexible Power BI modelling.
    fact = pd.DataFrame()
    if dimension_cols:
        dim_after = [c for c in preferred if c in wide.columns]
        indicator_columns = [c for c in wide.columns if c not in dim_after]
        rows = []
        for _, row in wide.iterrows():
            base = {c: row.get(c) for c in dim_after}
            for indicator in indicator_columns:
                numeric_value = pd.to_numeric(pd.Series([row.get(indicator)]), errors="coerce").iloc[0]
                if pd.notna(numeric_value):
                    rec = dict(base)
                    rec["PBI_Indicator"] = indicator
                    rec["PBI_Value"] = numeric_value
                    rows.append(rec)
        fact = pd.DataFrame(rows)

    raw = data.copy()
    raw.insert(0, "PBI_Row_ID", np.arange(1, len(raw) + 1))

    return wide, fact, raw


def _powerbi_generate_api_key():
    key = "nexus_pbi_" + secrets.token_urlsafe(32)
    POWERBI_API_RUNTIME["api_key"] = key
    st.session_state["powerbi_api_key"] = key
    return key


def _powerbi_api_authorized(headers):
    supplied = headers.get("x-api-key", "")
    expected = POWERBI_API_RUNTIME.get("api_key")
    return bool(expected and supplied and hmac.compare_digest(str(supplied), str(expected)))



def _powerbi_external_api_enabled():
    return bool(POWERBI_API_BASE_URL and POWERBI_API_KEY)


def _powerbi_publish_external(wide, fact, raw):
    """Publish current datasets to the separate public HTTPS Power BI API."""
    if not _powerbi_external_api_enabled():
        return False, "Public Power BI API is not configured."
    if "streamlit.app" in POWERBI_API_BASE_URL.lower():
        return False, (
            "POWERBI_API_BASE_URL cannot be the Streamlit UI URL. "
            "Deploy powerbi_api.py as a separate HTTPS API service."
        )
    payload={
        "wide": _powerbi_json_records(wide),
        "fact": _powerbi_json_records(fact),
        "raw": _powerbi_json_records(raw),
        "updated_at": datetime.utcnow().isoformat()+"Z",
    }
    try:
        r=requests.post(
            f"{POWERBI_API_BASE_URL}/api/powerbi/publish",
            headers={"x-api-key":POWERBI_API_KEY,"Content-Type":"application/json","Accept":"application/json"},
            json=payload, timeout=120,
        )
        r.raise_for_status()
        return True, r.json()
    except requests.RequestException as exc:
        return False, f"Public Power BI API publish failed: {exc}"
    except Exception as exc:
        return False, f"Public Power BI API publish failed: {exc}"

def _powerbi_start_embedded_server():
    """Start the lightweight API once per Python process."""
    global POWERBI_API_SERVER_STARTED
    if POWERBI_API_SERVER_STARTED:
        return

    class PowerBIRequestHandler(http.server.BaseHTTPRequestHandler):
        def _send_json(self, payload, status=200):
            body = json.dumps(payload, default=_powerbi_json_default, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"

            if path == "/api/powerbi/health":
                self._send_json({
                    "status": "ok",
                    "service": "NEXUS DANIP Power BI API",
                    "updated_at": POWERBI_API_RUNTIME.get("updated_at"),
                })
                return

            if not _powerbi_api_authorized(self.headers):
                self._send_json({"status": "error", "message": "Unauthorized — valid x-api-key required."}, 401)
                return

            if path == "/api/powerbi/wide":
                self._send_json({
                    "status": "success",
                    "dataset": "wide",
                    "grain": "period × organisation",
                    "updated_at": POWERBI_API_RUNTIME.get("updated_at"),
                    "data": POWERBI_API_RUNTIME.get("wide", []),
                })
                return

            if path == "/api/powerbi/fact":
                self._send_json({
                    "status": "success",
                    "dataset": "fact",
                    "grain": "period × organisation × indicator",
                    "updated_at": POWERBI_API_RUNTIME.get("updated_at"),
                    "data": POWERBI_API_RUNTIME.get("fact", []),
                })
                return

            if path == "/api/powerbi/raw":
                self._send_json({
                    "status": "success",
                    "dataset": "raw",
                    "grain": "source record",
                    "updated_at": POWERBI_API_RUNTIME.get("updated_at"),
                    "data": POWERBI_API_RUNTIME.get("raw", []),
                })
                return

            self._send_json({"status": "error", "message": "Endpoint not found."}, 404)

        def log_message(self, format, *args):
            return

    class ReusableTCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    try:
        server = ReusableTCPServer((POWERBI_API_HOST, POWERBI_API_PORT), PowerBIRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True, name="NEXUS-PowerBI-API")
        thread.start()
        POWERBI_API_SERVER_STARTED = True
    except OSError:
        # Streamlit may rerun while another process/thread already owns the port.
        # The application remains fully usable; only the embedded API is unavailable.
        POWERBI_API_SERVER_STARTED = False


# Keep the embedded API only for local Desktop compatibility.
if not POWERBI_API_BASE_URL:
    _powerbi_start_embedded_server()


def _render_universal_powerbi_workspace():
    """Universal Power BI workspace using Period × Organisation wide data."""
    st.markdown("## 📊 Universal Power BI Analytics")
    st.caption(
        "Universal analytical layer: one row per Period × Organisation, with each indicator preserved as a column. "
        "Raw and normalized datasets are also available."
    )

    df = st.session_state.get("loaded_df")
    loaded_url = st.session_state.get("loaded_source_url", "")

    if not isinstance(df, pd.DataFrame) or df.empty:
        st.info(
            "No dataset is currently loaded. Go to **🤖 DANIP AI Data Analyst**, "
            "connect your DHIS2/API source, and then return here."
        )
        return

    wide, fact, raw = _powerbi_prepare_tables(df)

    # Keep the local runtime populated for Power BI Desktop.
    POWERBI_API_RUNTIME["wide"] = _powerbi_json_records(wide)
    POWERBI_API_RUNTIME["fact"] = _powerbi_json_records(fact)
    POWERBI_API_RUNTIME["raw"] = _powerbi_json_records(raw)
    POWERBI_API_RUNTIME["updated_at"] = datetime.utcnow().isoformat() + "Z"

    # Also publish to the public API when configured.
    external_publish_ok = False
    external_publish_message = ""
    if _powerbi_external_api_enabled():
        external_publish_ok, external_publish_message = _powerbi_publish_external(wide, fact, raw)

    st.success(
        f"✅ Power BI dataset ready — {len(wide):,} Period × Organisation rows × {len(wide.columns):,} columns."
    )
    if loaded_url:
        st.caption(f"Source: `{loaded_url}`")

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.metric("Wide Rows", f"{len(wide):,}")
    with k2:
        st.metric("Indicator Columns", f"{max(len(wide.columns) - 5, 0):,}")
    with k3:
        st.metric("Organisation Units", f"{wide['organisationunitname'].nunique(dropna=True):,}" if "organisationunitname" in wide else "—")
    with k4:
        st.metric("Periods", f"{wide['periodcode'].nunique(dropna=True):,}" if "periodcode" in wide else "—")

    st.markdown("### 📊 Power BI Wide Analytical Dataset")
    st.caption(
        "This is the primary Power BI table. The grain is Period × Organisation. "
        "Indicator measures remain as separate columns, matching DHIS2 analytical exports."
    )
    st.dataframe(wide.head(5000), use_container_width=True, hide_index=True, height=500)

    st.markdown("### 🔢 Normalized Indicator Fact Dataset")
    st.caption("One row per Period × Organisation × Indicator for flexible Power BI modelling.")
    if fact.empty:
        st.info("No numeric indicator values were detected for the normalized fact table.")
    else:
        st.dataframe(fact.head(5000), use_container_width=True, hide_index=True, height=350)

    # API key and connection details.
    configured_key = POWERBI_API_KEY.strip()
    session_key = st.session_state.get("powerbi_api_key", "")
    existing_key = configured_key or session_key

    if not configured_key:
        if st.button("🔑 Generate Local Power BI API Key", key="pbi_generate_api_key", use_container_width=False):
            existing_key = _powerbi_generate_api_key()
            st.session_state["powerbi_api_key"] = existing_key

    if existing_key:
        st.code(existing_key, language="text")
        st.warning("Keep this API key private. Put it in the x-api-key header, never in the URL hostname.")
        local_url=f"http://localhost:{POWERBI_API_PORT}/api/powerbi/wide"
        public_api_base=POWERBI_API_BASE_URL
        invalid_streamlit_base=bool(public_api_base and "streamlit.app" in public_api_base.lower())
        public_url=(f"{public_api_base}/api/powerbi/wide" if public_api_base and not invalid_streamlit_base else "")
        st.markdown("**Power BI Desktop — local development:**")
        st.code(local_url, language="text")
        if invalid_streamlit_base:
            st.error("POWERBI_API_BASE_URL is set to the Streamlit UI URL. It cannot serve the custom /api/powerbi route. Deploy powerbi_api.py separately over HTTPS.")
        if public_url:
            st.markdown("**Power BI Service — public API:**")
            st.code(public_url, language="text")
            if external_publish_ok:
                st.success("☁️ Current dataset published to the public Power BI API.")
            elif external_publish_message:
                st.warning(str(external_publish_message))
        st.markdown("**Power Query:**")
        query_url=public_url or local_url
        st.code(
            'let\n'
            '    Source = Json.Document(\n'
            f'        Web.Contents(\n            "{query_url}",\n'
            '            [Headers=[#"x-api-key"="YOUR_POWERBI_API_KEY"]]\n'
            '        )\n'
            '    ),\n'
            '    Data = Table.FromRecords(Source[data])\n'
            'in\n'
            '    Data', language="powerquery")
        if public_url:
            st.caption("Use the public API URL in Power BI Service and the same POWERBI_API_KEY configured in both services.")
        else:
            st.caption("Local Power BI Desktop can use localhost. Power BI Service requires the separately deployed HTTPS API.")
    else:
        st.info("Configure POWERBI_API_BASE_URL and POWERBI_API_KEY for Power BI Service, or generate a local key for Power BI Desktop.")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button(
            "⬇️ Download Wide CSV",
            wide.to_csv(index=False).encode("utf-8-sig"),
            "DANIP_PowerBI_Wide.csv",
            "text/csv",
            use_container_width=True,
            key="pbi_wide_csv_export",
        )
    with c2:
        st.download_button(
            "⬇️ Download Fact CSV",
            fact.to_csv(index=False).encode("utf-8-sig"),
            "DANIP_PowerBI_Fact.csv",
            "text/csv",
            use_container_width=True,
            key="pbi_fact_csv_export",
        )
    with c3:
        st.download_button(
            "⬇️ Download Excel",
            _meal_build_excel_bytes({"Wide Data": wide, "Fact Data": fact, "Raw Data": raw}),
            "DANIP_PowerBI_Universal.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
            key="pbi_universal_excel_export",
        )


def render_existing_danip_ai_app():
    # ============================================================
    # CONNECTION STATUS
    # ============================================================

    status_items = []

    if DANIP_ACCESS_TOKEN:
        status_items.append("🟢 DHIS2 OAuth authenticated")
    else:
        status_items.append("🟠 DHIS2 authentication required")

    if OPENAI_API_KEY:
        status_items.append("🟢 NEXUS automatic intelligence ready")
    else:
        status_items.append("🟠 AI narrative disabled until OPENAI_API_KEY is added")

    st.info("  •  ".join(status_items))


    # ============================================================
    # USER INPUT
    # ============================================================

    st.markdown(
        """
        <div class="section-card">
            <div class="section-kicker">Step 1</div>
            <div class="section-title">📡 Connect your data</div>
            <div class="section-help">
                Paste a DHIS2 Analytics, CSV, XLS, XLSX or JSON API URL.
                Every row returned by the source is loaded and processed.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    user_url = st.text_area(
        "Data URL",
        placeholder="Paste your data/API URL here...",
        height=90,
        label_visibility="collapsed",
        key="data_url_input",
    )

    st.markdown(
        """
        <div class="section-card auto-analysis-card">
            <div class="section-kicker">AUTOMATIC ANALYSIS</div>
            <div class="section-title">🤖 NEXUS AI will analyze the complete dataset automatically</div>
            <div class="section-help">
                NEXUS AI automatically generates the baseline report and data-quality assessment.
                You can optionally select indicators, dimensions, graph type, analysis type and
                aggregation below to run a focused user-requested analysis.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Automatic mode: entering a data URL is the only trigger required.
    automatic_analysis = bool(user_url.strip())


    if not user_url.strip():
        st.markdown(
            """
            <div class="empty-state">
                <div style="font-size:2rem;">📡</div>
                <strong>Ready to analyze your data</strong>
                <div style="margin-top:.35rem;">
                    Paste your data URL and NEXUS AI will automatically build the analysis,
                    data-quality assessment, dashboard and intelligence report.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


    # ============================================================
    # FRESH URL
    # ============================================================

    def refresh_data_url(url):
        url = str(url or "").strip()

        if not url:
            return url

        separator = (
            "&"
            if "?" in url
            else "?"
        )

        return (
            f"{url}"
            f"{separator}"
            f"_ai_refresh={int(time.time())}"
        )



    # ============================================================
    # GUIDED ANALYSIS CONFIGURATION
    # ============================================================

    def guided_analysis_ui(df, user_question, initial_plan=None):
        """
        Guided analysis configuration.

        Important behaviour:
          - X axis is a single dimension.
          - Y axis supports MULTIPLE indicators.
          - Multiple indicators can be compared in the same analysis.
          - AI may suggest selections, but the user confirms them.
          - The confirmed configuration is the only configuration sent
            to the calculation engine.
        """
        options = get_analysis_options(df)
        numeric_columns = options["numeric_columns"]
        dimension_columns = options["dimension_columns"]

        st.markdown(
            """
            <div class="guided-panel">
                <div class="section-kicker">Analysis Guide</div>
                <div class="section-title">🎯 Define exactly what you want to compare</div>
                <div class="section-help">
                    Statistical Analysis is the default. Optionally select a dimension and one or more
                    indicators for comparisons, trends, rankings and other analyses.
                    The system will calculate the confirmed request using all applicable rows.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        suggested_x = None
        suggested_ys = []
        suggested_chart = None
        suggested_analysis = None

        if initial_plan:
            sx = initial_plan.get("x_column")
            if sx in dimension_columns:
                suggested_x = sx

            for y in initial_plan.get("y_columns", []) or []:
                if y in numeric_columns and y not in suggested_ys:
                    suggested_ys.append(y)

            if initial_plan.get("chart_type") in {"bar", "line", "pie", "scatter", "none"}:
                suggested_chart = initial_plan.get("chart_type")

            if initial_plan.get("analysis_type") in {
                "statistical", "comparison", "total", "average", "trend", "ranking",
                "percentage", "difference", "change", "distribution",
                "interpretation"
            }:
                suggested_analysis = initial_plan.get("analysis_type")

        if not suggested_ys and (not initial_plan or initial_plan.get("analysis_type") in {None, "custom", "statistical"}):
            suggested_ys = list(numeric_columns[:30])

        def idx(options, value):
            return options.index(value) if value in options else 0

        x_options = ["-- Select X-axis --"] + dimension_columns

        c1, c2 = st.columns([1, 1.7])

        with c1:
            x_selected = st.selectbox(
                "1️⃣ X-axis / comparison dimension",
                x_options,
                index=idx(x_options, suggested_x),
                key="guided_x_axis",
            )

        with c2:
            y_selected = st.multiselect(
                "2️⃣ Y-axis / indicators — select one or more",
                numeric_columns,
                default=[y for y in suggested_ys if y in numeric_columns],
                key="guided_y_axes",
                help="Select multiple indicators when you want a direct comparison.",
            )

        # ----------------------------------------------------------
        # 3️⃣ GRAPH TYPE — MULTI-SELECT
        # ----------------------------------------------------------
        # IMPORTANT:
        #   - Nothing is selected by default.
        #   - The user may select ONE, TWO, or MANY graph types.
        #   - We never silently insert a graph into the user's selection.
        # ----------------------------------------------------------
        chart_options = [
            "Grouped Bar",
            "Bar",
            "Line",
            "Pie",
            "Scatter",
        ]

        # Keep the AI suggestion only as information; do NOT use it
        # as a default selection because this control is intentionally
        # user-driven.
        suggested_chart_label = {
            "bar": "Bar",
            "line": "Line",
            "pie": "Pie",
            "scatter": "Scatter",
        }.get(suggested_chart)


        analysis_options = [
            "Statistical Analysis",
            "Comparison",
            "Total",
            "Average",
            "Trend",
            "Ranking",
            "Percentage",
            "Difference",
            "Change",
            "Distribution",
            "Interpretation",
        ]

        analysis_labels = {
            k: k.title()
            for k in [
                "statistical", "comparison", "total", "average", "trend", "ranking",
                "percentage", "difference", "change", "distribution",
                "interpretation"
            ]
        }

        c3, c4 = st.columns(2)

        with c3:
            chart_selected = st.multiselect(
                "3️⃣ Graph type — select one or more",
                options=chart_options,
                default=[],
                key="guided_chart_types",
                help=(
                    "Optional. Select one or more visualization types. "
                    "Nothing is selected automatically."
                ),
            )

            if chart_selected:
                st.caption(
                    f"📊 {len(chart_selected)} graph type"
                    f"{'s' if len(chart_selected) != 1 else ''} selected: "
                    + ", ".join(chart_selected)
                )
            else:
                st.caption(
                    "No graph selected. The analysis can still run without "
                    "a requested visualization when the analysis type allows it."
                )

        with c4:
            analysis_default = analysis_labels.get(
                suggested_analysis,
                "Statistical Analysis",
            )

            analysis_selected = st.selectbox(
                "4️⃣ Analysis type",
                analysis_options,
                index=idx(analysis_options, analysis_default),
                key="guided_analysis_type",
            )

        aggregation_options = [
            "Sum",
            "Average",
            "Median",
            "Minimum",
            "Maximum",
            "Count",
        ]

        aggregation_default_index = 1 if suggested_analysis == "statistical" else 0

        aggregation_selected = st.selectbox(
            "5️⃣ Aggregation",
            aggregation_options,
            index=aggregation_default_index,
            key="guided_aggregation",
        )

        x = None if x_selected.startswith("--") else x_selected

        chart_map = {
            "Grouped Bar": "bar",
            "Bar": "bar",
            "Line": "line",
            "Pie": "pie",
            "Scatter": "scatter",
        }

        # Convert every user selection to an internal chart type.
        # Preserve the user's order and remove duplicates.
        chart_types = []
        for selected_graph in chart_selected:
            internal_type = chart_map.get(selected_graph)
            if internal_type and internal_type not in chart_types:
                chart_types.append(internal_type)

        # Backward-compatible primary chart.
        chart = chart_types[0] if chart_types else "none"

        analysis = analysis_selected.lower()
        if analysis == "statistical analysis":
            analysis = "statistical"

        aggregation = {
            "Sum": "sum",
            "Average": "mean",
            "Median": "median",
            "Minimum": "min",
            "Maximum": "max",
            "Count": "count",
        }[aggregation_selected]

        # ----------------------------------------------------------
        # LIVE VISUALIZATION PREVIEW
        # ----------------------------------------------------------
        # Streamlit reruns the script whenever the user changes a
        # widget. Store the CURRENT widget values immediately so the
        # dashboard can render Bar/Pie/Line/Scatter without waiting
        # for the "Run detailed analysis" button.
        #
        # IMPORTANT:
        # chart_types is the source of truth for the visualization.
        # The automatic analysis plan is NOT allowed to replace it
        # with its default Line chart.
        # ----------------------------------------------------------
        if x and y_selected and chart_types:
            st.session_state["guided_preview_plan"] = {
                "needs_clarification": False,
                "analysis_requested": True,
                "analysis_type": analysis,
                "chart_requested": True,
                "chart_type": chart_types[0],
                "chart_types": list(chart_types),
                "chart_labels": list(chart_selected),
                "x_column": x,
                "y_columns": list(y_selected),
                "group_column": None,
                "indicator_columns": list(y_selected),
                "aggregation": aggregation,
                "filters": [],
                "ranking_limit": 10 if analysis == "ranking" else None,
                "comparison_groups": [],
                "title": (
                    f"{' vs '.join(map(str, y_selected))} by {x}"
                    if len(y_selected) > 1
                    else f"{y_selected[0]} by {x}"
                ),
                "reason": (
                    "Live visualization preview using the user's current "
                    "X-axis, indicators, graph types and aggregation."
                ),
                "comparison_mode": len(y_selected) > 1,
            }
        elif not chart_types:
            # User explicitly removed all graph selections.
            # Do not keep showing the previous graph.
            st.session_state["guided_preview_plan"] = None

        # ----------------------------------------------------------
        # Guidance
        # ----------------------------------------------------------
        if len(y_selected) > 1:
            st.markdown(
                f"""
                <div class="comparison-note">
                    <strong>📊 Multi-indicator comparison enabled</strong><br>
                    You selected <strong>{len(y_selected)} indicators</strong>.
                    The final analysis will compare them using the same X-axis:
                    <strong>{x or "not selected"}</strong>.
                </div>
                """,
                unsafe_allow_html=True,
            )

        if chart == "line" and x and "period" not in str(x).lower() and str(x).lower() not in {
            "pe", "date", "month", "year"
        }:
            st.info(
                "💡 Line charts are normally most useful for ordered time/period data. "
                "Confirm that your X-axis is intentionally non-time-based."
            )

        elif chart == "pie" and len(y_selected) > 1:
            st.warning(
                "🥧 A pie chart represents one measure at a time. "
                "For multiple indicators, a grouped bar chart is recommended."
            )

        elif chart == "scatter" and len(y_selected) > 1:
            st.info(
                "💡 Scatter comparison uses the first selected Y indicator. "
                "Use grouped bars or lines when comparing several indicators."
            )

        # ----------------------------------------------------------
        # Validation
        # ----------------------------------------------------------
        missing = []

        if analysis != "statistical" and not x:
            missing.append("X-axis")

        if not y_selected:
            missing.append("at least one Y-axis / indicator")

        if analysis != "statistical" and not chart_types:
            missing.append("at least one graph type")

        if not analysis:
            missing.append("analysis type")

        if missing:
            st.warning("Please select: " + ", ".join(missing) + ".")
            return None

        # ----------------------------------------------------------
        # Comparison summary before running
        # ----------------------------------------------------------
        st.markdown("### 🔎 Confirm your analysis")

        p1, p2, p3, p4 = st.columns(4)

        p1.metric("X-axis", x)
        p2.metric("Indicators", len(y_selected))
        p3.metric(
            "Graphs",
            str(len(chart_types)) if chart_types else "None",
        )
        p4.metric("Analysis", "Statistical Analysis" if analysis == "statistical" else analysis_selected)

        st.caption(
            "Selected indicators: " + ", ".join(map(str, y_selected))
        )

        st.caption(
            "Selected graph types: "
            + (", ".join(chart_selected) if chart_selected else "None")
        )

        st.info(
            f"⚙️ Calculation: **{analysis_selected}** analysis using **{aggregation_selected}** aggregation."
        )

        # ----------------------------------------------------------
        # Run
        # ----------------------------------------------------------
        run = st.button(
            "🚀 Run detailed analysis",
            type="primary",
            use_container_width=True,
            key="run_guided_analysis",
        )

        if not run:
            return None

        return {
            "needs_clarification": False,
            "analysis_requested": True,
            "analysis_type": analysis,
            "chart_requested": len(chart_types) > 0,
            "chart_type": chart,
            "chart_types": chart_types,
            "chart_labels": list(chart_selected),
            "x_column": x,
            "y_columns": list(y_selected),
            "group_column": None,
            "indicator_columns": list(y_selected),
            "aggregation": aggregation,
            "filters": [],
            "ranking_limit": 10 if analysis == "ranking" else None,
            "comparison_groups": [],
            "title": (
                f"{' vs '.join(map(str, y_selected))} by {x}"
                if len(y_selected) > 1
                else f"{y_selected[0]} by {x}"
            ),
            "reason": (
                "The user explicitly selected the X-axis, multiple indicators, "
                "graph, analysis type and aggregation."
            ),
            "comparison_mode": len(y_selected) > 1,
        }


    def get_analysis_options(df):
        columns = [str(c) for c in df.columns]
        numeric_columns = get_numeric_columns(df)
        dimension_columns = []
        for col in columns:
            lower = col.lower()
            if (
                "period" in lower or lower in {"pe", "date", "month", "year"}
                or "organisation" in lower or "organization" in lower or "org unit" in lower or "orgunit" in lower
                or "country" in lower or "region" in lower or "district" in lower or "province" in lower
                or "facility" in lower or "location" in lower
            ):
                dimension_columns.append(col)
        for col in columns:
            if col not in numeric_columns and col not in dimension_columns:
                dimension_columns.append(col)
        return {"all_columns": columns, "numeric_columns": numeric_columns, "dimension_columns": dimension_columns}



    # ============================================================
    # DANIP-NI AUTOMATIC ANALYSIS
    # ============================================================

    def _safe_unique_count(df, column):
        if not column or column not in df.columns:
            return 0
        try:
            return int(df[column].nunique(dropna=True))
        except Exception:
            return 0


    def build_automatic_analysis_plan(df):
        """
        Build an analysis plan without asking the user to configure X/Y,
        aggregation, chart type or analysis type.

        Python determines the structure first. AI is used later for
        narrative interpretation only.
        """
        columns = [str(c) for c in df.columns]
        numeric_columns = get_numeric_columns(df)

        period_column = find_period_column(df)
        ou_column = find_ou_column(df)

        plan = {
            "needs_clarification": False,
            "analysis_requested": True,
            "analysis_type": "statistical",
            "indicator_columns": list(numeric_columns),
            "dimension_column": ou_column or period_column,
            "x_column": None,
            "y_columns": [],
            "group_column": None,
            "filters": [],
            "aggregation": "sum",
            "chart_requested": False,
            "chart_type": "none",
            "chart_types": [],
            "chart_labels": [],
            "ranking_limit": 10,
            "comparison_groups": [],
            "title": "DANIP-NI Automatic Data Intelligence",
            "reason": (
                "Automatically generated from the complete dataset. "
                "No manual analysis configuration is required."
            ),
        }

        if not numeric_columns:
            return plan

        # Prefer a time view when multiple valid periods exist.
        # Otherwise use organisation-unit/category performance.
        period_count = _safe_unique_count(df, period_column)
        ou_count = _safe_unique_count(df, ou_column)

        if period_column and period_count > 1:
            plan["x_column"] = period_column
            plan["chart_type"] = "line"
            plan["chart_requested"] = True

            # Keep the automatic chart readable.
            plan["y_columns"] = list(numeric_columns[:8])

            # Organisation unit can be used as a grouping dimension only
            # when the number of OUs is small enough to remain readable.
            if ou_column and 1 < ou_count <= 12:
                plan["group_column"] = ou_column

        elif ou_column and ou_count > 1:
            plan["x_column"] = ou_column
            plan["chart_type"] = "bar"
            plan["chart_requested"] = True
            plan["y_columns"] = list(numeric_columns[:8])

        else:
            # Fall back to the first useful categorical dimension.
            candidate = None
            for column in columns:
                if column in numeric_columns:
                    continue
                if column in {period_column, ou_column}:
                    continue

                unique_count = _safe_unique_count(df, column)
                if 1 < unique_count <= 25:
                    candidate = column
                    break

            if candidate:
                plan["x_column"] = candidate
                plan["chart_type"] = "bar"
                plan["chart_requested"] = True
                plan["y_columns"] = list(numeric_columns[:8])

        return plan


    def build_automatic_analysis_evidence(df, chart_plan):
        """
        Deterministic automatic analysis.

        The complete dataframe is processed locally. This produces evidence
        for totals, averages, distributions, rankings, temporal changes,
        organisation-unit comparisons and indicator-level statistics.
        """
        evidence = {
            "status": "SUCCESS",
            "analysis_population": "ALL_ROWS",
            "source_rows": int(len(df)),
            "source_columns": int(len(df.columns)),
            "numeric_indicators": [],
            "dimensions": [],
            "automatic_findings": {},
        }

        numeric_columns = get_numeric_columns(df)
        period_column = find_period_column(df)
        ou_column = find_ou_column(df)

        evidence["numeric_indicators"] = list(map(str, numeric_columns))
        evidence["dimensions"] = {
            "period_column": str(period_column) if period_column else None,
            "organisation_unit_column": str(ou_column) if ou_column else None,
        }

        # --------------------------------------------------------
        # Indicator-level statistics
        # --------------------------------------------------------
        indicator_stats = {}

        for column in numeric_columns:
            values = pd.to_numeric(df[column], errors="coerce")
            valid = values.dropna()

            if valid.empty:
                continue

            q1 = valid.quantile(0.25)
            q3 = valid.quantile(0.75)
            iqr = q3 - q1

            if iqr == 0:
                outliers = 0
            else:
                outliers = int(
                    (
                        (valid < q1 - 1.5 * iqr)
                        | (valid > q3 + 1.5 * iqr)
                    ).sum()
                )

            indicator_stats[str(column)] = {
                "count": int(valid.count()),
                "missing": int(values.isna().sum()),
                "total": float(valid.sum()),
                "mean": float(valid.mean()),
                "median": float(valid.median()),
                "minimum": float(valid.min()),
                "maximum": float(valid.max()),
                "range": float(valid.max() - valid.min()),
                "zero_count": int((valid == 0).sum()),
                "negative_count": int((valid < 0).sum()),
                "outlier_count": outliers,
            }

        evidence["automatic_findings"]["indicator_statistics"] = indicator_stats

        # --------------------------------------------------------
        # Organisation-unit rankings
        # --------------------------------------------------------
        rankings = {}

        if ou_column and ou_column in df.columns:
            for indicator in numeric_columns[:20]:
                temp = pd.DataFrame({
                    "__ou__": df[ou_column],
                    "__value__": pd.to_numeric(
                        df[indicator],
                        errors="coerce",
                    ),
                }).dropna(subset=["__ou__", "__value__"])

                if temp.empty:
                    continue

                grouped = (
                    temp.groupby("__ou__", dropna=False)["__value__"]
                    .sum()
                    .sort_values(ascending=False)
                )

                rankings[str(indicator)] = {
                    "top_10": [
                        {
                            "organisation_unit": str(idx),
                            "value": float(value),
                        }
                        for idx, value in grouped.head(10).items()
                    ],
                    "bottom_10": [
                        {
                            "organisation_unit": str(idx),
                            "value": float(value),
                        }
                        for idx, value in grouped.tail(10).sort_values().items()
                    ],
                }

        evidence["automatic_findings"]["organisation_unit_rankings"] = rankings

        # --------------------------------------------------------
        # Period analysis
        # --------------------------------------------------------
        period_analysis = {}

        if period_column and period_column in df.columns:
            period_values = df[period_column].dropna().astype(str)

            if not period_values.empty:
                for indicator in numeric_columns[:20]:
                    temp = pd.DataFrame({
                        "__period__": df[period_column].astype(str),
                        "__value__": pd.to_numeric(
                            df[indicator],
                            errors="coerce",
                        ),
                    }).dropna(subset=["__period__", "__value__"])

                    if temp.empty:
                        continue

                    grouped = (
                        temp.groupby("__period__", dropna=False)["__value__"]
                        .sum()
                    )

                    period_analysis[str(indicator)] = [
                        {
                            "period": str(idx),
                            "value": float(value),
                        }
                        for idx, value in grouped.items()
                    ]

        evidence["automatic_findings"]["period_analysis"] = period_analysis

        # --------------------------------------------------------
        # Indicator comparison
        # --------------------------------------------------------
        comparison = []

        totals = []
        for indicator, stats in indicator_stats.items():
            totals.append({
                "indicator": indicator,
                "total": stats["total"],
                "mean": stats["mean"],
                "valid_observations": stats["count"],
            })

        totals = sorted(
            totals,
            key=lambda x: abs(x["total"]),
            reverse=True,
        )

        if totals:
            comparison = totals[:20]

        evidence["automatic_findings"]["indicator_comparison"] = comparison

        # --------------------------------------------------------
        # Complete-data profile
        # --------------------------------------------------------
        evidence["automatic_findings"]["dataset_profile"] = {
            "rows": int(len(df)),
            "columns": int(len(df.columns)),
            "numeric_columns": int(len(numeric_columns)),
            "missing_cells": int(df.isna().sum().sum()),
            "duplicate_rows": int(df.duplicated().sum()),
            "periods": _safe_unique_count(df, period_column),
            "organisation_units": _safe_unique_count(df, ou_column),
        }

        return evidence


    # ============================================================
    # ADVANCED ANALYTICS — ADDITIVE / NON-DESTRUCTIVE
    # ============================================================

    def _advanced_period_series(df, period_column):
        """Best-effort conversion of common DHIS2 period formats to dates."""
        if not period_column or period_column not in df.columns:
            return pd.Series(pd.NaT, index=df.index), False

        raw = df[period_column].astype("string").str.strip()
        parsed = pd.to_datetime(raw, errors="coerce")

        # DHIS2 monthly code: YYYYMM
        missing = parsed.isna()
        if missing.any():
            ym = raw.str.extract(r"^(20\\d{2})[-/]?(0[1-9]|1[0-2])$", expand=True)
            ym_dates = pd.to_datetime(
                ym[0].fillna("") + "-" + ym[1].fillna("") + "-01",
                errors="coerce",
            )
            parsed = parsed.fillna(ym_dates)

        # Quarter code: YYYYQ1 / YYYY-Q1
        missing = parsed.isna()
        if missing.any():
            q = raw.str.extract(r"^(20\\d{2})[- ]?Q([1-4])$", expand=True)
            q_year = pd.to_numeric(q[0], errors="coerce")
            q_num = pd.to_numeric(q[1], errors="coerce")
            q_month = ((q_num - 1) * 3 + 1).clip(1, 12)
            q_dates = pd.to_datetime(
                dict(year=q_year, month=q_month, day=1),
                errors="coerce",
            )
            parsed = parsed.fillna(q_dates)

        return parsed, bool(parsed.notna().sum() >= 3)


    def build_advanced_analytics(df, max_indicators=12, max_ous=30):
        """Deterministic advanced analytics. Never modifies the source dataframe."""
        result = {
            "status": "SUCCESS",
            "rows": int(len(df)),
            "advanced": {},
        }

        if not isinstance(df, pd.DataFrame) or df.empty:
            result["status"] = "NO_DATA"
            return result

        numeric_columns = get_numeric_columns(df)
        numeric_columns = numeric_columns[:max_indicators]
        period_column = find_period_column(df)
        ou_column = find_ou_column(df)

        # ------------------------------------------------------------
        # 1. Distribution / volatility profile
        # ------------------------------------------------------------
        volatility = {}
        for col in numeric_columns:
            values = pd.to_numeric(df[col], errors="coerce").dropna()
            if len(values) < 2:
                continue
            mean = float(values.mean())
            std = float(values.std()) if pd.notna(values.std()) else 0.0
            volatility[str(col)] = {
                "mean": mean,
                "std": std,
                "coefficient_of_variation_pct": (
                    round(abs(std / mean) * 100, 2) if mean != 0 else None
                ),
                "skewness": round(float(values.skew()), 4) if len(values) >= 3 else None,
            }
        result["advanced"]["volatility"] = volatility

        # ------------------------------------------------------------
        # 2. Correlation network / matrix
        # ------------------------------------------------------------
        correlation = {}
        if len(numeric_columns) >= 2:
            corr_df = df[numeric_columns].apply(pd.to_numeric, errors="coerce")
            corr = corr_df.corr(method="pearson", min_periods=5)
            correlation = {
                str(row): {
                    str(col): (
                        round(float(corr.loc[row, col]), 3)
                        if pd.notna(corr.loc[row, col]) else None
                    )
                    for col in corr.columns
                }
                for row in corr.index
            }

            pairs = []
            for i, a in enumerate(corr.columns):
                for b in corr.columns[i + 1:]:
                    value = corr.loc[a, b]
                    if pd.notna(value):
                        pairs.append({
                            "indicator_1": str(a),
                            "indicator_2": str(b),
                            "correlation": round(float(value), 3),
                            "strength": (
                                "Very strong" if abs(value) >= .8 else
                                "Strong" if abs(value) >= .6 else
                                "Moderate" if abs(value) >= .4 else
                                "Weak"
                            ),
                        })
            pairs.sort(key=lambda x: abs(x["correlation"]), reverse=True)
            result["advanced"]["correlation_pairs"] = pairs[:30]
        result["advanced"]["correlation_matrix"] = correlation

        # ------------------------------------------------------------
        # 3. Period trend, growth, volatility and simple forecast
        # ------------------------------------------------------------
        trend_analysis = {}
        forecast = {}
        parsed_period, valid_period = _advanced_period_series(df, period_column)

        if valid_period:
            period_work = df.copy()
            period_work["__advanced_period__"] = parsed_period
            period_work = period_work.dropna(subset=["__advanced_period__"])

            for col in numeric_columns:
                period_work["__advanced_value__"] = pd.to_numeric(
                    period_work[col], errors="coerce"
                )
                grouped = (
                    period_work.dropna(subset=["__advanced_value__"])
                    .groupby("__advanced_period__")["__advanced_value__"]
                    .sum()
                    .sort_index()
                )

                if len(grouped) < 3:
                    continue

                y = grouped.to_numpy(dtype=float)
                x = np.arange(len(y), dtype=float)
                slope, intercept = np.polyfit(x, y, 1)
                predicted = intercept + slope * x
                ss_res = float(np.sum((y - predicted) ** 2))
                ss_tot = float(np.sum((y - y.mean()) ** 2))
                r2 = 1.0 - ss_res / ss_tot if ss_tot != 0 else 0.0

                first = float(y[0])
                last = float(y[-1])
                change_pct = ((last - first) / abs(first) * 100) if first != 0 else None
                direction = "Increasing" if slope > 0 else "Decreasing" if slope < 0 else "Stable"

                trend_analysis[str(col)] = {
                    "periods": int(len(grouped)),
                    "first_period": str(grouped.index[0].date()),
                    "last_period": str(grouped.index[-1].date()),
                    "first_value": first,
                    "last_value": last,
                    "absolute_change": last - first,
                    "change_pct": round(float(change_pct), 2) if change_pct is not None else None,
                    "slope_per_period": round(float(slope), 4),
                    "r_squared": round(float(r2), 4),
                    "direction": direction,
                }

                # Conservative short-horizon linear forecast: 3 future periods.
                if len(grouped) >= 4:
                    future_x = np.arange(len(y), len(y) + 3, dtype=float)
                    future_y = intercept + slope * future_x
                    future_dates = pd.date_range(
                        grouped.index[-1] + pd.offsets.MonthBegin(1),
                        periods=3,
                        freq="MS",
                    )
                    forecast[str(col)] = [
                        {
                            "period": str(date.date()),
                            "forecast": round(float(value), 2),
                        }
                        for date, value in zip(future_dates, future_y)
                    ]

        result["advanced"]["trend_analysis"] = trend_analysis
        result["advanced"]["forecast"] = forecast

        # ------------------------------------------------------------
        # 4. Robust anomaly detection (IQR + MAD)
        # ------------------------------------------------------------
        anomalies = []
        for col in numeric_columns:
            values = pd.to_numeric(df[col], errors="coerce")
            valid = values.dropna()
            if len(valid) < 5:
                continue

            q1 = valid.quantile(.25)
            q3 = valid.quantile(.75)
            iqr = q3 - q1
            low = q1 - 1.5 * iqr
            high = q3 + 1.5 * iqr

            median = valid.median()
            mad = (valid - median).abs().median()
            if mad and pd.notna(mad):
                robust_z = (values - median).abs() / (1.4826 * mad)
                anomaly_mask = robust_z > 3.5
            else:
                anomaly_mask = (values < low) | (values > high) if iqr != 0 else pd.Series(False, index=df.index)

            indexes = df.index[anomaly_mask.fillna(False)]
            for idx in indexes[:100]:
                item = {
                    "row": int(idx) if isinstance(idx, (int, np.integer)) else str(idx),
                    "indicator": str(col),
                    "value": float(values.loc[idx]),
                    "method": "MAD" if mad and pd.notna(mad) else "IQR",
                }
                if ou_column and ou_column in df.columns:
                    item["organisation_unit"] = str(df.loc[idx, ou_column])
                if period_column and period_column in df.columns:
                    item["period"] = str(df.loc[idx, period_column])
                anomalies.append(item)

        result["advanced"]["anomalies"] = anomalies[:200]
        result["advanced"]["anomaly_count"] = int(len(anomalies))

        # ------------------------------------------------------------
        # 5. Organisation-unit benchmarking
        # ------------------------------------------------------------
        benchmarking = {}
        if ou_column and ou_column in df.columns:
            ou_counts = df[ou_column].nunique(dropna=True)
            if 1 < ou_counts <= max_ous:
                for col in numeric_columns[:8]:
                    temp = pd.DataFrame({
                        "__ou__": df[ou_column],
                        "__value__": pd.to_numeric(df[col], errors="coerce"),
                    }).dropna()
                    if temp.empty:
                        continue
                    grouped = temp.groupby("__ou__")["__value__"].agg(["sum", "mean", "count"])
                    grouped["share_pct"] = grouped["sum"] / grouped["sum"].sum() * 100 if grouped["sum"].sum() != 0 else np.nan
                    grouped = grouped.sort_values("sum", ascending=False)
                    benchmarking[str(col)] = [
                        {
                            "organisation_unit": str(idx),
                            "total": round(float(row["sum"]), 2),
                            "average": round(float(row["mean"]), 2),
                            "observations": int(row["count"]),
                            "share_pct": round(float(row["share_pct"]), 2) if pd.notna(row["share_pct"]) else None,
                        }
                        for idx, row in grouped.head(30).iterrows()
                    ]
        result["advanced"]["organisation_unit_benchmarking"] = benchmarking

        return result


    def render_advanced_analytics(df):
        """Optional advanced layer. It is isolated from the existing analysis pipeline."""
        st.subheader("🧠 Advanced Analytics")
        st.caption(
            "Additional deterministic analytics. These calculations do not modify "
            "the source data, current chart plan, aggregation, data-quality score, or AI result."
        )

        with st.expander("Open Advanced Analytics", expanded=False):
            advanced = build_advanced_analytics(df).get("advanced", {})

            volatility = advanced.get("volatility", {})
            trends = advanced.get("trend_analysis", {})
            correlations = advanced.get("correlation_pairs", [])
            anomalies = advanced.get("anomalies", [])
            forecasts = advanced.get("forecast", {})
            benchmarking = advanced.get("organisation_unit_benchmarking", {})

            t1, t2, t3, t4, t5 = st.tabs([
                "📈 Trends", "🔮 Forecast", "🔗 Correlation", "🚨 Anomalies", "🏆 Benchmarking"
            ])

            with t1:
                if trends:
                    trend_df = pd.DataFrame([
                        {"Indicator": k, **v} for k, v in trends.items()
                    ])
                    st.dataframe(trend_df, use_container_width=True, hide_index=True)
                    try:
                        import plotly.express as px
                        chart_rows = []
                        period_column = find_period_column(df)
                        parsed, valid = _advanced_period_series(df, period_column)
                        if valid:
                            for col in list(trends.keys())[:6]:
                                temp = pd.DataFrame({
                                    "Period": parsed,
                                    "Value": pd.to_numeric(df[col], errors="coerce"),
                                }).dropna()
                                grouped = temp.groupby("Period")["Value"].sum().reset_index()
                                grouped["Indicator"] = str(col)
                                chart_rows.append(grouped)
                        if chart_rows:
                            plot_df = pd.concat(chart_rows, ignore_index=True)
                            fig = px.line(
                                plot_df,
                                x="Period",
                                y="Value",
                                color="Indicator",
                                markers=True,
                                title="Advanced Trend Analysis",
                            )
                            st.plotly_chart(fig, use_container_width=True)
                    except Exception as e:
                        st.info(f"Trend chart unavailable: {e}")
                else:
                    st.info("A valid period dimension with at least three periods is required for trend analytics.")

                if volatility:
                    st.markdown("#### Volatility & Distribution")
                    st.dataframe(
                        pd.DataFrame([{ "Indicator": k, **v } for k, v in volatility.items()]),
                        use_container_width=True,
                        hide_index=True,
                    )

            with t2:
                if forecasts:
                    forecast_rows = []
                    for indicator, rows in forecasts.items():
                        for row in rows:
                            forecast_rows.append({"Indicator": indicator, **row})
                    st.dataframe(pd.DataFrame(forecast_rows), use_container_width=True, hide_index=True)
                    st.caption("Forecasts use a simple deterministic linear trend and should be treated as directional, not causal predictions.")
                else:
                    st.info("Forecasting requires at least four valid ordered periods.")

            with t3:
                if correlations:
                    corr_df = pd.DataFrame(correlations)
                    st.dataframe(corr_df, use_container_width=True, hide_index=True)
                    try:
                        import plotly.express as px
                        matrix = advanced.get("correlation_matrix", {})
                        matrix_df = pd.DataFrame(matrix).T
                        if not matrix_df.empty:
                            fig = px.imshow(
                                matrix_df,
                                text_auto=True,
                                aspect="auto",
                                zmin=-1,
                                zmax=1,
                                title="Indicator Correlation Matrix",
                            )
                            st.plotly_chart(fig, use_container_width=True)
                    except Exception as e:
                        st.info(f"Correlation heatmap unavailable: {e}")
                else:
                    st.info("At least two numeric indicators with five paired observations are required.")

            with t4:
                st.metric("Detected anomalies", f"{len(anomalies):,}")
                if anomalies:
                    st.dataframe(pd.DataFrame(anomalies), use_container_width=True, hide_index=True)
                    st.warning("Anomalies are flagged for investigation; they are never automatically deleted or changed.")
                else:
                    st.success("No advanced statistical anomalies were detected in the selected numeric fields.")

            with t5:
                if benchmarking:
                    for indicator, rows in list(benchmarking.items())[:8]:
                        st.markdown(f"**{indicator} — organisation-unit benchmark**")
                        bench_df = pd.DataFrame(rows)
                        st.dataframe(bench_df, use_container_width=True, hide_index=True)
                else:
                    st.info("Organisation-unit benchmarking requires a detected OU field and a manageable number of OUs.")


    # ============================================================
    # M&E PROGRAMME MANAGER NARRATION
    # ============================================================

    def _me_numeric(value):
        try:
            return float(value)
        except Exception:
            return None


    def build_me_programme_narrative(df, plan, quality_issues, quality_matrix, quality_summary):
        """Create a deterministic M&E interpretation from the exact requested analysis.

        The narrative is evidence-led. It does not claim causation and never changes
        the user's selected indicator, X-axis, aggregation or source data.
        """
        if not plan or not plan.get("chart_requested"):
            return None

        x = plan.get("x_column")
        indicators = [c for c in (plan.get("y_columns") or []) if c in df.columns]
        if not x or x not in df.columns or not indicators:
            return None

        chart_df, error = build_chart_data_dataframe(df, plan)
        if error or chart_df is None or chart_df.empty:
            return None

        aggregation = str(plan.get("aggregation", "sum")).lower()
        quality_score = float((quality_summary or {}).get("score", 0))
        quality_rating = str((quality_summary or {}).get("rating", "Unknown"))

        high = [i for i in (quality_issues or []) if str(i.get("Priority", "")).upper() == "HIGH"]
        medium = [i for i in (quality_issues or []) if str(i.get("Priority", "")).upper() == "MEDIUM"]

        # Build indicator-level evidence from the same dataframe used by the chart.
        indicator_evidence = []
        rows_for_table = []

        if "__series__" in chart_df.columns and "__value__" in chart_df.columns:
            working = chart_df.copy()
            working["__value__"] = pd.to_numeric(working["__value__"], errors="coerce")
            working = working.dropna(subset=["__value__"])

            for indicator in indicators:
                sub = working[working["__series__"].astype(str) == str(indicator)].copy()
                if sub.empty:
                    continue
                vals = sub["__value__"].astype(float)
                max_idx = vals.idxmax()
                min_idx = vals.idxmin()
                max_row = sub.loc[max_idx]
                min_row = sub.loc[min_idx]
                evidence = {
                    "indicator": str(indicator),
                    "observations": int(len(sub)),
                    "total": float(vals.sum()),
                    "average": float(vals.mean()),
                    "minimum": float(vals.min()),
                    "maximum": float(vals.max()),
                    "highest_category": str(max_row[x]),
                    "lowest_category": str(min_row[x]),
                }
                if len(vals) >= 2:
                    first_value = float(vals.iloc[0])
                    last_value = float(vals.iloc[-1])
                    evidence["first_value"] = first_value
                    evidence["last_value"] = last_value
                    evidence["absolute_change"] = last_value - first_value
                    evidence["percent_change"] = (
                        (last_value - first_value) / abs(first_value) * 100
                        if first_value != 0 else None
                    )
                indicator_evidence.append(evidence)

        else:
            for indicator in indicators:
                if indicator not in chart_df.columns:
                    continue
                vals = pd.to_numeric(chart_df[indicator], errors="coerce")
                valid = vals.notna()
                sub = chart_df.loc[valid, [x, indicator]].copy()
                if sub.empty:
                    continue
                nums = pd.to_numeric(sub[indicator], errors="coerce")
                max_idx = nums.idxmax()
                min_idx = nums.idxmin()
                evidence = {
                    "indicator": str(indicator),
                    "observations": int(nums.count()),
                    "total": float(nums.sum()),
                    "average": float(nums.mean()),
                    "minimum": float(nums.min()),
                    "maximum": float(nums.max()),
                    "highest_category": str(sub.loc[max_idx, x]),
                    "lowest_category": str(sub.loc[min_idx, x]),
                }
                if len(nums) >= 2:
                    first_value = float(nums.iloc[0])
                    last_value = float(nums.iloc[-1])
                    evidence["first_value"] = first_value
                    evidence["last_value"] = last_value
                    evidence["absolute_change"] = last_value - first_value
                    evidence["percent_change"] = (
                        (last_value - first_value) / abs(first_value) * 100
                        if first_value != 0 else None
                    )
                indicator_evidence.append(evidence)

        if not indicator_evidence:
            return None

        # Programme-facing interpretation based on evidence only.
        observations = []
        actions = []

        for item in indicator_evidence:
            direction = ""
            pct = item.get("percent_change")
            if pct is not None:
                if pct > 5:
                    direction = f"increased by {pct:.1f}%"
                elif pct < -5:
                    direction = f"decreased by {abs(pct):.1f}%"
                else:
                    direction = f"changed by {pct:.1f}%"

            observations.append(
                f"**{item['indicator']}** recorded {item['observations']:,} analysed observations, "
                f"with an average of {_format_viz_value(item['average'])}, a minimum of "
                f"{_format_viz_value(item['minimum'])}, and a maximum of {_format_viz_value(item['maximum'])}. "
                f"The highest observed value was in **{item['highest_category']}** and the lowest was in "
                f"**{item['lowest_category']}**."
                + (f" Across the displayed sequence, the indicator {direction}." if direction else "")
            )

        if high:
            actions.append("Resolve HIGH-priority data-quality findings before using the result for high-stakes programme decisions.")
        if medium:
            actions.append("Validate MEDIUM-priority findings with source registers, reporting units or responsible data owners.")
        if not actions:
            actions.append("Continue routine data-quality monitoring and document the current evidence as part of the reporting cycle.")
        actions.append("Use the observed differences to target programme follow-up, verification and learning; do not infer causality from the descriptive data alone.")

        if quality_score >= 90:
            quality_implication = "The quality assessment indicates strong evidence for routine interpretation under the implemented controls."
        elif quality_score >= 75:
            quality_implication = "The results can support routine programme monitoring, but the identified quality findings should be considered when interpreting differences."
        elif quality_score >= 50:
            quality_implication = "The results should be interpreted cautiously because the quality assessment indicates areas requiring review."
        else:
            quality_implication = "The results should not be treated as fully reliable for high-stakes management decisions until material quality issues are addressed."

        confidence = "High" if quality_score >= 90 and not high else "Medium" if quality_score >= 50 else "Low"

        return {
            "analysis": {
                "x_axis": str(x),
                "aggregation": aggregation,
                "indicators": [str(i) for i in indicators],
                "rows_analysed": int(len(df)),
                "chart_types": plan.get("chart_labels") or plan.get("chart_types") or [],
            },
            "indicator_evidence": indicator_evidence,
            "quality": {
                "score": quality_score,
                "rating": quality_rating,
                "high_priority": len(high),
                "medium_priority": len(medium),
            },
            "observations": observations,
            "quality_implication": quality_implication,
            "actions": actions,
            "confidence": confidence,
        }


    def ask_ai_me_programme_interpretation(evidence, quality_interpretation=None):
        """Optional AI layer for programme-manager interpretation with local fallback."""
        if not evidence:
            return {"status": "FALLBACK", "source": "LOCAL_RULES", "text": "No valid requested-analysis evidence is available."}

        if client is None:
            return {"status": "FALLBACK", "source": "LOCAL_RULES", "text": build_local_me_programme_interpretation(evidence)}

        prompt = f"""
    You are a senior Monitoring, Evaluation and Learning (M&E) advisor and programme
    manager supporting a DHIS2-based nutrition/public-health programme.

    Interpret ONLY the deterministic evidence supplied below. Do not recalculate it,
    do not invent values, and do not claim causation. The user's selected analysis,
    indicator(s), X-axis and aggregation are authoritative.

    Your purpose is to translate the result into a concise management narrative:
    - What does the result show?
    - What performance pattern, gap, change or exception matters most?
    - What does it mean for programme monitoring and implementation follow-up?
    - Which findings should a programme manager investigate?
    - What M&E actions should happen next?
    - How does data quality affect confidence in the interpretation?

    Use programme-management language, not technical statistical jargon. Distinguish
    observed patterns from possible explanations. Never state that a programme
    intervention caused a change unless the supplied evidence establishes causality.

    REQUESTED ANALYSIS EVIDENCE:
    {safe_json_dumps(evidence)}

    EXISTING DATA-QUALITY INTERPRETATION, IF AVAILABLE:
    {quality_interpretation or 'None'}

    Return exactly these sections:

    ## Executive Programme Message
    A concise 2-4 sentence management summary.

    ## What the Analysis Shows
    Describe the most important observed results, comparisons and changes.

    ## M&E Interpretation
    Explain what the pattern means for programme monitoring, performance review,
    implementation follow-up and learning. Clearly distinguish observation from hypothesis.

    ## Data Quality Implication
    Explain whether quality findings materially limit interpretation.

    ## Programme Management Attention
    List the most important issues a programme manager should review.

    ## Recommended M&E Actions
    Give 3-6 practical actions covering verification, performance follow-up, learning,
    and data-quality improvement where relevant.

    ## Confidence
    Give High, Medium or Low confidence and one short evidence-based reason.
    """

        try:
            response = client.responses.create(
                model=OPENAI_MODEL,
                input=prompt,
            )
            return {
                "status": "SUCCESS",
                "source": "OPENAI",
                "text": response.output_text or build_local_me_programme_interpretation(evidence),
            }
        except Exception:
            return {
                "status": "FALLBACK",
                "source": "LOCAL_RULES",
                "text": build_local_me_programme_interpretation(evidence),
            }


    def build_local_me_programme_interpretation(evidence):
        """Evidence-only programme-manager narrative used when AI is unavailable."""
        if not evidence:
            return "No programme interpretation is available because the requested analysis produced no valid evidence."

        lines = ["## Executive Programme Message"]
        lines.append(
            f"The requested analysis covers **{evidence['analysis']['rows_analysed']:,} records** using "
            f"**{evidence['analysis']['aggregation']}** aggregation across **{evidence['analysis']['x_axis']}**. "
            f"The interpretation is descriptive and should be used to guide programme review rather than establish causality."
        )

        lines.append("\n## What the Analysis Shows")
        lines.extend(f"- {x}" for x in evidence.get("observations", []))

        lines.append("\n## M&E Interpretation")
        lines.append(
            "The observed differences identify where programme performance, reporting patterns or implementation follow-up may warrant attention. "
            "The strongest and weakest observed categories should be reviewed with programme context, service-delivery information and responsible reporting teams before drawing operational conclusions."
        )

        lines.append("\n## Data Quality Implication")
        lines.append(evidence.get("quality_implication", "Data-quality implications should be reviewed alongside the result."))

        lines.append("\n## Programme Management Attention")
        for item in evidence.get("observations", [])[:5]:
            lines.append(f"- Review the programme context behind: {item}")
        if evidence["quality"]["high_priority"]:
            lines.append(f"- Address {evidence['quality']['high_priority']} HIGH-priority data-quality finding(s).")
        if evidence["quality"]["medium_priority"]:
            lines.append(f"- Validate {evidence['quality']['medium_priority']} MEDIUM-priority data-quality finding(s).")

        lines.append("\n## Recommended M&E Actions")
        for idx, action in enumerate(evidence.get("actions", []), 1):
            lines.append(f"{idx}. {action}")

        lines.append("\n## Confidence")
        lines.append(
            f"**{evidence.get('confidence', 'Medium')} confidence.** "
            "Confidence reflects the deterministic analysis and the current data-quality assessment."
        )
        return "\n\n".join(lines)


    def render_me_programme_narration(df, plan, quality_issues, quality_matrix, quality_summary):
        """Render the M&E interpretation module immediately below Requested Visualizations."""
        evidence = build_me_programme_narrative(
            df,
            plan,
            quality_issues,
            quality_matrix,
            quality_summary,
        )
        if not evidence:
            return

        st.markdown("---")
        st.subheader("🧭 M&E Programme Manager Interpretation")
        st.caption(
            "Translates the selected analysis, visualization evidence and DHIS2 quality findings into a programme-management narrative. "
            "It describes observed patterns and does not claim causality."
        )

        a1, a2, a3, a4 = st.columns(4)
        with a1:
            st.metric("Indicators", f"{len(evidence['analysis']['indicators']):,}")
        with a2:
            st.metric("Records analysed", f"{evidence['analysis']['rows_analysed']:,}")
        with a3:
            st.metric("Quality", f"{evidence['quality']['score']:.1f}/100")
        with a4:
            st.metric("Confidence", evidence["confidence"])

        st.markdown(
            f"""
            <div class="me-programme-card">
                <div class="me-programme-kicker">PROGRAMME MANAGEMENT VIEW</div>
                <div class="me-programme-title">Evidence-based interpretation of the selected result</div>
                <div class="me-programme-meta">
                    X-axis: <strong>{html.escape(evidence['analysis']['x_axis'])}</strong> ·
                    Aggregation: <strong>{html.escape(evidence['analysis']['aggregation'])}</strong> ·
                    Indicators: <strong>{html.escape(', '.join(evidence['analysis']['indicators']))}</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.button(
            "🤖 Generate AI M&E Programme Interpretation",
            key="generate_me_programme_interpretation",
            use_container_width=True,
        ):
            quality_ai = st.session_state.get("dq_ai_interpretation")
            quality_text = quality_ai.get("text", "") if isinstance(quality_ai, dict) else ""
            with st.spinner("🤖 Interpreting the analysis for programme managers..."):
                st.session_state["me_programme_interpretation"] = ask_ai_me_programme_interpretation(
                    evidence,
                    quality_interpretation=quality_text,
                )

        result = st.session_state.get("me_programme_interpretation")
        if result:
            source = result.get("source", "LOCAL_RULES")
            badge = "AI-ASSISTED" if source == "OPENAI" else "EVIDENCE-BASED FALLBACK"
            st.markdown(
                f"""
                <div class="me-ai-badge">{badge}</div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown(
                f'<div class="me-programme-result">{result.get("text", "")}</div>',
                unsafe_allow_html=True,
            )
        else:
            # Show the deterministic preview immediately; AI is an optional enhancement.
            preview = build_local_me_programme_interpretation(evidence)
            with st.expander("📋 Evidence-Based Programme Interpretation", expanded=True):
                st.markdown(preview)




    # ============================================================
    # COMPLETE DATASET TABLE — ISOLATED MODULE
    # ============================================================

    def render_complete_dataset_table(df, source_url=None):
        """
        Display ALL rows and ALL columns from the currently loaded dataset.

        This module does not modify the existing dataframe, charts,
        aggregation, data-quality calculations, or AI analysis.
        """
        if not isinstance(df, pd.DataFrame) or df.empty:
            st.info("No loaded dataset is available to display.")
            return

        st.markdown("### 📋 Complete Loaded Dataset")
        st.caption(
            f"All data currently loaded from the source: "
            f"{len(df):,} rows × {len(df.columns):,} columns"
        )

        c1, c2, c3 = st.columns([2, 1, 1])

        with c1:
            search_text = st.text_input(
                "🔎 Search data",
                value="",
                placeholder="Search across all columns...",
                key="complete_dataset_search",
            )

        with c2:
            show_rows = st.selectbox(
                "Rows displayed",
                options=[100, 500, 1000, 5000, 10000, "All"],
                index=2,
                key="complete_dataset_rows",
            )

        with c3:
            sort_column = st.selectbox(
                "Sort by",
                options=["None"] + [str(c) for c in df.columns],
                index=0,
                key="complete_dataset_sort",
            )

        display_df = df.copy()

        if search_text.strip():
            search_value = search_text.strip().lower()
            mask = display_df.astype(str).apply(
                lambda column: column.str.lower().str.contains(
                    search_value, na=False, regex=False
                )
            ).any(axis=1)
            display_df = display_df.loc[mask].copy()

        if sort_column != "None" and sort_column in display_df.columns:
            try:
                display_df = display_df.sort_values(by=sort_column, kind="stable")
            except Exception:
                pass

        filtered_count = len(display_df)

        csv_data = display_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="⬇️ Download Complete Data as CSV",
            data=csv_data,
            file_name="DANIP_complete_loaded_data.csv",
            mime="text/csv",
            use_container_width=True,
            key="download_complete_dataset_csv",
        )

        if show_rows == "All":
            table_df = display_df
            limited = False
        else:
            table_df = display_df.head(int(show_rows))
            limited = len(display_df) > int(show_rows)

        if search_text.strip():
            st.info(
                f"🔎 Search result: {filtered_count:,} matching rows "
                f"from {len(df):,} total loaded rows."
            )
        else:
            st.success(
                f"✅ Complete dataset loaded: {len(df):,} rows × "
                f"{len(df.columns):,} columns."
            )

        if limited:
            st.caption(
                f"Displaying the first {len(table_df):,} rows of "
                f"{filtered_count:,} matching rows. Select 'All' to display every matching row."
            )
        else:
            st.caption(f"Displaying all {len(table_df):,} matching rows.")

        st.dataframe(
            table_df,
            use_container_width=True,
            hide_index=True,
            height=600,
        )

        with st.expander("📊 Dataset Information", expanded=False):
            info_col1, info_col2, info_col3, info_col4 = st.columns(4)

            with info_col1:
                st.metric("Total Loaded Rows", f"{len(df):,}")
            with info_col2:
                st.metric("Columns", f"{len(df.columns):,}")
            with info_col3:
                st.metric("Rows After Search", f"{filtered_count:,}")
            with info_col4:
                st.metric("Missing Cells", f"{int(df.isna().sum().sum()):,}")

            st.markdown("#### Columns")
            column_info = pd.DataFrame({
                "Column": [str(c) for c in df.columns],
                "Data Type": [str(df[c].dtype) for c in df.columns],
                "Non-Missing": [int(df[c].notna().sum()) for c in df.columns],
                "Missing": [int(df[c].isna().sum()) for c in df.columns],
            })
            st.dataframe(column_info, use_container_width=True, hide_index=True)



    # ============================================================
    # MEAL INTELLIGENCE LAYER — ADDITIVE MODULE
    # ============================================================
    # This section is intentionally self-contained.
    # It reads the loaded dataframe and stores MEAL registers in
    # Streamlit session state only. It does not alter existing
    # DHIS2 retrieval, calculations, charts, quality scores or AI.
    # ============================================================

    def _meal_col(df, patterns, exclude=None):
        exclude = set(exclude or [])
        for c in df.columns:
            if c in exclude:
                continue
            n = re.sub(r"[^a-z0-9]+", " ", str(c).lower()).strip()
            if any(re.search(p, n) for p in patterns):
                return c
        return None


    def _meal_num(s):
        return pd.to_numeric(s, errors="coerce")


    def _meal_pct(a, t):
        try:
            a, t = float(a), float(t)
            return None if t == 0 else a / t * 100
        except Exception:
            return None


    def _meal_status(pct, direction="Higher is better"):
        if pct is None or not pd.notna(pct):
            return "⚪ No target"
        if direction == "Lower is better":
            if pct <= 100:
                return "🟢 On track"
            if pct <= 120:
                return "🟡 Attention"
            return "🔴 Off track"
        if pct >= 90:
            return "🟢 On track"
        if pct >= 75:
            return "🟡 Attention"
        return "🔴 Off track"


    def _meal_period_column(df):
        return find_period_column(df) or _meal_col(
            df, [r"month", r"reporting date", r"event date", r"year"]
        )


    # ============================================================
    # MEAL PERSISTENT STORAGE — SQLITE
    # ============================================================
    # Session state is only a UI cache. SQLite is the persistent source
    # for manually maintained MEAL registers, so records survive refresh,
    # browser reloads and Streamlit reruns.
    MEAL_DB_PATH = os.path.join(BASE_DIR, "danip_meal.db")

    _MEAL_TABLE_COLUMNS = {
        "meal_results_framework": [
            "Indicator", "Result Level", "Baseline", "Target",
            "Direction", "Frequency", "Responsible", "Definition", "Status"
        ],
        "meal_actions": [
            "Finding", "Action", "Owner", "Due Date", "Priority", "Status"
        ],
        "meal_learning": [
            "Learning", "Evidence", "Decision", "Adaptation", "Owner", "Date", "Status"
        ],
        "meal_feedback": [
            "Date", "Location", "Category", "Priority", "Feedback",
            "Owner", "Response Date", "Status", "Resolution"
        ],
        "meal_risks": [
            "Risk / Assumption", "Evidence", "Likelihood", "Impact",
            "Mitigation", "Owner", "Status"
        ],
        "meal_project_context": [
            "Programme / Project", "Country / Location", "Reporting Period",
            "Donor / Funding", "Prepared By", "Programme Context",
            "Executive Summary", "Key Challenges", "Key Recommendations",
            "Management Conclusion"
        ],
    }


    def _meal_db_connect():
        conn = sqlite3.connect(MEAL_DB_PATH, timeout=15)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS meal_registers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                register TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()
        return conn


    def _meal_db_load(register):
        columns = _MEAL_TABLE_COLUMNS[register]
        try:
            conn = _meal_db_connect()
            rows = conn.execute(
                "SELECT id, payload FROM meal_registers WHERE register=? ORDER BY id",
                (register,)
            ).fetchall()
            conn.close()
            if not rows:
                return pd.DataFrame(columns=columns)

            data = []
            for record_id, payload in rows:
                try:
                    item = json.loads(payload)
                except Exception:
                    item = {}
                item = {c: item.get(c, "") for c in columns}
                item["_MEAL_ID"] = record_id
                data.append(item)
            return pd.DataFrame(data, columns=["_MEAL_ID"] + columns)
        except Exception as exc:
            st.warning(f"MEAL persistent storage could not be loaded: {exc}")
            return pd.DataFrame(columns=columns)


    def _meal_db_replace(register, df):
        """Persist the complete current register while retaining stable IDs when possible."""
        columns = _MEAL_TABLE_COLUMNS[register]
        work = df.copy() if isinstance(df, pd.DataFrame) else pd.DataFrame(columns=columns)
        for c in columns:
            if c not in work.columns:
                work[c] = ""
        work = work[columns + (["_MEAL_ID"] if "_MEAL_ID" in work.columns else [])].copy()

        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        try:
            conn = _meal_db_connect()
            existing_ids = set(
                r[0] for r in conn.execute(
                    "SELECT id FROM meal_registers WHERE register=?", (register,)
                ).fetchall()
            )
            kept_ids = set()

            for _, row in work.iterrows():
                payload = {}
                for c in columns:
                    value = row.get(c, "")
                    if pd.isna(value):
                        value = ""
                    payload[c] = str(value)

                rid = row.get("_MEAL_ID", None)
                try:
                    rid = int(rid) if pd.notna(rid) else None
                except Exception:
                    rid = None

                if rid and rid in existing_ids:
                    conn.execute(
                        "UPDATE meal_registers SET payload=?, updated_at=? WHERE id=? AND register=?",
                        (json.dumps(payload, ensure_ascii=False), now, rid, register),
                    )
                    kept_ids.add(rid)
                else:
                    cur = conn.execute(
                        "INSERT INTO meal_registers(register,payload,created_at,updated_at) VALUES(?,?,?,?)",
                        (register, json.dumps(payload, ensure_ascii=False), now, now),
                    )
                    kept_ids.add(cur.lastrowid)

            for rid in existing_ids - kept_ids:
                conn.execute("DELETE FROM meal_registers WHERE id=? AND register=?", (rid, register))
            conn.commit()
            conn.close()
        except Exception as exc:
            st.error(f"Unable to save MEAL register '{register}': {exc}")


    def _meal_db_add(register, record):
        """Insert one MEAL record and return its database ID."""
        columns = _MEAL_TABLE_COLUMNS[register]
        payload = {}
        for c in columns:
            value = record.get(c, "")
            if pd.isna(value):
                value = ""
            payload[c] = str(value)
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        try:
            conn = _meal_db_connect()
            cur = conn.execute(
                "INSERT INTO meal_registers(register,payload,created_at,updated_at) VALUES(?,?,?,?)",
                (register, json.dumps(payload, ensure_ascii=False), now, now),
            )
            conn.commit()
            rid = cur.lastrowid
            conn.close()
            return rid
        except Exception as exc:
            st.error(f"Unable to save MEAL record: {exc}")
            return None


    def _meal_persistent_df(register):
        return _meal_db_load(register)


    def _meal_init_state():
        defaults = {
            "meal_results_framework": pd.DataFrame(columns=_MEAL_TABLE_COLUMNS["meal_results_framework"]),
            "meal_actions": pd.DataFrame(columns=_MEAL_TABLE_COLUMNS["meal_actions"]),
            "meal_learning": pd.DataFrame(columns=_MEAL_TABLE_COLUMNS["meal_learning"]),
            "meal_feedback": pd.DataFrame(columns=_MEAL_TABLE_COLUMNS["meal_feedback"]),
            "meal_risks": pd.DataFrame(columns=_MEAL_TABLE_COLUMNS["meal_risks"]),
            "meal_project_context": pd.DataFrame(columns=_MEAL_TABLE_COLUMNS["meal_project_context"]),
        }
        for key, value in defaults.items():
            if key not in st.session_state:
                stored = _meal_persistent_df(key)
                st.session_state[key] = stored if not stored.empty else value.copy()


    def build_meal_performance(df):
        if df.empty:
            return pd.DataFrame(), {}
        target = _meal_col(df, [
            r"^target$", r"annual target", r"monthly target",
            r"quarter target", r"planned", r"goal"
        ])
        actual = _meal_col(df, [
            r"^actual$", r"achievement", r"result", r"reported value",
            r"actual value", r"^value$"
        ], exclude=[target] if target else [])
        if not target or not actual:
            return pd.DataFrame(), {
                "target": target, "actual": actual, "status": "NOT_AVAILABLE"
            }

        work = pd.DataFrame({
            "Target": _meal_num(df[target]),
            "Actual": _meal_num(df[actual]),
        }).dropna()

        if work.empty:
            return pd.DataFrame(), {
                "target": target, "actual": actual, "status": "NO_VALID_DATA"
            }

        work["Achievement %"] = [
            _meal_pct(a, t) for a, t in zip(work["Actual"], work["Target"])
        ]
        work["Gap"] = work["Actual"] - work["Target"]
        work["Status"] = work["Achievement %"].apply(_meal_status)
        return work, {
            "target": str(target), "actual": str(actual),
            "status": "SUCCESS", "records": len(work)
        }


    def build_meal_equity(df):
        dimensions = {
            "Sex / Gender": [r"^sex$", r"gender"],
            "Age / Age Group": [r"^age$", r"age group", r"age_group"],
            "Geography": [
                r"district", r"region", r"province", r"county",
                r"zone", r"woreda", r"location"
            ],
            "Organisation Unit": [
                r"organisation unit", r"organization unit",
                r"org unit", r"orgunit", r"facility"
            ],
            "Population Group": [
                r"population group", r"beneficiary group", r"target group"
            ],
            "Disability": [r"disability", r"functional difficulty"],
            "Vulnerability": [r"vulnerab", r"refugee", r"displaced", r"migrant"],
        }
        return {
            label: _meal_col(df, pats)
            for label, pats in dimensions.items()
            if _meal_col(df, pats)
        }


    def build_meal_outcome_change(df):
        period = _meal_period_column(df)
        if not period:
            return pd.DataFrame(), "NO_PERIOD"

        work = df.copy()
        parsed = pd.to_datetime(work[period], errors="coerce")

        # Support common DHIS2 monthly period codes such as 2025Jan.
        if parsed.notna().sum() < 2:
            parsed = pd.to_datetime(
                work[period].astype(str).str.replace(
                    r"^(\d{4})([A-Za-z]{3})$", r"\1-\2-01", regex=True
                ),
                errors="coerce"
            )

        work["__meal_date"] = parsed
        work = work.dropna(subset=["__meal_date"]).sort_values("__meal_date")
        if work.empty or work["__meal_date"].nunique() < 2:
            return pd.DataFrame(), "INSUFFICIENT_PERIODS"

        first_date = work["__meal_date"].min()
        last_date = work["__meal_date"].max()
        first = work[work["__meal_date"] == first_date]
        last = work[work["__meal_date"] == last_date]

        rows = []
        for c in get_numeric_columns(df):
            a = _meal_num(first[c]).dropna()
            b = _meal_num(last[c]).dropna()
            if a.empty or b.empty:
                continue
            av, bv = float(a.mean()), float(b.mean())
            rows.append({
                "Indicator / Field": str(c),
                "First Period": str(first_date.date()),
                "Latest Period": str(last_date.date()),
                "First Value": av,
                "Latest Value": bv,
                "Absolute Change": bv - av,
                "% Change": ((bv - av) / abs(av) * 100) if av else None,
                "Direction": "Improved" if bv > av else "Declined" if bv < av else "No change",
            })
        return pd.DataFrame(rows), "SUCCESS" if rows else "NO_NUMERIC_INDICATORS"


    def build_meal_indicator_registry(df):
        numeric = get_numeric_columns(df)
        period = _meal_period_column(df)
        ou = find_ou_column(df)
        source = _meal_col(df, [r"data source", r"source"])
        numerator = _meal_col(df, [r"numerator"])
        denominator = _meal_col(df, [r"denominator"])

        rows = []
        for c in numeric:
            rows.append({
                "Indicator / Field": str(c),
                "Numeric": "Yes",
                "Reporting Period": str(period) if period else "Not detected",
                "Organisation Unit": str(ou) if ou else "Not detected",
                "Data Source": str(source) if source else "Not detected",
                "Numerator": str(numerator) if numerator else "Not detected",
                "Denominator": str(denominator) if denominator else "Not detected",
                "Definition": "User/configuration required",
            })
        return pd.DataFrame(rows)


    def _meal_download(df, filename, label):
        if isinstance(df, pd.DataFrame) and not df.empty:
            st.download_button(
                label, df.to_csv(index=False).encode("utf-8"),
                filename, "text/csv", use_container_width=True,
                key=f"meal_dl_{filename.replace('.', '_')}"
            )



    def _meal_context_record():
        """Return the single persistent project/programme context record."""
        stored = _meal_persistent_df("meal_project_context")
        if stored.empty:
            return {c: "" for c in _MEAL_TABLE_COLUMNS["meal_project_context"]}
        row = stored.iloc[0].to_dict()
        return {c: ("" if pd.isna(row.get(c, "")) else str(row.get(c, ""))) for c in _MEAL_TABLE_COLUMNS["meal_project_context"]}


    def _meal_save_context(record):
        """Persist project/programme reporting context as a single editable record."""
        context_df = pd.DataFrame([record], columns=_MEAL_TABLE_COLUMNS["meal_project_context"])
        _meal_db_replace("meal_project_context", context_df)
        st.session_state["meal_project_context"] = _meal_persistent_df("meal_project_context")


    def _meal_build_excel_bytes(sheets):
        """Build an editable multi-sheet Excel MEAL report."""
        output = BytesIO()
        try:
            with pd.ExcelWriter(output, engine="openpyxl") as writer:
                for name, frame in sheets.items():
                    safe_name = re.sub(r"[\\/*?:\[\]]", "-", str(name))[:31] or "Sheet"
                    data = frame.copy() if isinstance(frame, pd.DataFrame) else pd.DataFrame(frame)
                    data.to_excel(writer, sheet_name=safe_name, index=False)
                    ws = writer.book[safe_name]
                    ws.freeze_panes = "A2"
                    for col_cells in ws.columns:
                        max_len = 0
                        col_letter = col_cells[0].column_letter
                        for cell in col_cells[:200]:
                            value = "" if cell.value is None else str(cell.value)
                            max_len = max(max_len, len(value))
                        ws.column_dimensions[col_letter].width = min(max(max_len + 2, 12), 45)
        except Exception as exc:
            raise RuntimeError(f"Excel export failed: {exc}") from exc
        return output.getvalue()


    def _meal_add_word_table(doc, title, frame, max_rows=200):
        """Add a readable editable Word table from a dataframe."""
        if not isinstance(frame, pd.DataFrame):
            frame = pd.DataFrame(frame)
        doc.add_heading(str(title), level=2)
        if frame.empty:
            doc.add_paragraph("No records available.")
            return
        display = frame.drop(columns=["_MEAL_ID"], errors="ignore").copy().head(max_rows)
        table = doc.add_table(rows=1, cols=len(display.columns))
        table.style = "Table Grid"
        for i, col in enumerate(display.columns):
            table.rows[0].cells[i].text = str(col)
        for _, row in display.iterrows():
            cells = table.add_row().cells
            for i, col in enumerate(display.columns):
                value = row.get(col, "")
                if pd.isna(value):
                    value = ""
                cells[i].text = str(value)
        if len(frame) > max_rows:
            doc.add_paragraph(f"Note: Word table limited to first {max_rows:,} rows. Full data is available in the Excel export.")


    def _meal_build_word_bytes(context, report, performance, results_framework, outcome,
                               equity_tables, registry, feedback, learning, actions, risks,
                               quality_issues, complete_data=None):
        """Build an editable Word MEAL report containing context, findings and registers."""
        if not WORD_EXPORT_AVAILABLE:
            raise RuntimeError("Word export requires python-docx. Install it with: pip install python-docx")

        doc = Document()
        section = doc.sections[0]
        section.top_margin = Inches(0.65)
        section.bottom_margin = Inches(0.65)
        section.left_margin = Inches(0.65)
        section.right_margin = Inches(0.65)

        title = doc.add_heading("NEXUS AI — MEAL Intelligence & Programme Management Report", 0)
        title.runs[0].font.size = Pt(20)

        programme = context.get("Programme / Project", "") or "Programme / Project"
        period = context.get("Reporting Period", "")
        location = context.get("Country / Location", "")
        doc.add_paragraph(f"Programme/Project: {programme}")
        if location:
            doc.add_paragraph(f"Country / Location: {location}")
        if period:
            doc.add_paragraph(f"Reporting Period: {period}")
        if context.get("Donor / Funding"):
            doc.add_paragraph(f"Donor / Funding: {context['Donor / Funding']}")
        if context.get("Prepared By"):
            doc.add_paragraph(f"Prepared By: {context['Prepared By']}")

        doc.add_heading("1. Programme Context", level=1)
        doc.add_paragraph(context.get("Programme Context", "Edit this section to describe the programme context, implementation setting, target population and reporting purpose."))

        doc.add_heading("2. Executive Summary", level=1)
        doc.add_paragraph(context.get("Executive Summary", "Edit this section to provide the programme-specific management summary."))

        _meal_add_word_table(doc, "3. Evidence Snapshot", report, max_rows=50)
        _meal_add_word_table(doc, "4. Target vs Actual Performance", performance, max_rows=200)
        _meal_add_word_table(doc, "5. Results Framework / Logframe", results_framework, max_rows=200)
        _meal_add_word_table(doc, "6. Outcome Monitoring & Change", outcome, max_rows=200)

        doc.add_heading("7. Equity & Disaggregation", level=1)
        if equity_tables:
            for name, frame in equity_tables.items():
                _meal_add_word_table(doc, name, frame, max_rows=100)
        else:
            doc.add_paragraph("No standard equity/disaggregation fields were detected.")

        _meal_add_word_table(doc, "8. Indicator Registry", registry, max_rows=300)
        _meal_add_word_table(doc, "9. Accountability / Feedback", feedback, max_rows=200)
        _meal_add_word_table(doc, "10. Learning & Adaptation", learning, max_rows=200)
        _meal_add_word_table(doc, "11. Action Tracker", actions, max_rows=200)
        _meal_add_word_table(doc, "12. Risks & Assumptions", risks, max_rows=200)

        doc.add_heading("13. Data Quality Findings", level=1)
        if quality_issues:
            _meal_add_word_table(doc, "Priority Data Quality Issues", pd.DataFrame(quality_issues), max_rows=100)
        else:
            doc.add_paragraph("No priority data-quality findings were supplied to the MEAL report.")

        doc.add_heading("14. Programme-Specific Challenges", level=1)
        doc.add_paragraph(context.get("Key Challenges", "Edit this section to capture contextual implementation challenges."))
        doc.add_heading("15. Key Recommendations", level=1)
        doc.add_paragraph(context.get("Key Recommendations", "Edit this section to capture programme-specific recommendations and management decisions."))
        doc.add_heading("16. Management Conclusion", level=1)
        doc.add_paragraph(context.get("Management Conclusion", "Edit this conclusion based on programme context, evidence and decisions."))

        doc.add_paragraph("\nGenerated by NEXUS AI. Analytical values are evidence summaries; causal interpretation should use appropriate evaluation evidence.")

        output = BytesIO()
        doc.save(output)
        return output.getvalue()


    def _meal_export_bundle(df, performance, registry, outcome, equity, report, quality_issues):
        """Create the full editable Excel + Word reporting bundle."""
        context = _meal_context_record()
        rf = st.session_state.get("meal_results_framework", pd.DataFrame())
        feedback = st.session_state.get("meal_feedback", pd.DataFrame())
        learning = st.session_state.get("meal_learning", pd.DataFrame())
        actions = st.session_state.get("meal_actions", pd.DataFrame())
        risks = st.session_state.get("meal_risks", pd.DataFrame())

        equity_tables = {}
        for dim, col in (equity or {}).items():
            counts = (
                df[col].astype("string").fillna("Missing / blank")
                .value_counts(dropna=False)
                .rename_axis(dim).reset_index(name="Records")
            )
            counts["Share %"] = counts["Records"] / max(len(df), 1) * 100
            equity_tables[f"Equity - {dim}"] = counts

        sheets = {
            "Project Context": pd.DataFrame([context]),
            "Executive Review": report,
            "Performance": performance,
            "Results Framework": rf.drop(columns=["_MEAL_ID"], errors="ignore"),
            "Outcomes": outcome,
            **equity_tables,
            "Indicator Registry": registry,
            "Accountability": feedback.drop(columns=["_MEAL_ID"], errors="ignore"),
            "Learning": learning.drop(columns=["_MEAL_ID"], errors="ignore"),
            "Actions": actions.drop(columns=["_MEAL_ID"], errors="ignore"),
            "Risks Assumptions": risks.drop(columns=["_MEAL_ID"], errors="ignore"),
            "DQ Findings": pd.DataFrame(quality_issues or []),
        }

        # Keep the full dataset in Excel when it fits within Excel's row limit.
        excel_max_rows = 1_048_000
        if isinstance(df, pd.DataFrame):
            sheets["Complete Data"] = df.head(excel_max_rows).copy()
            if len(df) > excel_max_rows:
                sheets["Project Context"] = pd.concat([
                    sheets["Project Context"],
                    pd.DataFrame([{"Programme / Project": f"Complete Data note: {len(df):,} records loaded; Excel export includes first {excel_max_rows:,} rows due to Excel row limits."}])
                ], ignore_index=True)

        excel_bytes = _meal_build_excel_bytes(sheets)
        word_bytes = _meal_build_word_bytes(
            context, report, performance, rf, outcome, equity_tables, registry,
            feedback, learning, actions, risks, quality_issues, complete_data=df
        )
        return excel_bytes, word_bytes


    def render_meal_intelligence_layer(df, quality_issues=None, quality_summary=None):
        """Render all additional MEAL functionality without changing the core app."""
        if not isinstance(df, pd.DataFrame) or df.empty:
            return

        _meal_init_state()

        performance, pmeta = build_meal_performance(df)
        equity = build_meal_equity(df)
        outcome, outcome_status = build_meal_outcome_change(df)
        registry = build_meal_indicator_registry(df)

        st.markdown("---")
        st.markdown("## 🧭 MEAL Intelligence & Programme Management")
        st.caption(
            "Additive MEAL layer for results monitoring, indicator management, "
            "equity, outcome change, accountability, learning, action tracking "
            "and risk/assumption management."
        )
        st.caption(f"💾 Persistent MEAL storage: `{os.path.basename(MEAL_DB_PATH)}` — manual MEAL records survive refresh and app reruns.")

        # Executive KPI strip
        high_q = sum(
            1 for i in (quality_issues or [])
            if str(i.get("Priority", "")).upper() == "HIGH"
        )
        k = st.columns(6)
        k[0].metric("MEAL records", f"{len(df):,}")
        k[1].metric("Indicators", f"{len(registry):,}")
        k[2].metric("Equity dimensions", f"{len(equity):,}")
        k[3].metric("Actions", f"{len(st.session_state['meal_actions']):,}")
        k[4].metric("Learning", f"{len(st.session_state['meal_learning']):,}")
        k[5].metric("High DQ findings", f"{high_q:,}")

        tabs = st.tabs([
            "🎯 Performance", "🧩 Results Framework", "📊 Outcomes",
            "⚖️ Equity", "📖 Indicator Registry", "📣 Accountability",
            "💡 Learning", "✅ Actions", "⚠️ Risks & Assumptions",
            "📄 MEAL Report"
        ])

        # 1 Performance
        with tabs[0]:
            st.markdown("### Target vs Actual Performance")
            if pmeta.get("status") == "SUCCESS":
                st.caption(
                    f"Detected target: **{pmeta['target']}** | "
                    f"actual: **{pmeta['actual']}**"
                )
                avg = performance["Achievement %"].dropna().mean()
                a, b, c, d = st.columns(4)
                a.metric("Average achievement", f"{avg:.1f}%")
                b.metric("On track", int(performance["Status"].eq("🟢 On track").sum()))
                c.metric("Attention", int(performance["Status"].eq("🟡 Attention").sum()))
                d.metric("Off track", int(performance["Status"].eq("🔴 Off track").sum()))
                st.dataframe(
                    performance.style.format({
                        "Target": "{:,.2f}", "Actual": "{:,.2f}",
                        "Achievement %": "{:,.1f}%", "Gap": "{:,.2f}"
                    }),
                    use_container_width=True, hide_index=True
                )
                _meal_download(performance, "DANIP_MEAL_Performance.csv", "⬇️ Export Performance")
            else:
                st.info(
                    "Target/actual performance is not automatically available in this "
                    "dataset. Configure targets in the Results Framework tab."
                )

        # 2 Results Framework
        with tabs[1]:
            st.markdown("### Results Framework / Logframe")
            st.caption(
                "Map indicators to Impact, Outcome, Output or Activity and document "
                "baseline, target, direction, frequency and accountability."
            )
            existing = st.session_state["meal_results_framework"]
            display_existing = existing.drop(columns=["_MEAL_ID"], errors="ignore")
            edited = st.data_editor(
                display_existing,
                num_rows="dynamic",
                use_container_width=True,
                key="meal_results_framework_editor"
            )
            # Preserve stable database IDs for existing rows and persist edits.
            edited = edited.copy()
            if "_MEAL_ID" in existing.columns:
                old_ids = existing["_MEAL_ID"].tolist()
                ids = old_ids[:len(edited)] + [None] * max(0, len(edited) - len(old_ids))
                edited.insert(0, "_MEAL_ID", ids[:len(edited)])
            st.session_state["meal_results_framework"] = edited.copy()
            _meal_db_replace("meal_results_framework", edited)
            _meal_download(edited.drop(columns=["_MEAL_ID"], errors="ignore"), "DANIP_MEAL_Results_Framework.csv", "⬇️ Export Results Framework")

        # 3 Outcomes
        with tabs[2]:
            st.markdown("### Outcome Monitoring & Change")
            if outcome_status == "SUCCESS":
                st.dataframe(
                    outcome.style.format({
                        "First Value": "{:,.2f}",
                        "Latest Value": "{:,.2f}",
                        "Absolute Change": "{:,.2f}",
                        "% Change": "{:,.1f}%"
                    }),
                    use_container_width=True, hide_index=True
                )
                st.caption(
                    "Descriptive first-versus-latest comparison only. "
                    "It does not establish attribution or causal impact."
                )
                _meal_download(outcome, "DANIP_MEAL_Outcome_Change.csv", "⬇️ Export Outcome Analysis")
            else:
                st.info(f"Outcome change analysis: {outcome_status}.")
            st.markdown("#### MEAL Evaluation Questions")
            st.markdown(
                "- What changed from baseline/earliest observation to the latest observation?\n"
                "- Which results are on track, off track or uncertain?\n"
                "- Which population groups or locations show different patterns?\n"
                "- What additional qualitative or evaluation evidence is required before making causal claims?"
            )

        # 4 Equity
        with tabs[3]:
            st.markdown("### Equity, Inclusion & Disaggregation")
            if equity:
                selected = st.selectbox(
                    "Dimension", list(equity.keys()), key="meal_equity_dimension"
                )
                c = equity[selected]
                counts = (
                    df[c].astype("string").fillna("Missing / blank")
                    .value_counts(dropna=False)
                    .rename_axis(selected).reset_index(name="Records")
                )
                counts["Share %"] = counts["Records"] / max(len(df), 1) * 100
                st.dataframe(counts, use_container_width=True, hide_index=True)
                st.caption(
                    "Record shares are descriptive. Equity gaps should be assessed against "
                    "population denominators, programme targets and context."
                )
            else:
                st.info("No standard disaggregation fields were detected.")

        # 5 Indicator registry
        with tabs[4]:
            st.markdown("### Indicator Registry / Data Dictionary")
            st.dataframe(registry, use_container_width=True, hide_index=True)
            _meal_download(registry, "DANIP_MEAL_Indicator_Registry.csv", "⬇️ Export Indicator Registry")
            st.info(
                "The registry detects available technical fields from the live dataset. "
                "Definitions, calculation methods, source and targets should be maintained "
                "by the MEAL team rather than invented by the application."
            )

        # 6 Accountability
        with tabs[5]:
            st.markdown("### Accountability, Feedback & Complaints")
            feedback = st.session_state["meal_feedback"]
            resolved = feedback["Status"].astype(str).str.lower().isin(
                ["resolved", "closed"]
            ).sum() if not feedback.empty else 0
            a, b, c = st.columns(3)
            a.metric("Cases", len(feedback))
            b.metric("Open", len(feedback) - int(resolved))
            c.metric("Resolution rate", f"{(resolved/len(feedback)*100) if len(feedback) else 0:.1f}%")

            with st.form("meal_feedback_add", clear_on_submit=True):
                x1, x2, x3 = st.columns(3)
                with x1:
                    fdate = st.date_input("Date")
                    flocation = st.text_input("Location")
                    fcat = st.selectbox("Category", ["Feedback", "Complaint", "Suggestion", "Request", "Safeguarding", "Other"])
                with x2:
                    fpriority = st.selectbox("Priority", ["HIGH", "MEDIUM", "LOW"])
                    fowner = st.text_input("Owner")
                    fresponse = st.date_input("Response date")
                with x3:
                    fstatus = st.selectbox("Status", ["Open", "In progress", "Resolved", "Closed"])
                    fissue = st.text_area("Feedback / complaint")
                    fresolution = st.text_area("Resolution")
                if st.form_submit_button("➕ Add case", use_container_width=True):
                    new = pd.DataFrame([{
                        "Date": str(fdate), "Location": flocation, "Category": fcat,
                        "Priority": fpriority, "Feedback": fissue, "Owner": fowner,
                        "Response Date": str(fresponse), "Status": fstatus,
                        "Resolution": fresolution
                    }])
                    _meal_db_add("meal_feedback", new.iloc[0].to_dict())
                    st.session_state["meal_feedback"] = _meal_persistent_df("meal_feedback")
                    st.rerun()

            if not st.session_state["meal_feedback"].empty:
                st.dataframe(st.session_state["meal_feedback"].drop(columns=["_MEAL_ID"], errors="ignore"), use_container_width=True, hide_index=True)
                _meal_download(st.session_state["meal_feedback"].drop(columns=["_MEAL_ID"], errors="ignore"), "DANIP_MEAL_Accountability.csv", "⬇️ Export Accountability Register")

        # 7 Learning
        with tabs[6]:
            st.markdown("### Learning & Adaptation Register")
            learning = st.session_state["meal_learning"]
            with st.form("meal_learning_add", clear_on_submit=True):
                a, b = st.columns(2)
                with a:
                    lesson = st.text_area("Learning / lesson")
                    evidence = st.text_area("Evidence")
                    decision = st.text_area("Programme decision")
                with b:
                    adaptation = st.text_area("Adaptation / change")
                    owner = st.text_input("Owner")
                    ldate = st.date_input("Date")
                    status = st.selectbox("Status", ["Identified", "Under review", "Applied", "Closed"])
                if st.form_submit_button("➕ Add learning", use_container_width=True):
                    new = pd.DataFrame([{
                        "Learning": lesson, "Evidence": evidence,
                        "Decision": decision, "Adaptation": adaptation,
                        "Owner": owner, "Date": str(ldate), "Status": status
                    }])
                    _meal_db_add("meal_learning", new.iloc[0].to_dict())
                    st.session_state["meal_learning"] = _meal_persistent_df("meal_learning")
                    st.rerun()
            if not st.session_state["meal_learning"].empty:
                st.dataframe(st.session_state["meal_learning"].drop(columns=["_MEAL_ID"], errors="ignore"), use_container_width=True, hide_index=True)
                _meal_download(st.session_state["meal_learning"].drop(columns=["_MEAL_ID"], errors="ignore"), "DANIP_MEAL_Learning.csv", "⬇️ Export Learning Register")

        # 8 Actions
        with tabs[7]:
            st.markdown("### MEAL Action Tracker")
            actions = st.session_state["meal_actions"]
            if not actions.empty:
                overdue = int(actions["Status"].astype(str).str.lower().eq("overdue").sum())
            else:
                overdue = 0
            a, b, c = st.columns(3)
            a.metric("Total actions", len(actions))
            b.metric("Open / active", int(len(actions) - actions["Status"].astype(str).str.lower().isin(["completed", "closed"]).sum()) if not actions.empty else 0)
            c.metric("Marked overdue", overdue)

            with st.form("meal_action_add", clear_on_submit=True):
                a1, a2 = st.columns(2)
                with a1:
                    finding = st.text_area("Finding")
                    action = st.text_area("Action")
                    owner = st.text_input("Owner")
                with a2:
                    due = st.date_input("Due date")
                    priority = st.selectbox("Priority", ["HIGH", "MEDIUM", "LOW"])
                    status = st.selectbox("Status", ["Open", "In progress", "Completed", "Overdue"])
                if st.form_submit_button("➕ Add action", use_container_width=True):
                    new = pd.DataFrame([{
                        "Finding": finding, "Action": action, "Owner": owner,
                        "Due Date": str(due), "Priority": priority, "Status": status
                    }])
                    _meal_db_add("meal_actions", new.iloc[0].to_dict())
                    st.session_state["meal_actions"] = _meal_persistent_df("meal_actions")
                    st.rerun()
            if not st.session_state["meal_actions"].empty:
                st.dataframe(st.session_state["meal_actions"].drop(columns=["_MEAL_ID"], errors="ignore"), use_container_width=True, hide_index=True)
                _meal_download(st.session_state["meal_actions"].drop(columns=["_MEAL_ID"], errors="ignore"), "DANIP_MEAL_Action_Tracker.csv", "⬇️ Export Action Tracker")

        # 9 Risks / assumptions
        with tabs[8]:
            st.markdown("### Risk, Assumption & Theory-of-Change Register")
            st.caption(
                "Document risks and assumptions explicitly. The application does not "
                "infer programme risks from numbers alone."
            )
            existing_risks = st.session_state["meal_risks"]
            display_risks = existing_risks.drop(columns=["_MEAL_ID"], errors="ignore")
            risks = st.data_editor(
                display_risks,
                num_rows="dynamic",
                use_container_width=True,
                key="meal_risk_editor"
            )
            risks = risks.copy()
            if "_MEAL_ID" in existing_risks.columns:
                old_ids = existing_risks["_MEAL_ID"].tolist()
                ids = old_ids[:len(risks)] + [None] * max(0, len(risks) - len(old_ids))
                risks.insert(0, "_MEAL_ID", ids[:len(risks)])
            st.session_state["meal_risks"] = risks.copy()
            _meal_db_replace("meal_risks", risks)
            if not risks.empty:
                high = int(risks["Impact"].astype(str).str.upper().eq("HIGH").sum())
                st.metric("High-impact risks", high)
                _meal_download(risks.drop(columns=["_MEAL_ID"], errors="ignore"), "DANIP_MEAL_Risks_Assumptions.csv", "⬇️ Export Risk Register")

        # 10 Executive MEAL report
        with tabs[9]:
            st.markdown("### Project / Programme Reporting Context")
            st.caption(
                "Set the context once. These fields are persistent and are included in the editable Word and Excel reports."
            )
            context = _meal_context_record()
            with st.form("meal_project_context_form"):
                c1, c2 = st.columns(2)
                with c1:
                    project_name = st.text_input("Programme / Project", value=context.get("Programme / Project", ""))
                    location = st.text_input("Country / Location", value=context.get("Country / Location", ""))
                    reporting_period = st.text_input("Reporting Period", value=context.get("Reporting Period", ""))
                    donor = st.text_input("Donor / Funding", value=context.get("Donor / Funding", ""))
                    prepared_by = st.text_input("Prepared By", value=context.get("Prepared By", ""))
                with c2:
                    programme_context = st.text_area("Programme Context", value=context.get("Programme Context", ""), height=110)
                    executive_summary = st.text_area("Executive Summary", value=context.get("Executive Summary", ""), height=110)
                c3, c4, c5 = st.columns(3)
                with c3:
                    challenges = st.text_area("Key Challenges", value=context.get("Key Challenges", ""), height=110)
                with c4:
                    recommendations = st.text_area("Key Recommendations", value=context.get("Key Recommendations", ""), height=110)
                with c5:
                    conclusion = st.text_area("Management Conclusion", value=context.get("Management Conclusion", ""), height=110)
                if st.form_submit_button("💾 Save Project / Programme Context", use_container_width=True):
                    _meal_save_context({
                        "Programme / Project": project_name,
                        "Country / Location": location,
                        "Reporting Period": reporting_period,
                        "Donor / Funding": donor,
                        "Prepared By": prepared_by,
                        "Programme Context": programme_context,
                        "Executive Summary": executive_summary,
                        "Key Challenges": challenges,
                        "Key Recommendations": recommendations,
                        "Management Conclusion": conclusion,
                    })
                    st.success("Project/programme context saved permanently.")

            st.markdown("### MEAL Executive Review")
            qscore = (quality_summary or {}).get("score")
            qrating = (quality_summary or {}).get("rating", "Unknown")
            perf_avg = performance["Achievement %"].dropna().mean() if not performance.empty else None

            st.markdown("#### Evidence Snapshot")
            report = pd.DataFrame([{
                "Measure": "Loaded records",
                "Value": f"{len(df):,}",
                "Interpretation": "Complete dataset currently loaded"
            }, {
                "Measure": "Data quality score",
                "Value": f"{float(qscore):.1f}/100" if qscore is not None else "Not available",
                "Interpretation": str(qrating)
            }, {
                "Measure": "Average target achievement",
                "Value": f"{perf_avg:.1f}%" if perf_avg is not None and pd.notna(perf_avg) else "Not available",
                "Interpretation": "Detected target/actual fields"
            }, {
                "Measure": "High-priority DQ findings",
                "Value": f"{high_q:,}",
                "Interpretation": "Findings requiring MEAL attention"
            }, {
                "Measure": "Open actions",
                "Value": str(int(len(st.session_state["meal_actions"]) - st.session_state["meal_actions"]["Status"].astype(str).str.lower().isin(["completed", "closed"]).sum()) if not st.session_state["meal_actions"].empty else 0),
                "Interpretation": "Items requiring follow-up"
            }])
            st.dataframe(report, use_container_width=True, hide_index=True)

            st.markdown("#### Recommended MEAL Review Questions")
            st.markdown(
                "1. **Performance:** Which indicators are below target and why?\n"
                "2. **Quality:** Which data-quality findings could materially affect decisions?\n"
                "3. **Equity:** Which groups or locations require deeper analysis?\n"
                "4. **Outcomes:** What has changed over time, and what additional evidence is needed?\n"
                "5. **Accountability:** Are feedback and complaints being responded to on time?\n"
                "6. **Learning:** What evidence should trigger programme adaptation?\n"
                "7. **Action:** Who owns each decision and when is follow-up due?\n"
                "8. **Risk:** Which assumptions or contextual risks need active monitoring?"
            )

            export = pd.concat([
                report,
                pd.DataFrame([{
                    "Measure": "Actions registered",
                    "Value": len(st.session_state["meal_actions"]),
                    "Interpretation": "Session register"
                }])
            ], ignore_index=True)
            _meal_download(export, "DANIP_MEAL_Executive_Review.csv", "⬇️ Export MEAL Executive Review")

            st.markdown("### 📦 Full Editable MEAL Report")
            st.caption(
                "Excel contains separate editable sheets for the project context, executive review, performance, results framework, outcomes, equity, indicator registry, accountability, learning, actions, risks, data quality and complete data. Word contains an editable narrative report with the same MEAL evidence and registers."
            )
            try:
                excel_bytes, word_bytes = _meal_export_bundle(
                    df=df,
                    performance=performance,
                    registry=registry,
                    outcome=outcome,
                    equity=equity,
                    report=report,
                    quality_issues=quality_issues,
                )
                e1, e2 = st.columns(2)
                with e1:
                    st.download_button(
                        "📊 Download Full MEAL Report — Excel",
                        excel_bytes,
                        "DANIP_AI_Full_MEAL_Report.xlsx",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        use_container_width=True,
                        key="meal_full_excel_export",
                    )
                with e2:
                    if WORD_EXPORT_AVAILABLE:
                        st.download_button(
                            "📝 Download Full MEAL Report — Word",
                            word_bytes,
                            "DANIP_AI_Full_MEAL_Report.docx",
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True,
                            key="meal_full_word_export",
                        )
                    else:
                        st.warning("Word export requires python-docx. Run: pip install python-docx")
            except Exception as exc:
                st.error(f"Full MEAL report export is unavailable: {exc}")

            st.success(
                "MEAL layer is additive: the existing complete-data processing, "
                "user-requested analysis, Data Quality Matrix, visualizations, "
                "Advanced Analytics, AI interpretation and chatbot are not modified."
            )


    # ============================================================
    # MAIN
    # ============================================================

    if automatic_analysis or st.session_state.get("data_loaded", False):

        if not user_url.strip():
            st.warning(
                "Please paste a DHIS2 URL."
            )
            st.stop()

        source_url = user_url.strip()

        previous_url = st.session_state.get(
            "last_analyzed_url"
        )

        url_changed = (
            previous_url != source_url
        )

        st.session_state[
            "last_analyzed_url"
        ] = source_url

        if url_changed:
            st.session_state["last_chart_plan"] = None
            st.session_state["data_loaded"] = False

        source_type = identify_url_type(
            source_url
        )

        st.info(
            f"Detected source: **{source_type}**"
        )

        # ========================================================
        # RETRIEVE / REUSE CURRENT DATASET
        # ========================================================

        if (
            st.session_state.get("data_loaded", False)
            and st.session_state.get("loaded_source_url") == source_url
            and isinstance(st.session_state.get("loaded_df"), pd.DataFrame)
        ):
            _nexus_sidebar_status(
                "Reusing the loaded dataset",
                "running",
                "DATASET CACHE",
                "NEXUS found the current source in memory and is preparing it for analysis.",
            )
            df = st.session_state["loaded_df"].copy()
            st.info("♻️ Using the already loaded dataset for automatic NEXUS AI analysis.")
        else:
            _nexus_sidebar_status(
                "Connecting to the data source",
                "running",
                "DHIS2 / API CONNECTION",
                f"Reading the requested {source_type} source and retrieving the complete dataset.",
            )
            with st.spinner("📥 Retrieving the complete dataset..."):
                try:
                    request_url = refresh_data_url(source_url)
                    raw_data = get_direct_api_data(request_url)
                except Exception:
                    try:
                        raw_data = get_direct_api_data(source_url)
                    except Exception as retry_error:
                        st.error("Unable to retrieve DHIS2 data.")
                        st.code(str(retry_error))
                        st.stop()

            _nexus_sidebar_status(
                "Normalizing the retrieved dataset",
                "running",
                "DATA NORMALIZATION",
                "Converting the source response into a consistent analytical table.",
            )
            df = normalize_dataframe(raw_data)

            if df.empty:
                st.error("DHIS2 returned data, but no tabular data could be identified.")
                if isinstance(raw_data, dict):
                    st.json(raw_data)
                st.stop()

            st.session_state["loaded_df"] = df.copy()
            st.session_state["loaded_source_url"] = source_url
            st.session_state["data_loaded"] = True

            _nexus_sidebar_status(
                f"Dataset loaded successfully — {len(df):,} records",
                "success",
                "DATASET LOADED",
                f"Complete dataset available: {len(df):,} rows × {len(df.columns):,} columns.",
            )

        # ========================================================
        # DATA LOADED
        # ========================================================

        st.success(
            f"Successfully retrieved {len(df):,} records. "
            "ALL retrieved rows are available for analysis."
        )

        st.caption(
            f"🔄 Current source: {source_url} • "
            f"Complete dataset: "
            f"{len(df):,} rows × {len(df.columns):,} columns"
        )


        # ========================================================
        # COMPLETE DATASET TABLE
        # ========================================================

        render_complete_dataset_table(
            df=df,
            source_url=source_url,
        )

        # ========================================================
        # DATA QUALITY — CALCULATE ON THE COMPLETE DATASET
        # ========================================================

        _nexus_sidebar_status(
            "Running Data Quality Matrix",
            "running",
            "DATA QUALITY ASSESSMENT",
            "Checking completeness, validity, plausibility, timeliness, integrity, consistency and other implemented controls.",
        )
        with st.spinner("🛡️ Running the Data Quality Matrix across the complete dataset..."):
            top_quality_issues, top_quality_matrix, top_quality_summary = build_quality_matrix(df)

        _nexus_sidebar_status(
            "Data Quality assessment completed",
            "success",
            "DATA QUALITY COMPLETE",
            f"Quality score: {top_quality_summary.get('score', 'N/A')}/100 · {len(top_quality_issues):,} findings.",
        )

        # Share the deterministic DQ results with the separate M&E Management Hub.
        # This does not alter the existing DQ engine or its calculations.
        st.session_state["danip_api_quality_issues"] = top_quality_issues
        st.session_state["danip_api_quality_summary"] = top_quality_summary

        # ========================================================
        # USER-REQUESTED ANALYSIS ONLY
        # ========================================================

        st.subheader("🎯 User-Requested Analysis")

        selected_plan = guided_analysis_ui(
            df=df,
            user_question="User-requested analysis",
            initial_plan=None,
        )

        live_visual_plan = st.session_state.get("guided_preview_plan")

        # Use the confirmed plan only on the button-click rerun. Otherwise use the
        # live plan so changing Analysis Type or Aggregation immediately updates
        # the calculation/visualization instead of leaving the previous Sum result.
        chart_plan = selected_plan if selected_plan is not None else live_visual_plan

        if selected_plan is not None:
            st.success(
                "✅ User-selected analysis confirmed. The selected indicators, X-axis, "
                "graph type, analysis type and aggregation will be used against the complete dataset."
            )

        # ========================================================
        # REQUESTED VISUALIZATION — ONLY THE GRAPH SELECTED BY USER
        # ========================================================

        if chart_plan and chart_plan.get("chart_requested"):
            render_requested_visualizations(
                df=df,
                plan=chart_plan,
            )

            # ====================================================
            # M&E PROGRAMME MANAGER INTERPRETATION
            # ====================================================
            render_me_programme_narration(
                df=df,
                plan=chart_plan,
                quality_issues=top_quality_issues,
                quality_matrix=top_quality_matrix,
                quality_summary=top_quality_summary,
            )

        # ========================================================
        # DATA QUALITY MATRIX
        # ========================================================

        quality_issues, quality_matrix, quality_summary = (top_quality_issues, top_quality_matrix, top_quality_summary)

        selected_quality_indicators = (
            chart_plan.get("y_columns", [])
            if chart_plan
            else []
        )

        render_quality_dashboard(
            df=df,
            quality_issues=quality_issues,
            quality_matrix=quality_matrix,
            quality_summary=quality_summary,
            selected_indicators=selected_quality_indicators,
        )

        # ========================================================

        _nexus_sidebar_status(
            "Preparing the requested analysis",
            "running",
            "USER ANALYSIS",
            "Applying the confirmed indicators, dimension, graph type, analysis type and aggregation to the complete dataset.",
        )

        # Keep the current dataset available to the independent chatbot across
        # Streamlit reruns. The chatbot itself is rendered at the top of the
        # workspace, before any DHIS2/API URL is required.
        st.session_state["nexus_chat_df"] = df
        st.session_state["nexus_chat_source_url"] = source_url

        _nexus_sidebar_status(
            "Analysis workspace is ready",
            "success",
            "ANALYSIS READY",
            "The deterministic evidence, data-quality results and available AI interpretation are ready for review.",
        )

        # ========================================================
        # MEAL INTELLIGENCE LAYER — ADDITIVE MODULE
        # ========================================================
        # Uses the same complete loaded dataset and existing DQ outputs.
        # It does not replace or modify the existing analysis, charts,
        # data-quality calculations, AI interpretation or chatbot.
        render_meal_intelligence_layer(
            df=df,
            quality_issues=quality_issues,
            quality_summary=quality_summary,
        )

        _nexus_sidebar_status(
            "NEXUS processing completed",
            "success",
            "SYSTEM READY",
            "All current dataset, DQ, analysis, visualization and M&E intelligence modules are available.",
        )



    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# COMMON SIDEBAR — SHARED BY BOTH WORKSPACES
# ============================================================
# Live monitor styling is isolated to the sidebar monitor.
st.markdown(
    """
    <style>
/* =========================================================
   NEXUS RESPONSIVE SIDEBAR — VISUAL ONLY
   Keeps the existing application logic unchanged.
   ========================================================= */
section[data-testid="stSidebar"] {
    width: 330px !important;
    min-width: 330px !important;
    max-width: 360px !important;
}
section[data-testid="stSidebar"] > div:first-child {
    width: 100% !important;
    padding: 1rem .85rem 1.2rem .85rem !important;
}

[data-testid="stSidebar"] .block-container,
[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
    max-width: 100% !important;
}

[data-testid="stSidebar"] .stMarkdown,
[data-testid="stSidebar"] .stCaption {
    width: 100% !important;
}

.common-sidebar-brand {
    display:flex !important;
    align-items:center !important;
    gap:11px !important;
    padding:3px 2px 13px !important;
    margin-bottom:12px !important;
    border-bottom:1px solid rgba(255,255,255,.12) !important;
}
.common-sidebar-mark {
    width:38px !important;
    height:38px !important;
    min-width:38px !important;
    border-radius:10px !important;
    background:#2563eb !important;
    color:#fff !important;
    display:flex !important;
    align-items:center !important;
    justify-content:center !important;
    font-size:1.05rem !important;
    font-weight:900 !important;
}
.common-sidebar-name {
    color:#fff !important;
    -webkit-text-fill-color:#fff !important;
    font-size:.88rem !important;
    line-height:1.15 !important;
    font-weight:900 !important;
}
.common-sidebar-subtitle {
    color:#b9c7d8 !important;
    -webkit-text-fill-color:#b9c7d8 !important;
    font-size:.69rem !important;
    line-height:1.25 !important;
    margin-top:3px !important;
}

.common-sidebar-section {
    margin:15px 2px 7px !important;
    color:#9fb0c4 !important;
    -webkit-text-fill-color:#9fb0c4 !important;
    font-size:.64rem !important;
    line-height:1.2 !important;
    font-weight:900 !important;
    letter-spacing:.10em !important;
    text-transform:uppercase !important;
}

.common-sidebar-card,
.sidebar-nav-card,
.sidebar-workspace-card,
.sidebar-empty-activity {
    width:100% !important;
    box-sizing:border-box !important;
    border-radius:10px !important;
}
.common-sidebar-card {
    padding:10px 11px !important;
    background:rgba(255,255,255,.065) !important;
    border:1px solid rgba(255,255,255,.10) !important;
    color:#e8eef6 !important;
    -webkit-text-fill-color:#e8eef6 !important;
}
.common-sidebar-live {
    background:rgba(34,197,94,.10) !important;
    border-color:rgba(34,197,94,.28) !important;
}
.common-sidebar-waiting {
    background:rgba(245,158,11,.08) !important;
    border-color:rgba(245,158,11,.22) !important;
}
.sidebar-card-title {
    font-size:.78rem !important;
    font-weight:850 !important;
    line-height:1.25 !important;
    color:#fff !important;
    -webkit-text-fill-color:#fff !important;
    display:flex !important;
    align-items:center !important;
    gap:7px !important;
}
.sidebar-card-text {
    margin-top:4px !important;
    font-size:.70rem !important;
    line-height:1.45 !important;
    color:#c5d1df !important;
    -webkit-text-fill-color:#c5d1df !important;
}
.status-dot {
    width:8px !important;
    height:8px !important;
    min-width:8px !important;
    display:inline-block !important;
    border-radius:50% !important;
}
.status-dot.green { background:#22c55e !important; box-shadow:0 0 0 3px rgba(34,197,94,.13) !important; }
.status-dot.orange { background:#f59e0b !important; box-shadow:0 0 0 3px rgba(245,158,11,.13) !important; }
.status-dot.blue { background:#60a5fa !important; box-shadow:0 0 0 3px rgba(96,165,250,.13) !important; }

/* System control / restart */
.nexus-reset-card {
    padding:10px 11px !important;
    border-radius:10px !important;
    background:rgba(255,255,255,.055) !important;
    border:1px solid rgba(255,255,255,.10) !important;
}
.nexus-reset-title {
    color:#ffffff !important;
    -webkit-text-fill-color:#ffffff !important;
    font-size:.76rem !important;
    font-weight:850 !important;
    line-height:1.25 !important;
}
.nexus-reset-text {
    margin-top:4px !important;
    color:#c5d1df !important;
    -webkit-text-fill-color:#c5d1df !important;
    font-size:.64rem !important;
    line-height:1.4 !important;
}
[data-testid="stSidebar"] .nexus-reset-button button {
    width:100% !important;
    min-height:38px !important;
    border-radius:8px !important;
    border:1px solid rgba(255,255,255,.18) !important;
    background:#ffffff !important;
    color:#17374b !important;
    -webkit-text-fill-color:#17374b !important;
    font-weight:850 !important;
    font-size:.72rem !important;
}
[data-testid="stSidebar"] .nexus-reset-button button:hover {
    border-color:#ffffff !important;
    background:#f3f7fa !important;
    color:#17374b !important;
}

/* Workspace navigation */
.sidebar-nav-card {
    padding:7px !important;
    background:rgba(255,255,255,.045) !important;
    border:1px solid rgba(255,255,255,.08) !important;
}
.sidebar-nav-item {
    display:flex !important;
    gap:9px !important;
    align-items:flex-start !important;
    padding:8px !important;
    border-radius:8px !important;
    background:rgba(255,255,255,.035) !important;
}
.sidebar-nav-item + .sidebar-nav-item { margin-top:5px !important; }
.sidebar-nav-icon { font-size:.88rem !important; line-height:1.25 !important; }
.sidebar-nav-item b {
    display:block !important;
    color:#f8fafc !important;
    -webkit-text-fill-color:#f8fafc !important;
    font-size:.72rem !important;
    line-height:1.3 !important;
}
.sidebar-nav-item small {
    display:block !important;
    margin-top:3px !important;
    color:#aebdce !important;
    -webkit-text-fill-color:#aebdce !important;
    font-size:.64rem !important;
    line-height:1.35 !important;
}

/* Dataset metrics */
.sidebar-metric-grid {
    display:grid !important;
    grid-template-columns:repeat(2,minmax(0,1fr)) !important;
    gap:6px !important;
}
.sidebar-metric {
    min-width:0 !important;
    padding:8px 9px !important;
    border-radius:8px !important;
    background:rgba(255,255,255,.055) !important;
    border:1px solid rgba(255,255,255,.08) !important;
}
.sidebar-metric span {
    display:block !important;
    color:#9fb0c4 !important;
    -webkit-text-fill-color:#9fb0c4 !important;
    font-size:.59rem !important;
    line-height:1.2 !important;
}
.sidebar-metric b {
    display:block !important;
    margin-top:3px !important;
    color:#f8fafc !important;
    -webkit-text-fill-color:#f8fafc !important;
    font-size:.82rem !important;
    line-height:1.2 !important;
}

/* Recent activity */
.nexus-history {
    display:flex !important;
    flex-direction:column !important;
    gap:5px !important;
}
.nexus-history-row {
    display:flex !important;
    align-items:flex-start !important;
    gap:7px !important;
    width:100% !important;
    box-sizing:border-box !important;
    padding:7px 8px !important;
    border:1px solid rgba(255,255,255,.09) !important;
    border-radius:8px !important;
    background:rgba(255,255,255,.045) !important;
}
.nexus-history-icon { font-size:.68rem !important; line-height:1.35 !important; }
.nexus-history-content { min-width:0 !important; flex:1 !important; }
.nexus-history-message {
    color:#dce6f2 !important;
    -webkit-text-fill-color:#dce6f2 !important;
    font-size:.66rem !important;
    line-height:1.35 !important;
    font-weight:650 !important;
    overflow-wrap:anywhere !important;
}
.nexus-history-time {
    margin-top:2px !important;
    color:#8294a9 !important;
    -webkit-text-fill-color:#8294a9 !important;
    font-size:.56rem !important;
    line-height:1.2 !important;
}
.sidebar-empty-activity {
    padding:9px 10px !important;
    color:#aebdce !important;
    -webkit-text-fill-color:#aebdce !important;
    background:rgba(255,255,255,.04) !important;
    border:1px dashed rgba(255,255,255,.12) !important;
    font-size:.66rem !important;
    line-height:1.35 !important;
}
.sidebar-workspace-card {
    display:flex !important;
    align-items:center !important;
    gap:8px !important;
    padding:9px 10px !important;
    background:rgba(37,99,235,.10) !important;
    border:1px solid rgba(96,165,250,.20) !important;
}
.sidebar-workspace-card b {
    display:block !important;
    color:#eef6ff !important;
    -webkit-text-fill-color:#eef6ff !important;
    font-size:.69rem !important;
    line-height:1.25 !important;
}
.sidebar-workspace-card small {
    display:block !important;
    margin-top:2px !important;
    color:#9fb0c4 !important;
    -webkit-text-fill-color:#9fb0c4 !important;
    font-size:.58rem !important;
}

/* Live monitor */
.nexus-live-monitor {
    width:100% !important;
    box-sizing:border-box !important;
    border:1px solid #dbe4ef !important;
    border-left:4px solid var(--nexus-accent,#2563eb) !important;
    border-radius:12px !important;
    background:#fff !important;
    padding:12px !important;
    margin:0 0 12px 0 !important;
    box-shadow:0 4px 14px rgba(15,23,42,.08) !important;
}
.nexus-live-head {
    display:flex !important;
    align-items:flex-start !important;
    justify-content:space-between !important;
    gap:8px !important;
    margin-bottom:9px !important;
}
.nexus-live-kicker {
    color:#000000 !important;
    -webkit-text-fill-color:#000000 !important;
    font-weight:900 !important;
    font-size:.58rem !important;
    line-height:1.2 !important;
    font-weight:900 !important;
    letter-spacing:.09em !important;
}
.nexus-live-title {
    margin-top:3px !important;
    color:#172033 !important;
    font-size:.92rem !important;
    line-height:1.2 !important;
    font-weight:900 !important;
}
.nexus-live-clock {
    flex:0 0 auto !important;
    color:#64748b !important;
    font-size:.59rem !important;
    line-height:1.2 !important;
    font-variant-numeric:tabular-nums !important;
}
.nexus-live-current {
    display:flex !important;
    align-items:flex-start !important;
    gap:9px !important;
    padding:9px !important;
    background:#f8fafc !important;
    border:1px solid #e5eaf0 !important;
    border-radius:9px !important;
}
.nexus-live-pulse {
    width:9px !important;
    height:9px !important;
    min-width:9px !important;
    margin-top:4px !important;
    border-radius:50% !important;
    background:var(--nexus-accent,#2563eb) !important;
    box-shadow:0 0 0 4px rgba(37,99,235,.10) !important;
}
.nexus-live-activity {
    color:#172033 !important;
    font-size:.72rem !important;
    line-height:1.4 !important;
    font-weight:850 !important;
    overflow-wrap:anywhere !important;
}
.nexus-live-detail {
    margin-top:3px !important;
    color:#64748b !important;
    font-size:.61rem !important;
    line-height:1.4 !important;
    overflow-wrap:anywhere !important;
}
.nexus-live-stage {
    margin:9px 1px 6px !important;
    color:#64748b !important;
    font-size:.56rem !important;
    line-height:1.25 !important;
    font-weight:900 !important;
    letter-spacing:.06em !important;
}
.nexus-live-pipeline {
    padding-top:3px !important;
    border-top:1px solid #e5eaf0 !important;
}
.nexus-live-pipeline-row {
    display:grid !important;
    grid-template-columns:15px minmax(0,1fr) auto !important;
    align-items:center !important;
    gap:5px !important;
    padding:4px 0 !important;
    color:#334155 !important;
    font-size:.64rem !important;
    line-height:1.2 !important;
}
.nexus-live-pipeline-row b {
    color:#64748b !important;
    font-size:.52rem !important;
    line-height:1.2 !important;
    font-weight:850 !important;
}
.nexus-live-footer {
    display:flex !important;
    flex-wrap:wrap !important;
    justify-content:space-between !important;
    gap:5px !important;
    margin-top:6px !important;
    padding-top:7px !important;
    border-top:1px solid #e5eaf0 !important;
    color:#64748b !important;
    font-size:.56rem !important;
    line-height:1.25 !important;
}

/* =========================================================
   HIGH-CONTRAST LIVE SYSTEM MONITOR
   Force ALL monitor text to solid black and bold.
   This overrides Streamlit/theme inherited text colors.
   ========================================================= */
.nexus-live-monitor,
.nexus-live-monitor * {
    opacity:1 !important;
}

.nexus-live-monitor .nexus-live-kicker,
.nexus-live-monitor .nexus-live-title,
.nexus-live-monitor .nexus-live-clock,
.nexus-live-monitor .nexus-live-activity,
.nexus-live-monitor .nexus-live-detail,
.nexus-live-monitor .nexus-live-stage,
.nexus-live-monitor .nexus-live-pipeline,
.nexus-live-monitor .nexus-live-pipeline-row,
.nexus-live-monitor .nexus-live-pipeline-row span,
.nexus-live-monitor .nexus-live-pipeline-row b,
.nexus-live-monitor .nexus-live-footer,
.nexus-live-monitor .nexus-live-footer span {
    color:#000000 !important;
    -webkit-text-fill-color:#000000 !important;
    text-shadow:none !important;
    font-weight:900 !important;
    opacity:1 !important;
}

/* Keep the status dots colored while keeping their text black. */
.nexus-live-monitor .nexus-live-pipeline-row > span:first-child {
    -webkit-text-fill-color:initial !important;
}

/* Responsive sidebar sizes */
@media (max-width: 1100px) {
    section[data-testid="stSidebar"] { width:300px !important; min-width:300px !important; }
    section[data-testid="stSidebar"] > div:first-child { padding-left:.75rem !important; padding-right:.75rem !important; }
}
@media (max-width: 760px) {
    section[data-testid="stSidebar"] { width:285px !important; min-width:285px !important; }
    .nexus-live-monitor { padding:10px !important; }
    .nexus-live-title { font-size:.84rem !important; }
    .sidebar-nav-item b { font-size:.69rem !important; }
}
@media (max-width: 480px) {
    section[data-testid="stSidebar"] { width:275px !important; min-width:275px !important; }
    section[data-testid="stSidebar"] > div:first-child { padding:.75rem .65rem 1rem .65rem !important; }
    .common-sidebar-section { margin-top:12px !important; }
}
</style>
    """,
    unsafe_allow_html=True,
)

render_common_sidebar()


st.markdown(
    """
<style>
/* ============================================================
   DANIP WORKSPACE TABS — TRANSPARENT ADMIN NAVIGATION
   No filled background. Active workspace uses red indicator.
   ============================================================ */

/* Horizontal workspace selector */
div[data-testid="stRadio"] {
    width: 100% !important;
    margin: 0 !important;
    padding: 0 !important;
}

/* Remove the radio group's default visual label spacing */
div[data-testid="stRadio"] > label {
    display: none !important;
}

/* The horizontal option row */
div[data-testid="stRadio"] div[role="radiogroup"] {
    display: flex !important;
    flex-direction: row !important;
    align-items: center !important;
    gap: 0 !important;
    width: 100% !important;
    min-height: 46px !important;
    padding: 0 !important;
    margin: 0 !important;
    background: transparent !important;
    border: 0 !important;
    box-shadow: none !important;
    overflow-x: auto !important;
    scrollbar-width: none !important;
}
div[data-testid="stRadio"] div[role="radiogroup"]::-webkit-scrollbar {
    display: none !important;
}

/* Each workspace option */
div[data-testid="stRadio"] div[role="radiogroup"] > label {
    position: relative !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    flex: 0 0 auto !important;
    min-height: 46px !important;
    padding: 0 22px !important;
    margin: 0 !important;
    background: transparent !important;
    border: 0 !important;
    border-radius: 0 !important;
    box-shadow: none !important;
    color: #17374b !important;
    -webkit-text-fill-color: #17374b !important;
    font-weight: 650 !important;
    font-size: 0.92rem !important;
    cursor: pointer !important;
    white-space: nowrap !important;
    transition: color .15s ease, background .15s ease !important;
}

/* Kill Streamlit's selected filled background */
div[data-testid="stRadio"] div[role="radiogroup"] > label,
div[data-testid="stRadio"] div[role="radiogroup"] > label:hover,
div[data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked) {
    background: transparent !important;
}

/* Text inside options */
div[data-testid="stRadio"] div[role="radiogroup"] > label p,
div[data-testid="stRadio"] div[role="radiogroup"] > label span,
div[data-testid="stRadio"] div[role="radiogroup"] > label div {
    color: #17374b !important;
    -webkit-text-fill-color: #17374b !important;
}

/* Native radio indicator — white/transparent by default */
div[data-testid="stRadio"] div[role="radiogroup"] > label input {
    accent-color: #b03a2e !important;
}

/* Active red indicator and red text */
div[data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked) {
    color: #17374b !important;
    -webkit-text-fill-color: #17374b !important;
}

/* Red underline for active workspace, like the reference */
div[data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked)::after {
    content: "" !important;
    position: absolute !important;
    left: 14px !important;
    right: 14px !important;
    bottom: 0 !important;
    height: 3px !important;
    background: #b03a2e !important;
    border-radius: 0 !important;
}

/* ============================================================
   NO HOVER / NO FOCUS BACKGROUND
   Workspace navigation stays transparent at all times.
   Only the active workspace gets the red underline.
   ============================================================ */
div[data-testid="stRadio"],
div[data-testid="stRadio"] > div,
div[data-testid="stRadio"] > div > div,
div[data-testid="stRadio"] div[role="radiogroup"],
div[data-testid="stRadio"] div[role="radiogroup"] > label,
div[data-testid="stRadio"] div[role="radiogroup"] > label:hover,
div[data-testid="stRadio"] div[role="radiogroup"] > label:focus,
div[data-testid="stRadio"] div[role="radiogroup"] > label:focus-within,
div[data-testid="stRadio"] div[role="radiogroup"] > label:active,
div[data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked),
div[data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked):hover,
div[data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked):focus,
div[data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked):focus-within {
    background: transparent !important;
    background-color: transparent !important;
    box-shadow: none !important;
    outline: none !important;
}

div[data-testid="stRadio"] div[role="radiogroup"] > label:hover,
div[data-testid="stRadio"] div[role="radiogroup"] > label:focus,
div[data-testid="stRadio"] div[role="radiogroup"] > label:focus-within,
div[data-testid="stRadio"] div[role="radiogroup"] > label:active {
    color: #17374b !important;
    -webkit-text-fill-color: #17374b !important;
    filter: none !important;
    transform: none !important;
}

div[data-testid="stRadio"] div[role="radiogroup"] > label:hover p,
div[data-testid="stRadio"] div[role="radiogroup"] > label:hover span,
div[data-testid="stRadio"] div[role="radiogroup"] > label:hover div,
div[data-testid="stRadio"] div[role="radiogroup"] > label:focus p,
div[data-testid="stRadio"] div[role="radiogroup"] > label:focus span,
div[data-testid="stRadio"] div[role="radiogroup"] > label:focus div,
div[data-testid="stRadio"] div[role="radiogroup"] > label:focus-within p,
div[data-testid="stRadio"] div[role="radiogroup"] > label:focus-within span,
div[data-testid="stRadio"] div[role="radiogroup"] > label:focus-within div {
    color: #17374b !important;
    -webkit-text-fill-color: #17374b !important;
    background: transparent !important;
}

/* Remove Streamlit's focus ring / keyboard highlight */
div[data-testid="stRadio"] input:focus,
div[data-testid="stRadio"] input:focus-visible {
    outline: none !important;
    box-shadow: none !important;
}

/* Mobile */
@media (max-width: 700px) {
    div[data-testid="stRadio"] div[role="radiogroup"] > label {
        padding: 0 14px !important;
        font-size: 0.84rem !important;
    }
}
</style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# TOP-LEVEL DANIP WORKSPACE NAVIGATION
# ============================================================
# Use a horizontal Streamlit radio as the workspace switcher rather than
# st.tabs. The refresh control is placed beside the workspace selector so
# users can restart the application without using the browser refresh icon.

nav_col, refresh_col = st.columns([8.5, 1.5], gap="small", vertical_alignment="center")

with nav_col:
    workspace = st.radio(
        "DANIP workspace",
        [
            "🤖 DANIP AI Data Analyst",
            "🧭 DANIP M&E Management Hub",
            "📊 Universal Power BI Analytics",
            "🌐 AI Public Website Builder",
            "📅 My Reports & Monitoring",
        ],
        horizontal=True,
        label_visibility="collapsed",
        key="danip_workspace_selector",
    )

with refresh_col:
    st.markdown(
        """
        <style>
        div[data-testid="stButton"] > button.nexus-top-refresh {
            min-height: 38px !important;
            height: 38px !important;
            border: 1px solid #17374b !important;
            border-radius: 6px !important;
            background: #17374b !important;
            color: #ffffff !important;
            font-size: 0.82rem !important;
            font-weight: 650 !important;
            padding: 0 12px !important;
            white-space: nowrap !important;
        }
        div[data-testid="stButton"] > button.nexus-top-refresh:hover {
            background: #244f66 !important;
            border-color: #244f66 !important;
            color: #ffffff !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    if st.button("🔄 Refresh", key="nexus_top_refresh", use_container_width=True):
        # Full application reset: also remove the pasted API/Data URL so the
        # user returns to a completely blank starting point. Persistent MEAL
        # records in danip_meal.db are intentionally preserved.
        _auth_state = {
            "danip_authenticated": st.session_state.get("danip_authenticated", False),
            "danip_user": st.session_state.get("danip_user", {}),
            "danip_access_token": st.session_state.get("danip_access_token", ""),
            "danip_refresh_token": st.session_state.get("danip_refresh_token", ""),
        }
        st.session_state.clear()
        st.session_state.update(_auth_state)
        st.session_state["data_url_input"] = ""
        st.session_state["last_analyzed_url"] = ""
        st.session_state["loaded_source_url"] = ""
        st.session_state["data_loaded"] = False
        try:
            st.query_params.clear()
        except Exception:
            pass
        st.rerun()


# ============================================================
# WORKSPACE ROUTING
# ============================================================

if workspace == "🤖 DANIP AI Data Analyst":

    # ============================================================
    # INDEPENDENT M&E / INDICATOR CHATBOT
    # ============================================================
    # IMPORTANT: this is intentionally outside the DHIS2/API loading flow.
    # It must render even when no API URL has been pasted and even when the
    # DHIS2 dataset is empty. Current-data questions are routed to DHIS2 only
    # when data is actually available. Indicator definitions, compendium
    # questions and general M&E questions do not require an API.
    render_analysis_chatbot()

    render_existing_danip_ai_app()


elif workspace == "🧭 DANIP M&E Management Hub":

    render_danip_me_management_hub()


elif workspace == "📊 Universal Power BI Analytics":

    _render_universal_powerbi_workspace()


elif workspace == "🌐 AI Public Website Builder":

    # The website-builder module uses Streamlit Markdown for its HTML header.
    # Render that specific header through Streamlit's HTML component so the
    # HTML is interpreted by the browser instead of appearing as source text.
    _original_st_markdown = st.markdown

    def _website_builder_safe_markdown(body, *args, **kwargs):
        try:
            body_text = str(body)
        except Exception:
            body_text = ""

        is_builder_header = (
            "website-builder-header" in body_text
            and "website-builder-title" in body_text
            and "AI Public Website Builder" in body_text
            and "underlying analysis" in body_text
        )

        if is_builder_header and kwargs.get("unsafe_allow_html", False):
            try:
                import streamlit.components.v1 as components
                components.html(
                    body_text,
                    height=150,
                    scrolling=False,
                )
                return None
            except Exception:
                # Fall back to normal Streamlit rendering if the HTML
                # component is unavailable.
                pass

        return _original_st_markdown(body, *args, **kwargs)

    st.markdown = _website_builder_safe_markdown
    try:
        render_ai_public_website_builder()
    finally:
        st.markdown = _original_st_markdown


elif workspace == "📅 My Reports & Monitoring":

    render_my_reports_monitoring()


# ============================================================
# END — DANIP AI + SEPARATE DANIP M&E MANAGEMENT HUB
# ============================================================app
