# ============================================================
# NEXUS DANIP
# SECURE DHIS2 OAUTH2 AUTHENTICATION GATEWAY
# ============================================================
#
# RUN THIS FILE:
#
# streamlit run app_secure_dhis2_clean.py
#
# LOCAL:
#
# http://localhost:8501
#
#
# FLOW:
#
# NEXUS DANIP
#       ↓
# 🔐 Sign in with DHIS2
#       ↓
# Official DHIS2 Login
#       ↓
# User enters DHIS2 username/password
#       ↓
# DHIS2 authenticates user
#       ↓
# Authorization Code
#       ↓
# http://localhost:8501/?code=...&state=...
#       ↓
# NEXUS exchanges code for token
#       ↓
# NEXUS calls /api/me
#       ↓
# User authenticated
#       ↓
# Existing app.py
#
#
# IMPORTANT:
#
# NEXUS DANIP never receives the user's DHIS2 password.
#
# ============================================================


# ============================================================
# IMPORTS
# ============================================================

import base64
import hashlib
import hmac
import os
import runpy
import secrets
import time

from pathlib import Path
from urllib.parse import urlencode

import requests
import streamlit as st


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="DANIP AI | Secure Access",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# DHIS2 BASE URL
# ============================================================

DHIS2_BASE_URL = os.getenv(
    "DANIP_DHIS2_BASE_URL",
    "https://dhis2.nutritionintl.org",
).rstrip("/")


# ============================================================
# SECRET HELPER
# ============================================================

def get_secret(key, default=""):
    """
    Read configuration from:

        .streamlit/secrets.toml

    under:

        [DANIP_DHIS2]

    Environment variables are used as fallback.
    """

    try:

        section = st.secrets.get(
            "DANIP_DHIS2",
            {}
        )

        value = section.get(
            key,
            None
        )

        if value is not None:

            return str(value).strip()

    except Exception:

        pass

    return os.getenv(
        key,
        default
    ).strip()


# ============================================================
# OAUTH CONFIGURATION
# ============================================================

CLIENT_ID = get_secret(
    "CLIENT_ID"
)

CLIENT_SECRET = get_secret(
    "CLIENT_SECRET"
)

REDIRECT_URI = get_secret(
    "REDIRECT_URI"
)

STATE_SECRET = get_secret(
    "STATE_SECRET"
)

AUTHORIZE_URL = get_secret(
    "AUTHORIZE_URL",
    f"{DHIS2_BASE_URL}/uaa/oauth/authorize"
)

TOKEN_URL = get_secret(
    "TOKEN_URL",
    f"{DHIS2_BASE_URL}/uaa/oauth/token"
)

ME_URL = get_secret(
    "ME_URL",
    f"{DHIS2_BASE_URL}/api/me"
)


# ============================================================
# CLIENT AUTHENTICATION METHOD
# ============================================================
#
# Default:
#
# basic
#
# This sends:
#
# Authorization: Basic base64(client_id:client_secret)
#
# Alternative:
#
# post
#
# This sends:
#
# client_id=...
# client_secret=...
#
# If DHIS2 rejects "basic", you can change:
#
# CLIENT_AUTH_METHOD = "post"
#
# in secrets.toml.
#
# ============================================================

CLIENT_AUTH_METHOD = get_secret(
    "CLIENT_AUTH_METHOD",
    "basic"
).lower()


# ============================================================
# SESSION STATE
# ============================================================

if "danip_authenticated" not in st.session_state:

    st.session_state.danip_authenticated = False


if "danip_user" not in st.session_state:

    st.session_state.danip_user = {}


if "danip_access_token" not in st.session_state:

    st.session_state.danip_access_token = ""


# ============================================================
# CSS
# ============================================================

st.markdown(
    """
<style>

/* ============================================================
   APPLICATION BACKGROUND
   ============================================================ */

.stApp {
    background: #f4f7fa;
}


/* ============================================================
   STREAMLIT HEADER
   ============================================================ */

[data-testid="stHeader"] {
    background: transparent;
}


/* ============================================================
   MAIN CONTAINER
   ============================================================ */

.block-container {
    box-sizing: border-box;
    width: 100%;
    max-width: 720px;
    padding: clamp(1rem, 4vh, 2.5rem) clamp(.75rem, 3vw, 1.5rem) 2rem;
}


/* ============================================================
   LOGIN CARD
   ============================================================ */

.danip-card {
    box-sizing: border-box;
    width: 100%;
    max-width: 620px;
    margin: 0 auto;
    background: #ffffff;
    border: 1px solid #d7dee6;
    border-radius: 15px;
    padding: clamp(18px, 4vw, 30px);
    box-shadow: 0 8px 28px rgba(23,55,75,0.08);
}


/* ============================================================
   TITLE
   ============================================================ */

.danip-title {
    text-align: center;
    color: #17374b;
    font-size: clamp(22px, 4vw, 30px);
    font-weight: 900;
    letter-spacing: -0.3px;
    margin-top: 2px;
    margin-bottom: 5px;
}


/* ============================================================
   SUBTITLE
   ============================================================ */

.danip-subtitle {
    text-align: center;
    color: #557087;
    font-size: clamp(12px, 2vw, 14px);
    font-weight: 500;
    margin-bottom: 28px;
}


/* ============================================================
   SECURITY BOX
   ============================================================ */

.danip-security {
    background: #1d1f27;
    color: #ffffff;
    border-radius: 8px;
    padding: 14px 16px;
    margin-bottom: 16px;
    overflow-wrap: anywhere;
}


.danip-security-title {
    color: #ffffff;
    font-size: 12px;
    font-weight: 900;
    margin-bottom: 7px;
}


.danip-security-text {
    color: #ffffff;
    font-size: 13px;
    line-height: 1.65;
    font-weight: 600;
}


/* ============================================================
   PROVIDER BOX
   ============================================================ */

.danip-provider {
    background: #edf6fb;
    border: 1px solid #c9dce8;
    border-radius: 8px;
    padding: 11px 13px;
    color: #174b72;
    font-size: 12px;
    line-height: 1.65;
    margin-bottom: 16px;
    overflow-wrap: anywhere;
}


.danip-provider b {
    color: #17374b;
}


/* ============================================================
   DHIS2 LOGIN BUTTON
   ============================================================ */

div[data-testid="stLinkButton"] > a {

    width: 100%;

    min-height: 48px;
    box-sizing: border-box;

    border-radius: 7px;

    border: none;

    background: #ff4b4b;

    color: #ffffff !important;

    font-size: 14px;

    font-weight: 800;

    text-decoration: none !important;

    display: flex;

    align-items: center;

    justify-content: center;

    transition: all 0.15s ease;
}


div[data-testid="stLinkButton"] > a:hover {

    background: #e83e3e;

    color: #ffffff !important;

    transform: translateY(-1px);
}


/* ============================================================
   AUTHENTICATED USER
   ============================================================ */

.danip-user-box {

    background: #eaf7ef;

    border: 1px solid #b9dec6;

    border-radius: 8px;

    padding: 9px 10px;

    color: #174b34;

    font-size: 10px;

    font-weight: 800;

    margin-bottom: 10px;
}


/* ============================================================
   FOOTER
   ============================================================ */

.danip-footer {

    text-align: center;

    color: #8292a1;

    font-size: 11px;

    margin-top: 27px;
}

/* Keep the login card readable and touch friendly on tablets and phones. */
@media (max-width: 640px) {
    .block-container {
        max-width: 100%;
        padding: 1rem .75rem 1.5rem;
    }

    .danip-card {
        max-width: 100%;
        padding: 20px 16px;
        border-radius: 12px;
    }

    .danip-subtitle {
        margin-bottom: 22px;
    }

    .danip-security,
    .danip-provider {
        padding: 13px;
    }

    div[data-testid="stLinkButton"] > a {
        min-height: 50px;
    }
}

@media (max-width: 380px) {
    .block-container {
        padding-right: .5rem;
        padding-left: .5rem;
    }

    .danip-card {
        padding: 16px 13px;
    }

    .danip-security-text,
    .danip-provider {
        font-size: 12px;
    }
}


/* ============================================================
   SIDEBAR
   ============================================================ */

[data-testid="stSidebar"] {

    background: #f4f7fa;
}

</style>
""",
    unsafe_allow_html=True,
)

# The sign-in page uses a full-bleed hero; keep these styles separate from the
# older card rules above so every login element shares one responsive layout.
try:
    _login_hero_bytes = Path(__file__).with_name("assets").joinpath("danip-login-hero.jpg").read_bytes()
    _login_hero_background = (
        'url("data:image/jpeg;base64,'
        + base64.b64encode(_login_hero_bytes).decode("ascii")
        + '")'
    )
except OSError:
    _login_hero_background = "none"

st.markdown(
    """
<style>
.stApp {
    min-height: 100vh;
    background-color: #172746;
    background-image: linear-gradient(90deg, rgba(18,31,66,.92) 0%, rgba(26,41,79,.78) 48%, rgba(22,37,74,.40) 100%), __DANIP_LOGIN_BACKGROUND__;
    background-position: center;
    background-size: cover;
    background-repeat: no-repeat;
}
[data-testid="stAppViewContainer"] { min-height: 100vh; }
.block-container {
    box-sizing: border-box;
    width: 100%;
    max-width: none;
    min-height: 100vh;
    padding: 0 clamp(22px, 8vw, 140px);
}
[data-testid="stHeader"], [data-testid="stToolbar"], [data-testid="stDecoration"], .stAppDeployButton {
    display: none !important;
}
.st-key-danip_login_hero {
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: flex-start;
    width: min(100%, 620px);
    min-height: 100vh;
    padding: 64px 0 56px;
    color: #fff;
}
.danip-login-content { width: 100%; }
.danip-login-brand {
    color: #fff;
    font-size: clamp(2.6rem, 6vw, 4rem);
    font-weight: 950;
    line-height: 1;
    letter-spacing: -.065em;
    margin: 0 0 40px;
    text-shadow: 0 2px 18px rgba(0,0,0,.12);
}
.danip-login-kicker {
    color: #b9d4ff;
    font-size: .75rem;
    font-weight: 800;
    letter-spacing: .17em;
    text-transform: uppercase;
    margin-bottom: 12px;
}
.danip-login-title {
    color: #fff;
    font-size: clamp(1.9rem, 4vw, 2.75rem);
    line-height: 1.13;
    letter-spacing: -.035em;
    font-weight: 850;
    margin: 0 0 15px;
}
.danip-login-description {
    max-width: 540px;
    color: rgba(244,247,255,.86);
    font-size: clamp(1rem, 1.8vw, 1.12rem);
    line-height: 1.65;
    margin: 0 0 26px;
}
.danip-login-security {
    display: flex;
    align-items: center;
    gap: 9px;
    color: rgba(235,241,255,.78);
    font-size: .86rem;
    margin: 25px 0 0;
}
.danip-login-security-mark {
    width: 24px;
    height: 24px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 1px solid rgba(255,255,255,.28);
    border-radius: 50%;
    color: #d7e5ff;
    flex: 0 0 auto;
}
div[data-testid="stLinkButton"] { width: fit-content; max-width: 100%; }
div[data-testid="stLinkButton"] > a {
    width: auto;
    min-width: 218px;
    min-height: 50px;
    box-sizing: border-box;
    padding: 0 27px;
    border-radius: 999px;
    border: 1px solid rgba(255,255,255,.9);
    background: #fff;
    color: #465b91 !important;
    font-size: .96rem;
    font-weight: 800;
    text-decoration: none !important;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: transform .16s ease, background-color .16s ease, box-shadow .16s ease;
}
div[data-testid="stLinkButton"] > a:hover {
    background: #eef3ff;
    color: #344b85 !important;
    transform: translateY(-2px);
    box-shadow: 0 8px 24px rgba(8,17,40,.20);
}
.danip-login-footer { color: rgba(230,237,252,.65); font-size: .76rem; margin-top: 36px; }
[data-testid="stSidebar"] { display: none !important; }
@media (max-width: 760px) {
    .stApp {
        background-image: linear-gradient(90deg, rgba(18,31,66,.88), rgba(20,35,73,.68)), __DANIP_LOGIN_BACKGROUND__;
        background-position: 60% center;
    }
    .block-container { padding: 0 clamp(20px, 6vw, 52px); }
    .st-key-danip_login_hero { width: min(100%, 560px); min-height: 100svh; padding: 44px 0; }
    .danip-login-brand { margin-bottom: 32px; }
    div[data-testid="stLinkButton"] > a { min-height: 52px; }
}
@media (max-width: 480px) {
    .stApp {
        background-image: linear-gradient(90deg, rgba(16,29,62,.87), rgba(16,29,62,.73)), __DANIP_LOGIN_BACKGROUND__;
        background-position: 63% center;
    }
    .block-container { padding: 0 22px; }
    .st-key-danip_login_hero {
        justify-content: flex-end;
        min-height: 100svh;
        padding: 0 0 max(34px, env(safe-area-inset-bottom));
    }
    .danip-login-brand { font-size: 2.65rem; margin-bottom: 28px; }
    .danip-login-title { font-size: clamp(1.85rem, 9vw, 2.35rem); }
    .danip-login-description { font-size: 1rem; margin-bottom: 22px; }
    div[data-testid="stLinkButton"], div[data-testid="stLinkButton"] > a { width: 100%; }
    div[data-testid="stLinkButton"] > a { min-height: 54px; }
    .danip-login-footer { margin-top: 27px; }
}
</style>
""".replace("__DANIP_LOGIN_BACKGROUND__", _login_hero_background),
    unsafe_allow_html=True,
)


# ============================================================
# BASE64 URL ENCODING
# ============================================================

def b64url(data):

    return (
        base64.urlsafe_b64encode(data)
        .decode("utf-8")
        .rstrip("=")
    )


# ============================================================
# CREATE OAUTH STATE
# ============================================================

def create_state():

    if not STATE_SECRET:

        return ""

    timestamp = str(
        int(time.time())
    )

    nonce = secrets.token_urlsafe(
        32
    )

    payload = (
        f"{timestamp}.{nonce}"
    )

    signature = hmac.new(

        STATE_SECRET.encode(
            "utf-8"
        ),

        payload.encode(
            "utf-8"
        ),

        hashlib.sha256,

    ).digest()

    return (
        f"{b64url(payload.encode('utf-8'))}."
        f"{b64url(signature)}"
    )


# ============================================================
# VERIFY OAUTH STATE
# ============================================================

def verify_state(
    state,
    max_age=600
):

    if not state:

        return False

    if not STATE_SECRET:

        return False

    try:

        encoded_payload, encoded_signature = (
            state.split(
                ".",
                1
            )
        )


        payload = base64.urlsafe_b64decode(

            encoded_payload
            + "=" * (
                -len(encoded_payload) % 4
            )

        ).decode(
            "utf-8"
        )


        signature = base64.urlsafe_b64decode(

            encoded_signature
            + "=" * (
                -len(encoded_signature) % 4
            )

        )


        expected_signature = hmac.new(

            STATE_SECRET.encode(
                "utf-8"
            ),

            payload.encode(
                "utf-8"
            ),

            hashlib.sha256,

        ).digest()


        if not hmac.compare_digest(
            signature,
            expected_signature
        ):

            return False


        timestamp, nonce = payload.split(
            ".",
            1
        )


        if not nonce:

            return False


        timestamp = int(
            timestamp
        )


        if abs(
            int(time.time()) - timestamp
        ) > max_age:

            return False


        return True


    except Exception:

        return False


# ============================================================
# CONFIGURATION CHECK
# ============================================================

def config_missing():

    missing = []


    if not CLIENT_ID:

        missing.append(
            "CLIENT_ID"
        )


    if not CLIENT_SECRET:

        missing.append(
            "CLIENT_SECRET"
        )


    if not REDIRECT_URI:

        missing.append(
            "REDIRECT_URI"
        )


    if not STATE_SECRET:

        missing.append(
            "STATE_SECRET"
        )


    if not AUTHORIZE_URL:

        missing.append(
            "AUTHORIZE_URL"
        )


    if not TOKEN_URL:

        missing.append(
            "TOKEN_URL"
        )


    if not ME_URL:

        missing.append(
            "ME_URL"
        )


    return missing


# ============================================================
# CREATE AUTHORIZATION URL
# ============================================================

def authorization_url():

    state = create_state()


    params = {

        "client_id":
            CLIENT_ID,

        "response_type":
            "code",

        "redirect_uri":
            REDIRECT_URI,

        "scope":
            "ALL",

        "state":
            state,

    }


    return (
        AUTHORIZE_URL
        + "?"
        + urlencode(params)
    )


# ============================================================
# EXCHANGE AUTHORIZATION CODE
# ============================================================

def exchange_code(code):

    # ========================================================
    # COMMON TOKEN REQUEST DATA
    # ========================================================

    token_data = {

        "grant_type":
            "authorization_code",

        "code":
            code,

        "redirect_uri":
            REDIRECT_URI,

    }


    # ========================================================
    # METHOD 1
    # HTTP BASIC AUTHENTICATION
    # ========================================================

    if CLIENT_AUTH_METHOD == "basic":

        response = requests.post(

            TOKEN_URL,

            auth=(

                CLIENT_ID,

                CLIENT_SECRET,

            ),

            data=token_data,

            headers={

                "Accept":
                    "application/json",

            },

            timeout=30,

        )


    # ========================================================
    # METHOD 2
    # CLIENT SECRET IN POST BODY
    # ========================================================

    elif CLIENT_AUTH_METHOD == "post":

        token_data["client_id"] = CLIENT_ID

        token_data["client_secret"] = CLIENT_SECRET


        response = requests.post(

            TOKEN_URL,

            data=token_data,

            headers={

                "Accept":
                    "application/json",

            },

            timeout=30,

        )


    # ========================================================
    # INVALID CONFIGURATION
    # ========================================================

    else:

        raise RuntimeError(
            "CLIENT_AUTH_METHOD must be "
            "'basic' or 'post'."
        )


    # ========================================================
    # CHECK RESPONSE
    # ========================================================

    if not response.ok:

        try:

            error_body = response.json()

        except Exception:

            error_body = {}


        error_code = error_body.get(
            "error",
            ""
        )

        error_description = error_body.get(
            "error_description",
            ""
        )


        if (
            error_code
            == "invalid_client"
        ):

            raise RuntimeError(
                "DHIS2 rejected the OAuth client "
                "credentials: invalid_client."
            )


        if error_description:

            raise RuntimeError(
                f"DHIS2 OAuth error: "
                f"{error_description}"
            )


        raise RuntimeError(
            f"DHIS2 token endpoint returned "
            f"HTTP {response.status_code}."
        )


    # ========================================================
    # PARSE TOKEN RESPONSE
    # ========================================================

    try:

        return response.json()

    except Exception:

        raise RuntimeError(
            "DHIS2 returned an invalid token response."
        )


# ============================================================
# GET CURRENT DHIS2 USER
# ============================================================

def get_dhis2_user(token):

    response = requests.get(

        ME_URL,

        headers={

            "Authorization":
                f"Bearer {token}",

            "Accept":
                "application/json",

        },

        timeout=30,

    )


    response.raise_for_status()


    return response.json()


# ============================================================
# CLEAR QUERY PARAMETERS
# ============================================================

def clear_query_params():

    try:

        st.query_params.clear()

    except Exception:

        pass


# ============================================================
# HANDLE OAUTH CALLBACK
# ============================================================

def handle_callback():

    params = st.query_params


    code = params.get(
        "code"
    )

    state = params.get(
        "state"
    )

    error = params.get(
        "error"
    )

    error_description = params.get(
        "error_description"
    )


    # ========================================================
    # DHIS2 RETURNED AN ERROR
    # ========================================================

    if error:

        st.error(
            "DHIS2 authentication was unsuccessful."
        )


        if error_description:

            st.caption(
                str(error_description)
            )


        clear_query_params()

        return False


    # ========================================================
    # NO CALLBACK CODE
    # ========================================================

    if not code:

        return False


    # ========================================================
    # VERIFY STATE
    # ========================================================

    if not verify_state(
        state or ""
    ):

        st.error(
            "The DHIS2 authentication response "
            "could not be verified."
        )


        st.caption(
            "The OAuth state was invalid or expired."
        )


        clear_query_params()

        return False


    # ========================================================
    # EXCHANGE AUTHORIZATION CODE
    # ========================================================

    try:

        token_data = exchange_code(
            code
        )


        access_token = token_data.get(
            "access_token"
        )


        if not access_token:

            raise RuntimeError(
                "DHIS2 did not return an access token."
            )


        # ====================================================
        # VERIFY USER
        # ====================================================

        user = get_dhis2_user(
            access_token
        )


        # ====================================================
        # SAVE AUTHENTICATION
        # ====================================================

        st.session_state.danip_authenticated = True

        st.session_state.danip_user = user

        st.session_state.danip_access_token = (
            access_token
        )


        # ====================================================
        # CLEAN URL
        # ====================================================

        clear_query_params()


        return True


    # ========================================================
    # HTTP ERROR
    # ========================================================

    except requests.HTTPError as exc:

        st.error(
            "DANIP AI could not complete "
            "DHIS2 authentication."
        )


        if exc.response is not None:

            st.caption(
                f"DHIS2 returned HTTP "
                f"{exc.response.status_code}."
            )


        clear_query_params()

        return False


    # ========================================================
    # REQUEST ERROR
    # ========================================================

    except requests.RequestException:

        st.error(
            "DANIP AI could not connect "
            "to the DHIS2 authentication service."
        )


        st.caption(
            "Check the DHIS2 server URL and "
            "network connection."
        )


        clear_query_params()

        return False


    # ========================================================
    # OAUTH / CONFIGURATION ERROR
    # ========================================================

    except RuntimeError as exc:

        st.error(
            "DHIS2 OAuth authentication failed."
        )


        message = str(exc)


        if "invalid_client" in message:

            st.warning(
                "DHIS2 rejected the OAuth Client ID "
                "or Client Secret."
            )


            st.info(
                "Verify the OAuth2 client in DHIS2. "
                "The Client ID and Client Secret in "
                "secrets.toml must belong to the same "
                "DHIS2 OAuth2 client."
            )


        else:

            st.caption(
                message
            )


        clear_query_params()

        return False


    # ========================================================
    # GENERAL ERROR
    # ========================================================

    except Exception:

        st.error(
            "DANIP AI could not complete "
            "DHIS2 authentication."
        )


        st.caption(
            "Check the OAuth configuration "
            "and application logs."
        )


        clear_query_params()

        return False


# ============================================================
# LOGOUT
# ============================================================

def logout():

    st.session_state.danip_authenticated = False

    st.session_state.danip_user = {}

    st.session_state.danip_access_token = ""

    clear_query_params()

    st.rerun()


# ============================================================
# LOGIN PAGE
# ============================================================

def login_page():
    """Render the full-screen DHIS2 welcome page while preserving OAuth routing."""
    with st.container(key="danip_login_hero"):
        st.markdown(
            """
            <div class="danip-login-content">
                <div class="danip-login-brand">DANIP</div>
                <div class="danip-login-kicker">Data + M&amp;E Intelligence</div>
                <h1 class="danip-login-title">DANIP AI Data Analyst</h1>
                <p class="danip-login-description">
                    Access output analytics, indicator trends, and reporting insights
                    through your connected DHIS2 account.
                </p>
                <div class="danip-login-security">
                    <span class="danip-login-security-mark" aria-hidden="true">&#10003;</span>
                    <span>Secure sign-in through your organization&#8217;s DHIS2 server</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        missing = config_missing()
        if missing:
            st.warning("DHIS2 OAuth authentication still needs to be configured.")
            st.write("Missing configuration:")
            for item in missing:
                st.code(item)
        else:
            st.link_button(
                "Access Dashboard  →",
                authorization_url(),
                use_container_width=False,
            )

        st.markdown(
            """
            <div class="danip-login-footer">
                Protected access via DHIS2 &middot; dhis2.nutritionintl.org
            </div>
            """,
            unsafe_allow_html=True,
        )


# ============================================================
# RUN EXISTING DANIP APPLICATION
# ============================================================

def run_danip():

    core_file = (
        Path(__file__)
        .resolve()
        .with_name("app.py")
    )


    # ========================================================
    # USER
    # ========================================================

    user = st.session_state.get(
        "danip_user",
        {}
    )


    username = (

        user.get("username")

        or user.get("displayName")

        or user.get("name")

        or "Authenticated DHIS2 user"

    )


    # ========================================================
    # SIDEBAR
    # ========================================================

    with st.sidebar:

        st.markdown(
            """
<div class="danip-user-box">
🔓 DHIS2 authenticated
</div>
""",
            unsafe_allow_html=True,
        )


        st.caption(
            f"User: {username}"
        )


        if st.button(
            "🔒 Sign Out",
            use_container_width=True,
        ):

            logout()


    # ========================================================
    # CHECK app.py
    # ========================================================

    if not core_file.exists():

        st.error(
            "app.py was not found."
        )


        st.info(
            "Keep both Python files "
            "in the same folder."
        )


        st.code(
            """
DANIP/
├── app.py
├── app_secure_dhis2_clean.py
└── .streamlit/
    └── secrets.toml
""",
            language="text",
        )


        return


    # ========================================================
    # START EXISTING NEXUS APPLICATION
    # ========================================================

    runpy.run_path(
        str(core_file),
        run_name="__main__",
    )


# ============================================================
# APPLICATION ENTRY
# ============================================================

# ============================================================
# STEP 1
# HANDLE DHIS2 CALLBACK
# ============================================================

if not st.session_state.danip_authenticated:

    callback_completed = handle_callback()


    if callback_completed:

        st.rerun()


# ============================================================
# STEP 2
# AUTHENTICATED → RUN app.py
# ============================================================

if st.session_state.danip_authenticated:

    run_danip()


# ============================================================
# STEP 3
# NOT AUTHENTICATED → LOGIN
# ============================================================

else:

    login_page()

