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



st.write("DEBUG - root secrets:", list(st.secrets.keys()))

if "OPENAI_API_KEY" in st.secrets:
    st.success("OPENAI_API_KEY FOUND at root level")
else:
    st.error("OPENAI_API_KEY NOT FOUND at root level")

if "OPENAI" in st.secrets:
    st.success("OPENAI section FOUND")
    st.write("OPENAI keys:", list(st.secrets["OPENAI"].keys()))
else:
    st.warning("OPENAI section NOT FOUND")
# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="NEXUS DANIP | Secure Access",
    page_icon="🔐",
    layout="centered",
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
    max-width: 760px;
    padding-top: 1.5rem;
    padding-bottom: 2rem;
}


/* ============================================================
   LOGIN CARD
   ============================================================ */

.danip-card {
    background: #ffffff;
    border: 1px solid #d7dee6;
    border-radius: 15px;
    padding: 28px;
    box-shadow: 0 8px 28px rgba(23,55,75,0.08);
}


/* ============================================================
   TITLE
   ============================================================ */

.danip-title {
    text-align: center;
    color: #17374b;
    font-size: 25px;
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
    font-size: 11px;
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
}


.danip-security-title {
    color: #ffffff;
    font-size: 12px;
    font-weight: 900;
    margin-bottom: 7px;
}


.danip-security-text {
    color: #ffffff;
    font-size: 10px;
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
    font-size: 10px;
    line-height: 1.65;
    margin-bottom: 16px;
}


.danip-provider b {
    color: #17374b;
}


/* ============================================================
   DHIS2 LOGIN BUTTON
   ============================================================ */

div[data-testid="stLinkButton"] > a {

    width: 100%;

    min-height: 42px;

    border-radius: 7px;

    border: none;

    background: #ff4b4b;

    color: #ffffff !important;

    font-size: 11px;

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

    font-size: 9px;

    margin-top: 27px;
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
            "NEXUS DANIP could not complete "
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
            "NEXUS DANIP could not connect "
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
            "NEXUS DANIP could not complete "
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

    # ========================================================
    # CARD
    # ========================================================

    st.markdown(
        '<div class="danip-card">',
        unsafe_allow_html=True,
    )


    # ========================================================
    # TITLE
    # ========================================================

    st.markdown(
        """
<div class="danip-title">
NEXUS DANIP
</div>
""",
        unsafe_allow_html=True,
    )


    # ========================================================
    # SUBTITLE
    # ========================================================

    st.markdown(
        """
<div class="danip-subtitle">
Data + M&amp;E Intelligence Platform
</div>
""",
        unsafe_allow_html=True,
    )


    # ========================================================
    # SECURITY NOTICE
    # ========================================================

    st.markdown(
        """
<div class="danip-security">

<div class="danip-security-title">
🔐 Authorized access only
</div>

<div class="danip-security-text">
Sign in using your existing DHIS2 account. Your DHIS2 username and password are entered on the official DHIS2 authentication page and are not collected by NEXUS DANIP.
</div>

</div>
""",
        unsafe_allow_html=True,
    )


    # ========================================================
    # PROVIDER
    # ========================================================

    st.markdown(
        """
<div class="danip-provider">

<b>Authentication provider:</b>
Datalytics for Nutrition International Program (DANIP)

<br>

<b>DHIS2 server:</b>
dhis2.nutritionintl.org

</div>
""",
        unsafe_allow_html=True,
    )


    # ========================================================
    # CONFIGURATION CHECK
    # ========================================================

    missing = config_missing()


    if missing:

        st.warning(
            "DHIS2 OAuth authentication still needs "
            "to be configured."
        )


        st.write(
            "Missing configuration:"
        )


        for item in missing:

            st.code(
                item
            )


    else:

        # ====================================================
        # LOGIN URL
        # ====================================================

        auth_url = authorization_url()


        # ====================================================
        # SIGN IN BUTTON
        # ====================================================

        st.link_button(

            "🔐 Sign in with DHIS2",

            auth_url,

            use_container_width=True,

        )


    # ========================================================
    # FOOTER
    # ========================================================

    st.markdown(
        """
<div class="danip-footer">
Protected NEXUS DANIP workspace
</div>
""",
        unsafe_allow_html=True,
    )


    # ========================================================
    # END CARD
    # ========================================================

    st.markdown(
        "</div>",
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
