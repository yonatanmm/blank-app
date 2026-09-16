

import os
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
DHIS2_USERNAME = _get_secret("DHIS2_USERNAME", "")
DHIS2_PASSWORD = _get_secret("DHIS2_PASSWORD", "")
OPENAI_API_KEY = _get_secret("OPENAI_API_KEY", "")
OPENAI_MODEL = _get_secret("OPENAI_MODEL", "gpt-5")


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
        margin: .65rem 0 .9rem 0 !imp
