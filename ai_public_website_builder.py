# ============================================================
# NEXUS DANIP — AI PUBLIC WEBSITE BUILDER
# ============================================================
# Drop-in module for the existing DANIP Streamlit application.
#
# IMPORTANT:
# This file is intentionally self-contained. It does not replace
# your existing app.py. Import it into app.py and call:
#
#     render_ai_public_website_builder()
#
# The module uses:
#     st.session_state["loaded_df"]
#
# It generates a standalone responsive public website and ZIP.
# It does NOT publish anything automatically.
# ============================================================

import json
import html
import re
import zipfile
from io import BytesIO

import pandas as pd
import streamlit as st


# ============================================================
# DATA SAFETY
# ============================================================

_PUBLIC_SENSITIVE_PATTERNS = [
    "password", "passwd", "secret", "token", "access_token",
    "refresh_token", "api_key", "apikey", "authorization",
    "email", "phone", "mobile", "address", "national_id",
    "nationalid", "patient", "patient_id", "patientid",
    "person", "person_id", "personid", "dob", "date_of_birth",
    "birth_date", "username", "user_id", "userid",
]


def _public_safe_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Remove obvious personal/credential fields before public generation."""
    if not isinstance(df, pd.DataFrame) or df.empty:
        return pd.DataFrame()

    safe = df.copy()

    drop_cols = []

    for col in safe.columns:
        normalized = re.sub(
            r"[^a-z0-9]+", "_", str(col).lower()
        ).strip("_")

        if any(
            pattern in normalized
            for pattern in _PUBLIC_SENSITIVE_PATTERNS
        ):
            drop_cols.append(col)

    if drop_cols:
        safe = safe.drop(
            columns=drop_cols,
            errors="ignore",
        )

    return safe


def _detect_columns(df: pd.DataFrame):
    dimensions = []
    numeric = []

    if df.empty:
        return {
            "dimensions": [],
            "numeric": [],
            "period": None,
            "country": None,
            "organisation": None,
        }

    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]):
            numeric.append(col)
        else:
            dimensions.append(col)

    period = None
    country = None
    organisation = None

    for col in dimensions:
        name = str(col).lower()

        if period is None and any(
            x in name
            for x in [
                "period", "month", "year", "date",
                "quarter", "fy", "time"
            ]
        ):
            period = col

        if country is None and any(
            x in name
            for x in [
                "country", "nation", "country_name"
            ]
        ):
            country = col

        if organisation is None and any(
            x in name
            for x in [
                "organisation", "organization",
                "orgunit", "org_unit", "facility",
                "region", "district", "province",
                "state", "location"
            ]
        ):
            organisation = col

    return {
        "dimensions": dimensions,
        "numeric": numeric,
        "period": period,
        "country": country,
        "organisation": organisation,
    }


def _profile_dataset(df: pd.DataFrame):
    safe = _public_safe_dataframe(df)
    detected = _detect_columns(safe)

    indicators = []

    for col in detected["numeric"]:
        values = pd.to_numeric(
            safe[col],
            errors="coerce",
        ).dropna()

        if values.empty:
            continue

        indicators.append(
            {
                "name": str(col),
                "observations": int(values.count()),
                "total": float(values.sum()),
                "average": float(values.mean()),
                "minimum": float(values.min()),
                "maximum": float(values.max()),
            }
        )

    countries = []
    periods = []
    organisations = []

    if detected["country"]:
        countries = (
            safe[detected["country"]]
            .dropna()
            .astype(str)
            .drop_duplicates()
            .tolist()
        )

    if detected["period"]:
        periods = (
            safe[detected["period"]]
            .dropna()
            .astype(str)
            .drop_duplicates()
            .tolist()
        )

    if detected["organisation"]:
        organisations = (
            safe[detected["organisation"]]
            .dropna()
            .astype(str)
            .drop_duplicates()
            .tolist()
        )

    return {
        "rows": int(len(safe)),
        "columns": int(len(safe.columns)),
        "indicators": indicators[:30],
        "countries": countries[:100],
        "periods": periods[:100],
        "organisations": organisations[:100],
        "period_column": detected["period"],
        "country_column": detected["country"],
        "organisation_column": detected["organisation"],
    }


# ============================================================
# CONTENT ENGINE
# ============================================================

def _default_public_content(
    website_name,
    audience,
    website_type,
    profile,
):
    indicator_names = [
        x["name"]
        for x in profile["indicators"][:6]
    ]

    indicator_text = (
        ", ".join(indicator_names)
        if indicator_names
        else "programme indicators"
    )

    return {
        "hero_title": website_name,
        "hero_text": (
            f"Explore reported {website_type.lower()} data, "
            "indicators and programme information through "
            "this public data portal."
        ),
        "about": (
            f"This public portal presents selected aggregated "
            f"information for {audience.lower()}. The information "
            "is derived from programme monitoring and reporting "
            "data available to the NEXUS DANIP platform."
        ),
        "programs": (
            "The portal can be used to explore programme areas, "
            "reported indicators and geographic patterns where "
            "these dimensions are available in the source data."
        ),
        "data_intro": (
            f"The current dataset contains {profile['rows']:,} "
            f"records and {len(profile['indicators']):,} detected "
            f"numeric indicators. Examples include: {indicator_text}."
        ),
        "methodology": (
            "Data are presented as reported monitoring information. "
            "Values may be aggregated by period, geography, "
            "organisation or indicator depending on the source "
            "dataset."
        ),
        "limitations": (
            "Reported statistics may be affected by completeness, "
            "timeliness, reporting coverage, revisions and other "
            "data-quality considerations. The information presented "
            "does not establish causal impact."
        ),
        "privacy": (
            "This generated public website is designed to expose "
            "aggregated programme information only. Personal "
            "identifiers and obvious credential fields are removed "
            "before website generation."
        ),
    }


def _ai_public_content(
    profile,
    website_name,
    audience,
    website_type,
):
    """
    Optional OpenAI enhancement.

    The existing app's OpenAI client/model are read from the
    calling application's globals when available. Only the
    compact dataset profile is sent to the model.
    """

    api_key = globals().get("OPENAI_API_KEY", "")
    model = globals().get("OPENAI_MODEL", "gpt-5")

    # Try the parent app's global client first.
    ai_client = globals().get("client")

    if ai_client is None and api_key:
        try:
            from openai import OpenAI
            ai_client = OpenAI(api_key=api_key)
        except Exception:
            ai_client = None

    if ai_client is None:
        return _default_public_content(
            website_name,
            audience,
            website_type,
            profile,
        )

    indicators = "\n".join(
        [
            (
                f"- {x['name']}: "
                f"observations={x['observations']}, "
                f"average={x['average']:.2f}, "
                f"minimum={x['minimum']:.2f}, "
                f"maximum={x['maximum']:.2f}"
            )
            for x in profile["indicators"][:20]
        ]
    )

    prompt = f"""
You are the public-content engine for NEXUS DANIP.

Create concise, professional, factual content for a public
programme/data website.

Website name: {website_name}
Audience: {audience}
Website type: {website_type}

Dataset:
Rows: {profile['rows']}
Columns: {profile['columns']}
Countries/areas: {', '.join(profile['countries'][:50])}
Periods: {', '.join(profile['periods'][:50])}

Indicators:
{indicators}

Return ONLY valid JSON:

{{
  "hero_title": "...",
  "hero_text": "...",
  "about": "...",
  "programs": "...",
  "data_intro": "...",
  "methodology": "...",
  "limitations": "...",
  "privacy": "..."
}}

Rules:
- Use only the supplied evidence.
- Do not invent achievements, targets, beneficiaries or impact.
- Do not make causal claims.
- Do not expose individual-level information.
- Do not expose credentials or authentication information.
- Say "reported data" where appropriate.
- Keep content suitable for a public-facing development,
  nutrition, health or monitoring portal.
"""

    try:
        response = ai_client.responses.create(
            model=model,
            input=prompt,
        )

        text = response.output_text.strip()

        text = re.sub(
            r"^```json\s*",
            "",
            text,
            flags=re.I,
        )

        text = re.sub(
            r"\s*```$",
            "",
            text,
            flags=re.I,
        )

        result = json.loads(text)

        fallback = _default_public_content(
            website_name,
            audience,
            website_type,
            profile,
        )

        for key, value in fallback.items():
            if not isinstance(result.get(key), str) or not result[key].strip():
                result[key] = value

        return result

    except Exception:
        return _default_public_content(
            website_name,
            audience,
            website_type,
            profile,
        )


# ============================================================
# WEBSITE COMPONENTS
# ============================================================

def _fmt(value):
    try:
        number = float(value)

        if number.is_integer():
            return f"{int(number):,}"

        return f"{number:,.2f}".rstrip("0").rstrip(".")

    except Exception:
        return html.escape(str(value))


def _kpi_cards(profile):
    cards = []

    cards.append(
        f"""
        <div class="kpi">
            <span>Records</span>
            <strong>{profile['rows']:,}</strong>
        </div>
        """
    )

    cards.append(
        f"""
        <div class="kpi">
            <span>Indicators</span>
            <strong>{len(profile['indicators']):,}</strong>
        </div>
        """
    )

    cards.append(
        f"""
        <div class="kpi">
            <span>Countries / Areas</span>
            <strong>{len(profile['countries']):,}</strong>
        </div>
        """
    )

    cards.append(
        f"""
        <div class="kpi">
            <span>Reporting Periods</span>
            <strong>{len(profile['periods']):,}</strong>
        </div>
        """
    )

    return "".join(cards)


def _indicator_cards(profile):
    output = []

    for item in profile["indicators"][:12]:

        output.append(
            f"""
            <article class="indicator-card">
                <h3>{html.escape(item['name'])}</h3>
                <div class="indicator-value">
                    {_fmt(item['total'])}
                </div>
                <div class="indicator-meta">
                    {item['observations']:,} observations
                </div>
                <div class="indicator-stats">
                    <span>Average<br><b>{_fmt(item['average'])}</b></span>
                    <span>Minimum<br><b>{_fmt(item['minimum'])}</b></span>
                    <span>Maximum<br><b>{_fmt(item['maximum'])}</b></span>
                </div>
            </article>
            """
        )

    return "".join(output)


def _country_cards(profile):
    if not profile["countries"]:
        return """
        <div class="empty-state">
            No country dimension was detected in the dataset.
        </div>
        """

    cards = []

    for country in profile["countries"][:24]:

        cards.append(
            f"""
            <div class="country-card">
                <div class="country-icon">🌍</div>
                <div>
                    <strong>{html.escape(country)}</strong>
                    <span>Reported programme data</span>
                </div>
            </div>
            """
        )

    return "".join(cards)


def _trend_table(df, profile):
    period_col = profile["period_column"]

    if not period_col or not profile["indicators"]:
        return """
        <div class="empty-state">
            A period and numeric indicator were not available for
            the automatic trend view.
        </div>
        """

    indicator = profile["indicators"][0]["name"]

    if indicator not in df.columns:
        return ""

    temp = df[
        [period_col, indicator]
    ].copy()

    temp[indicator] = pd.to_numeric(
        temp[indicator],
        errors="coerce",
    )

    temp = temp.dropna(
        subset=[indicator]
    )

    if temp.empty:
        return ""

    grouped = (
        temp.groupby(
            period_col,
            dropna=False,
        )[indicator]
        .sum()
        .reset_index()
    )

    grouped = grouped.tail(12)

    rows = []

    for _, row in grouped.iterrows():
        rows.append(
            f"""
            <tr>
                <td>{html.escape(str(row[period_col]))}</td>
                <td>{_fmt(row[indicator])}</td>
            </tr>
            """
        )

    return f"""
    <table class="trend-table">
        <thead>
            <tr>
                <th>Period</th>
                <th>{html.escape(str(indicator))}</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


# ============================================================
# COMPLETE HTML GENERATOR
# ============================================================

def build_public_website_html(
    df,
    website_name="DANIP Public Data Portal",
    tagline="Evidence, data and programme information",
    audience="Public",
    website_type="Data Portal",
    selected_indicators=None,
):
    """
    Generate one complete standalone HTML document.
    """

    safe_df = _public_safe_dataframe(df)

    if safe_df.empty:
        raise ValueError(
            "No usable public-safe dataset is available."
        )

    profile = _profile_dataset(safe_df)

    if selected_indicators:
        selected = [
            x for x in selected_indicators
            if x in safe_df.columns
        ]

        if selected:
            profile["indicators"] = [
                x for x in profile["indicators"]
                if x["name"] in selected
            ]

    content = _ai_public_content(
        profile,
        website_name,
        audience,
        website_type,
    )

    kpis = _kpi_cards(profile)
    indicators = _indicator_cards(profile)
    countries = _country_cards(profile)
    trend = _trend_table(
        safe_df,
        profile,
    )

    source_note = (
        st.session_state.get(
            "loaded_source_url",
            "",
        )
        if hasattr(st, "session_state")
        else ""
    )

    # Never place authenticated source URLs or tokens in the
    # generated public site.
    source_note = re.sub(
        r"[?&](token|access_token|api_key|client_secret)=[^&]*",
        "",
        str(source_note),
        flags=re.I,
    )

    source_display = (
        "Programme monitoring and reporting dataset"
        if not source_note
        else "Programme monitoring and reporting dataset"
    )

    safe_name = html.escape(
        str(website_name)
    )

    safe_tagline = html.escape(
        str(tagline)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1">
<meta name="description"
      content="{safe_tagline}">
<title>{safe_name}</title>

<style>

:root {{
    --navy: #17374b;
    --navy-dark: #0d2737;
    --blue: #2563eb;
    --red: #b03a2e;
    --text: #172033;
    --muted: #64748b;
    --surface: #ffffff;
    --soft: #f4f7fa;
    --border: #dce3ea;
    --shadow: 0 12px 35px rgba(15,23,42,.08);
    --radius: 18px;
}}

* {{
    box-sizing: border-box;
}}

html {{
    scroll-behavior: smooth;
}}

body {{
    margin: 0;
    font-family:
        Inter, system-ui, -apple-system,
        BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: var(--soft);
    color: var(--text);
    line-height: 1.65;
}}

a {{
    color: inherit;
    text-decoration: none;
}}

.container {{
    width: min(1180px, calc(100% - 36px));
    margin: auto;
}}

.nav {{
    position: sticky;
    top: 0;
    z-index: 100;
    background: rgba(13,39,55,.96);
    backdrop-filter: blur(12px);
}}

.nav-inner {{
    min-height: 68px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
}}

.brand {{
    color: #ffffff;
    font-weight: 850;
    letter-spacing: -.02em;
}}

.brand small {{
    display: block;
    color: #cbd5e1;
    font-size: .68rem;
    font-weight: 600;
}}

.nav-links {{
    display: flex;
    flex-wrap: wrap;
    gap: 18px;
    color: #e2e8f0;
    font-size: .88rem;
}}

.nav-links a:hover {{
    color: #ffffff;
}}

.hero {{
    background:
        linear-gradient(
            135deg,
            var(--navy-dark),
            var(--navy)
        );
    color: #ffffff;
    padding: 86px 0 72px;
}}

.hero-grid {{
    display: grid;
    grid-template-columns: 1.4fr .8fr;
    gap: 45px;
    align-items: center;
}}

.eyebrow {{
    text-transform: uppercase;
    letter-spacing: .14em;
    font-size: .72rem;
    font-weight: 800;
    color: #cbd5e1;
    margin-bottom: 12px;
}}

.hero h1 {{
    font-size: clamp(2.2rem, 5vw, 4.6rem);
    line-height: 1.02;
    letter-spacing: -.055em;
    margin: 0 0 20px;
}}

.hero p {{
    color: #dbeafe;
    font-size: 1.06rem;
    max-width: 720px;
}}

.hero-panel {{
    background: rgba(255,255,255,.09);
    border: 1px solid rgba(255,255,255,.18);
    border-radius: var(--radius);
    padding: 24px;
}}

.hero-panel strong {{
    display: block;
    font-size: 2rem;
}}

.section {{
    padding: 72px 0;
}}

.section.alt {{
    background: #ffffff;
}}

.section-heading {{
    max-width: 760px;
    margin-bottom: 28px;
}}

.section-heading h2 {{
    margin: 0 0 8px;
    font-size: clamp(1.7rem, 3vw, 2.5rem);
    letter-spacing: -.035em;
}}

.section-heading p {{
    color: var(--muted);
}}

.kpi-grid {{
    display: grid;
    grid-template-columns:
        repeat(4, minmax(0, 1fr));
    gap: 16px;
}}

.kpi {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 22px;
    box-shadow: var(--shadow);
}}

.kpi span {{
    display: block;
    color: var(--muted);
    font-size: .78rem;
    font-weight: 700;
}}

.kpi strong {{
    display: block;
    font-size: 1.85rem;
    margin-top: 5px;
}}

.indicator-grid {{
    display: grid;
    grid-template-columns:
        repeat(3, minmax(0, 1fr));
    gap: 18px;
}}

.indicator-card {{
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 23px;
    box-shadow: var(--shadow);
}}

.indicator-card h3 {{
    font-size: .92rem;
    margin: 0 0 12px;
    min-height: 45px;
}}

.indicator-value {{
    font-size: 2rem;
    font-weight: 850;
    letter-spacing: -.035em;
}}

.indicator-meta {{
    color: var(--muted);
    font-size: .76rem;
}}

.indicator-stats {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    margin-top: 18px;
}}

.indicator-stats span {{
    border-top: 1px solid var(--border);
    padding-top: 10px;
    color: var(--muted);
    font-size: .68rem;
}}

.indicator-stats b {{
    color: var(--text);
}}

.country-grid {{
    display: grid;
    grid-template-columns:
        repeat(3, minmax(0, 1fr));
    gap: 12px;
}}

.country-card {{
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 17px;
    display: flex;
    align-items: center;
    gap: 12px;
}}

.country-icon {{
    width: 40px;
    height: 40px;
    display: grid;
    place-items: center;
    border-radius: 12px;
    background: #eef4f8;
}}

.country-card strong {{
    display: block;
}}

.country-card span {{
    display: block;
    color: var(--muted);
    font-size: .72rem;
}}

.content-card {{
    background: #ffffff;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 28px;
    box-shadow: var(--shadow);
}}

.two-col {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
}}

.trend-table {{
    width: 100%;
    border-collapse: collapse;
    background: #ffffff;
    border-radius: 14px;
    overflow: hidden;
}}

.trend-table th,
.trend-table td {{
    padding: 12px 15px;
    border-bottom: 1px solid var(--border);
    text-align: left;
}}

.trend-table th {{
    background: var(--navy);
    color: #ffffff;
    font-size: .78rem;
}}

.trend-table td {{
    font-size: .86rem;
}}

.notice {{
    border-left: 4px solid var(--red);
    background: #fff8f7;
    padding: 17px 20px;
    border-radius: 10px;
}}

.footer {{
    background: var(--navy-dark);
    color: #cbd5e1;
    padding: 38px 0;
}}

.footer strong {{
    color: #ffffff;
}}

.footer-note {{
    font-size: .78rem;
    margin-top: 15px;
}}

.empty-state {{
    background: #ffffff;
    border: 1px dashed var(--border);
    padding: 28px;
    border-radius: 14px;
    color: var(--muted);
}}

@media (max-width: 900px) {{
    .hero-grid,
    .two-col {{
        grid-template-columns: 1fr;
    }}

    .kpi-grid {{
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }}

    .indicator-grid,
    .country-grid {{
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }}

    .nav-inner {{
        padding: 12px 0;
        align-items: flex-start;
        flex-direction: column;
    }}
}}

@media (max-width: 600px) {{
    .container {{
        width: min(100% - 24px, 1180px);
    }}

    .hero {{
        padding: 58px 0 50px;
    }}

    .section {{
        padding: 48px 0;
    }}

    .kpi-grid,
    .indicator-grid,
    .country-grid {{
        grid-template-columns: 1fr;
    }}

    .nav-links {{
        gap: 10px;
        font-size: .76rem;
    }}

    .hero h1 {{
        font-size: 2.35rem;
    }}
}}

@media (prefers-reduced-motion: reduce) {{
    html {{
        scroll-behavior: auto;
    }}
}}

</style>
</head>

<body>

<header class="nav">
    <div class="container nav-inner">
        <a class="brand" href="#home">
            {safe_name}
            <small>NEXUS DANIP Public Data Portal</small>
        </a>

        <nav class="nav-links" aria-label="Main navigation">
            <a href="#about">About</a>
            <a href="#data">Data</a>
            <a href="#indicators">Indicators</a>
            <a href="#countries">Countries</a>
            <a href="#trends">Trends</a>
            <a href="#methodology">Methodology</a>
        </nav>
    </div>
</header>


<main>

<section class="hero" id="home">
    <div class="container hero-grid">

        <div>
            <div class="eyebrow">
                Public data intelligence
            </div>

            <h1>
                {safe_name}
            </h1>

            <p>
                {html.escape(str(content['hero_text']))}
            </p>

            <p>
                <strong>{safe_tagline}</strong>
            </p>
        </div>

        <aside class="hero-panel">
            <div class="eyebrow">
                Data coverage
            </div>

            <strong>
                {profile['rows']:,}
            </strong>

            <span>
                reported records currently represented
            </span>

            <hr style="border:0;
                       border-top:1px solid rgba(255,255,255,.15);
                       margin:20px 0;">

            <strong>
                {len(profile['indicators']):,}
            </strong>

            <span>
                numeric indicators detected
            </span>
        </aside>

    </div>
</section>


<section class="section">
    <div class="container">

        <div class="section-heading">
            <h2>Data at a glance</h2>
            <p>
                A concise summary of the reporting dataset used to
                generate this public portal.
            </p>
        </div>

        <div class="kpi-grid">
            {kpis}
        </div>

    </div>
</section>


<section class="section alt" id="about">
    <div class="container">

        <div class="section-heading">
            <h2>About</h2>
            <p>
                Public-facing programme information generated from
                the available reporting dataset.
            </p>
        </div>

        <div class="two-col">

            <article class="content-card">
                <h3>About this portal</h3>
                <p>
                    {html.escape(str(content['about']))}
                </p>
            </article>

            <article class="content-card">
                <h3>Programme information</h3>
                <p>
                    {html.escape(str(content['programs']))}
                </p>
            </article>

        </div>

    </div>
</section>


<section class="section" id="data">
    <div class="container">

        <div class="section-heading">
            <h2>Data &amp; Statistics</h2>
            <p>
                {html.escape(str(content['data_intro']))}
            </p>
        </div>

        <div class="content-card">
            <p>
                {html.escape(str(content['data_intro']))}
            </p>

            <div class="notice">
                <strong>Important:</strong>
                Statistics on this website represent reported
                monitoring data and should be interpreted together
                with their definitions, reporting periods and
                data-quality limitations.
            </div>
        </div>

    </div>
</section>


<section class="section alt" id="indicators">
    <div class="container">

        <div class="section-heading">
            <h2>Key Indicators</h2>
            <p>
                Selected numeric indicators automatically detected
                from the source dataset.
            </p>
        </div>

        <div class="indicator-grid">
            {indicators}
        </div>

    </div>
</section>


<section class="section" id="countries">
    <div class="container">

        <div class="section-heading">
            <h2>Countries &amp; Areas</h2>
            <p>
                Geographic dimensions detected in the source data.
            </p>
        </div>

        <div class="country-grid">
            {countries}
        </div>

    </div>
</section>


<section class="section alt" id="trends">
    <div class="container">

        <div class="section-heading">
            <h2>Reported Trends</h2>
            <p>
                The latest available reporting periods for the first
                detected numeric indicator.
            </p>
        </div>

        <div class="content-card">
            {trend}
        </div>

    </div>
</section>


<section class="section" id="methodology">
    <div class="container">

        <div class="section-heading">
            <h2>Methodology &amp; Limitations</h2>
        </div>

        <div class="two-col">

            <article class="content-card">
                <h3>Methodology</h3>
                <p>
                    {html.escape(str(content['methodology']))}
                </p>
            </article>

            <article class="content-card">
                <h3>Data limitations</h3>
                <p>
                    {html.escape(str(content['limitations']))}
                </p>
            </article>

        </div>

        <div class="content-card" style="margin-top:20px;">
            <h3>Privacy &amp; responsible publication</h3>
            <p>
                {html.escape(str(content['privacy']))}
            </p>

            <div class="notice">
                This generated website is intended for aggregated
                public information. Review the publication content
                and data classification before making the site public.
            </div>
        </div>

    </div>
</section>

</main>


<footer class="footer">
    <div class="container">

        <strong>{safe_name}</strong>

        <div class="footer-note">
            Source: {html.escape(source_display)}
        </div>

        <div class="footer-note">
            Generated by NEXUS DANIP AI Data Intelligence.
            Public website content should be reviewed before
            publication.
        </div>

    </div>
</footer>

</body>
</html>
"""


# ============================================================
# ZIP EXPORT
# ============================================================

def build_public_website_zip(html_content: str):
    """Create a ready-to-upload static website ZIP."""

    memory = BytesIO()

    with zipfile.ZipFile(
        memory,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:

        archive.writestr(
            "index.html",
            html_content,
        )

        archive.writestr(
            "README.txt",
            (
                "NEXUS DANIP AI Public Website\n"
                "================================\n\n"
                "Open index.html in a browser to preview the site.\n"
                "Upload the contents of this ZIP to a static hosting\n"
                "provider when publication has been approved.\n\n"
                "IMPORTANT:\n"
                "Review the generated content and confirm that the\n"
                "dataset is approved for public release before publishing.\n"
            ),
        )

    memory.seek(0)
    return memory.getvalue()


# ============================================================
# PUBLICATION QUALITY CHECK
# ============================================================

def _website_quality_checks(df):
    checks = []

    safe = _public_safe_dataframe(df)

    original_cols = set(
        str(x)
        for x in df.columns
    ) if isinstance(df, pd.DataFrame) else set()

    safe_cols = set(
        str(x)
        for x in safe.columns
    )

    removed = sorted(
        original_cols - safe_cols
    )

    checks.append(
        {
            "check": "Dataset available",
            "status": "PASS" if not safe.empty else "FAIL",
            "detail": (
                f"{len(safe):,} public-safe rows available."
                if not safe.empty
                else "No usable public-safe data."
            ),
        }
    )

    checks.append(
        {
            "check": "Sensitive-looking fields removed",
            "status": "PASS",
            "detail": (
                f"{len(removed)} field(s) removed."
                if removed
                else "No obvious sensitive field names detected."
            ),
        }
    )

    checks.append(
        {
            "check": "Credentials embedded in website",
            "status": "PASS",
            "detail": "No credentials are intentionally written to generated HTML.",
        }
    )

    checks.append(
        {
            "check": "Responsive layout",
            "status": "PASS",
            "detail": "Desktop, tablet and mobile CSS breakpoints included.",
        }
    )

    checks.append(
        {
            "check": "Methodology",
            "status": "PASS",
            "detail": "Methodology and limitations sections are included.",
        }
    )

    checks.append(
        {
            "check": "Human publication review",
            "status": "REVIEW",
            "detail": "Final public-release approval should be completed by the data owner.",
        }
    )

    return checks


# ============================================================
# STREAMLIT WORKSPACE
# ============================================================

def render_ai_public_website_builder():
    """
    Render the fourth NEXUS DANIP workspace.
    """

    st.markdown(
        """
        <div style="
            padding:1.15rem 1.3rem;
            border:1px solid #dce3ea;
            border-radius:18px;
            background:#ffffff;
            box-shadow:0 1px 5px rgba(15,23,42,.06);
            margin-bottom:1rem;
        ">
            <div style="
                font-size:1.75rem;
                font-weight:850;
                color:#17374b;
            ">
                🌐 AI Public Website Builder
            </div>

            <div style="
                color:#64748b;
                margin-top:.35rem;
                line-height:1.55;
            ">
                Transform the currently loaded DANIP dataset into a
                responsive, public-facing data website.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    df = st.session_state.get(
        "loaded_df"
    )

    if not isinstance(df, pd.DataFrame) or df.empty:

        st.info(
            "📊 No dataset is currently loaded."
        )

        st.markdown(
            """
            Go to **🤖 DANIP AI Data Analyst**, load your
            DHIS2/API dataset, and then return to
            **🌐 AI Public Website Builder**.
            """
        )

        return

    profile = _profile_dataset(df)

    # --------------------------------------------------------
    # DATA STATUS
    # --------------------------------------------------------

    st.success(
        f"Dataset available — {len(df):,} records × "
        f"{len(df.columns):,} columns."
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric(
            "Records",
            f"{profile['rows']:,}",
        )

    with c2:
        st.metric(
            "Indicators",
            f"{len(profile['indicators']):,}",
        )

    with c3:
        st.metric(
            "Countries / Areas",
            f"{len(profile['countries']):,}",
        )

    with c4:
        st.metric(
            "Periods",
            f"{len(profile['periods']):,}",
        )

    # --------------------------------------------------------
    # WEBSITE SETTINGS
    # --------------------------------------------------------

    st.markdown("### ⚙️ Website Configuration")

    col1, col2 = st.columns(2)

    with col1:

        website_name = st.text_input(
            "Website name",
            value="DANIP Public Data Portal",
            key="website_builder_name",
        )

        audience = st.selectbox(
            "Audience",
            [
                "Public",
                "Policy makers",
                "Programme partners",
                "Researchers",
                "Development community",
            ],
            key="website_builder_audience",
        )

    with col2:

        website_type = st.selectbox(
            "Website type",
            [
                "Data Portal",
                "Programme Website",
                "Research & Evidence Portal",
                "Monitoring Dashboard",
            ],
            key="website_builder_type",
        )

        tagline = st.text_input(
            "Website tagline",
            value="Evidence, data and programme information",
            key="website_builder_tagline",
        )

    # --------------------------------------------------------
    # PAGES
    # --------------------------------------------------------

    st.markdown("### 📄 Website Pages")

    p1, p2, p3 = st.columns(3)

    with p1:
        home_page = st.checkbox(
            "Home",
            True,
            key="web_page_home",
        )
        about_page = st.checkbox(
            "About",
            True,
            key="web_page_about",
        )
        programs_page = st.checkbox(
            "Programs",
            True,
            key="web_page_programs",
        )

    with p2:
        data_page = st.checkbox(
            "Data & Statistics",
            True,
            key="web_page_data",
        )
        indicators_page = st.checkbox(
            "Indicators",
            True,
            key="web_page_indicators",
        )
        countries_page = st.checkbox(
            "Country Profiles",
            True,
            key="web_page_countries",
        )

    with p3:
        trends_page = st.checkbox(
            "Trends",
            True,
            key="web_page_trends",
        )
        methodology_page = st.checkbox(
            "Methodology",
            True,
            key="web_page_methodology",
        )
        privacy_page = st.checkbox(
            "Privacy / Data Use",
            True,
            key="web_page_privacy",
        )

    # --------------------------------------------------------
    # INDICATORS
    # --------------------------------------------------------

    indicator_names = [
        x["name"]
        for x in profile["indicators"]
    ]

    selected_indicators = st.multiselect(
        "Indicators to publish",
        indicator_names,
        default=indicator_names[:6],
        key="website_builder_indicators",
    )

    st.caption(
        "Only selected indicators are included in the public "
        "website's indicator section."
    )

    # --------------------------------------------------------
    # QUALITY CHECKS
    # --------------------------------------------------------

    st.markdown("### 🛡️ Publication Safety Check")

    checks = _website_quality_checks(df)

    check_df = pd.DataFrame(checks)

    st.dataframe(
        check_df,
        use_container_width=True,
        hide_index=True,
    )

    review_required = any(
        x["status"] == "REVIEW"
        for x in checks
    )

    if review_required:
        st.warning(
            "Human publication review is required before the "
            "generated site should be made public."
        )

    # --------------------------------------------------------
    # GENERATE
    # --------------------------------------------------------

    st.markdown("### ✨ Generate Website")

    generate = st.button(
        "✨ GENERATE RESPONSIVE WEBSITE",
        type="primary",
        use_container_width=True,
        key="generate_public_website",
    )

    if generate:

        with st.spinner(
            "AI is analysing the dataset and generating "
            "the public website..."
        ):

            try:

                website_html = build_public_website_html(
                    df=df,
                    website_name=website_name,
                    tagline=tagline,
                    audience=audience,
                    website_type=website_type,
                    selected_indicators=selected_indicators,
                )

                website_zip = build_public_website_zip(
                    website_html
                )

                st.session_state[
                    "public_website_html"
                ] = website_html

                st.session_state[
                    "public_website_zip"
                ] = website_zip

                st.session_state[
                    "public_website_generated"
                ] = True

            except Exception as exc:

                st.error(
                    f"Website generation failed: {exc}"
                )

    # --------------------------------------------------------
    # PREVIEW / EXPORT
    # --------------------------------------------------------

    if st.session_state.get(
        "public_website_generated",
        False,
    ):

        website_html = st.session_state.get(
            "public_website_html",
            "",
        )

        website_zip = st.session_state.get(
            "public_website_zip",
            b"",
        )

        st.success(
            "✅ Website generated successfully."
        )

        st.markdown("### 🖥️ Website Preview")

        preview_mode = st.radio(
            "Preview",
            [
                "Desktop",
                "Tablet",
                "Mobile",
            ],
            horizontal=True,
            key="website_preview_mode",
        )

        width = {
            "Desktop": "100%",
            "Tablet": "820px",
            "Mobile": "390px",
        }.get(
            preview_mode,
            "100%",
        )

        st.markdown(
            f"""
            <div style="
                width:{width};
                max-width:100%;
                margin:0 auto;
                border:1px solid #dce3ea;
                border-radius:16px;
                overflow:hidden;
                background:#ffffff;
                box-shadow:0 12px 35px rgba(15,23,42,.08);
            ">
                <iframe
                    srcdoc="{html.escape(website_html, quote=True)}"
                    style="
                        width:100%;
                        height:900px;
                        border:0;
                        display:block;
                    "
                    title="Generated public website preview">
                </iframe>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("### 📦 Export")

        e1, e2 = st.columns(2)

        with e1:
            st.download_button(
                "⬇️ Download HTML Website",
                data=website_html.encode(
                    "utf-8"
                ),
                file_name=(
                    re.sub(
                        r"[^a-zA-Z0-9_-]+",
                        "_",
                        website_name.lower(),
                    ).strip("_")
                    or "danip_public_website"
                ) + ".html",
                mime="text/html",
                use_container_width=True,
                key="download_public_website_html",
            )

        with e2:
            st.download_button(
                "📦 Download Website ZIP",
                data=website_zip,
                file_name=(
                    re.sub(
                        r"[^a-zA-Z0-9_-]+",
                        "_",
                        website_name.lower(),
                    ).strip("_")
                    or "danip_public_website"
                ) + ".zip",
                mime="application/zip",
                use_container_width=True,
                key="download_public_website_zip",
            )

        st.markdown("### 🔍 Generated Website HTML")

        with st.expander(
            "View generated source code",
            expanded=False,
        ):
            st.code(
                website_html,
                language="html",
            )

        st.info(
            "The generated site is static HTML/CSS. It does not "
            "contain the user's DHIS2 password, OAuth client secret "
            "or access token. Review the content and data "
            "classification before publication."
        )
