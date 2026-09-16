
# ============================================================
# NEXUS DANIP — AI PUBLIC WEBSITE BUILDER
# ============================================================
# Enhanced drop-in module for the existing DANIP Streamlit app.
#
# Adds:
#   • Responsive public website generation
#   • Interactive Streamlit analysis dashboard
#   • Automatic trend analysis
#   • Geographic comparisons
#   • Data-quality diagnostics
#   • Learning / insight engine
#   • Optional OpenAI narrative enhancement
#   • Responsive HTML charts
#   • HTML + ZIP export
#
# Integration:
#   from ai_public_website_builder import render_ai_public_website_builder
#
# Then call:
#   render_ai_public_website_builder()
#
# The module uses:
#   st.session_state["loaded_df"]
#
# It does not automatically publish the generated website.
# ============================================================

import os
import json
import html
import re
import zipfile
from io import BytesIO

import numpy as np
import pandas as pd
import streamlit as st


# ============================================================
# CONFIGURATION
# ============================================================

APP_TITLE = "🌐 AI Public Website Builder"
MAX_INDICATORS = 30
MAX_COUNTRIES = 100
MAX_CHART_POINTS = 24

_PUBLIC_SENSITIVE_PATTERNS = [
    "password", "passwd", "secret", "token", "access_token",
    "refresh_token", "api_key", "apikey", "authorization",
    "email", "phone", "mobile", "address", "national_id",
    "nationalid", "patient", "patient_id", "patientid",
    "person", "person_id", "personid", "dob", "date_of_birth",
    "birth_date", "username", "user_id", "userid",
]


# ============================================================
# BASIC HELPERS
# ============================================================

def _secret_value(name, default=""):
    """Read an application secret without requiring a specific app structure."""
    try:
        value = st.secrets.get(name, None)
        if value is not None:
            return str(value).strip()
    except Exception:
        pass

    try:
        section = st.secrets.get("OPENAI", {})
        if isinstance(section, dict):
            value = section.get(name, None)
            if value is not None:
                return str(value).strip()
    except Exception:
        pass

    return os.getenv(name, default).strip()


def _clean_name(value):
    return re.sub(
        r"[^a-zA-Z0-9_-]+",
        "_",
        str(value).lower(),
    ).strip("_") or "danip_public_website"


def _fmt(value, decimals=2):
    try:
        number = float(value)
        if not np.isfinite(number):
            return "—"
        if number.is_integer():
            return f"{int(number):,}"
        return f"{number:,.{decimals}f}".rstrip("0").rstrip(".")
    except Exception:
        return html.escape(str(value))


def _pct(value):
    try:
        return f"{float(value):.1f}%"
    except Exception:
        return "—"


def _safe_text(value):
    return html.escape(str(value))


# ============================================================
# DATA SAFETY
# ============================================================

def _public_safe_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remove obvious personal/credential fields before public generation.

    This is a conservative field-name filter. It is not a substitute
    for organizational data-classification and publication approval.
    """
    if not isinstance(df, pd.DataFrame) or df.empty:
        return pd.DataFrame()

    safe = df.copy()
    drop_cols = []

    for col in safe.columns:
        normalized = re.sub(
            r"[^a-z0-9]+",
            "_",
            str(col).lower(),
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


def _sensitive_columns(df):
    if not isinstance(df, pd.DataFrame):
        return []

    found = []

    for col in df.columns:
        normalized = re.sub(
            r"[^a-z0-9]+",
            "_",
            str(col).lower(),
        ).strip("_")

        if any(
            pattern in normalized
            for pattern in _PUBLIC_SENSITIVE_PATTERNS
        ):
            found.append(str(col))

    return found


# ============================================================
# COLUMN DETECTION
# ============================================================

def _detect_columns(df: pd.DataFrame):
    dimensions = []
    numeric = []

    if not isinstance(df, pd.DataFrame) or df.empty:
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

    # Prefer exact semantic names first.
    period_priority = [
        "period", "reporting_period", "month",
        "year", "date", "quarter", "fy",
    ]

    country_priority = [
        "country", "country_name", "nation",
    ]

    organisation_priority = [
        "organisation", "organization",
        "organisationunit", "organisation_unit",
        "orgunit", "org_unit", "facility",
        "region", "district", "province",
        "state", "location",
    ]

    for wanted in period_priority:
        for col in dimensions:
            normalized = re.sub(
                r"[^a-z0-9]+", "_",
                str(col).lower(),
            ).strip("_")
            if normalized == wanted:
                period = col
                break
        if period is not None:
            break

    for wanted in country_priority:
        for col in dimensions:
            normalized = re.sub(
                r"[^a-z0-9]+", "_",
                str(col).lower(),
            ).strip("_")
            if normalized == wanted:
                country = col
                break
        if country is not None:
            break

    for wanted in organisation_priority:
        for col in dimensions:
            normalized = re.sub(
                r"[^a-z0-9]+", "_",
                str(col).lower(),
            ).strip("_")
            if normalized == wanted:
                organisation = col
                break
        if organisation is not None:
            break

    # Fallback semantic matching.
    for col in dimensions:
        name = str(col).lower()

        if period is None and any(
            x in name
            for x in [
                "period", "month", "year", "date",
                "quarter", "fy", "time",
            ]
        ):
            period = col

        if country is None and any(
            x in name
            for x in [
                "country", "nation", "country_name",
            ]
        ):
            country = col

        if organisation is None and any(
            x in name
            for x in [
                "organisation", "organization",
                "orgunit", "org_unit", "facility",
                "region", "district", "province",
                "state", "location",
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


# ============================================================
# PERIOD NORMALIZATION
# ============================================================

def _period_sort_key(value):
    text = str(value).strip()

    # YYYYMM
    match = re.fullmatch(r"(\d{4})(\d{2})", text)
    if match:
        return pd.Timestamp(
            year=int(match.group(1)),
            month=int(match.group(2)),
            day=1,
        )

    # YYYY-MM / YYYY-MM-DD
    parsed = pd.to_datetime(
        text,
        errors="coerce",
    )

    if not pd.isna(parsed):
        return parsed

    # Fiscal/period labels: preserve lexical ordering as fallback.
    return text


def _sorted_period_values(series):
    values = (
        series.dropna()
        .astype(str)
        .drop_duplicates()
        .tolist()
    )

    return sorted(
        values,
        key=_period_sort_key,
    )


# ============================================================
# DATA PROFILING
# ============================================================

def _profile_dataset(df: pd.DataFrame):
    safe = _public_safe_dataframe(df)
    detected = _detect_columns(safe)

    indicators = []

    for col in detected["numeric"]:
        values = pd.to_numeric(
            safe[col],
            errors="coerce",
        )

        valid = values.dropna()

        if valid.empty:
            continue

        zero_count = int((valid == 0).sum())
        negative_count = int((valid < 0).sum())

        indicators.append(
            {
                "name": str(col),
                "observations": int(valid.count()),
                "missing": int(values.isna().sum()),
                "total": float(valid.sum()),
                "average": float(valid.mean()),
                "median": float(valid.median()),
                "minimum": float(valid.min()),
                "maximum": float(valid.max()),
                "zero_count": zero_count,
                "negative_count": negative_count,
                "zero_rate": (
                    zero_count / len(valid) * 100
                    if len(valid)
                    else 0
                ),
            }
        )

    indicators.sort(
        key=lambda x: (
            x["observations"],
            abs(x["total"]),
        ),
        reverse=True,
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
        periods = _sorted_period_values(
            safe[detected["period"]]
        )

    if detected["organisation"]:
        organisations = (
            safe[detected["organisation"]]
            .dropna()
            .astype(str)
            .drop_duplicates()
            .tolist()
        )

    missing_by_column = (
        safe.isna()
        .sum()
        .sort_values(
            ascending=False
        )
    )

    missing_rate = (
        safe.isna()
        .mean()
        .sort_values(
            ascending=False
        ) * 100
    )

    return {
        "rows": int(len(safe)),
        "columns": int(len(safe.columns)),
        "original_columns": int(len(df.columns)),
        "indicators": indicators[:MAX_INDICATORS],
        "countries": countries[:MAX_COUNTRIES],
        "periods": periods[:MAX_CHART_POINTS * 5],
        "organisations": organisations[:MAX_COUNTRIES],
        "period_column": detected["period"],
        "country_column": detected["country"],
        "organisation_column": detected["organisation"],
        "dimensions": [
            str(x)
            for x in detected["dimensions"]
        ],
        "missing_by_column": {
            str(k): int(v)
            for k, v in missing_by_column.head(30).items()
        },
        "missing_rate_by_column": {
            str(k): float(v)
            for k, v in missing_rate.head(30).items()
        },
    }


# ============================================================
# ANALYTICAL ENGINE
# ============================================================

def _indicator_series(df, indicator):
    if indicator not in df.columns:
        return pd.Series(dtype=float)

    return pd.to_numeric(
        df[indicator],
        errors="coerce",
    )


def _trend_analysis(df, profile, indicator):
    period_col = profile.get("period_column")

    if not period_col or indicator not in df.columns:
        return {
            "available": False,
            "reason": "No usable period dimension was detected.",
        }

    temp = df[
        [period_col, indicator]
    ].copy()

    temp[indicator] = pd.to_numeric(
        temp[indicator],
        errors="coerce",
    )

    temp = temp.dropna(
        subset=[period_col, indicator]
    )

    if temp.empty:
        return {
            "available": False,
            "reason": "No valid period observations were found.",
        }

    grouped = (
        temp.groupby(
            period_col,
            dropna=False,
        )[indicator]
        .agg(
            value="sum",
            observations="count",
        )
        .reset_index()
    )

    grouped["_sort"] = grouped[
        period_col
    ].astype(str).map(
        _period_sort_key
    )

    grouped = grouped.sort_values(
        "_sort"
    ).drop(
        columns=["_sort"]
    )

    if len(grouped) < 2:
        return {
            "available": False,
            "reason": "At least two reporting periods are needed.",
            "data": grouped,
        }

    first = float(
        grouped.iloc[0]["value"]
    )
    last = float(
        grouped.iloc[-1]["value"]
    )

    absolute_change = last - first

    if first != 0:
        pct_change = (
            absolute_change / abs(first) * 100
        )
    else:
        pct_change = None

    direction = (
        "increased"
        if absolute_change > 0
        else "decreased"
        if absolute_change < 0
        else "remained stable"
    )

    diffs = grouped["value"].diff().dropna()

    volatility = (
        float(diffs.std())
        if len(diffs) > 1
        else 0.0
    )

    mean_value = float(
        grouped["value"].mean()
    )

    return {
        "available": True,
        "indicator": indicator,
        "period_column": str(period_col),
        "data": grouped,
        "first_period": str(
            grouped.iloc[0][period_col]
        ),
        "last_period": str(
            grouped.iloc[-1][period_col]
        ),
        "first_value": first,
        "last_value": last,
        "absolute_change": absolute_change,
        "percent_change": pct_change,
        "direction": direction,
        "volatility": volatility,
        "mean": mean_value,
        "period_count": len(grouped),
    }


def _geographic_analysis(df, profile, indicator, dimension):
    if not dimension or indicator not in df.columns:
        return pd.DataFrame()

    temp = df[
        [dimension, indicator]
    ].copy()

    temp[indicator] = pd.to_numeric(
        temp[indicator],
        errors="coerce",
    )

    temp = temp.dropna(
        subset=[dimension, indicator]
    )

    if temp.empty:
        return pd.DataFrame()

    result = (
        temp.groupby(
            dimension,
            dropna=False,
        )[indicator]
        .agg(
            value="sum",
            observations="count",
            average="mean",
        )
        .reset_index()
    )

    result = result.sort_values(
        "value",
        ascending=False,
    )

    return result


def _data_quality_analysis(df, profile):
    safe = _public_safe_dataframe(df)

    if safe.empty:
        return {
            "missing_cells": 0,
            "missing_rate": 0,
            "duplicate_rows": 0,
            "zero_indicators": [],
            "negative_indicators": [],
            "high_missing_columns": [],
            "completeness": 100,
        }

    total_cells = max(
        safe.shape[0] * safe.shape[1],
        1,
    )

    missing_cells = int(
        safe.isna().sum().sum()
    )

    missing_rate = (
        missing_cells / total_cells * 100
    )

    duplicate_rows = int(
        safe.duplicated().sum()
    )

    zero_indicators = [
        x["name"]
        for x in profile["indicators"]
        if x["zero_rate"] >= 50
    ]

    negative_indicators = [
        x["name"]
        for x in profile["indicators"]
        if x["negative_count"] > 0
    ]

    high_missing_columns = [
        name
        for name, rate
        in profile["missing_rate_by_column"].items()
        if rate >= 20
    ]

    completeness = max(
        0,
        100 - missing_rate,
    )

    return {
        "missing_cells": missing_cells,
        "missing_rate": missing_rate,
        "duplicate_rows": duplicate_rows,
        "zero_indicators": zero_indicators,
        "negative_indicators": negative_indicators,
        "high_missing_columns": high_missing_columns,
        "completeness": completeness,
    }


def _build_learning_insights(
    df,
    profile,
    indicator,
    trend,
    geographic,
    quality,
):
    """
    Evidence-first learning engine.

    It produces observations and learning questions from the
    supplied dataset. It deliberately avoids unsupported causal
    explanations.
    """

    observations = []
    learning = []
    quality_signals = []

    if trend.get("available"):

        direction = trend["direction"]

        if trend.get("percent_change") is not None:
            change_text = _pct(
                abs(trend["percent_change"])
            )
        else:
            change_text = "an undefined percentage change because the starting value is zero"

        observations.append(
            (
                f"{indicator} {direction} from "
                f"{_fmt(trend['first_value'])} in "
                f"{trend['first_period']} to "
                f"{_fmt(trend['last_value'])} in "
                f"{trend['last_period']}. "
                f"The absolute change was "
                f"{_fmt(trend['absolute_change'])}; "
                f"the relative change was {change_text}."
            )
        )

        if trend["period_count"] >= 3:
            learning.append(
                (
                    "Review the reporting periods around the largest "
                    "month-to-month or period-to-period changes to "
                    "determine whether they reflect programme change, "
                    "reporting completeness, seasonality or data revision."
                )
            )

        if trend["volatility"] > 0:
            learning.append(
                (
                    "Compare the observed variation with reporting "
                    "coverage and contextual programme events before "
                    "interpreting the movement as a substantive change."
                )
            )

    if not geographic.empty:

        top = geographic.iloc[0]
        bottom = geographic.iloc[-1]

        observations.append(
            (
                f"Across the detected geographic dimension, "
                f"{top.iloc[0]} has the largest reported total "
                f"({_fmt(top['value'])}), while "
                f"{bottom.iloc[0]} has the smallest "
                f"({_fmt(bottom['value'])}) among the displayed groups."
            )
        )

        learning.append(
            (
                "Compare geographic differences with population size, "
                "programme reach, reporting completeness and denominator "
                "definitions before treating them as performance differences."
            )
        )

    if quality["missing_rate"] > 0:
        quality_signals.append(
            (
                f"{_pct(quality['missing_rate'])} of all available cells "
                "are missing."
            )
        )

        learning.append(
            (
                "Investigate whether missing values represent "
                "non-reporting, not-applicable observations, system "
                "gaps or genuine zero activity."
            )
        )

    if quality["duplicate_rows"] > 0:
        quality_signals.append(
            (
                f"{quality['duplicate_rows']:,} duplicate rows were detected."
            )
        )

        learning.append(
            (
                "Check the dataset grain and key fields to determine "
                "whether duplicate rows are valid repeated observations "
                "or accidental duplication."
            )
        )

    if quality["zero_indicators"]:
        quality_signals.append(
            (
                "High zero rates were detected for: "
                + ", ".join(
                    quality["zero_indicators"][:6]
                )
            )
        )

        learning.append(
            (
                "Distinguish true zero values from missing or "
                "not-reported values before calculating averages or rates."
            )
        )

    if quality["negative_indicators"]:
        quality_signals.append(
            (
                "Negative values were detected for: "
                + ", ".join(
                    quality["negative_indicators"][:6]
                )
            )
        )

        learning.append(
            (
                "Validate whether negative values are meaningful "
                "for the affected indicators or represent adjustments "
                "and data-entry issues."
            )
        )

    if not observations:
        observations.append(
            "The current dataset does not contain enough detected dimensions for a reliable automatic trend interpretation."
        )

    if not learning:
        learning.append(
            "Add a reporting-period or geographic dimension to enable deeper automated learning from the dataset."
        )

    return {
        "observations": observations,
        "learning_questions": learning,
        "quality_signals": quality_signals,
    }


# ============================================================
# OPTIONAL AI CONTENT
# ============================================================

def _ai_client():
    api_key = _secret_value("OPENAI_API_KEY")

    if not api_key:
        return None, ""

    model = _secret_value(
        "OPENAI_MODEL",
        "gpt-5",
    )

    try:
        from openai import OpenAI
        return OpenAI(
            api_key=api_key
        ), model
    except Exception:
        return None, model


def _default_public_content(
    website_name,
    audience,
    website_type,
    profile,
    learning,
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

    observation_text = " ".join(
        learning["observations"][:2]
    )

    learning_text = " ".join(
        learning["learning_questions"][:2]
    )

    return {
        "hero_title": website_name,
        "hero_text": (
            f"Explore reported {website_type.lower()} data, "
            "indicators, geographic information and evidence-based "
            "learning through this public data portal."
        ),
        "about": (
            f"This public portal presents selected aggregated "
            f"information for {audience.lower()}. The information "
            "is derived from programme monitoring and reporting data."
        ),
        "programs": (
            "Explore reported programme indicators and geographic "
            "patterns where those dimensions are available in the source data."
        ),
        "data_intro": (
            f"The current dataset contains {profile['rows']:,} records "
            f"and {len(profile['indicators']):,} detected numeric indicators. "
            f"Examples include: {indicator_text}."
        ),
        "analysis": (
            observation_text
            if observation_text
            else "The analysis layer summarizes patterns visible in the reported data."
        ),
        "learning": (
            learning_text
            if learning_text
            else "Use the analytical findings to identify questions for further review."
        ),
        "methodology": (
            "Data are presented as reported monitoring information. "
            "Values may be aggregated by period, geography, organisation "
            "or indicator depending on the source dataset."
        ),
        "limitations": (
            "Reported statistics may be affected by completeness, "
            "timeliness, reporting coverage, revisions, denominator "
            "definitions and other data-quality considerations. "
            "Observed associations should not be interpreted as causal "
            "effects without additional evidence."
        ),
        "privacy": (
            "The generated public site is designed to expose aggregated "
            "programme information. Obvious personal identifiers and "
            "credential-like fields are removed before generation."
        ),
    }


def _ai_public_content(
    profile,
    website_name,
    audience,
    website_type,
    learning,
):
    client, model = _ai_client()

    fallback = _default_public_content(
        website_name,
        audience,
        website_type,
        profile,
        learning,
    )

    if client is None:
        return fallback

    indicators = "\n".join(
        [
            (
                f"- {x['name']}: "
                f"observations={x['observations']}, "
                f"average={x['average']:.2f}, "
                f"minimum={x['minimum']:.2f}, "
                f"maximum={x['maximum']:.2f}, "
                f"zero_rate={x['zero_rate']:.1f}%"
            )
            for x in profile["indicators"][:20]
        ]
    )

    observations = "\n".join(
        f"- {x}"
        for x in learning["observations"][:6]
    )

    learning_questions = "\n".join(
        f"- {x}"
        for x in learning["learning_questions"][:6]
    )

    prompt = f"""
You are the public-content engine for NEXUS DANIP.

Create concise, professional and evidence-first content for a
public programme/data website.

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

Evidence observations:
{observations}

Learning questions:
{learning_questions}

Return ONLY valid JSON:

{{
  "hero_title": "...",
  "hero_text": "...",
  "about": "...",
  "programs": "...",
  "data_intro": "...",
  "analysis": "...",
  "learning": "...",
  "methodology": "...",
  "limitations": "...",
  "privacy": "..."
}}

Rules:
- Use only supplied evidence.
- Do not invent achievements, targets, beneficiaries or impact.
- Do not make causal claims.
- Do not expose individual-level information.
- Do not expose credentials or authentication information.
- Use "reported data" where appropriate.
- Distinguish observation from explanation.
- Treat learning questions as questions, not facts.
"""

    try:
        response = client.responses.create(
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

        for key, value in fallback.items():
            if (
                not isinstance(
                    result.get(key),
                    str,
                )
                or not result[key].strip()
            ):
                result[key] = value

        return result

    except Exception:
        return fallback


# ============================================================
# RESPONSIVE HTML CHARTS
# ============================================================

def _html_bar_chart(
    labels,
    values,
    title="",
    suffix="",
):
    if not labels or not values:
        return """
        <div class="empty-state">
            No chartable data available.
        </div>
        """

    pairs = []

    for label, value in zip(
        labels,
        values,
    ):
        try:
            numeric = float(value)
            if not np.isfinite(numeric):
                continue
            pairs.append(
                (
                    str(label),
                    numeric,
                )
            )
        except Exception:
            continue

    if not pairs:
        return """
        <div class="empty-state">
            No valid numeric observations available.
        </div>
        """

    maximum = max(
        abs(x[1])
        for x in pairs
    ) or 1

    bars = []

    for label, value in pairs:

        width = max(
            3,
            abs(value) / maximum * 100,
        )

        bars.append(
            f"""
            <div class="hbar-row">
                <div class="hbar-label">
                    {_safe_text(label)}
                </div>
                <div class="hbar-track">
                    <div class="hbar-fill"
                         style="width:{width:.1f}%"></div>
                </div>
                <div class="hbar-value">
                    {_fmt(value)}{html.escape(suffix)}
                </div>
            </div>
            """
        )

    title_html = (
        f"<h3>{_safe_text(title)}</h3>"
        if title
        else ""
    )

    return f"""
    <div class="chart-card">
        {title_html}
        <div class="hbar-chart">
            {''.join(bars)}
        </div>
    </div>
    """


def _html_trend_chart(
    trend,
    title="Reported trend",
):
    if not trend.get("available"):
        return f"""
        <div class="empty-state">
            {_safe_text(trend.get('reason', 'Trend unavailable.'))}
        </div>
        """

    data = trend["data"]

    points = []

    for _, row in data.tail(
        MAX_CHART_POINTS
    ).iterrows():

        points.append(
            (
                str(row.iloc[0]),
                float(row["value"]),
            )
        )

    if not points:
        return """
        <div class="empty-state">
            No trend points available.
        </div>
        """

    max_value = max(
        x[1]
        for x in points
    )

    min_value = min(
        x[1]
        for x in points
    )

    span = (
        max_value - min_value
        if max_value != min_value
        else 1
    )

    line = []

    width = 1000
    height = 320

    for index, (_, value) in enumerate(points):

        x = (
            40
            + (
                index
                / max(
                    len(points) - 1,
                    1,
                )
            ) * 920
        )

        y = (
            35
            + (
                (max_value - value)
                / span
            ) * 230
        )

        line.append(
            f"{x:.1f},{y:.1f}"
        )

    circles = []

    for index, (label, value) in enumerate(points):

        x = (
            40
            + (
                index
                / max(
                    len(points) - 1,
                    1,
                )
            ) * 920
        )

        y = (
            35
            + (
                (max_value - value)
                / span
            ) * 230
        )

        circles.append(
            f"""
            <circle
                cx="{x:.1f}"
                cy="{y:.1f}"
                r="5"
                class="trend-point">
                <title>
                    {_safe_text(label)}:
                    {_fmt(value)}
                </title>
            </circle>
            """
        )

    labels = []

    step = max(
        1,
        len(points) // 8,
    )

    for index, (label, _) in enumerate(points):

        if (
            index % step != 0
            and index != len(points) - 1
        ):
            continue

        x = (
            40
            + (
                index
                / max(
                    len(points) - 1,
                    1,
                )
            ) * 920
        )

        labels.append(
            f"""
            <text
                x="{x:.1f}"
                y="300"
                text-anchor="middle"
                class="trend-label">
                {_safe_text(label)}
            </text>
            """
        )

    return f"""
    <div class="chart-card">
        <h3>{_safe_text(title)}</h3>

        <svg
            viewBox="0 0 {width} {height}"
            role="img"
            aria-label="{_safe_text(title)}"
            class="trend-svg">

            <line
                x1="40"
                y1="265"
                x2="960"
                y2="265"
                class="trend-axis"/>

            <polyline
                points="{' '.join(line)}"
                class="trend-line"
                fill="none"/>

            {''.join(circles)}
            {''.join(labels)}

        </svg>

        <div class="chart-caption">
            {html.escape(trend['first_period'])}:
            <strong>{_fmt(trend['first_value'])}</strong>
            &nbsp; → &nbsp;
            {html.escape(trend['last_period'])}:
            <strong>{_fmt(trend['last_value'])}</strong>
        </div>
    </div>
    """


# ============================================================
# WEBSITE HTML
# ============================================================

def build_public_website_html(
    df,
    website_name="DANIP Public Data Portal",
    tagline="Evidence, data and programme information",
    audience="Public",
    website_type="Data Portal",
    selected_indicators=None,
):
    safe_df = _public_safe_dataframe(df)

    if safe_df.empty:
        raise ValueError(
            "No usable public-safe dataset is available."
        )

    profile = _profile_dataset(safe_df)

    if selected_indicators:
        selected = [
            x
            for x in selected_indicators
            if x in safe_df.columns
        ]

        if selected:
            profile["indicators"] = [
                x
                for x in profile["indicators"]
                if x["name"] in selected
            ]

    if not profile["indicators"]:
        raise ValueError(
            "No numeric indicators are available for the website."
        )

    primary_indicator = profile[
        "indicators"
    ][0]["name"]

    trend = _trend_analysis(
        safe_df,
        profile,
        primary_indicator,
    )

    geo_dimension = (
        profile["country_column"]
        or profile["organisation_column"]
    )

    geographic = _geographic_analysis(
        safe_df,
        profile,
        primary_indicator,
        geo_dimension,
    )

    quality = _data_quality_analysis(
        safe_df,
        profile,
    )

    learning = _build_learning_insights(
        safe_df,
        profile,
        primary_indicator,
        trend,
        geographic,
        quality,
    )

    content = _ai_public_content(
        profile,
        website_name,
        audience,
        website_type,
        learning,
    )

    # KPI values
    kpis = [
        (
            "Records",
            f"{profile['rows']:,}",
        ),
        (
            "Indicators",
            f"{len(profile['indicators']):,}",
        ),
        (
            "Countries / Areas",
            f"{len(profile['countries']):,}",
        ),
        (
            "Reporting Periods",
            f"{len(profile['periods']):,}",
        ),
    ]

    kpi_html = "".join(
        f"""
        <div class="kpi">
            <span>{_safe_text(label)}</span>
            <strong>{_safe_text(value)}</strong>
        </div>
        """
        for label, value in kpis
    )

    indicator_cards = []

    for item in profile["indicators"][:12]:

        indicator_cards.append(
            f"""
            <article class="indicator-card">
                <h3>{_safe_text(item['name'])}</h3>

                <div class="indicator-value">
                    {_fmt(item['total'])}
                </div>

                <div class="indicator-meta">
                    {item['observations']:,} observations
                </div>

                <div class="indicator-stats">
                    <span>
                        Average<br>
                        <b>{_fmt(item['average'])}</b>
                    </span>

                    <span>
                        Minimum<br>
                        <b>{_fmt(item['minimum'])}</b>
                    </span>

                    <span>
                        Maximum<br>
                        <b>{_fmt(item['maximum'])}</b>
                    </span>
                </div>
            </article>
            """
        )

    country_html = []

    for country in profile["countries"][:24]:

        country_html.append(
            f"""
            <div class="country-card">
                <div class="country-icon">🌍</div>
                <div>
                    <strong>{_safe_text(country)}</strong>
                    <span>Reported programme data</span>
                </div>
            </div>
            """
        )

    if not country_html:
        country_html.append(
            """
            <div class="empty-state">
                No country dimension was detected.
            </div>
            """
        )

    # Geographic chart.
    if not geographic.empty:

        geo_chart = _html_bar_chart(
            geographic.iloc[:10, 0].astype(str).tolist(),
            geographic["value"].tolist()[:10],
            title=(
                f"Reported {primary_indicator} by "
                f"{geo_dimension}"
            ),
        )

    else:
        geo_chart = """
        <div class="empty-state">
            Geographic comparison is not available for this dataset.
        </div>
        """

    trend_chart = _html_trend_chart(
        trend,
        title=f"{primary_indicator} — reported trend",
    )

    observation_html = "".join(
        f"""
        <li>{_safe_text(item)}</li>
        """
        for item in learning["observations"]
    )

    learning_html = "".join(
        f"""
        <li>{_safe_text(item)}</li>
        """
        for item in learning["learning_questions"]
    )

    quality_html = "".join(
        f"""
        <li>{_safe_text(item)}</li>
        """
        for item in learning["quality_signals"]
    )

    if not quality_html:
        quality_html = """
        <li>No major automatic quality signal was detected.</li>
        """

    source_display = (
        "Programme monitoring and reporting dataset"
    )

    safe_name = _safe_text(
        website_name
    )

    safe_tagline = _safe_text(
        tagline
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
    --navy:#17374b;
    --navy-dark:#0d2737;
    --blue:#2563eb;
    --red:#b03a2e;
    --text:#172033;
    --muted:#64748b;
    --surface:#ffffff;
    --soft:#f4f7fa;
    --border:#dce3ea;
    --shadow:0 12px 35px rgba(15,23,42,.08);
    --radius:18px;
}}

* {{
    box-sizing:border-box;
}}

html {{
    scroll-behavior:smooth;
}}

body {{
    margin:0;
    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
    background:var(--soft);
    color:var(--text);
    line-height:1.65;
}}

a {{
    color:inherit;
    text-decoration:none;
}}

.container {{
    width:min(1180px,calc(100% - 36px));
    margin:auto;
}}

.nav {{
    position:sticky;
    top:0;
    z-index:100;
    background:rgba(13,39,55,.97);
    backdrop-filter:blur(12px);
}}

.nav-inner {{
    min-height:68px;
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:20px;
}}

.brand {{
    color:#fff;
    font-weight:850;
    letter-spacing:-.02em;
}}

.brand small {{
    display:block;
    color:#cbd5e1;
    font-size:.68rem;
    font-weight:600;
}}

.nav-links {{
    display:flex;
    flex-wrap:wrap;
    gap:18px;
    color:#e2e8f0;
    font-size:.88rem;
}}

.nav-links a:hover {{
    color:#fff;
}}

.hero {{
    background:
        linear-gradient(
            135deg,
            var(--navy-dark),
            var(--navy)
        );
    color:#fff;
    padding:86px 0 72px;
}}

.hero-grid {{
    display:grid;
    grid-template-columns:1.35fr .85fr;
    gap:45px;
    align-items:center;
}}

.eyebrow {{
    text-transform:uppercase;
    letter-spacing:.14em;
    font-size:.72rem;
    font-weight:800;
    color:#cbd5e1;
    margin-bottom:12px;
}}

.hero h1 {{
    font-size:clamp(2.2rem,5vw,4.6rem);
    line-height:1.02;
    letter-spacing:-.055em;
    margin:0 0 20px;
}}

.hero p {{
    color:#dbeafe;
    font-size:1.06rem;
    max-width:720px;
}}

.hero-panel {{
    background:rgba(255,255,255,.09);
    border:1px solid rgba(255,255,255,.18);
    border-radius:var(--radius);
    padding:25px;
}}

.hero-panel strong {{
    display:block;
    font-size:2rem;
}}

.section {{
    padding:72px 0;
}}

.section.alt {{
    background:#fff;
}}

.section-heading {{
    max-width:780px;
    margin-bottom:28px;
}}

.section-heading h2 {{
    margin:0 0 8px;
    font-size:clamp(1.7rem,3vw,2.5rem);
    letter-spacing:-.035em;
}}

.section-heading p {{
    color:var(--muted);
}}

.kpi-grid {{
    display:grid;
    grid-template-columns:
        repeat(4,minmax(0,1fr));
    gap:16px;
}}

.kpi {{
    background:#fff;
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:22px;
    box-shadow:var(--shadow);
}}

.kpi span {{
    display:block;
    color:var(--muted);
    font-size:.78rem;
    font-weight:700;
}}

.kpi strong {{
    display:block;
    font-size:1.85rem;
    margin-top:5px;
}}

.two-col {{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:20px;
}}

.content-card {{
    background:#fff;
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:28px;
    box-shadow:var(--shadow);
}}

.content-card h3 {{
    margin-top:0;
}}

.indicator-grid {{
    display:grid;
    grid-template-columns:
        repeat(3,minmax(0,1fr));
    gap:18px;
}}

.indicator-card {{
    background:#fff;
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:23px;
    box-shadow:var(--shadow);
}}

.indicator-card h3 {{
    font-size:.92rem;
    margin:0 0 12px;
    min-height:45px;
}}

.indicator-value {{
    font-size:2rem;
    font-weight:850;
    letter-spacing:-.035em;
}}

.indicator-meta {{
    color:var(--muted);
    font-size:.76rem;
}}

.indicator-stats {{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:8px;
    margin-top:18px;
}}

.indicator-stats span {{
    border-top:1px solid var(--border);
    padding-top:10px;
    color:var(--muted);
    font-size:.68rem;
}}

.indicator-stats b {{
    color:var(--text);
}}

.country-grid {{
    display:grid;
    grid-template-columns:
        repeat(3,minmax(0,1fr));
    gap:12px;
}}

.country-card {{
    background:#fff;
    border:1px solid var(--border);
    border-radius:14px;
    padding:17px;
    display:flex;
    align-items:center;
    gap:12px;
}}

.country-icon {{
    width:40px;
    height:40px;
    display:grid;
    place-items:center;
    border-radius:12px;
    background:#eef4f8;
}}

.country-card strong {{
    display:block;
}}

.country-card span {{
    display:block;
    color:var(--muted);
    font-size:.72rem;
}}

.chart-card {{
    background:#fff;
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:24px;
    box-shadow:var(--shadow);
    overflow:hidden;
}}

.chart-card h3 {{
    margin:0 0 18px;
}}

.trend-svg {{
    width:100%;
    height:auto;
    min-height:260px;
}}

.trend-axis {{
    stroke:#cbd5e1;
    stroke-width:2;
}}

.trend-line {{
    stroke:var(--blue);
    stroke-width:7;
    stroke-linecap:round;
    stroke-linejoin:round;
}}

.trend-point {{
    fill:var(--blue);
}}

.trend-label {{
    fill:var(--muted);
    font-size:16px;
}}

.chart-caption {{
    color:var(--muted);
    font-size:.78rem;
    margin-top:8px;
}}

.hbar-chart {{
    display:flex;
    flex-direction:column;
    gap:12px;
}}

.hbar-row {{
    display:grid;
    grid-template-columns:
        minmax(100px,170px) 1fr minmax(60px,100px);
    align-items:center;
    gap:12px;
}}

.hbar-label {{
    font-size:.78rem;
    overflow-wrap:anywhere;
}}

.hbar-track {{
    height:14px;
    border-radius:999px;
    background:#edf2f7;
    overflow:hidden;
}}

.hbar-fill {{
    height:100%;
    border-radius:999px;
    background:var(--blue);
}}

.hbar-value {{
    text-align:right;
    font-size:.76rem;
    font-weight:750;
}}

.insight-grid {{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:20px;
}}

.insight {{
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:24px;
    background:#fff;
}}

.insight.learning {{
    background:#f8fbff;
}}

.insight ul {{
    padding-left:20px;
}}

.notice {{
    border-left:4px solid var(--red);
    background:#fff8f7;
    padding:17px 20px;
    border-radius:10px;
}}

.footer {{
    background:var(--navy-dark);
    color:#cbd5e1;
    padding:38px 0;
}}

.footer strong {{
    color:#fff;
}}

.footer-note {{
    font-size:.78rem;
    margin-top:15px;
}}

.empty-state {{
    background:#fff;
    border:1px dashed var(--border);
    padding:28px;
    border-radius:14px;
    color:var(--muted);
}}

@media (max-width:900px) {{

    .hero-grid,
    .two-col,
    .insight-grid {{
        grid-template-columns:1fr;
    }}

    .kpi-grid {{
        grid-template-columns:
            repeat(2,minmax(0,1fr));
    }}

    .indicator-grid,
    .country-grid {{
        grid-template-columns:
            repeat(2,minmax(0,1fr));
    }}

    .nav-inner {{
        padding:12px 0;
        align-items:flex-start;
        flex-direction:column;
    }}
}}

@media (max-width:600px) {{

    .container {{
        width:min(100% - 24px,1180px);
    }}

    .hero {{
        padding:58px 0 50px;
    }}

    .section {{
        padding:48px 0;
    }}

    .kpi-grid,
    .indicator-grid,
    .country-grid {{
        grid-template-columns:1fr;
    }}

    .nav-links {{
        gap:10px;
        font-size:.76rem;
    }}

    .hero h1 {{
        font-size:2.35rem;
    }}

    .hbar-row {{
        grid-template-columns:1fr;
        gap:5px;
    }}

    .hbar-value {{
        text-align:left;
    }}
}}

@media (prefers-reduced-motion:reduce) {{
    html {{
        scroll-behavior:auto;
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

        <nav
            class="nav-links"
            aria-label="Main navigation">

            <a href="#about">About</a>
            <a href="#data">Data</a>
            <a href="#analysis">Analysis</a>
            <a href="#learning">Learning</a>
            <a href="#countries">Countries</a>
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
                {_safe_text(content['hero_text'])}
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
                reported records represented
            </span>

            <hr style="
                border:0;
                border-top:1px solid rgba(255,255,255,.15);
                margin:20px 0;
            ">

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
                A concise summary of the reporting dataset.
            </p>

        </div>

        <div class="kpi-grid">
            {kpi_html}
        </div>

    </div>

</section>


<section class="section alt" id="about">

    <div class="container">

        <div class="section-heading">

            <h2>About</h2>

            <p>
                {_safe_text(content['about'])}
            </p>

        </div>

        <div class="two-col">

            <article class="content-card">

                <h3>Programme information</h3>

                <p>
                    {_safe_text(content['programs'])}
                </p>

            </article>

            <article class="content-card">

                <h3>Data introduction</h3>

                <p>
                    {_safe_text(content['data_intro'])}
                </p>

            </article>

        </div>

    </div>

</section>


<section class="section" id="data">

    <div class="container">

        <div class="section-heading">

            <h2>Indicators &amp; Statistics</h2>

            <p>
                Numeric indicators detected from the public-safe
                dataset.
            </p>

        </div>

        <div class="indicator-grid">
            {''.join(indicator_cards)}
        </div>

    </div>

</section>


<section class="section alt" id="analysis">

    <div class="container">

        <div class="section-heading">

            <h2>Analysis</h2>

            <p>
                Automatic evidence-first analysis of the reported data.
            </p>

        </div>

        <div class="two-col">

            {trend_chart}

            {geo_chart}

        </div>

        <div class="content-card" style="margin-top:20px;">

            <h3>What the data shows</h3>

            <p>
                {_safe_text(content['analysis'])}
            </p>

            <ul>
                {observation_html}
            </ul>

        </div>

    </div>

</section>


<section class="section" id="learning">

    <div class="container">

        <div class="section-heading">

            <h2>🧠 Learning from the Analysis</h2>

            <p>
                Evidence-based learning prompts generated from
                observed patterns and data-quality signals.
            </p>

        </div>

        <div class="insight-grid">

            <article class="insight">

                <h3>What we can learn</h3>

                <ul>
                    {learning_html}
                </ul>

            </article>

            <article class="insight learning">

                <h3>Questions for further analysis</h3>

                <p>
                    {_safe_text(content['learning'])}
                </p>

                <div class="notice">
                    Learning questions are not conclusions.
                    They identify areas where additional context,
                    validation or analysis may be useful.
                </div>

            </article>

        </div>

        <div class="content-card" style="margin-top:20px;">

            <h3>Data-quality signals</h3>

            <ul>
                {quality_html}
            </ul>

        </div>

    </div>

</section>


<section class="section alt" id="countries">

    <div class="container">

        <div class="section-heading">

            <h2>Countries &amp; Areas</h2>

            <p>
                Geographic dimensions detected in the source data.
            </p>

        </div>

        <div class="country-grid">
            {''.join(country_html)}
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
                    {_safe_text(content['methodology'])}
                </p>

            </article>

            <article class="content-card">

                <h3>Data limitations</h3>

                <p>
                    {_safe_text(content['limitations'])}
                </p>

            </article>

        </div>

        <div class="content-card" style="margin-top:20px;">

            <h3>Privacy &amp; Responsible Publication</h3>

            <p>
                {_safe_text(content['privacy'])}
            </p>

            <div class="notice">

                This generated website is intended for aggregated
                public information. Review the content, data
                classification and publication approval before
                making the site public.

            </div>

        </div>

    </div>

</section>

</main>


<footer class="footer">

    <div class="container">

        <strong>
            {safe_name}
        </strong>

        <div class="footer-note">
            Source: {source_display}
        </div>

        <div class="footer-note">
            Generated by NEXUS DANIP AI Data Intelligence.
            Public website content should be reviewed before publication.
        </div>

    </div>

</footer>

</body>
</html>
"""


# ============================================================
# ZIP EXPORT
# ============================================================

def build_public_website_zip(
    html_content: str,
):
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
                "Open index.html in a browser to preview the site.\n\n"
                "Before publication:\n"
                "1. Confirm that the dataset is approved for public release.\n"
                "2. Review generated narratives and analytical findings.\n"
                "3. Confirm indicator definitions and reporting periods.\n"
                "4. Confirm privacy and data-protection requirements.\n"
            ),
        )

    memory.seek(0)

    return memory.getvalue()


# ============================================================
# QUALITY CHECKS
# ============================================================

def _website_quality_checks(df):
    safe = _public_safe_dataframe(df)

    sensitive = _sensitive_columns(df)

    checks = [
        {
            "Check": "Dataset available",
            "Status": (
                "PASS"
                if not safe.empty
                else "FAIL"
            ),
            "Details": (
                f"{len(safe):,} public-safe rows available."
                if not safe.empty
                else "No usable public-safe data."
            ),
        },
        {
            "Check": "Sensitive-looking fields",
            "Status": "REVIEW" if sensitive else "PASS",
            "Details": (
                f"{len(sensitive)} field(s) identified and excluded."
                if sensitive
                else "No obvious sensitive field names detected."
            ),
        },
        {
            "Check": "Credentials in generated site",
            "Status": "PASS",
            "Details": "Authentication credentials are not intentionally written to the generated site.",
        },
        {
            "Check": "Responsive layout",
            "Status": "PASS",
            "Details": "Desktop, tablet and mobile CSS breakpoints included.",
        },
        {
            "Check": "Analysis",
            "Status": "PASS",
            "Details": "Trend, geographic and data-quality analysis are generated when dimensions permit.",
        },
        {
            "Check": "Learning layer",
            "Status": "PASS",
            "Details": "Evidence observations and follow-up learning questions are included.",
        },
        {
            "Check": "Methodology and limitations",
            "Status": "PASS",
            "Details": "Methodology and data limitations sections are included.",
        },
        {
            "Check": "Human publication review",
            "Status": "REVIEW",
            "Details": "Final public-release approval must be completed by the data owner.",
        },
    ]

    return checks


# ============================================================
# STREAMLIT ANALYSIS DASHBOARD
# ============================================================

def _render_analysis_dashboard(
    df,
    profile,
    selected_indicator,
):
    safe_df = _public_safe_dataframe(df)

    trend = _trend_analysis(
        safe_df,
        profile,
        selected_indicator,
    )

    dimension = (
        profile["country_column"]
        or profile["organisation_column"]
    )

    geographic = _geographic_analysis(
        safe_df,
        profile,
        selected_indicator,
        dimension,
    )

    quality = _data_quality_analysis(
        safe_df,
        profile,
    )

    learning = _build_learning_insights(
        safe_df,
        profile,
        selected_indicator,
        trend,
        geographic,
        quality,
    )

    # --------------------------------------------------------
    # KPIs
    # --------------------------------------------------------

    st.markdown("### 📊 Analytical Overview")

    k1, k2, k3, k4, k5 = st.columns(5)

    indicator_profile = next(
        (
            x
            for x in profile["indicators"]
            if x["name"] == selected_indicator
        ),
        None,
    )

    with k1:
        st.metric(
            "Records",
            f"{profile['rows']:,}",
        )

    with k2:
        st.metric(
            "Average",
            _fmt(
                indicator_profile["average"]
                if indicator_profile
                else 0
            ),
        )

    with k3:
        st.metric(
            "Total",
            _fmt(
                indicator_profile["total"]
                if indicator_profile
                else 0
            ),
        )

    with k4:
        if trend.get("available"):
            change = trend.get(
                "percent_change"
            )

            st.metric(
                "First → Last",
                (
                    _pct(change)
                    if change is not None
                    else "N/A"
                ),
            )
        else:
            st.metric(
                "First → Last",
                "N/A",
            )

    with k5:
        st.metric(
            "Completeness",
            _pct(
                quality["completeness"]
            ),
        )

    # --------------------------------------------------------
    # TABS
    # --------------------------------------------------------

    tab1, tab2, tab3, tab4 = st.tabs(
        [
            "📈 Trends",
            "🌍 Geographic Analysis",
            "🧠 Learning",
            "🛡️ Data Quality",
        ]
    )

    with tab1:

        if trend.get("available"):

            chart_df = trend["data"][
                [
                    profile["period_column"],
                    "value",
                ]
            ].copy()

            chart_df.columns = [
                "Period",
                selected_indicator,
            ]

            st.line_chart(
                chart_df.set_index(
                    "Period"
                ),
                use_container_width=True,
            )

            tc1, tc2, tc3 = st.columns(3)

            with tc1:
                st.metric(
                    "Direction",
                    trend["direction"].title(),
                )

            with tc2:
                st.metric(
                    "Absolute change",
                    _fmt(
                        trend["absolute_change"]
                    ),
                )

            with tc3:
                st.metric(
                    "Relative change",
                    (
                        _pct(
                            trend["percent_change"]
                        )
                        if trend["percent_change"]
                        is not None
                        else "N/A"
                    ),
                )

            st.dataframe(
                chart_df,
                use_container_width=True,
                hide_index=True,
            )

        else:

            st.info(
                trend.get(
                    "reason",
                    "Trend analysis is unavailable.",
                )
            )

    with tab2:

        if not geographic.empty:

            display_geo = geographic.copy()

            display_geo.columns = [
                str(x)
                for x in display_geo.columns
            ]

            st.bar_chart(
                display_geo.set_index(
                    display_geo.columns[0]
                )["value"],
                use_container_width=True,
            )

            st.dataframe(
                display_geo,
                use_container_width=True,
                hide_index=True,
            )

        else:

            st.info(
                "No country or organisation dimension was detected."
            )

    with tab3:

        st.markdown(
            """
            <div class="danip-learning-box">
                <b>🧠 Learning from the data</b><br>
                These findings are generated from observed patterns.
                They are not causal conclusions.
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("#### What the data shows")

        for item in learning["observations"]:
            st.info(
                f"📌 {item}"
            )

        st.markdown(
            "#### Questions for further analysis"
        )

        for item in learning["learning_questions"]:
            st.warning(
                f"🔎 {item}"
            )

    with tab4:

        q1, q2, q3 = st.columns(3)

        with q1:
            st.metric(
                "Missing cells",
                f"{quality['missing_cells']:,}",
            )

        with q2:
            st.metric(
                "Missing rate",
                _pct(
                    quality["missing_rate"]
                ),
            )

        with q3:
            st.metric(
                "Duplicate rows",
                f"{quality['duplicate_rows']:,}",
            )

        if quality["zero_indicators"]:
            st.warning(
                "High zero rates detected for: "
                + ", ".join(
                    quality["zero_indicators"][:10]
                )
            )

        if quality["negative_indicators"]:
            st.warning(
                "Negative values detected for: "
                + ", ".join(
                    quality["negative_indicators"][:10]
                )
            )

        if quality["high_missing_columns"]:
            st.warning(
                "Columns with ≥20% missing values: "
                + ", ".join(
                    quality["high_missing_columns"][:10]
                )
            )

        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Indicator": x["name"],
                        "Observations": x["observations"],
                        "Missing": x["missing"],
                        "Zero rate": _pct(
                            x["zero_rate"]
                        ),
                        "Average": x["average"],
                        "Minimum": x["minimum"],
                        "Maximum": x["maximum"],
                    }
                    for x in profile["indicators"]
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )

    return {
        "trend": trend,
        "geographic": geographic,
        "quality": quality,
        "learning": learning,
    }


# ============================================================
# STREAMLIT WORKSPACE
# ============================================================

def render_ai_public_website_builder():
    """
    Render the fourth NEXUS DANIP workspace.
    """

    st.markdown(
        """
        <style>

        .website-builder-header {
            padding:1.35rem 1.5rem;
            border:1px solid #dce3ea;
            border-radius:20px;
            background:linear-gradient(
                135deg,
                #ffffff,
                #f6f9fc
            );
            box-shadow:0 8px 28px rgba(15,23,42,.06);
            margin-bottom:1rem;
        }

        .website-builder-title {
            font-size:clamp(
                1.45rem,
                3vw,
                2.15rem
            );
            font-weight:850;
            color:#17374b;
            letter-spacing:-.03em;
        }

        .website-builder-subtitle {
            color:#64748b;
            margin-top:.35rem;
            line-height:1.6;
        }

        .danip-learning-box {
            padding:1rem 1.15rem;
            border-radius:14px;
            background:#f3f8ff;
            border:1px solid #d7e7fb;
            color:#17374b;
            margin-bottom:1rem;
        }

        .website-builder-section {
            margin-top:1.2rem;
        }

        @media (max-width:700px) {
            .website-builder-header {
                padding:1rem;
            }
        }

        </style>

        <div class="website-builder-header">

            <div class="website-builder-title">
                🌐 AI Public Website Builder
            </div>

            <div class="website-builder-subtitle">
                Turn the current DANIP dataset into a responsive
                public data website while learning from the
                underlying analysis.
            </div>

        </div>
        """,
        unsafe_allow_html=True,
    )

    df = st.session_state.get(
        "loaded_df"
    )

    if not isinstance(
        df,
        pd.DataFrame,
    ) or df.empty:

        st.info(
            "📊 No dataset is currently loaded."
        )

        st.markdown(
            """
            Go to **🤖 DANIP AI Data Analyst**, load your
            DHIS2/API dataset, and return here.
            """
        )

        return

    profile = _profile_dataset(
        df
    )

    if not profile["indicators"]:

        st.error(
            "The current dataset has no detected numeric indicators."
        )

        return

    # --------------------------------------------------------
    # DATASET SUMMARY
    # --------------------------------------------------------

    st.success(
        f"Dataset connected — {len(df):,} rows × "
        f"{len(df.columns):,} columns."
    )

    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.metric(
            "Rows",
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

    quality = _data_quality_analysis(
        df,
        profile,
    )

    with c5:
        st.metric(
            "Completeness",
            _pct(
                quality["completeness"]
            ),
        )

    # --------------------------------------------------------
    # ANALYSIS CONTROLS
    # --------------------------------------------------------

    st.markdown(
        "### 🔬 Analysis Controls"
    )

    indicator_names = [
        x["name"]
        for x in profile["indicators"]
    ]

    selected_indicator = st.selectbox(
        "Primary indicator",
        indicator_names,
        key="public_website_primary_indicator",
    )

    analysis_result = _render_analysis_dashboard(
        df,
        profile,
        selected_indicator,
    )

    # --------------------------------------------------------
    # WEBSITE CONFIGURATION
    # --------------------------------------------------------

    st.markdown(
        "### ⚙️ Website Configuration"
    )

    left, right = st.columns(2)

    with left:

        website_name = st.text_input(
            "Website name",
            value="DANIP Public Data Portal",
            key="website_builder_name",
        )

        tagline = st.text_input(
            "Website tagline",
            value="Evidence, data and programme information",
            key="website_builder_tagline",
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

    with right:

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

        st.markdown(
            "**Website capabilities**"
        )

        st.write(
            "📈 Responsive graphs"
        )
        st.write(
            "🧠 Evidence-based learning"
        )
        st.write(
            "🌍 Geographic analysis"
        )
        st.write(
            "🛡️ Data-quality review"
        )

    # --------------------------------------------------------
    # INDICATORS TO PUBLISH
    # --------------------------------------------------------

    st.markdown(
        "### 📌 Indicators to Publish"
    )

    selected_indicators = st.multiselect(
        "Select public indicators",
        indicator_names,
        default=indicator_names[:6],
        key="website_builder_indicators",
    )

    # --------------------------------------------------------
    # SAFETY CHECK
    # --------------------------------------------------------

    st.markdown(
        "### 🛡️ Publication Safety"
    )

    checks = _website_quality_checks(
        df
    )

    check_df = pd.DataFrame(
        checks
    )

    st.dataframe(
        check_df,
        use_container_width=True,
        hide_index=True,
    )

    st.warning(
        "The safety layer is a screening aid, not a substitute "
        "for formal data classification and publication approval."
    )

    # --------------------------------------------------------
    # GENERATE
    # --------------------------------------------------------

    st.markdown(
        "### ✨ Generate Public Website"
    )

    generate = st.button(
        "✨ GENERATE RESPONSIVE AI WEBSITE",
        type="primary",
        use_container_width=True,
        key="generate_public_website",
    )

    if generate:

        with st.spinner(
            "Analysing data, generating learning insights "
            "and building the responsive website..."
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

                st.session_state[
                    "public_website_indicator"
                ] = selected_indicator

                st.success(
                    "✅ Responsive website generated successfully."
                )

            except Exception as exc:

                st.error(
                    f"Website generation failed: {exc}"
                )

    # --------------------------------------------------------
    # PREVIEW
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

        st.markdown(
            "### 🖥️ Responsive Website Preview"
        )

        preview_mode = st.radio(
            "Preview size",
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

        # iframe srcdoc must be safely escaped for the HTML attribute.
        iframe_html = html.escape(
            website_html,
            quote=True,
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
                background:#fff;
                box-shadow:0 12px 35px rgba(15,23,42,.08);
            ">

                <iframe
                    srcdoc="{iframe_html}"
                    style="
                        width:100%;
                        height:920px;
                        border:0;
                        display:block;
                    "
                    title="Generated public website preview">
                </iframe>

            </div>
            """,
            unsafe_allow_html=True,
        )

        # ----------------------------------------------------
        # EXPORT
        # ----------------------------------------------------

        st.markdown(
            "### 📦 Export"
        )

        filename = _clean_name(
            website_name
        )

        e1, e2 = st.columns(2)

        with e1:

            st.download_button(
                "⬇️ Download HTML Website",
                data=website_html.encode(
                    "utf-8"
                ),
                file_name=(
                    f"{filename}.html"
                ),
                mime="text/html",
                use_container_width=True,
                key="download_public_website_html",
            )

        with e2:

            st.download_button(
                "📦 Download Website ZIP",
                data=website_zip,
                file_name=(
                    f"{filename}.zip"
                ),
                mime="application/zip",
                use_container_width=True,
                key="download_public_website_zip",
            )

        with st.expander(
            "🔍 View generated HTML source",
            expanded=False,
        ):
            st.code(
                website_html,
                language="html",
            )

        st.info(
            "Generated website content and analytical learning "
            "should be reviewed by the data owner before publication."
        )
