"""
DANIP - My Reports & Monitoring
--------------------------------
Separate authenticated-user reporting workspace.

Analytical model:
    X = Report Period
    Series = Organisation Name
    Y = Indicator value

Core grain:
    Report Period × Organisation Name × Indicator

This module intentionally does not create a second authentication system.
It reads the authenticated-user information already stored by the main
DANIP OAuth2 application and never displays/stores Bearer tokens.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import html
import math

import pandas as pd
import streamlit as st


# ---------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------

_CSS = """
<style>
.danip-report-shell {
    padding: 4px 0 28px 0;
}
.danip-report-title {
    font-size: 34px;
    font-weight: 800;
    color: #17374b;
    margin-bottom: 4px;
}
.danip-report-subtitle {
    color: #5d7185;
    font-size: 15px;
    margin-bottom: 22px;
}
.danip-user-card {
    border: 1px solid #d9e2ea;
    border-radius: 14px;
    padding: 18px 20px;
    background: #ffffff;
    box-shadow: 0 5px 18px rgba(23,55,75,.07);
    margin-bottom: 18px;
}
.danip-kpi {
    border: 1px solid #d9e2ea;
    border-radius: 14px;
    padding: 16px 18px;
    background: #ffffff;
    min-height: 112px;
    box-shadow: 0 5px 18px rgba(23,55,75,.05);
}
.danip-kpi-label {
    font-size: 12px;
    color: #6b7c8d;
    text-transform: uppercase;
    letter-spacing: .04em;
    font-weight: 700;
}
.danip-kpi-value {
    font-size: 27px;
    color: #17374b;
    font-weight: 800;
    margin-top: 7px;
}
.danip-section {
    font-size: 21px;
    color: #17374b;
    font-weight: 800;
    margin: 22px 0 10px 0;
}
.danip-report-note {
    border-left: 4px solid #17374b;
    background: #f4f7f9;
    padding: 12px 15px;
    border-radius: 7px;
    color: #34495e;
    margin: 12px 0 18px 0;
}
.danip-private-badge {
    display: inline-block;
    padding: 5px 9px;
    border-radius: 999px;
    background: #edf3f7;
    color: #17374b;
    font-weight: 700;
    font-size: 12px;
}
</style>
"""


# ---------------------------------------------------------------------
# Authentication context
# ---------------------------------------------------------------------

def _is_user_mapping(value: Any) -> bool:
    return isinstance(value, dict) and any(
        key in value
        for key in (
            "username",
            "userName",
            "displayName",
            "displayname",
            "name",
            "email",
            "emailAddress",
        )
    )


def _get_authenticated_user() -> Dict[str, str]:
    """
    Find the existing authenticated DHIS2/OAuth user in session state.

    No token fields are returned or displayed.

    If your app uses a specific session-state key, add it to the preferred
    keys below. The function also checks common nested user objects.
    """
    preferred_keys = (
        "dhis2_user",
        "authenticated_user",
        "auth_user",
        "oauth_user",
        "user_info",
        "current_user",
        "me",
        "user",
    )

    candidate = None

    for key in preferred_keys:
        value = st.session_state.get(key)
        if _is_user_mapping(value):
            candidate = value
            break

    if candidate is None:
        for _, value in st.session_state.items():
            if _is_user_mapping(value):
                candidate = value
                break

    if candidate is None:
        return {}

    username = (
        candidate.get("username")
        or candidate.get("userName")
        or candidate.get("user")
        or ""
    )
    display_name = (
        candidate.get("displayName")
        or candidate.get("displayname")
        or candidate.get("name")
        or username
        or "Authenticated user"
    )
    email = (
        candidate.get("email")
        or candidate.get("emailAddress")
        or ""
    )

    return {
        "username": str(username),
        "display_name": str(display_name),
        "email": str(email),
    }


# ---------------------------------------------------------------------
# Column detection
# ---------------------------------------------------------------------

def _normalise_column_name(value: Any) -> str:
    return (
        str(value)
        .strip()
        .lower()
        .replace(" ", "")
        .replace("_", "")
        .replace("-", "")
    )


def _find_column(
    df: pd.DataFrame,
    aliases: list[str],
) -> Optional[str]:
    normalised = {
        _normalise_column_name(column): column
        for column in df.columns
    }

    for alias in aliases:
        key = _normalise_column_name(alias)
        if key in normalised:
            return normalised[key]

    # Slightly broader fallback.
    for column in df.columns:
        n = _normalise_column_name(column)
        for alias in aliases:
            a = _normalise_column_name(alias)
            if a and (a in n or n in a):
                return column

    return None


def _detect_columns(df: pd.DataFrame) -> Dict[str, Optional[str]]:
    period_col = _find_column(
        df,
        [
            "Report Period",
            "Period Name",
            "Period",
            "periodname",
            "period",
            "reportperiod",
            "period_id",
            "periodid",
        ],
    )

    org_col = _find_column(
        df,
        [
            "Organisation Name",
            "Organization Name",
            "OrganisationUnitName",
            "Organisation Unit Name",
            "OrganizationUnitName",
            "Organization Unit Name",
            "Org Unit Name",
            "OrgUnitName",
            "OU Name",
            "Organisation",
            "Organization",
        ],
    )

    indicator_col = _find_column(
        df,
        [
            "Indicator",
            "Indicator Name",
            "Indicator name",
            "Data Element",
            "Data Element Name",
            "IndicatorID",
            "Indicator Id",
            "dx",
        ],
    )

    value_col = _find_column(
        df,
        [
            "Value",
            "Indicator Value",
            "Numeric Value",
            "Value Numeric",
            "value",
            "numericvalue",
            "value_numeric",
        ],
    )

    return {
        "period": period_col,
        "organisation": org_col,
        "indicator": indicator_col,
        "value": value_col,
    }


# ---------------------------------------------------------------------
# Data preparation
# ---------------------------------------------------------------------

def _coerce_numeric(series: pd.Series) -> pd.Series:
    return pd.to_numeric(
        series.astype(str).str.replace(",", "", regex=False).str.strip(),
        errors="coerce",
    )


def _period_key(value: Any) -> tuple:
    """
    Sort periods chronologically where possible.
    """
    text = str(value).strip()
    parsed = pd.to_datetime(text, errors="coerce")

    if not pd.isna(parsed):
        return (0, parsed.to_pydatetime())

    # Handle common DHIS2 monthly forms such as 2026M03.
    upper = text.upper().replace(" ", "")
    if "M" in upper:
        try:
            year, month = upper.split("M", 1)
            if len(year) == 4 and month.isdigit():
                return (0, datetime(int(year), int(month), 1))
        except Exception:
            pass

    return (1, text.lower())


def _sorted_periods(values: list[Any]) -> list[str]:
    unique = []
    seen = set()

    for value in values:
        if pd.isna(value):
            continue
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            unique.append(text)

    return sorted(unique, key=_period_key)


def _prepare_data(
    df: pd.DataFrame,
    columns: Dict[str, Optional[str]],
) -> pd.DataFrame:
    period_col = columns["period"]
    org_col = columns["organisation"]
    indicator_col = columns["indicator"]
    value_col = columns["value"]

    if not all((period_col, org_col, indicator_col, value_col)):
        return pd.DataFrame()

    work = df[
        [period_col, org_col, indicator_col, value_col]
    ].copy()

    work = work.rename(
        columns={
            period_col: "Report Period",
            org_col: "Organisation Name",
            indicator_col: "Indicator",
            value_col: "Value",
        }
    )

    work["Report Period"] = work["Report Period"].astype(str).str.strip()
    work["Organisation Name"] = (
        work["Organisation Name"].astype(str).str.strip()
    )
    work["Indicator"] = work["Indicator"].astype(str).str.strip()
    work["Value"] = _coerce_numeric(work["Value"])

    work = work[
        (work["Report Period"] != "")
        & (work["Organisation Name"] != "")
        & (work["Indicator"] != "")
        & work["Value"].notna()
    ].copy()

    return work


def _apply_filters(
    data: pd.DataFrame,
    indicator: str,
    organisation: str,
) -> pd.DataFrame:
    result = data.copy()

    if indicator != "All indicators":
        result = result[result["Indicator"] == indicator]

    if organisation != "All organisations":
        result = result[result["Organisation Name"] == organisation]

    return result


# ---------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------

def _latest_period(data: pd.DataFrame) -> Optional[str]:
    periods = _sorted_periods(data["Report Period"].tolist())
    return periods[-1] if periods else None


def _previous_period(
    data: pd.DataFrame,
    latest: Optional[str],
) -> Optional[str]:
    if not latest:
        return None

    periods = _sorted_periods(data["Report Period"].tolist())
    if latest not in periods:
        return None

    index = periods.index(latest)
    if index <= 0:
        return None

    return periods[index - 1]


def _format_number(value: Any) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "—"

    try:
        number = float(value)
    except Exception:
        return str(value)

    if number.is_integer():
        return f"{int(number):,}"
    return f"{number:,.2f}"


def _build_report_summary(
    data: pd.DataFrame,
    indicator: str,
    organisation: str,
    frequency: str,
) -> Dict[str, Any]:
    filtered = _apply_filters(data, indicator, organisation)

    latest = _latest_period(filtered)
    previous = _previous_period(filtered, latest)

    latest_df = (
        filtered[filtered["Report Period"] == latest]
        if latest
        else filtered.iloc[0:0]
    )

    previous_df = (
        filtered[filtered["Report Period"] == previous]
        if previous
        else filtered.iloc[0:0]
    )

    latest_total = float(latest_df["Value"].sum()) if not latest_df.empty else 0
    previous_total = (
        float(previous_df["Value"].sum())
        if not previous_df.empty
        else None
    )

    change = None
    if previous_total is not None:
        change = latest_total - previous_total

    return {
        "frequency": frequency,
        "latest_period": latest,
        "previous_period": previous,
        "latest_total": latest_total,
        "previous_total": previous_total,
        "change": change,
        "rows": len(filtered),
        "organisations": filtered["Organisation Name"].nunique(),
        "indicators": filtered["Indicator"].nunique(),
    }


def _learning_text(
    data: pd.DataFrame,
    indicator: str,
    organisation: str,
) -> list[str]:
    """
    Evidence-first observations from the same
    Report Period × Organisation × Indicator grain.
    """
    filtered = _apply_filters(data, indicator, organisation)

    if filtered.empty:
        return ["No observations are available for the selected filters."]

    observations = []

    latest = _latest_period(filtered)
    previous = _previous_period(filtered, latest)

    if latest:
        latest_df = filtered[filtered["Report Period"] == latest]

        if not latest_df.empty:
            latest_total = latest_df["Value"].sum()
            observations.append(
                f"Latest reported period: {latest}. "
                f"Reported value across the selected records: "
                f"{_format_number(latest_total)}."
            )

            org_values = (
                latest_df.groupby("Organisation Name", as_index=False)["Value"]
                .sum()
                .sort_values("Value", ascending=False)
            )

            if len(org_values) > 0:
                top = org_values.iloc[0]
                observations.append(
                    f"At {latest}, "
                    f"{top['Organisation Name']} has the highest reported "
                    f"value among the selected organisation series: "
                    f"{_format_number(top['Value'])}."
                )

    if previous and latest:
        latest_total = filtered[
            filtered["Report Period"] == latest
        ]["Value"].sum()
        previous_total = filtered[
            filtered["Report Period"] == previous
        ]["Value"].sum()

        change = latest_total - previous_total

        if change > 0:
            direction = "increased"
        elif change < 0:
            direction = "decreased"
        else:
            direction = "did not change"

        observations.append(
            f"Compared with {previous}, the selected reported value "
            f"{direction} by {_format_number(abs(change))}."
        )

    observations.append(
        "The analysis uses Report Period as X, Organisation Name as the "
        "series dimension, and the selected indicator value as Y."
    )

    return observations


def _make_chart_data(
    data: pd.DataFrame,
    indicator: str,
    organisation: str,
) -> pd.DataFrame:
    filtered = _apply_filters(data, indicator, organisation)

    if filtered.empty:
        return pd.DataFrame()

    chart = (
        filtered.groupby(
            ["Report Period", "Organisation Name"],
            as_index=False,
        )["Value"]
        .sum()
    )

    periods = _sorted_periods(chart["Report Period"].tolist())
    order = {period: index for index, period in enumerate(periods)}

    chart["_period_order"] = chart["Report Period"].map(order)
    chart = chart.sort_values(
        ["_period_order", "Organisation Name"]
    ).drop(columns=["_period_order"])

    return chart


# ---------------------------------------------------------------------
# Main renderer
# ---------------------------------------------------------------------

def render_my_reports_monitoring() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)

    st.markdown(
        '<div class="danip-report-shell">'
        '<div class="danip-report-title">📅 My Reports & Monitoring</div>'
        '<div class="danip-report-subtitle">'
        "Private daily and weekly reporting for the authenticated user."
        "</div></div>",
        unsafe_allow_html=True,
    )

    # ---------------------------------------------------------------
    # Authenticated user
    # ---------------------------------------------------------------

    user = _get_authenticated_user()

    if not user:
        st.warning(
            "No authenticated user profile was found in the current "
            "session. Please sign in through the existing DHIS2 OAuth2 "
            "gateway before using My Reports & Monitoring."
        )
        return

    display_name = user.get("display_name") or "Authenticated user"
    username = user.get("username") or "—"
    email = user.get("email") or "—"

    st.markdown(
        f"""
        <div class="danip-user-card">
            <span class="danip-private-badge">🔒 PRIVATE USER REPORT</span>
            <h3 style="margin:10px 0 4px 0;color:#17374b;">
                {html.escape(display_name)}
            </h3>
            <div style="color:#5d7185;">
                Username: <strong>{html.escape(username)}</strong>
                &nbsp; | &nbsp;
                Email: <strong>{html.escape(email)}</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ---------------------------------------------------------------
    # Dataset
    # ---------------------------------------------------------------

    df = st.session_state.get("loaded_df")

    if not isinstance(df, pd.DataFrame) or df.empty:
        st.info(
            "Load a dataset first. My Reports & Monitoring uses the "
            "dataset already loaded by the DANIP application."
        )
        return

    columns = _detect_columns(df)
    data = _prepare_data(df, columns)

    missing = [
        label
        for label, key in (
            ("Report Period", "period"),
            ("Organisation Name", "organisation"),
            ("Indicator", "indicator"),
            ("Indicator value", "value"),
        )
        if not columns.get(key)
    ]

    if missing:
        st.error(
            "The reporting model requires these fields: "
            + ", ".join(missing)
            + "."
        )
        st.caption(
            "Required analytical grain: "
            "Report Period × Organisation Name × Indicator."
        )
        return

    if data.empty:
        st.warning(
            "The dataset contains the required columns, but no valid "
            "numeric observations were found."
        )
        return

    # ---------------------------------------------------------------
    # Frequency
    # ---------------------------------------------------------------

    st.markdown(
        '<div class="danip-section">⚙️ Reporting Preferences</div>',
        unsafe_allow_html=True,
    )

    frequency = st.radio(
        "Report frequency",
        ["Daily", "Weekly"],
        horizontal=True,
        index=1,
        key="my_reports_frequency",
    )

    st.caption(
        f"{frequency} reporting is calculated from the currently loaded "
        "dataset. This page does not create a second authentication system."
    )

    # ---------------------------------------------------------------
    # Selectors: ALL by default
    # ---------------------------------------------------------------

    indicators = sorted(
        data["Indicator"].dropna().astype(str).unique().tolist()
    )
    organisations = sorted(
        data["Organisation Name"].dropna().astype(str).unique().tolist()
    )

    selected_indicator = st.selectbox(
        "Primary Indicator",
        ["All indicators"] + indicators,
        index=0,
        key="my_reports_indicator",
    )

    selected_organisation = st.selectbox(
        "Organisation Name",
        ["All organisations"] + organisations,
        index=0,
        key="my_reports_organisation",
    )

    st.markdown(
        '<div class="danip-report-note">'
        "<strong>Analytical model:</strong> "
        "X = Report Period · Series = Organisation Name · "
        "Y = Indicator value. "
        "All organisations remain separate series; they are not combined "
        "into one organisation."
        "</div>",
        unsafe_allow_html=True,
    )

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------

    summary = _build_report_summary(
        data,
        selected_indicator,
        selected_organisation,
        frequency,
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.markdown(
            f"""
            <div class="danip-kpi">
                <div class="danip-kpi-label">Latest period</div>
                <div class="danip-kpi-value">
                    {html.escape(str(summary["latest_period"] or "—"))}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            f"""
            <div class="danip-kpi">
                <div class="danip-kpi-label">Reported value</div>
                <div class="danip-kpi-value">
                    {_format_number(summary["latest_total"])}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c3:
        st.markdown(
            f"""
            <div class="danip-kpi">
                <div class="danip-kpi-label">Organisations</div>
                <div class="danip-kpi-value">
                    {summary["organisations"]:,}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c4:
        st.markdown(
            f"""
            <div class="danip-kpi">
                <div class="danip-kpi-label">Observations</div>
                <div class="danip-kpi-value">
                    {summary["rows"]:,}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ---------------------------------------------------------------
    # Trend
    # ---------------------------------------------------------------

    st.markdown(
        '<div class="danip-section">📈 Report Period Analysis</div>',
        unsafe_allow_html=True,
    )

    chart = _make_chart_data(
        data,
        selected_indicator,
        selected_organisation,
    )

    if chart.empty:
        st.info("No data is available for the selected filters.")
    else:
        pivot = chart.pivot_table(
            index="Report Period",
            columns="Organisation Name",
            values="Value",
            aggfunc="sum",
        )

        periods = _sorted_periods(pivot.index.tolist())
        pivot = pivot.reindex(periods)

        st.line_chart(pivot, use_container_width=True)

        st.caption(
            "X-axis: Report Period · Series: Organisation Name · "
            "Y-axis: Indicator value"
        )

    # ---------------------------------------------------------------
    # Latest organisation comparison
    # ---------------------------------------------------------------

    st.markdown(
        '<div class="danip-section">🏢 Organisation Comparison</div>',
        unsafe_allow_html=True,
    )

    latest = summary["latest_period"]

    if latest:
        latest_org = _apply_filters(
            data,
            selected_indicator,
            selected_organisation,
        )
        latest_org = latest_org[
            latest_org["Report Period"] == latest
        ]

        latest_org = (
            latest_org.groupby("Organisation Name", as_index=False)["Value"]
            .sum()
            .sort_values("Value", ascending=False)
        )

        if not latest_org.empty:
            st.bar_chart(
                latest_org.set_index("Organisation Name")["Value"],
                use_container_width=True,
            )
            st.caption(
                f"Latest reported period: {latest}. "
                "Y = indicator value; X = Organisation Name."
            )

    # ---------------------------------------------------------------
    # AI/evidence learning
    # ---------------------------------------------------------------

    st.markdown(
        '<div class="danip-section">🧠 Report Learning & Insights</div>',
        unsafe_allow_html=True,
    )

    insights = _learning_text(
        data,
        selected_indicator,
        selected_organisation,
    )

    for insight in insights:
        st.write(f"• {insight}")

    # ---------------------------------------------------------------
    # Analytical table
    # ---------------------------------------------------------------

    st.markdown(
        '<div class="danip-section">📋 Analytical Data</div>',
        unsafe_allow_html=True,
    )

    analytical = _apply_filters(
        data,
        selected_indicator,
        selected_organisation,
    )

    analytical = (
        analytical.groupby(
            ["Report Period", "Organisation Name", "Indicator"],
            as_index=False,
        )["Value"]
        .sum()
    )

    periods = _sorted_periods(analytical["Report Period"].tolist())
    order = {period: i for i, period in enumerate(periods)}

    analytical["_sort"] = analytical["Report Period"].map(order)
    analytical = (
        analytical.sort_values(
            ["_sort", "Organisation Name", "Indicator"]
        )
        .drop(columns="_sort")
        .reset_index(drop=True)
    )

    st.dataframe(
        analytical,
        use_container_width=True,
        hide_index=True,
    )

    # ---------------------------------------------------------------
    # Export
    # ---------------------------------------------------------------

    csv_data = analytical.to_csv(index=False).encode("utf-8")

    st.download_button(
        "⬇️ Export My Report Data",
        data=csv_data,
        file_name=(
            "danip_daily_report.csv"
            if frequency == "Daily"
            else "danip_weekly_report.csv"
        ),
        mime="text/csv",
        key="my_reports_export",
    )

    # ---------------------------------------------------------------
    # Status
    # ---------------------------------------------------------------

    st.markdown(
        '<div class="danip-section">🕒 Report Status</div>',
        unsafe_allow_html=True,
    )

    if frequency == "Daily":
        st.info(
            "Daily report view is active. The report is refreshed whenever "
            "the dashboard data is refreshed."
        )
    else:
        st.info(
            "Weekly report view is active. The report is refreshed whenever "
            "the dashboard data is refreshed."
        )

    st.caption(
        "This module provides the reporting view inside Streamlit. "
        "For unattended email delivery on a fixed daily/weekly schedule, "
        "a persistent scheduler/backend should be added separately."
    )
