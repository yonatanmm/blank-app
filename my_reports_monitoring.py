"""
DANIP - My Reports & Monitoring
--------------------------------
System-wide reporting and usage-monitoring workspace.

Analytical model:
    X = Report Period
    Series = Organisation Name
    Y = Indicator value

Core grain:
    Report Period × Organisation Name × Indicator

Usage model:
    ALL authenticated DHIS2/OAuth2 users
    Session duration = session_start -> last_activity/session_end
    Persistent storage = PostgreSQL when configured
    Streamlit session state is used only for the current session.

Authentication:
    This module does not create a second authentication system.
    It reads the authenticated-user information already established by
    the main DANIP OAuth2 application and never stores/displays Bearer tokens.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import html
import math
import os

import pandas as pd
import streamlit as st

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except Exception:
    psycopg2 = None
    RealDictCursor = None


# ---------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------

_CSS = """
<style>
.danip-report-shell { padding:4px 0 28px 0; }
.danip-report-title {
    font-size:34px; font-weight:800; color:#17374b; margin-bottom:4px;
}
.danip-report-subtitle {
    color:#5d7185; font-size:15px; margin-bottom:22px;
}
.danip-user-card, .danip-kpi, .danip-panel {
    border:1px solid #d9e2ea; border-radius:14px; background:#fff;
    box-shadow:0 5px 18px rgba(23,55,75,.06);
}
.danip-user-card { padding:18px 20px; margin-bottom:18px; }
.danip-kpi { padding:16px 18px; min-height:112px; }
.danip-kpi-label {
    font-size:12px; color:#6b7c8d; text-transform:uppercase;
    letter-spacing:.04em; font-weight:700;
}
.danip-kpi-value {
    font-size:27px; color:#17374b; font-weight:800; margin-top:7px;
}
.danip-section {
    font-size:21px; color:#17374b; font-weight:800; margin:22px 0 10px 0;
}
.danip-report-note {
    border-left:4px solid #17374b; background:#f4f7f9; padding:12px 15px;
    border-radius:7px; color:#34495e; margin:12px 0 18px 0;
}
.danip-private-badge {
    display:inline-block; padding:5px 9px; border-radius:999px;
    background:#edf3f7; color:#17374b; font-weight:700; font-size:12px;
}
.danip-system-badge {
    display:inline-block; padding:5px 9px; border-radius:999px;
    background:#eaf5ed; color:#245b36; font-weight:700; font-size:12px;
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
            "username", "userName", "displayName", "displayname",
            "name", "email", "emailAddress", "id", "user_id", "uid"
        )
    )


def _get_authenticated_user() -> Dict[str, str]:
    """Read the existing authenticated-user profile without exposing tokens."""
    preferred_keys = (
        "dhis2_user", "authenticated_user", "auth_user", "oauth_user",
        "user_info", "current_user", "me", "user"
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
    user_id = (
        candidate.get("id")
        or candidate.get("user_id")
        or candidate.get("uid")
        or candidate.get("userId")
        or username
        or ""
    )
    display_name = (
        candidate.get("displayName")
        or candidate.get("displayname")
        or candidate.get("name")
        or username
        or "Authenticated user"
    )
    email = candidate.get("email") or candidate.get("emailAddress") or ""

    return {
        "user_id": str(user_id),
        "username": str(username),
        "display_name": str(display_name),
        "email": str(email),
    }


# ---------------------------------------------------------------------
# PostgreSQL configuration
# ---------------------------------------------------------------------

def _get_database_url() -> Optional[str]:
    """Read a PostgreSQL URL from Streamlit secrets or environment."""
    keys = (
        "DANIP_DATABASE_URL",
        "DATABASE_URL",
        "POSTGRES_URL",
        "POSTGRESQL_URL",
    )

    for key in keys:
        try:
            value = st.secrets.get(key)
            if value:
                return str(value)
        except Exception:
            pass

    for key in keys:
        value = os.getenv(key)
        if value:
            return str(value)

    return None


def _db_connect():
    """Return a PostgreSQL connection or None when PostgreSQL is unavailable."""
    if psycopg2 is None:
        return None

    database_url = _get_database_url()
    if not database_url:
        return None

    try:
        return psycopg2.connect(database_url, connect_timeout=5)
    except Exception:
        return None


def _ensure_usage_table() -> bool:
    """Create the persistent system-wide usage table if PostgreSQL is configured."""
    connection = _db_connect()
    if connection is None:
        return False

    sql = """
    CREATE TABLE IF NOT EXISTS danip_user_sessions (
        id BIGSERIAL PRIMARY KEY,
        user_id TEXT,
        username TEXT,
        display_name TEXT,
        email TEXT,
        session_start TIMESTAMPTZ NOT NULL,
        last_activity TIMESTAMPTZ NOT NULL,
        session_end TIMESTAMPTZ,
        duration_seconds BIGINT DEFAULT 0,
        workspace TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_danip_sessions_start
        ON danip_user_sessions(session_start);

    CREATE INDEX IF NOT EXISTS idx_danip_sessions_user
        ON danip_user_sessions(user_id);

    CREATE INDEX IF NOT EXISTS idx_danip_sessions_workspace
        ON danip_user_sessions(workspace);
    """

    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(sql)
        return True
    except Exception:
        return False
    finally:
        connection.close()


# ---------------------------------------------------------------------
# Session tracking
# ---------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _start_local_session(user: Dict[str, str]) -> None:
    """Initialize one Streamlit session; persistence is handled separately."""
    if "danip_usage_session_start" not in st.session_state:
        st.session_state.danip_usage_session_start = _utc_now()
        st.session_state.danip_usage_last_activity = _utc_now()
        st.session_state.danip_usage_session_id = None
        st.session_state.danip_usage_db_enabled = _ensure_usage_table()

    st.session_state.danip_usage_last_activity = _utc_now()


def _current_workspace() -> str:
    return str(
        st.session_state.get(
            "workspace",
            st.session_state.get("selected_workspace", "My Reports & Monitoring"),
        )
    )


def _create_or_update_persistent_session(user: Dict[str, str]) -> None:
    """
    Persist one record for the current authenticated user.

    A session record is created once and updated on subsequent reruns.
    This avoids counting every Streamlit rerun as a new session.
    """
    if not st.session_state.get("danip_usage_db_enabled"):
        return

    connection = _db_connect()
    if connection is None:
        st.session_state.danip_usage_db_enabled = False
        return

    now = _utc_now()
    start = st.session_state.danip_usage_session_start
    duration = max(0, int((now - start).total_seconds()))
    workspace = _current_workspace()

    try:
        with connection:
            with connection.cursor() as cursor:
                session_id = st.session_state.get("danip_usage_session_id")

                if session_id is None:
                    cursor.execute(
                        """
                        INSERT INTO danip_user_sessions
                        (user_id, username, display_name, email,
                         session_start, last_activity,
                         duration_seconds, workspace)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                        RETURNING id
                        """,
                        (
                            user.get("user_id", ""),
                            user.get("username", ""),
                            user.get("display_name", ""),
                            user.get("email", ""),
                            start,
                            now,
                            duration,
                            workspace,
                        ),
                    )
                    row = cursor.fetchone()
                    if row:
                        st.session_state.danip_usage_session_id = row[0]
                else:
                    cursor.execute(
                        """
                        UPDATE danip_user_sessions
                        SET last_activity=%s,
                            duration_seconds=%s,
                            workspace=%s
                        WHERE id=%s
                        """,
                        (now, duration, workspace,
                         st.session_state.danip_usage_session_id),
                    )
    except Exception:
        # Monitoring must never break the reporting workspace.
        st.session_state.danip_usage_db_enabled = False
    finally:
        connection.close()


# ---------------------------------------------------------------------
# Usage analytics
# ---------------------------------------------------------------------

def _format_duration(seconds: Any) -> str:
    try:
        seconds = max(0, int(float(seconds)))
    except Exception:
        seconds = 0

    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)

    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _format_number(value: Any) -> str:
    if value is None:
        return "—"
    try:
        number = float(value)
    except Exception:
        return str(value)
    if math.isnan(number):
        return "—"
    if number.is_integer():
        return f"{int(number):,}"
    return f"{number:,.2f}"


def _usage_dataframe() -> pd.DataFrame:
    """Load all persisted usage records for system-wide reporting."""
    connection = _db_connect()
    if connection is None:
        return pd.DataFrame()

    sql = """
    SELECT
        id,
        user_id,
        username,
        display_name,
        email,
        session_start,
        last_activity,
        session_end,
        duration_seconds,
        workspace,
        created_at
    FROM danip_user_sessions
    ORDER BY session_start DESC
    """

    try:
        with connection:
            return pd.read_sql_query(sql, connection)
    except Exception:
        return pd.DataFrame()
    finally:
        connection.close()


def _usage_summary(df: pd.DataFrame) -> Dict[str, Any]:
    if df.empty:
        return {
            "users": 0,
            "sessions": 0,
            "seconds": 0,
            "avg_seconds": 0,
            "active": 0,
        }

    work = df.copy()
    work["duration_seconds"] = pd.to_numeric(
        work["duration_seconds"], errors="coerce"
    ).fillna(0)

    today = pd.Timestamp.now(tz="UTC").date()
    starts = pd.to_datetime(work["session_start"], errors="coerce", utc=True)
    active = int(
        (
            work["session_end"].isna()
            & (
                pd.to_datetime(
                    work["last_activity"], errors="coerce", utc=True
                )
                >= pd.Timestamp.now(tz="UTC") - pd.Timedelta(minutes=30)
            )
        ).sum()
    )

    return {
        "users": int(work["user_id"].replace("", pd.NA).dropna().nunique()),
        "sessions": int(len(work)),
        "seconds": int(work["duration_seconds"].sum()),
        "avg_seconds": int(work["duration_seconds"].mean()),
        "active": active,
        "today_seconds": int(
            work.loc[
                starts.dt.date == today, "duration_seconds"
            ].sum()
        ),
    }


def _render_usage_monitoring(user: Dict[str, str]) -> None:
    st.markdown(
        '<div class="danip-section">📊 DANIP System-Wide Usage</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="danip-report-note">'
        '<span class="danip-system-badge">👥 ALL AUTHENTICATED USERS</span> '
        "<strong>System-wide monitoring:</strong> usage is aggregated across "
        "authenticated DHIS2/OAuth2 users. Individual sessions are not "
        "recreated from Streamlit reruns."
        "</div>",
        unsafe_allow_html=True,
    )

    usage = _usage_dataframe()

    # If PostgreSQL is not configured, still show the current session,
    # but make it explicit that historical all-user analytics require persistence.
    if usage.empty:
        current_seconds = max(
            0,
            int(
                (
                    _utc_now()
                    - st.session_state.danip_usage_session_start
                ).total_seconds()
            ),
        )

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("👤 Current User", user.get("display_name", "User"))
        with c2:
            st.metric("🕒 Current Session", _format_duration(current_seconds))
        with c3:
            st.metric("👥 System Users", "—")
        with c4:
            st.metric("📈 Historical Usage", "—")

        st.warning(
            "PostgreSQL usage storage is not available. "
            "The current session can be measured, but a persistent "
            "all-user trend requires DANIP_DATABASE_URL/DATABASE_URL "
            "to point to PostgreSQL."
        )
        return

    summary = _usage_summary(usage)

    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.metric("👥 Users", f'{summary["users"]:,}')
    with c2:
        st.metric("🟢 Active", f'{summary["active"]:,}')
    with c3:
        st.metric("🔄 Sessions", f'{summary["sessions"]:,}')
    with c4:
        st.metric("⏱️ Total Usage", _format_duration(summary["seconds"]))
    with c5:
        st.metric("📅 Today", _format_duration(summary["today_seconds"]))

    # ---------------------------------------------------------------
    # Trend through time
    # ---------------------------------------------------------------

    st.markdown(
        '<div class="danip-section">📈 Usage Trend Through Time</div>',
        unsafe_allow_html=True,
    )

    trend_frequency = st.radio(
        "Trend period",
        ["Daily", "Weekly", "Monthly"],
        horizontal=True,
        key="danip_usage_trend_frequency",
    )

    trend = usage.copy()
    trend["session_start"] = pd.to_datetime(
        trend["session_start"], errors="coerce", utc=True
    )
    trend["duration_hours"] = (
        pd.to_numeric(trend["duration_seconds"], errors="coerce")
        .fillna(0)
        / 3600
    )
    trend = trend.dropna(subset=["session_start"])

    if trend_frequency == "Daily":
        trend["Period"] = trend["session_start"].dt.strftime("%Y-%m-%d")
    elif trend_frequency == "Weekly":
        trend["Period"] = (
            trend["session_start"]
            .dt.to_period("W-MON")
            .astype(str)
        )
    else:
        trend["Period"] = trend["session_start"].dt.strftime("%Y-%m")

    trend_chart = (
        trend.groupby("Period", as_index=True)["duration_hours"]
        .sum()
        .sort_index()
    )

    if not trend_chart.empty:
        st.line_chart(
            trend_chart,
            use_container_width=True,
        )
        st.caption("X-axis = time period · Y-axis = total platform usage (hours)")

    # ---------------------------------------------------------------
    # Users over time
    # ---------------------------------------------------------------

    st.markdown(
        '<div class="danip-section">👥 Authenticated Users Through Time</div>',
        unsafe_allow_html=True,
    )

    user_trend = (
        trend.groupby("Period")["user_id"]
        .nunique()
        .sort_index()
    )

    if not user_trend.empty:
        st.line_chart(
            user_trend,
            use_container_width=True,
        )
        st.caption("Unique authenticated users per selected time period")

    # ---------------------------------------------------------------
    # Workspace usage
    # ---------------------------------------------------------------

    st.markdown(
        '<div class="danip-section">🧩 Usage by DANIP Workspace</div>',
        unsafe_allow_html=True,
    )

    workspace_usage = (
        usage.assign(
            duration_hours=pd.to_numeric(
                usage["duration_seconds"], errors="coerce"
            ).fillna(0) / 3600
        )
        .groupby("workspace")["duration_hours"]
        .sum()
        .sort_values(ascending=False)
    )

    if not workspace_usage.empty:
        st.bar_chart(workspace_usage, use_container_width=True)

    # ---------------------------------------------------------------
    # User activity
    # ---------------------------------------------------------------

    st.markdown(
        '<div class="danip-section">👤 User Activity</div>',
        unsafe_allow_html=True,
    )

    user_activity = (
        usage.assign(
            duration_seconds=pd.to_numeric(
                usage["duration_seconds"], errors="coerce"
            ).fillna(0)
        )
        .groupby(
            ["user_id", "username", "display_name"],
            dropna=False,
            as_index=False,
        )
        .agg(
            Sessions=("id", "count"),
            Usage_Seconds=("duration_seconds", "sum"),
            Last_Activity=("last_activity", "max"),
        )
        .sort_values(
            ["Usage_Seconds", "Sessions"],
            ascending=False,
        )
    )

    user_activity["Usage"] = user_activity["Usage_Seconds"].apply(
        _format_duration
    )

    display_activity = user_activity[
        ["username", "display_name", "Sessions", "Usage", "Last_Activity"]
    ].rename(
        columns={
            "username": "Username",
            "display_name": "User",
            "Sessions": "Sessions",
            "Usage": "Total Usage",
            "Last_Activity": "Last Activity",
        }
    )

    st.dataframe(
        display_activity,
        use_container_width=True,
        hide_index=True,
    )

    # ---------------------------------------------------------------
    # Raw usage records / export
    # ---------------------------------------------------------------

    with st.expander("📋 Usage Records"):
        records = usage.copy()
        records["Duration"] = records["duration_seconds"].apply(
            _format_duration
        )
        show_columns = [
            "username",
            "display_name",
            "session_start",
            "last_activity",
            "session_end",
            "Duration",
            "workspace",
        ]
        st.dataframe(
            records[show_columns],
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "⬇️ Export System Usage",
            data=records.to_csv(index=False).encode("utf-8"),
            file_name="danip_system_usage.csv",
            mime="text/csv",
            key="danip_system_usage_export",
        )


# ---------------------------------------------------------------------
# Reporting model
# ---------------------------------------------------------------------

def _normalise_column_name(value: Any) -> str:
    return (
        str(value).strip().lower()
        .replace(" ", "").replace("_", "").replace("-", "")
    )


def _find_column(df: pd.DataFrame, aliases: list[str]) -> Optional[str]:
    normalised = {
        _normalise_column_name(column): column for column in df.columns
    }

    for alias in aliases:
        key = _normalise_column_name(alias)
        if key in normalised:
            return normalised[key]

    for column in df.columns:
        n = _normalise_column_name(column)
        for alias in aliases:
            a = _normalise_column_name(alias)
            if a and (a in n or n in a):
                return column

    return None


def _detect_columns(df: pd.DataFrame) -> Dict[str, Optional[str]]:
    return {
        "period": _find_column(df, [
            "Report Period", "Period Name", "Period", "periodname",
            "period", "reportperiod", "period_id", "periodid",
        ]),
        "organisation": _find_column(df, [
            "Organisation Name", "Organization Name",
            "OrganisationUnitName", "Organisation Unit Name",
            "OrganizationUnitName", "Organization Unit Name",
            "Org Unit Name", "OrgUnitName", "OU Name",
            "Organisation", "Organization",
        ]),
        "indicator": _find_column(df, [
            "Indicator", "Indicator Name", "Data Element",
            "Data Element Name", "IndicatorID", "Indicator Id", "dx",
        ]),
        "value": _find_column(df, [
            "Value", "Indicator Value", "Numeric Value",
            "Value Numeric", "value", "numericvalue", "value_numeric",
        ]),
    }


def _coerce_numeric(series: pd.Series) -> pd.Series:
    return pd.to_numeric(
        series.astype(str).str.replace(",", "", regex=False).str.strip(),
        errors="coerce",
    )


def _period_key(value: Any) -> tuple:
    text = str(value).strip()
    parsed = pd.to_datetime(text, errors="coerce")
    if not pd.isna(parsed):
        return (0, parsed.to_pydatetime())

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
    unique, seen = [], set()
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
    if not all(columns.values()):
        return pd.DataFrame()

    work = df[
        [
            columns["period"],
            columns["organisation"],
            columns["indicator"],
            columns["value"],
        ]
    ].copy()

    work.columns = [
        "Report Period",
        "Organisation Name",
        "Indicator",
        "Value",
    ]

    work["Report Period"] = work["Report Period"].astype(str).str.strip()
    work["Organisation Name"] = (
        work["Organisation Name"].astype(str).str.strip()
    )
    work["Indicator"] = work["Indicator"].astype(str).str.strip()
    work["Value"] = _coerce_numeric(work["Value"])

    return work[
        (work["Report Period"] != "")
        & (work["Organisation Name"] != "")
        & (work["Indicator"] != "")
        & work["Value"].notna()
    ].copy()


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
    return periods[index - 1] if index > 0 else None


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
        if latest else filtered.iloc[0:0]
    )
    previous_df = (
        filtered[filtered["Report Period"] == previous]
        if previous else filtered.iloc[0:0]
    )

    latest_total = (
        float(latest_df["Value"].sum()) if not latest_df.empty else 0
    )
    previous_total = (
        float(previous_df["Value"].sum())
        if not previous_df.empty else None
    )

    return {
        "frequency": frequency,
        "latest_period": latest,
        "previous_period": previous,
        "latest_total": latest_total,
        "previous_total": previous_total,
        "change": (
            latest_total - previous_total
            if previous_total is not None else None
        ),
        "rows": len(filtered),
        "organisations": filtered["Organisation Name"].nunique(),
        "indicators": filtered["Indicator"].nunique(),
    }


def _learning_text(
    data: pd.DataFrame,
    indicator: str,
    organisation: str,
) -> list[str]:
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
                f"Latest reported period: {latest}. Reported value across "
                f"the selected records: {_format_number(latest_total)}."
            )

            org_values = (
                latest_df.groupby("Organisation Name", as_index=False)["Value"]
                .sum()
                .sort_values("Value", ascending=False)
            )

            if not org_values.empty:
                top = org_values.iloc[0]
                observations.append(
                    f"At {latest}, {top['Organisation Name']} has the highest "
                    f"reported value among the selected organisation series: "
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
        direction = (
            "increased" if change > 0
            else "decreased" if change < 0
            else "did not change"
        )

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
        )["Value"].sum()
    )

    periods = _sorted_periods(chart["Report Period"].tolist())
    order = {period: index for index, period in enumerate(periods)}

    chart["_period_order"] = chart["Report Period"].map(order)
    return chart.sort_values(
        ["_period_order", "Organisation Name"]
    ).drop(columns=["_period_order"])


# ---------------------------------------------------------------------
# Main renderer
# ---------------------------------------------------------------------

def render_my_reports_monitoring() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)

    st.markdown(
        '<div class="danip-report-shell">'
        '<div class="danip-report-title">📅 My Reports & Monitoring</div>'
        '<div class="danip-report-subtitle">'
        "System-wide reporting and usage monitoring for authenticated DANIP users."
        "</div></div>",
        unsafe_allow_html=True,
    )

    user = _get_authenticated_user()

    if not user:
        st.warning(
            "No authenticated user profile was found in the current session. "
            "Please sign in through the existing DHIS2 OAuth2 gateway."
        )
        return

    _start_local_session(user)
    _create_or_update_persistent_session(user)

    display_name = user.get("display_name") or "Authenticated user"
    username = user.get("username") or "—"
    email = user.get("email") or "—"

    st.markdown(
        f"""
        <div class="danip-user-card">
            <span class="danip-private-badge">🔐 AUTHENTICATED SESSION</span>
            <span class="danip-system-badge">👥 SYSTEM-WIDE MONITORING</span>
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

    # ================================================================
    # SYSTEM-WIDE USAGE FIRST
    # ================================================================

    _render_usage_monitoring(user)

    # ================================================================
    # REPORTING DATA
    # ================================================================

    st.markdown(
        '<div class="danip-section">📋 Reports & Indicator Monitoring</div>',
        unsafe_allow_html=True,
    )

    df = st.session_state.get("loaded_df")

    if not isinstance(df, pd.DataFrame) or df.empty:
        st.info(
            "No reporting dataset is currently loaded. The system-wide "
            "usage monitoring above remains available independently."
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
            "The reporting model requires: " + ", ".join(missing) + "."
        )
        st.caption(
            "Required analytical grain: "
            "Report Period × Organisation Name × Indicator."
        )
        return

    if data.empty:
        st.warning(
            "The required columns were found, but no valid numeric "
            "observations were found."
        )
        return

    frequency = st.radio(
        "Report frequency",
        ["Daily", "Weekly"],
        horizontal=True,
        index=1,
        key="my_reports_frequency",
    )

    indicators = sorted(data["Indicator"].unique().tolist())
    organisations = sorted(data["Organisation Name"].unique().tolist())

    selected_indicator = st.selectbox(
        "Primary Indicator",
        ["All indicators"] + indicators,
        key="my_reports_indicator",
    )

    selected_organisation = st.selectbox(
        "Organisation Name",
        ["All organisations"] + organisations,
        key="my_reports_organisation",
    )

    st.markdown(
        '<div class="danip-report-note">'
        "<strong>Analytical model:</strong> "
        "X = Report Period · Series = Organisation Name · "
        "Y = Indicator value. All organisations remain separate series."
        "</div>",
        unsafe_allow_html=True,
    )

    summary = _build_report_summary(
        data, selected_indicator, selected_organisation, frequency
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric("Latest period", summary["latest_period"] or "—")
    with c2:
        st.metric("Reported value", _format_number(summary["latest_total"]))
    with c3:
        st.metric("Organisations", f'{summary["organisations"]:,}')
    with c4:
        st.metric("Observations", f'{summary["rows"]:,}')

    st.markdown(
        '<div class="danip-section">📈 Report Period Analysis</div>',
        unsafe_allow_html=True,
    )

    chart = _make_chart_data(
        data, selected_indicator, selected_organisation
    )

    if not chart.empty:
        pivot = chart.pivot_table(
            index="Report Period",
            columns="Organisation Name",
            values="Value",
            aggfunc="sum",
        )

        pivot = pivot.reindex(_sorted_periods(pivot.index.tolist()))
        st.line_chart(pivot, use_container_width=True)

        st.caption(
            "X-axis: Report Period · Series: Organisation Name · "
            "Y-axis: Indicator value"
        )
    else:
        st.info("No data is available for the selected filters.")

    st.markdown(
        '<div class="danip-section">🏢 Organisation Comparison</div>',
        unsafe_allow_html=True,
    )

    latest = summary["latest_period"]
    if latest:
        latest_org = _apply_filters(
            data, selected_indicator, selected_organisation
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

    st.markdown(
        '<div class="danip-section">🧠 Report Learning & Insights</div>',
        unsafe_allow_html=True,
    )

    for insight in _learning_text(
        data, selected_indicator, selected_organisation
    ):
        st.write(f"• {insight}")

    st.markdown(
        '<div class="danip-section">📋 Analytical Data</div>',
        unsafe_allow_html=True,
    )

    analytical = _apply_filters(
        data, selected_indicator, selected_organisation
    )

    analytical = (
        analytical.groupby(
            ["Report Period", "Organisation Name", "Indicator"],
            as_index=False,
        )["Value"].sum()
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

    st.download_button(
        "⬇️ Export My Report Data",
        data=analytical.to_csv(index=False).encode("utf-8"),
        file_name=(
            "danip_daily_report.csv"
            if frequency == "Daily"
            else "danip_weekly_report.csv"
        ),
        mime="text/csv",
        key="my_reports_export",
    )

    st.caption(
        "System-wide usage monitoring is based on persistent PostgreSQL "
        "session records. Reporting analysis remains at the "
        "Report Period × Organisation Name × Indicator grain."
    )
