import json
from pathlib import Path

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh


# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Alert file path
ALERT_FILE = BASE_DIR / "output" / "alerts.json"


# Streamlit page settings
st.set_page_config(
    page_title="Mini IDS Dashboard",
    layout="wide"
)

# Auto-refresh every 5 seconds
st_autorefresh(interval=5000, key="refresh")


# Title
st.title("Mini IDS / Packet Analyzer Dashboard")


try:

    # Load alerts
    with open(ALERT_FILE, "r") as file:
        alerts = json.load(file)

    # If alerts exist
    if alerts:

        # Convert JSON alerts into dataframe
        df = pd.json_normalize(alerts)

        # Alert table
        st.subheader("Alert Overview")
        st.dataframe(df)

        # Severity chart
        st.subheader("Severity Counts")

        severity_counts = df["severity"].value_counts()

        st.bar_chart(severity_counts)

        # Top source IPs
        st.subheader("Top Source IPs")

        if "details.source_ip" in df.columns:

            top_ips = df["details.source_ip"].value_counts()

            st.bar_chart(top_ips)

        else:
            st.info("No source IP data found yet.")

        # Recent alerts
        st.subheader("Recent Alerts")

        for alert in alerts[::-1]:

            st.markdown("---")

            st.write(f"Title: {alert['title']}")
            st.write(f"Severity: {alert['severity']}")
            st.write(f"Timestamp: {alert['timestamp']}")

            st.write(alert["details"])

    else:
        st.warning("No alerts found.")

except FileNotFoundError:
    st.error(f"alerts.json not found at: {ALERT_FILE}")
