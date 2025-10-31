import os
import requests
import pandas as pd
import streamlit as st
from google.cloud import bigquery


CLOUD_FUNC_URL = os.getenv("CLOUD_FUNC_URL")
PROJECT_ID = os.getenv("PROJECT_ID")  
DATASET = os.getenv("BQ_DATASET", "threatintel")
TABLE = os.getenv("BQ_TABLE", "detections")

st.title("AdThreatIntel – Threat Intelligence Dashboard")

#button
st.subheader("Trigger a fresh scan")
if st.button("Run scan now"):
    if not CLOUD_FUNC_URL:
        st.error("CLOUD_FUNC_URL env var is not set.")
    else:
        try:
            # POST is fine; your function can accept GET or POST
            r = requests.post(CLOUD_FUNC_URL, timeout=30)
            r.raise_for_status()
            st.success("Scan triggered successfully!")
            st.json(r.json())
        except Exception as e:
            st.error(f"Error triggering scan: {e}")

st.divider()

#detections from BigQuery
st.subheader("Latest detections")

try:
    bq = bigquery.Client()
    table_id = f"{PROJECT_ID}.{DATASET}.{TABLE}"
    #fq_table = f"`{PROJECT_ID}.{DATASET}.{TABLE}`" if PROJECT_ID else f"{DATASET}.{TABLE}"
    # query = f"""
    # SELECT url, score, reasons, time
    # FROM {fq_table}
    # ORDER BY time DESC
    # LIMIT 100
    # """
    query = f"""
    SELECT url, score, reasons, time
    FROM `{table_id}`
    ORDER BY time DESC
    LIMIT 100
    """
    
    df = bq.query(query).to_dataframe()
    if df.empty:
        st.info("No detections yet. Trigger a scan to populate data.")
    else:
        st.dataframe(df, use_container_width=True)

        st.subheader("High-risk URLs (score ≥ 4)")
        high_risk = df[df["score"] >= 4]
        st.write(high_risk[["url", "score", "reasons"]])

        st.subheader("Score distribution")
        st.bar_chart(df["score"])
except Exception as e:
    st.error(f"Error reading BigQuery: {e}")
