import json
from google.cloud import bigquery, storage
from datetime import datetime
from analyzer import analyze_file, summarize
import os

# Environment variables
PROJECT_ID  = os.getenv("PROJECT_ID")
BQ_DATASET  = os.getenv("BQ_DATASET", "threatintel")
BQ_TABLE    = os.getenv("BQ_TABLE", "detections")
BUCKET_NAME = os.getenv("BUCKET_NAME")

# Build table ID safely even if PROJECT_ID isn't set yet
if PROJECT_ID:
    BQ_TABLE_ID = f"{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}"
else:
    BQ_TABLE_ID = f"{BQ_DATASET}.{BQ_TABLE}"

bq  = bigquery.Client()
gcs = storage.Client()

def run_analysis(request):
    try:
        #load URLs & score
        detections = analyze_file("urls.csv")
        report = summarize(detections)

        # prepare rows for BigQuery
        rows_to_insert = []
        for d in detections:
            rows_to_insert.append({
                "url": d["url"].replace("\\", "\\\\"),
                "score": d["score"],
                "reasons": " | ".join(r.replace("\\", "\\\\") for r in d["reasons"]),
                "time": d["time"]   
            })

        #insert into BigQuery
        errors = bq.insert_rows_json(BQ_TABLE_ID, rows_to_insert)
        if errors:
            print("BigQuery insert errors:", errors)
            return (
                json.dumps({"status": "bq_insert_error", "errors": errors}),
                500,
                {"Content-Type": "application/json"}
            )

        #bucket
        if not BUCKET_NAME:
            return (
                json.dumps({"status": "missing_bucket_env"}),
                500,
                {"Content-Type": "application/json"}
            )

        #upload summary JSON to GCS
        bucket = gcs.bucket(BUCKET_NAME)
        blob = bucket.blob("reports/latest_report.json")

        blob.upload_from_string(
            json.dumps(
                {
                    "generated_at": datetime.utcnow().isoformat(),
                    "summary": report,
                },
                indent=2
            ),
            content_type="application/json"
        )

        #success
        return (
            json.dumps({"status": "ok", "summary": report}),
            200,
            {"Content-Type": "application/json"}
        )

    except Exception as e:
        print("Error in run_analysis:", str(e))
        return (
            json.dumps({"status": "function_error", "error": str(e)}),
            500,
            {"Content-Type": "application/json"}
        )
