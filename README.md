# AdThreatIntel – Cloud-Based Malvertising Detection System

AdThreatIntel is a serverless threat-intelligence system that analyzes advertising URLs for suspicious patterns, stores results in BigQuery, and visualizes detections via a Streamlit dashboard on Cloud Run using Cloud Run Function.

This project demonstrates practical skills in cloud security engineering, threat intelligence automation, and serverless architecture on Google Cloud.
<img width="3595" height="1732" alt="image" src="https://github.com/user-attachments/assets/176ce118-1a40-4ccc-8518-5eb3aa191e35" />

GCP services used: Cloud Run, Cloud Functions, BigQuery, Cloud Storage, IAM, Cloud Logging
---

## Overview

Malicious advertising (malvertising) frequently includes encoded URLs, redirect chains, and suspicious domains to disseminate harmful content.  
This is a simulation of a lightweight threat-detection pipeline designed to identify suspicious ad URLs.It is something I can build on top of over time.

**Pipeline flow:**

1. User triggers a scan in the dashboard
   <img width="2484" height="1462" alt="image" src="https://github.com/user-attachments/assets/54d0863c-03f6-4625-a24b-7de7751517ac" />

2. Cloud Function loads and analyzes URLs
   <img width="2425" height="1577" alt="image" src="https://github.com/user-attachments/assets/f8160230-c62e-4506-9c17-eb58672c3d1a" />

3. Results written to BigQuery
   <img width="2421" height="1188" alt="image" src="https://github.com/user-attachments/assets/96630c6b-1017-4a2d-8f42-1eade551c61a" />

4. Summary report stored in Cloud Storage
   <img width="3273" height="1077" alt="image" src="https://github.com/user-attachments/assets/c1c2dfd8-61eb-48ab-83c2-4e075f9fc7a6" />

5. Dashboard fetches and displays detections
<img width="2254" height="1701" alt="image" src="https://github.com/user-attachments/assets/e008eda2-884d-471f-b52f-a0ebba29f993" />
<img width="1629" height="1522" alt="image" src="https://github.com/user-attachments/assets/0f6cab92-2301-43cf-80c6-b6f1391d6bd6" />


---

## Features

- Static analysis of URLs for malicious indicators
- Rule-based threat scoring 
- Serverless analysis using Cloud Functions
- Threat data stored in BigQuery
- Dashboard deployed on Cloud Run
- JSON report stored in Cloud Storage

---

## Detection Logic

Indicators analyzed include:

| Indicator | Example | Purpose |
|----------|--------|---------|
Suspicious TLDs | `.xyz`, `.top`, `.click` | Common in malicious infra |
Encoded characters | `%2F`, `%3D`, hex sequences | Obfuscation techniques |
Redirect params | `redirect=`, `url=` | Redirect-based exploitation |
Long/complex URLs | 100+ chars | Cloaking/affiliate hops |
Keyword patterns | `login`, `verify`, `secure` | Phishing behaviors |

Output includes URL, score, reasons, and timestamp.

