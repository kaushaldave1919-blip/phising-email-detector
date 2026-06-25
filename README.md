# Phishing Email Detection System

Flask web app for scanning email content, showing phishing indicators, and generating PDF reports.

## Run locally

Install Python 3.11 or newer, then run:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

## Deploy on Render

1. Push this folder to a GitHub repository.
2. In Render, create a new Web Service from that repository.
3. Use these settings:

```text
Runtime: Python
Build Command: pip install -r requirements.txt
Start Command: gunicorn app:app
```

This repo also includes `.python-version` and `render.yaml`, so Render can deploy it as a Blueprint with the intended Python version.

## Notes

Generated PDF reports are stored in the `reports` folder while the app is running. On free hosting tiers, old generated reports may disappear after an app restart.
