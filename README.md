<h1>AI-Powered Real-Time Phishing Email Detection</h1>

An intelligent cybersecurity platform that connects to a real Gmail account, monitors incoming emails, analyzes phishing indicators, checks suspicious URLs using VirusTotal, assigns a transparent risk score, displays results on a live dashboard, quarantines high-risk emails, and alerts the administrator.

<h2>Project Title</h2>

AI-Powered Real-Time Phishing Email Detection with Automated Quarantine and Intelligent Security Dashboard

<h2>Overview</h2>

Phishing emails are designed to steal passwords, banking details, personal information, or deliver malware. Many phishing messages look similar to genuine emails, making manual detection difficult.

This project provides an automated email-security solution that:

Connects securely to a real Gmail account

Monitors newly received emails

Extracts sender details, headers, body content, URLs, and attachments

Detects phishing indicators using rules, machine learning, and threat intelligence

Checks suspicious URLs using the VirusTotal API

Calculates a phishing-risk score

Classifies emails as Safe, Suspicious, or Phishing

Displays detections on a live dashboard

Quarantines high-risk emails when enabled

Sends alerts to the administrator

Stores scan results and audit logs in a database

The system does not claim 100% detection accuracy. It uses multiple detection methods, transparent evidence, risk scoring, and analyst review to reduce false positives.

<h2>Key Features</h2>

Real Gmail Monitoring

Gmail API integration using OAuth 2.0

Optional IMAP fallback using a Gmail app password

Configurable mailbox scan interval

Manual Scan Now option

Duplicate-email prevention using Gmail message IDs

Monitoring status and last-scan time

Hybrid Phishing Detection

The detection engine combines:

Email-content analysis

URL and domain analysis

Sender and header analysis

SPF, DKIM, and DMARC results

VirusTotal URL reputation

Machine-learning classification

Optional AI-generated explanations

URL Analysis

The system detects and analyzes:

http:// and https:// links

IP-address-based URLs

URL shorteners

Punycode domains

Typosquatting

Long or obfuscated URLs

Suspicious keywords such as login, verify, password, and account

Visible-link and actual-destination mismatches

An HTTP link increases the risk score, but an email is not classified as phishing only because it contains HTTP.

Automated Response

Safe emails remain in the inbox

Suspicious emails can receive an AI-Phishing-Review label

High-risk emails can receive an AI-Phishing-Quarantine label

Inbox removal is performed only when automatic quarantine is enabled

Administrators receive an alert containing the risk score and detection reasons

All actions are recorded in audit logs

Live Dashboard

The dashboard displays:

Gmail connection status

Monitoring status

Total emails scanned

Safe emails

Suspicious emails

Phishing emails

Quarantined emails

Critical alerts

Recent detections

Daily and weekly threat trends

Top suspicious domains

Common phishing indicators

<h2>How the System Works</h2>

flowchart LR
    A[Real Gmail Inbox] --> B[Email Monitoring Service]
    B --> C[Email Parser]
    C --> D[Header and Sender Analysis]
    C --> E[Content Rule Engine]
    C --> F[URL Extraction]
    F --> G[Static URL Analysis]
    G --> H[VirusTotal API]
    C --> I[ML Classifier]
    D --> J[Risk Scoring Engine]
    E --> J
    H --> J
    I --> J
    J --> K{Final Classification}
    K -->|Safe| L[Keep in Inbox]
    K -->|Suspicious| M[Review Label]
    K -->|Phishing| N[Quarantine Label]
    N --> O[Admin Alert]
    K --> P[Database]
    P --> Q[Live Dashboard]

<h2>Processing Workflow</h2>

The application connects to Gmail using OAuth 2.0.

The monitoring service checks for new emails.

The email parser extracts headers, sender details, body text, URLs, and attachment metadata.

The rule engine analyzes phishing language and suspicious patterns.

The header analyzer checks SPF, DKIM, DMARC, Reply-To, and Return-Path information.

The URL analyzer checks HTTP usage, suspicious domains, typosquatting, and obfuscation.

VirusTotal provides URL reputation information.

The machine-learning model predicts phishing probability.

The risk engine calculates the final score.

The result is stored and displayed on the dashboard.

High-risk emails are quarantined and an administrator alert is sent.
<h2>Technology Stack</h2>

Frontend

React

Vite

Tailwind CSS

React Router

Axios

Recharts

Lucide React

React Hook Form

SweetAlert2

Backend

Python 3.11+

FastAPI

Uvicorn

SQLAlchemy

Alembic

Pydantic

APScheduler

WebSockets or Server-Sent Events

Database

SQLite for local development

PostgreSQL for production

Email Integration

Gmail API

OAuth 2.0

Gmail labels

Optional IMAP/SMTP fallback

Threat Intelligence and AI

VirusTotal API

Scikit-learn

TF-IDF

Logistic Regression

Optional LLM explanation module

Deployment

Docker

Docker Compose

Nginx

<h2>Project Structure</h2>

phishing-email-detector/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── database/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   │   ├── gmail_service.py
│   │   │   ├── monitoring_service.py
│   │   │   ├── email_parser.py
│   │   │   ├── header_analyzer.py
│   │   │   ├── rule_engine.py
│   │   │   ├── url_extractor.py
│   │   │   ├── url_analyzer.py
│   │   │   ├── virustotal_service.py
│   │   │   ├── ml_service.py
│   │   │   ├── risk_engine.py
│   │   │   ├── quarantine_service.py
│   │   │   ├── alert_service.py
│   │   │   └── report_service.py
│   │   ├── tasks/
│   │   ├── utils/
│   │   ├── main.py
│   │   └── config.py
│   ├── alembic/
│   ├── ml/
│   │   ├── datasets/
│   │   ├── prepare_dataset.py
│   │   ├── train_model.py
│   │   ├── evaluate_model.py
│   │   └── models/
│   ├── tests/
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── layouts/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── context/
│   │   ├── utils/
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   ├── Dockerfile
│   └── .env.example
│
├── sample_emails/
├── docs/
├── nginx/
├── docker-compose.yml
├── README.md
├── SECURITY.md
└── .gitignore

<h2>Prerequisites</h2>

Install the following software:

Python 3.11 or later

Node.js 20 or later

npm

Git

Docker Desktop, optional

A Gmail account used only for project testing

A Google Cloud project with Gmail API enabled

A VirusTotal API key

<img><img width="959" height="446" alt="image" src="https://github.com/user-attachments/assets/223cf4ea-b161-4a09-89ac-21959c5973d0" /></img>
<img><img width="959" height="447" alt="image" src="https://github.com/user-attachments/assets/b01eaf87-198a-4174-bf52-79bd79a2c47d" /></img>
<img><img width="959" height="444" alt="image" src="https://github.com/user-attachments/assets/1fce66d9-653d-4ece-841c-67f64e6f1ca8" /></img>
<img><img width="922" height="438" alt="image" src="https://github.com/user-attachments/assets/8f22430f-d9fb-4692-a4b3-0092fb607617" /></img>
<img><img width="959" height="452" alt="image" src="https://github.com/user-attachments/assets/b09b839c-f1a7-4b97-8224-7accacbfa019" /></img>
<img><img width="959" height="443" alt="image" src="https://github.com/user-attachments/assets/bca2efd9-617e-40d6-a3a9-bc06ad4f39e6" /></img>
<img><img width="954" height="449" alt="image" src="https://github.com/user-attachments/assets/a6de5eba-7d3c-4290-b177-42b0d7a49d01" /></img>
<img><img width="956" height="446" alt="image" src="https://github.com/user-attachments/assets/741a896e-f7c0-4448-bf5c-8cfa8b4fc2c2" /></img>
<img><img width="959" height="424" alt="image" src="https://github.com/user-attachments/assets/9b570bee-20db-487c-8709-f4c0aca2c3e2" /></img>
<img><img width="959" height="446" alt="image" src="https://github.com/user-attachments/assets/428b578a-1273-4b5e-b2eb-877d2b618343" /></img>
