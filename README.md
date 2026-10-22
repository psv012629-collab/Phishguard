# PhishGuard - Smart Phishing URL Risk Analyzer

## About
PhishGuard is an educational cybersecurity project that analyzes URLs and estimates their potential phishing risk using rule-based checks.

## Features
- Analyzes URLs using heuristic rules.
- Assigns a risk score from 0 to 100.
- Classifies results as LOW RISK, MEDIUM RISK, or HIGH RISK.
- Explains suspicious URL characteristics.
- Provides a security recommendation.
- Stores recent analysis history.
- Displays dashboard statistics.
- Supports mobile-friendly browser access.

## Technologies Used
- Python 3
- Flask
- HTML
- CSS
- JavaScript
- JSON

## Project Files
- app.py - Flask web application.
- phishguard.py - URL analysis and risk scoring logic.
- templates/index.html - Dashboard interface.
- history.json - Saved analysis history.
- requirements.txt - Python dependency list.

## Installation
1. Install Python 3.
2. Install dependencies:

   pip install -r requirements.txt

## Run the Application
From the project directory, run:

   python app.py

Open this address in your browser:

   http://127.0.0.1:5000

## Risk Classification
- LOW RISK: Score below 30.
- MEDIUM RISK: Score from 30 to 59.
- HIGH RISK: Score 60 or above.

## Important Note
PhishGuard uses heuristic rules for educational purposes. Its score is an estimate, not a guarantee that a URL is safe or malicious. Do not rely on this tool alone to decide whether a website is trustworthy.
