# LogAnalyser

Real-time security log analysis dashboard — auth.log & access.log

## Description

LogAnalyser is a Python-based tool that parses system log files,
detects suspicious behavior (brute force attacks, malicious IPs,
abnormal access), and displays results in an interactive web dashboard
built with Flask and Chart.js.

## Requirements

- Python 3.x
- Flask

## Installation

pip install flask

## Usage

1. Place your log files in the logs/ folder
2. Run the application:

   cd src
   python app.py

3. Open your browser at: http://127.0.0.1:5000
4. Upload auth.log and access.log via the dashboard
5. Click Analyze

## Features

- Brute force SSH detection
- Malicious IP scoring
- Abnormal HTTP access detection
- Severity breakdown (INFO / WARNING / CRITICAL)
- Interactive charts via Chart.js

## Configuration

Edit src/config.py to adjust:
- Log file paths
- Brute force detection threshold

## Author

Ziyad — Université Chouaib Doukkali, El Jadida
June 2026
