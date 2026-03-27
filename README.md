# Anomaly Detection Server
This repository is for academy researches of real time monitoring of log files and anomaly detection.

## Required python packages

- pip install locust
- pip install flask

## Test server

The test server is a written in Flask micro web framework found at *flask_server.py*.

Endpoints:
1. **/**
2. **/api/data**
3. **/api/post**

## Request generating server

The requests are generated with unique test ips from a locust server at *locustfile.py*. This is used for generating a train and test logs.

Anomalies:
- DOS user
- Brute Force user
- Fuzzing user
- Method abuser user
- Mixed attack user
- Log injection user

## Run steps

### Test server

1. **source venv/bin/activate** at venv location
2. **python flask_server.py** at *flask_server.py* location

### Request sender

1. **source venv/bin/activate** at venv location
2. **locust -f locustfile.py --host=http://localhost:5000 --headless -u 50 -r 10 -t 5m** at *locustfile.py* location
    - *-u* number of user objects
    - *-r* rate of user spawn (users per second)
    - *-t* test duration (10s -> 10 seconds, 10m -> 10 minutes, 10h -> 10 hours)

