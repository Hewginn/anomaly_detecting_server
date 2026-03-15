import threading

from flask import Flask, request, Response
import logging
import os
from datetime import datetime
from collections import Counter
import time

app = Flask(__name__)

USERNAME = "admin"
PASSWORD = "1234"

# create log folder
ACCESS_LOGS_DIR = "logs"
os.makedirs(ACCESS_LOGS_DIR, exist_ok=True)

# setting log file name
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
ACCESS_LOG = os.path.join(ACCESS_LOGS_DIR, f"access_{timestamp}.log")

#configure logging
logging.basicConfig(
    filename=ACCESS_LOG,
    level=logging.INFO,
    format="%(message)s"
)

#log analizer
def analyze_access_logs():
    while True:
        try:
            ip_counter = Counter()
            total_requests = 0
            error_requests = 0

            with open(ACCESS_LOG, "r") as f:
                for line in f:
                    parts = line.split()

                    if len(parts) < 4:
                        continue

                    ip = parts[0]
                    status = int(parts[-2])

                    ip_counter[ip] += 1
                    total_requests += 1

                    if status >= 400:
                        error_requests += 1

            print("----- Access Log Analysis -----")
            print("Total requests:", total_requests)
            print("Error requests:", error_requests)

            print("Top IPs:")
            for ip, count in ip_counter.most_common(5):
                print(ip, count)

        except Exception as e:
            print("Log analysis error:", e)

        time.sleep(60)  # run every 60 seconds

#logging after every http request
@app.after_request
def log_request(response):
    ip = request.remote_addr
    method = request.method
    path = request.path
    status = response.status_code
    user_agent = request.headers.get("User-Agent")

    logging.info(
        f'{ip} - - [{datetime.now()}] "{method} {path} HTTP/1.1" {status} "{user_agent}"'
    )

    return response

#checking username and password
def check_auth(username, password, ip):
    if username == USERNAME and password == PASSWORD:
        logging.info(f"SUCCESS login from {ip} with username '{username}'")
        return True
    else:
        logging.warning(f"FAILED login from {ip} with username '{username}'")
        return False


#not authenticated response
def authenticate():
    return Response(
        "Authentication required", 401,
        {"WWW-Authenticate": 'Basic realm="Login Required"'}
    )

#main page
#   -protected with username and password
@app.route("/")
def home():
    auth = request.authorization
    ip = request.remote_addr

    if not auth or not check_auth(auth.username, auth.password, ip):
        return authenticate()

    return "Welcome, authenticated user!"

#running server
if __name__ == "__main__":

    #setting analyzer thread
    thread = threading.Thread(target=analyze_access_logs, daemon=True)
    thread.start()

    #running server
    app.run(host="0.0.0.0", port=5000)