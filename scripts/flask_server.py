import threading

from flask import Flask, request, Response, jsonify
import logging
import os
from datetime import datetime
from collections import Counter
import time

app = Flask(__name__)

AUTH = {
    "admin": "1234",
    "tommy": "password",
    "roland": "bestpassword01",
    "meandmyself": "badassPassword!",
    "admin2": "4321",
    "user": "key123",
}

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

#logging after every http request
@app.after_request
def log_request(response):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_type = request.headers.get("X-User-Type", "unknown")
    method = request.method
    path = request.path
    status = response.status_code
    user_agent = request.headers.get("User-Agent")
    user_name = request.authorization.username if request.authorization is not None else 'unknown'

    logging.info(
        f'{ip} - - {user_name} [{datetime.now()}] "{method} {path} HTTP/1.1" {status} "{user_agent}" "{user_type}"'
    )
    return response

#checking username and password
def check_auth(username, password, ip):
    if username in AUTH.keys() and AUTH[username] == password:
        return True
    else:
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

@app.route("/api/data", methods=["GET"])
def get_data():

    auth = request.authorization
    ip = request.remote_addr

    if not auth or not check_auth(auth.username, auth.password, ip):
        return authenticate()

    return jsonify({"data": "example"})

@app.route("/api/post", methods=["POST"])
def post_data():

    auth = request.authorization
    ip = request.remote_addr

    if not auth or not check_auth(auth.username, auth.password, ip):
        return authenticate()

    data = request.json
    return jsonify({"received": data})

#running server
if __name__ == "__main__":

    # suppress default werkzeug logs
    werkzeug_log = logging.getLogger('werkzeug')
    werkzeug_log.setLevel(logging.ERROR)

    #running server
    app.run(host="0.0.0.0", port=5000)