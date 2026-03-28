from locust import HttpUser, task, between
import random
import base64
import string

VALID_USERS = {
    "admin": "1234",
    "tommy": "password",
    "roland": "bestpassword01",
    "meandmyself": "badassPassword!",
    "admin2": "4321",
    "user": "key123",
}

def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def basic_auth(username, password):
    creds = f"{username}:{password}"
    encoded = base64.b64encode(creds.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}

def random_user_agent():
    return random.choice([
        "Mozilla/5.0",
        "curl/7.68.0",
        "python-requests/2.28",
        "sqlmap/1.6",
        ''.join(random.choices(string.ascii_letters + string.digits, k=50))
    ])

def common_headers(user_type: str):
    return {
        "X-Forwarded-For": random_ip(),
        "X-User-Type": user_type,
        "User-Agent": random_user_agent()
    }

def random_valid_auth():
        authentication = {}
        authentication["username"] = random.choice(list(VALID_USERS.keys()))
        authentication["password"] = VALID_USERS[authentication["username"]]

        return authentication

class NormalUser(HttpUser):
    wait_time = between(1, 3)  # realistic human pacing

    def on_start(self):
        # stable identity (important for baseline!)
        self.ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        self.user_type = "normal"
        auth = random_valid_auth()
        self.username = auth["username"]
        self.password = auth["password"]

    def auth_headers(self):
        headers = {
            "X-Forwarded-For": self.ip,
            "X-User-Type": self.user_type,
            "User-Agent": random_user_agent()
        }
        headers.update(basic_auth(self.username, self.password))
        return headers
    
    def without_auth_headers(self):
        headers = {
            "X-Forwarded-For": self.ip,
            "X-User-Type": self.user_type,
            "User-Agent": "Mozilla/5.0"
        }
        return headers
    
    @task(2)
    def view_home(self):
        self.client.get("/", headers=self.without_auth_headers())

    @task(3)
    def view_home(self):
        self.client.get("/", headers=self.auth_headers())

    @task(2)
    def get_data(self):
        self.client.get("/api/data", headers=self.auth_headers())

    @task(1)
    def post_data(self):
        payload = {"action": "view", "value": random.randint(1, 100)}
        self.client.post("/api/post", json=payload, headers=self.auth_headers())

    weight = 70

# ===== DoS Simulation =====

class DoSUser(HttpUser):
    wait_time = between(0.01, 0.1)  # very aggressive

    headers = common_headers("anomaly")

    def on_start(self):
        if random.randint(0, 1) == 1:
            auth = random_valid_auth()
            self.headers.update((basic_auth(auth["username"], auth["password"])))

    @task
    def flood_home(self):
        self.client.get("/", headers=self.headers)

    @task
    def flood_api(self):
        self.client.get("/api/data", headers=self.headers)

    weight = 5


# ===== Brute Force Login =====

class BruteForceUser(HttpUser):
    wait_time = between(0.1, 0.5)

    usernames = ["admin", "root", "user", "user1", "user2", "user3", "master"]
    passwords = ["1234", "password", "admin", "123456", "letmein", "truePassword", "break"]

    headers = common_headers("anomaly")

    @task
    def brute_login(self):
        username = random.choice(self.usernames)
        password = random.choice(self.passwords)

        self.headers.update(basic_auth(username, password))

        self.client.get("/", headers=self.headers)

    weight = 5

# ===== Endpoint Fuzzing =====

class FuzzingUser(HttpUser):
    wait_time = between(0.2, 1)

    fuzz_paths = [
        "/admin",
        "/login",
        "/.env",
        "/config",
        "/backup",
        "/secret",
        "/api/admin",
        "/api/hidden",
        "/random" + ''.join(random.choices(string.ascii_letters, k=5))
    ]

    headers = common_headers("anomaly")

    def on_start(self):
        if random.randint(0, 1) == 1:
            auth = random_valid_auth()
            self.headers.update((basic_auth(auth["username"], auth["password"])))

    @task
    def fuzz_endpoints(self):
        path = random.choice(self.fuzz_paths)

        self.client.get(path, headers=self.headers)

    weight = 5

# ===== HTTP Method Abuse =====

class MethodAbuseUser(HttpUser):
    wait_time = between(0.2, 1)

    headers = common_headers("anomaly")

    def on_start(self):
        if random.randint(0, 1) == 1:
            auth = random_valid_auth()
            self.headers.update((basic_auth(auth["username"], auth["password"])))

    @task
    def abuse_methods(self):

        method = random.choice(["PUT", "DELETE", "PATCH", "TRACE", "OPTIONS"])
        path = random.choice(["/", "/api/data", "/api/post"])

        self.client.request(method, path, headers=self.headers)

    weight = 5


# ===== Mixed Attack User =====

class MixedAttackUser(HttpUser):
    wait_time = between(0.05, 0.5)

    headers = common_headers("anomaly")

    @task(3)
    def dos(self):
        self.client.get("/", headers=self.headers)

    @task(2)
    def brute(self):
        self.headers.update(basic_auth("admin", random.choice(["wrong", "1234", "guess"])))
        self.client.get("/", headers=self.headers)

    @task(2)
    def fuzz(self):
        path = "/random" + ''.join(random.choices(string.ascii_letters, k=6))
        self.client.get(path, headers=self.headers)

    @task(1)
    def method_abuse(self):
        self.client.request("DELETE", "/api/data", headers=self.headers)

    weight = 5

class LogInjectionUser(HttpUser):
    wait_time = between(0.2, 1)

    ip = ".".join(str(random.randint(1, 255)) for _ in range(4))

    def injection_payloads(self):
        return [
            # newline injection (log splitting)
            'normal-agent"\n1.2.3.4 - - [FAKE] "GET /admin HTTP/1.1" 200 "hacker" "admin"',
            
            # quote breaking
            'bad-agent" "injected-field',
            
            # long payload
            'A' * 500,
            
            # log format confusion
            '"] 500 "evil" "root',
            
            # fake timestamp injection
            '[01/Jan/2000:00:00:00] "GET /secret HTTP/1.1" 200',
            
            # control characters
            'evil\tagent\nanotherline',
            
            # JSON-like injection
            '{"role":"admin","attack":true}',
        ]

    def headers_with_injection(self):
        payload = random.choice(self.injection_payloads())

        return {
            "X-Forwarded-For": self.ip,
            "X-User-Type": "anomaly",
            "User-Agent": payload
        }

    @task(3)
    def inject_home(self):
        self.client.get("/", headers=self.headers_with_injection())

    @task(2)
    def inject_api(self):
        self.client.get("/api/data", headers=self.headers_with_injection())

    @task(1)
    def inject_post(self):
        self.client.post(
            "/api/post",
            json={"test": "data"},
            headers=self.headers_with_injection()
        )

    weight = 5