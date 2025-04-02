import requests
import argparse
import random
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
import os, json

load_dotenv()

BASE_URL = os.getenv("BASE_URL", "http://localhost:80")
LOGIN_ENDPOINT = os.getenv("LOGIN_ENDPOINT", "/api/login")

ACCOUNTS = {
    "admin": {
        "user_id": os.getenv("ADMIN_USER_ID"),
        "password": os.getenv("ADMIN_PASSWORD"),
    },
    "user": {
        "user_id": os.getenv("USER_USER_ID"),
        "password": os.getenv("USER_PASSWORD"),
    },
}

ADMIN_ENDPOINTS = json.loads(os.getenv("ADMIN_ENDPOINTS", "[]"))
USER_ENDPOINTS = json.loads(os.getenv("USER_ENDPOINTS", "[]"))

COMMON_HEADERS = {"Content-Type": "application/json"}

total_requests = 0
total_requests_lock = threading.Lock()


def increment_request_count():
    global total_requests
    with total_requests_lock:
        total_requests += 1


def stats_printer():
    global total_requests
    prev_total = 0
    start_time = time.time()

    while True:
        time.sleep(1)
        with total_requests_lock:
            current_total = total_requests
        qps = current_total - prev_total
        elapsed = int(time.time() - start_time)
        print(
            f"[STATS] {elapsed}s elapsed | Total Requests: {current_total} | QPS: {qps}"
        )
        prev_total = current_total


def login(user_type):
    creds = ACCOUNTS[user_type]
    try:
        res = requests.post(
            BASE_URL + LOGIN_ENDPOINT, json=creds, headers=COMMON_HEADERS
        )
        if res.status_code == 200 and "session_id" in res.cookies:
            return res.cookies["session_id"]
    except Exception as e:
        print(f"[!] Exception in login: {e}")
    return None


def call_api(session_id, endpoint):
    url = BASE_URL + endpoint["url"]
    method = endpoint["method"]
    headers = COMMON_HEADERS.copy()
    cookies = {"session_id": session_id}

    try:
        if method == "GET":
            res = requests.get(url, headers=headers, cookies=cookies)
        elif method == "POST":
            res = requests.post(
                url, headers=headers, json=endpoint.get("body", {}), cookies=cookies
            )
        elif method == "PUT":
            res = requests.put(
                url, headers=headers, json=endpoint.get("body", {}), cookies=cookies
            )
        elif method == "DELETE":
            res = requests.delete(
                url, headers=headers, json=endpoint.get("body", {}), cookies=cookies
            )
        else:
            print(f"[!] Unsupported method: {method}")
            return
        increment_request_count()
    except Exception as e:
        print(f"[!] Exception on {method} {endpoint['url']}: {str(e)}")


def load_test_worker(user_type):
    session_id = login(user_type)
    if not session_id:
        return

    endpoints = ADMIN_ENDPOINTS if user_type == "admin" else USER_ENDPOINTS
    for _ in range(10):
        endpoint = random.choice(endpoints)
        call_api(session_id, endpoint)
        time.sleep(random.uniform(0.3, 1.2))


def main(admin_count, user_count):
    stats_thread = threading.Thread(target=stats_printer, daemon=True)
    stats_thread.start()

    while True:
        try:
            with ThreadPoolExecutor(max_workers=admin_count + user_count) as executor:
                futures = []
                for _ in range(admin_count):
                    futures.append(executor.submit(load_test_worker, "admin"))
                for _ in range(user_count):
                    futures.append(executor.submit(load_test_worker, "user"))
                for f in as_completed(futures):
                    f.result()
            time.sleep(0.2)
        except Exception as e:
            print(f"[!] Exception in main loop: {e}")
            time.sleep(5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Load test with user/admin concurrency control"
    )
    parser.add_argument("--admin", type=int, default=5, help="Number of admin workers")
    parser.add_argument("--user", type=int, default=30, help="Number of user workers")
    args = parser.parse_args()

    main(admin_count=args.admin, user_count=args.user)
