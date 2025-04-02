# Sigall Benchmark

A lightweight tool for simulating concurrent admin and user API interactions to benchmark performance.

---

## Requirements

- Python 3.8+
- Recommended: use a virtual environment (`venv` or `virtualenv`)

### Install dependencies

```bash
pip install -r requirements.txt
```

### Target API Requirements
Target API Requirements

- The login API must accept POST { user_id, password } in JSON body. (If it doesn't, it must be modified to meet your format.)
- A successful login should return a session_id cookie
- Authenticated endpoints must accept that cookie
- API must be reachable at BASE_URL (e.g. http://localhost:80)

## Environment Configuration
Create a .env file in the root of the project with the following values
```env
BASE_URL=http://localhost:80
LOGIN_ENDPOINT=/api/login

ADMIN_USER_ID=your_admin_id
ADMIN_PASSWORD=your_admin_password
USER_USER_ID=your_user_id
USER_PASSWORD=your_user_password

ADMIN_ENDPOINTS=[{"method": "GET", "url": "/api/rule/admin"}]
USER_ENDPOINTS=[{"method": "GET", "url": "/api/rule/user"}, {"method": "GET", "url": "/api/rule/user/count"}]
```

## Run the bench
```bash
python bench.py --admin 5 --user 30
```

### Available Options

| Option     | Description                          | Default |
|------------|--------------------------------------|---------|
| `--admin`  | Number of concurrent admin workers   | `5`     |
| `--user`   | Number of concurrent user workers    | `30`    |
