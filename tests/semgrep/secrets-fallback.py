import os
from decouple import config

# ruleid: ethos.python.secret-env-fallback
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# ruleid: ethos.python.secret-env-fallback
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")

# ruleid: ethos.python.secret-env-fallback
STRIPE_API_KEY = config("STRIPE_API_KEY", default="sk_test_placeholder")

# ruleid: ethos.python.secret-env-fallback
FLASK_SECRET = os.getenv("SECRET_KEY") or "dev-secret"

# ruleid: ethos.python.secret-env-fallback
JWT_SIGNING = os.environ.get("JWT_SECRET", default="change-me")

# ruleid: ethos.python.secret-env-fallback
API_TOKEN = os.environ.get("API_TOKEN", "") or "change-me"

# ruleid: ethos.python.secret-env-fallback
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", default="admin")

# ruleid: ethos.python.secret-env-fallback
VALID_API_TOKENS = os.getenv("VALID_API_TOKENS", "tok-1,tok-2")

# ok: ethos.python.secret-env-fallback
SECRET_KEY_STRICT = os.environ["SECRET_KEY"]

# ok: ethos.python.secret-env-fallback
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "1024"))

# ok: ethos.python.secret-env-fallback
OPENAI_MAX_TOKENS = os.environ.get("OPENAI_MAX_TOKENS", "4096")

# ok: ethos.python.secret-env-fallback
PASSWORD_RESET_TIMEOUT = int(os.environ.get("PASSWORD_RESET_TIMEOUT", "3600"))

# ok: ethos.python.secret-env-fallback
PASSWORD_HASH_ROUNDS = int(os.getenv("PASSWORD_HASH_ROUNDS", default="12"))

# ok: ethos.python.secret-env-fallback
CSRF_TOKEN_COOKIE = os.getenv("CSRF_TOKEN_COOKIE") or "csrftoken"

# ok: ethos.python.secret-env-fallback
ACCESS_TOKEN_EXPIRES_IN = os.environ.get("ACCESS_TOKEN_EXPIRES_IN") or "15m"

# ok: ethos.python.secret-env-fallback
OPTIONAL_GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") or ""

# ok: ethos.python.secret-env-fallback
TOKEN_EXPIRES_MINUTES = os.getenv("TOKEN_EXPIRES_MINUTES", "30")

# ok: ethos.python.secret-env-fallback
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")

# ok: ethos.python.secret-env-fallback
OPTIONAL_TOKEN = os.getenv("GITHUB_TOKEN", "")

# ok: ethos.python.secret-env-fallback
DEBUG = os.environ.get("DEBUG", "0")
