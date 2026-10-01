import os
from decouple import config

# ruleid: ethos.python.secret-env-fallback
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# ruleid: ethos.python.secret-env-fallback
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")

# ruleid: ethos.python.secret-env-fallback
STRIPE_API_KEY = config("STRIPE_API_KEY", default="sk_test_placeholder")

# ok: ethos.python.secret-env-fallback
SECRET_KEY_STRICT = os.environ["SECRET_KEY"]

# ok: ethos.python.secret-env-fallback
TOKEN_EXPIRES_MINUTES = os.getenv("TOKEN_EXPIRES_MINUTES", "30")

# ok: ethos.python.secret-env-fallback
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")

# ok: ethos.python.secret-env-fallback
OPTIONAL_TOKEN = os.getenv("GITHUB_TOKEN", "")

# ok: ethos.python.secret-env-fallback
DEBUG = os.environ.get("DEBUG", "0")
