# ============================================================
# AUTH — Google OAuth + Stripe billing helpers
# ============================================================

import os
from datetime import datetime, timedelta

import stripe
from authlib.integrations.flask_client import OAuth

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
STRIPE_SECRET_KEY    = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUB_KEY       = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SEC   = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID      = os.getenv("STRIPE_PRICE_ID", "")
TRIAL_DAYS           = int(os.getenv("TRIAL_DAYS", "14"))

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

oauth = OAuth()


def init_auth(app):
    """Call once after creating the Flask app."""
    oauth.init_app(app)
    if GOOGLE_CLIENT_ID:
        oauth.register(
            name="google",
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )


def is_user_subscribed(user: dict) -> bool:
    """Return True if user has an active subscription or a valid trial."""
    if not user:
        return False
    status = user.get("subscription_status", "")
    if status == "active":
        return True
    if status == "trial":
        try:
            created = datetime.fromisoformat(user["created_at"])
            return datetime.now() < created + timedelta(days=TRIAL_DAYS)
        except (KeyError, ValueError):
            return False
    return False


def trial_days_left(user: dict) -> int:
    """Days remaining in trial (0 if not on trial or expired)."""
    if not user or user.get("subscription_status") != "trial":
        return 0
    try:
        created = datetime.fromisoformat(user["created_at"])
        remaining = (created + timedelta(days=TRIAL_DAYS)) - datetime.now()
        return max(0, remaining.days)
    except (KeyError, ValueError):
        return 0
