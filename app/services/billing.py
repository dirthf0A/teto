from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.models import Plan, Subscription


DEFAULT_PLANS = [
    {"name": "Free", "description": "Starter monitoring and basic asset inventory.", "price_monthly": 0.0},
    {"name": "Team", "description": "Continuous scanning, alerts, and reporting.", "price_monthly": 499.0},
    {"name": "Enterprise", "description": "Dedicated workers, SLA, and advanced intelligence.", "price_monthly": 1999.0},
]


def ensure_default_plans(db: Session) -> list[Plan]:
    existing = db.execute(select(Plan)).scalars().all()
    if existing:
        return existing
    for plan in DEFAULT_PLANS:
        db.add(
            Plan(
                name=plan["name"],
                description=plan["description"],
                price_monthly=plan["price_monthly"],
                currency="usd",
            )
        )
    db.commit()
    return db.execute(select(Plan)).scalars().all()


def get_or_create_subscription(db: Session, org_id: int) -> Subscription:
    subscription = (
        db.execute(select(Subscription).where(Subscription.org_id == org_id))
        .scalars()
        .first()
    )
    if subscription:
        return subscription
    subscription = Subscription(org_id=org_id, status="trialing")
    db.add(subscription)
    db.commit()
    db.refresh(subscription)
    return subscription


def create_checkout_session(db: Session, org_id: int, plan_id: int) -> str:
    secret = config.get_stripe_secret_key()
    if not secret:
        raise RuntimeError("Stripe is not configured.")
    try:
        import stripe
    except ImportError as exc:
        raise RuntimeError("Stripe SDK not installed.") from exc

    plan = db.get(Plan, plan_id)
    if not plan:
        raise RuntimeError("Plan not found.")
    price_id = plan.stripe_price_id or config.get_stripe_default_price_id()
    if not price_id:
        raise RuntimeError("Stripe price id not configured.")

    stripe.api_key = secret
    session = stripe.checkout.Session.create(
        mode="subscription",
        success_url=config.get_stripe_success_url(),
        cancel_url=config.get_stripe_cancel_url(),
        line_items=[{"price": price_id, "quantity": 1}],
        metadata={"org_id": str(org_id), "plan_id": str(plan_id)},
    )

    subscription = get_or_create_subscription(db, org_id)
    subscription.plan_id = plan_id
    subscription.status = "pending"
    db.commit()
    return session.url or ""


def parse_webhook(payload: bytes, sig_header: Optional[str]) -> Optional[dict]:
    secret = config.get_stripe_webhook_secret()
    try:
        import stripe
    except ImportError:
        stripe = None

    event = None
    if stripe and secret and sig_header:
        event = stripe.Webhook.construct_event(payload, sig_header, secret)
    if event is None:
        try:
            event = json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError:
            return None
    return event if isinstance(event, dict) else None


def apply_webhook_event(db: Session, event: dict) -> None:
    event_type = event.get("type")
    data = event.get("data", {}).get("object", {}) if isinstance(event.get("data"), dict) else {}
    metadata = data.get("metadata") or {}
    org_id = metadata.get("org_id")
    if org_id:
        try:
            org_id = int(org_id)
        except ValueError:
            org_id = None

    if not org_id:
        return

    subscription = get_or_create_subscription(db, org_id)
    subscription.stripe_customer_id = data.get("customer") or subscription.stripe_customer_id
    subscription.stripe_subscription_id = data.get("subscription") or data.get("id") or subscription.stripe_subscription_id

    if event_type == "checkout.session.completed":
        subscription.status = "active"
    elif event_type in {"customer.subscription.updated", "customer.subscription.deleted"}:
        subscription.status = data.get("status") or subscription.status

    period_end = data.get("current_period_end")
    if isinstance(period_end, (int, float)):
        subscription.current_period_end = datetime.utcfromtimestamp(period_end)
    db.commit()
