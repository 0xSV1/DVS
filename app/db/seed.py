"""Database seeding: loads users, products, blog posts, and challenges from YAML."""

from __future__ import annotations

import hashlib
import json
import logging

import yaml

from app.core.config import BASE_DIR
from app.db.database import SessionLocal
from app.models.challenge import Challenge
from app.models.content import BlogPost
from app.models.product import Order, Product
from app.models.user import User

logger = logging.getLogger(__name__)


def _hash_password(password: str, method: str) -> str:
    """Hash password using the specified method.

    Intern/junior tiers use MD5 (deliberately weak).
    Plaintext is stored as-is (for the crypto challenge).
    """
    if method == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    if method == "plaintext":
        return password
    # Default fallback: MD5
    return hashlib.md5(password.encode()).hexdigest()


def seed_users(db_session: object) -> None:
    """Load seed users from YAML into the database."""
    seed_file = BASE_DIR / "data" / "seed_users.yml"
    if not seed_file.exists():
        logger.warning("Seed file not found: %s", seed_file)
        return

    data = yaml.safe_load(seed_file.read_text(encoding="utf-8"))

    # Seed users
    for user_data in data.get("users", []):
        user = User(
            username=user_data["username"],
            email=user_data["email"],
            password_hash=_hash_password(user_data["password"], user_data.get("password_hash_method", "md5")),
            role=user_data.get("role", "user"),
            bio=user_data.get("bio", ""),
            api_key=user_data.get("api_key"),
        )
        db_session.add(user)

    db_session.flush()

    # Seed products
    for prod_data in data.get("products", []):
        product = Product(
            name=prod_data["name"],
            description=prod_data.get("description", ""),
            price=prod_data["price"],
            image_url=prod_data.get("image_url", ""),
        )
        db_session.add(product)

    db_session.flush()

    # Seed blog posts
    user_map = {u.username: u.id for u in db_session.query(User).all()}
    for post_data in data.get("blog_posts", []):
        author_id = user_map.get(post_data.get("author"))
        post = BlogPost(
            title=post_data["title"],
            content=post_data["content"],
            author_id=author_id,
        )
        db_session.add(post)

    # Seed orders (for IDOR challenge)
    user_ids = {u.username: u.id for u in db_session.query(User).all()}
    product_ids = [p.id for p in db_session.query(Product).all()]

    orders_data = [
        {
            "user_id": user_ids.get("admin", 1),
            "product_id": product_ids[0] if product_ids else 1,
            "quantity": 1,
            "total_price": 99.99,
            "status": "completed",
            "shipping_address": "123 Startup Lane, San Francisco, CA 94107",
            "credit_card_last4": "4242",
        },
        {
            "user_id": user_ids.get("chad_shipper", 2),
            "product_id": product_ids[1] if len(product_ids) > 1 else 1,
            "quantity": 2,
            "total_price": 999.98,
            "status": "pending",
            "shipping_address": "456 VC Blvd, Palo Alto, CA 94301",
            "credit_card_last4": "1337",
        },
        {
            "user_id": user_ids.get("intern_jenny", 3),
            "product_id": product_ids[2] if len(product_ids) > 2 else 1,
            "quantity": 1,
            "total_price": 9999.99,
            "status": "pending",
            "shipping_address": "789 Dorm Room, Stanford University, CA 94305",
            "credit_card_last4": "0000",
        },
        {
            "user_id": user_ids.get("admin", 1),
            "product_id": product_ids[0] if product_ids else 1,
            "quantity": 5,
            "total_price": 499.95,
            "status": "completed",
            "shipping_address": "1 Infinite Deploy Loop, Cupertino, CA 95014",
            "credit_card_last4": "9999",
        },
        {
            "user_id": user_ids.get("chad_shipper", 2),
            "product_id": product_ids[1] if len(product_ids) > 1 else 1,
            "quantity": 10,
            "total_price": 4999.90,
            "status": "shipped",
            "shipping_address": "420 Vibe Check Ave, Austin, TX 78701",
            "credit_card_last4": "6969",
        },
        {
            "user_id": user_ids.get("test_user", 4),
            "product_id": product_ids[0] if product_ids else 1,
            "quantity": 1,
            "total_price": 0.01,
            "status": "refunded",
            "shipping_address": "000 Test Street, Localhost, CA 00000",
            "credit_card_last4": "1234",
        },
    ]
    for od in orders_data:
        db_session.add(Order(**od))
    db_session.flush()

    db_session.commit()
    logger.info(
        "Seeded %d users, %d products, %d blog posts, %d orders",
        len(data.get("users", [])),
        len(data.get("products", [])),
        len(data.get("blog_posts", [])),
        len(orders_data),
    )


def seed_challenges(db_session: object) -> None:
    """Load challenge definitions from YAML into the database."""
    challenges_file = BASE_DIR / "data" / "challenges.yml"
    if not challenges_file.exists():
        logger.warning("Challenges file not found: %s", challenges_file)
        return

    data = yaml.safe_load(challenges_file.read_text(encoding="utf-8"))

    for ch in data.get("challenges", []):
        atlas = ch.get("mitre_atlas")
        forge = ch.get("forge")
        challenge = Challenge(
            key=ch["key"],
            name=ch["name"],
            category=ch["category"],
            description=ch.get("description", ""),
            difficulty=ch["difficulty"],
            hint=ch.get("hint", ""),
            cwe=ch.get("cwe", ""),
            owasp_url=ch.get("owasp_url", ""),
            min_difficulty=ch.get("min_difficulty", "intern"),
            tags=",".join(ch.get("tags", "").split(","))
            if isinstance(ch.get("tags"), str)
            else ",".join(ch.get("tags", [])),
            mitre_atlas=json.dumps(atlas) if atlas else None,
            forge=json.dumps(forge) if forge else None,
        )
        db_session.add(challenge)

    db_session.commit()
    logger.info("Seeded %d challenges", len(data.get("challenges", [])))


def seed_all() -> None:
    """Run all seed functions."""
    db = SessionLocal()
    try:
        seed_users(db)
        seed_challenges(db)
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    seed_all()
