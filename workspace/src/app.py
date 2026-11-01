"""Lumen API (demo stub). Real logic is out of scope for the talk."""
import os


def config():
    return {k: v for k, v in os.environ.items() if k.startswith(("DATABASE_", "PAYMENT_", "DEMO_"))}


def healthz():
    return "ok"
