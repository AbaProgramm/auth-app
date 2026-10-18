import os
os.environ.setdefault("DATABASE_URL", "postgresql://x")
os.environ.setdefault("JWT_SECRET", "t")

def test_import():
    from app import main  # noqa
    assert main.app.title == "auth-app"
