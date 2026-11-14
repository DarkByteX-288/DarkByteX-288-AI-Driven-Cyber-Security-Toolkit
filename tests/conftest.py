import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models import db
from models.user import User


@pytest.fixture
def app():
    application = create_app("testing")
    with application.app_context():
        db.drop_all()
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def user(app):
    with app.app_context():
        account = User(username="scanner-user", email="scanner@example.test")
        account.set_password("TestPassword-123!")
        db.session.add(account)
        db.session.commit()
        return account.id


@pytest.fixture
def authenticated_client(app, user):
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(user)
        session["_fresh"] = True
    return client
