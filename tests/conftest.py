import os
import tempfile
from app import app
from flask import Flask
import pytest

#Disable CSRF for testing
app.config['WTF_CSRF_METHODS'] = [] 
app.config['WTF_CSRF_ENABLED'] = False


@pytest.fixture
def client():
    #A test client for the app.
    return app.test_client()


@pytest.fixture
def runner():
    #A test runner for the app's Click commands.
    return app.test_cli_runner()


class AuthActions(object):
    #Preset login account to log into the application
    def __init__(self, client):
        self._client = client

    def login(self, uname="jack", pword="Test@1234", fa="00000000000"):
        return self._client.post(
            "/login", data={"uname": uname, "pword": pword, "2fa":fa}
        )

    def logout(self):
        return self._client.get("/logout")


@pytest.fixture
def auth(client):
    return AuthActions(client)
