import pytest
import os
import subprocess
from subprocess import Popen, PIPE
from subprocess import check_output
from flask import Flask, render_template, request
import json
from flask import session, redirect, url_for

 # Test page load successfully
def test_register(client):   
    assert client.get("/register").status_code == 200


#Test login page has required fields
def test_login_page(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b"uname" in response.data
    assert b"pword" in response.data
    assert b"2fa" in response.data


def test_login(client, auth):
    # Test page load successfully
    assert client.get("/login").status_code == 200

    # Log into the page
    response = auth.login()

    # login request set the loggin_in in the session
    # check that the user is loaded from the session
    with client:
        client.get("/login")
        assert session["logged_in"] == True


# Test spell check
@pytest.mark.parametrize(
    ("inputtext", "result"),
    (
        ("Test tsd bed tekd", b"tsd, tekd"),
    ),
)
def test_spell_check(client, auth, inputtext, result):
     # Login the system
    response = auth.login()

    with client:
        client.get("/spell_check")
        response = client.get('/spell_check')
        # Test load spell_check page successfully
        assert response.status_code == 200
        response = client.post("/spell_check", data={"inputtext": inputtext})
        # Check spell check return
        assert result in response.data


# Test logout
def test_logout(client, auth):
    auth.login()

    with client:
        auth.logout()
        assert "logged_in" not in session
