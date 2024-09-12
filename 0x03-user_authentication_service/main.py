#!/usr/bin/env python3
"""
A simple end-to-end (E2E) integration test for `app.py`.

This script tests user registration, login, profile access, session handling,
password reset, and update functionalities for a Flask web application.
"""
import requests

# Constants for test values
EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"
BASE_URL = "http://0.0.0.0:5000"


def register_user(email: str, password: str) -> None:
    """
    Test registering a new user.

    Args:
        email (str): The user's email.
        password (str): The user's password.

    Tests:
        - Registers a new user.
        - Ensures registration fails if the email is already registered.
    """
    url = f"{BASE_URL}/users"
    body = {
        'email': email,
        'password': password,
    }
    res = requests.post(url, data=body)
    assert res.status_code == 200
    assert res.json() == {"email": email, "message": "user created"}

    # Test registration with the same email (should fail)
    res = requests.post(url, data=body)
    assert res.status_code == 400
    assert res.json() == {"message": "email already registered"}


def log_in_wrong_password(email: str, password: str) -> None:
    """
    Test logging in with a wrong password.

    Args:
        email (str): The user's email.
        password (str): The wrong password.

    Tests:
        - Ensures login fails with an incorrect password.
    """
    url = f"{BASE_URL}/sessions"
    body = {
        'email': email,
        'password': password,
    }
    res = requests.post(url, data=body)
    assert res.status_code == 401


def log_in(email: str, password: str) -> str:
    """
    Test logging in with correct credentials.

    Args:
        email (str): The user's email.
        password (str): The user's correct password.

    Returns:
        str: The session ID.

    Tests:
        - Ensures login is successful with valid credentials.
        - Retrieves the session ID.
    """
    url = f"{BASE_URL}/sessions"
    body = {
        'email': email,
        'password': password,
    }
    res = requests.post(url, data=body)
    assert res.status_code == 200
    assert res.json() == {"email": email, "message": "logged in"}
    return res.cookies.get('session_id')


def profile_unlogged() -> None:
    """
    Test accessing the profile while not logged in.

    Tests:
        - Ensures access to the profile is forbidden without login.
    """
    url = f"{BASE_URL}/profile"
    res = requests.get(url)
    assert res.status_code == 403


def profile_logged(session_id: str) -> None:
    """
    Test accessing the profile while logged in.

    Args:
        session_id (str): The session ID for authentication.

    Tests:
        - Ensures profile information can be retrieved when logged in.
    """
    url = f"{BASE_URL}/profile"
    req_cookies = {
        'session_id': session_id,
    }
    res = requests.get(url, cookies=req_cookies)
    assert res.status_code == 200
    assert "email" in res.json()


def log_out(session_id: str) -> None:
    """
    Test logging out from a session.

    Args:
        session_id (str): The session ID for authentication.

    Tests:
        - Ensures the user is successfully logged out.
    """
    url = f"{BASE_URL}/sessions"
    req_cookies = {
        'session_id': session_id,
    }
    res = requests.delete(url, cookies=req_cookies)
    assert res.status_code == 200
    assert res.json() == {"message": "Bienvenue"}


def reset_password_token(email: str) -> str:
    """
    Test requesting a password reset token.

    Args:
        email (str): The user's email.

    Returns:
        str: The password reset token.

    Tests:
        - Ensures a password reset token is issued for a valid email.
    """
    url = f"{BASE_URL}/reset_password"
    body = {'email': email}
    res = requests.post(url, data=body)
    assert res.status_code == 200
    assert "email" in res.json()
    assert res.json()["email"] == email
    assert "reset_token" in res.json()
    return res.json().get('reset_token')


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """
    Test updating a user's password with a reset token.

    Args:
        email (str): The user's email.
        reset_token (str): The password reset token.
        new_password (str): The new password to be set.

    Tests:
        - Ensures the password is updated successfully using a valid token.
    """
    url = f"{BASE_URL}/reset_password"
    body = {
        'email': email,
        'reset_token': reset_token,
        'new_password': new_password,
    }
    res = requests.put(url, data=body)
    assert res.status_code == 200
    assert res.json() == {"email": email, "message": "Password updated"}


if __name__ == "__main__":
    # Test the complete flow from registration to password reset and login
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
