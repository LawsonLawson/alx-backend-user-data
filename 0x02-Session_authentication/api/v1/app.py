#!/usr/bin/env python3
"""
Route module for the API.
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import CORS
import os

app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

# Initialize auth based on environment variable
auth = None
AUTH_TYPE = getenv("AUTH_TYPE")
if AUTH_TYPE == 'auth':
    from api.v1.auth.auth import Auth
    auth = Auth()
elif AUTH_TYPE == 'basic_auth':
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()
elif AUTH_TYPE == "session_auth":
    from api.v1.auth.session_auth import SessionAuth
    auth = SessionAuth()


@app.errorhandler(401)
def unauthorized(error) -> str:
    """
    Error handler for 401 Unauthorized.
    Returns:
        A JSON response with a 401 status code.
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """
    Error handler for 403 Forbidden.
    Returns:
        A JSON response with a 403 status code.
    """
    return jsonify({"error": "Forbidden"}), 403


@app.errorhandler(404)
def not_found(error) -> str:
    """
    Error handler for 404 Not Found.
    Returns:
        A JSON response with a 404 status code.
    """
    return jsonify({"error": "Not found"}), 404


@app.before_request
def before_request() -> str:
    """
    Function to handle operations before each request.
    Ensures proper authentication for protected routes.
    """
    if auth is None:
        return
    excluded_paths = [
        '/api/v1/status/',
        '/api/v1/unauthorized/',
        '/api/v1/forbidden/',
        '/api/v1/auth_session/login/'
    ]
    if not auth.require_auth(request.path, excluded_paths):
        return
    if not auth.authorization_header(request) and not\
            auth.session_cookie(request):
        abort(401)
    if auth.current_user(request) is None:
        abort(403)
    request.current_user = auth.current_user(request)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
