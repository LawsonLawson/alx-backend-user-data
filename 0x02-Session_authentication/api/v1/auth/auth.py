#!/usr/bin/env python3
"""Auth class, manages authentication with wildcard paths."""
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """Class to manage the API authentication methods."""
    
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determine if a given path requires authentication.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): A list of paths that don't require authentication.

        Returns:
            bool: True if the path requires authentication, False otherwise.
        """
        if path is None or excluded_paths is None or not len(excluded_paths):
            return True
        if path[-1] != "/":
            path += "/"
        for i in excluded_paths:
            if i.endswith("*"):
                if path.startswith(i[:-1]):
                    return False
        if path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieve the Authorization header from the incoming request.

        Args:
            request (Request): The request object.

        Returns:
            str: The Authorization header, or None if not present.
        """
        if request is None:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar("User"):
        """
        Placeholder method for retrieving the current user.

        Args:
            request (Request): The request object.

        Returns:
            User: None for now (to be implemented in subclasses).
        """
        return None

    def session_cookie(self, request=None):
        """
        Retrieve the session cookie from the request.

        Args:
            request (Request): The request object.

        Returns:
            str: The session cookie value, or None if not present.
        """
        if request is None:
            return None
        session_name = getenv("SESSION_NAME")
        return request.cookies.get(session_name)
