#!/usr/bin/env python3
"""Define SessionAuth class."""

from api.v1.auth.auth import Auth
from uuid import uuid4
from models.user import User


class SessionAuth(Auth):
    """
    Extend behavior of Auth class for session authentication.
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Create and return a session ID for a user ID.

        Args:
            user_id (str): The user ID to create a session for.

        Returns:
            str: The session ID generated for the user, or None if invalid.
        """
        if user_id is None or not isinstance(user_id, str):
            return None

        session_id = str(uuid4())
        SessionAuth.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Return the user ID associated with a given session ID.

        Args:
            session_id (str): The session ID to look up.

        Returns:
            str: The associated user ID, or None if invalid.
        """
        if session_id is None or not isinstance(session_id, str):
            return None

        return SessionAuth.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """
        Return a User instance based on a session cookie from the request.

        Args:
            request (Request): The incoming request.

        Returns:
            User: The User instance associated with the session ID, or None.
        """
        session_id = self.session_cookie(request)
        if session_id is None:
            return None

        user_id = self.user_id_for_session_id(session_id)

        return User.get(user_id)

    def destroy_session(self, request=None):
        """
        Destroy a user's session, effectively logging them out.

        Args:
            request (Request): The incoming request.

        Returns:
            bool: True if the session was successfully destroyed, False
            otherwise.
        """
        if request is None:
            return False

        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        user_id = self.user_id_for_session_id(session_id)
        if not user_id:
            return False

        try:
            del self.user_id_by_session_id[session_id]
        except Exception:
            pass

        return True
