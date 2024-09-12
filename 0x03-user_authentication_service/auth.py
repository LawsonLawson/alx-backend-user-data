#!/usr/bin/env python3
"""A module for authentication-related routines.

This module provides the authentication-related operations such as
user registration, login validation, session management, password
reset handling, and password updates. It leverages bcrypt for
password hashing and SQLAlchemy for database interactions.
"""
import bcrypt
from uuid import uuid4
from typing import Union
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt.

    Args:
        password (str): The plain text password to hash.

    Returns:
        bytes: The hashed password as a byte string.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generates a UUID.

    Returns:
        str: A new unique identifier as a string.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.

    This class provides methods to register users, validate logins,
    manage user sessions, and handle password resets.
    """

    def __init__(self) -> None:
        """Initializes a new Auth instance.

        This method sets up the database object used for user-related
        operations.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user.

        This method checks if the user already exists. If not, it
        creates a new user with the provided email and hashed password.

        Args:
            email (str): The user's email.
            password (str): The user's plain text password.

        Raises:
            ValueError: If the user already exists.

        Returns:
            User: The newly created user instance.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError("User {} already exists".format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """Validates user login credentials.

        This method checks if the provided email and password match
        the user's stored credentials.

        Args:
            email (str): The user's email.
            password (str): The user's plain text password.

        Returns:
            bool: True if the credentials are valid, False otherwise.
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                return bcrypt.checkpw(
                    password.encode("utf-8"),
                    user.hashed_password,
                )
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> Union[str, None]:
        """Creates a new session for the user.

        This method generates a session ID for the user and stores it
        in the database.

        Args:
            email (str): The user's email.

        Returns:
            Union[str, None]: The session ID or None if the user is not found.
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if user is None:
            return None
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Retrieves a user from a given session ID.

        Args:
            session_id (str): The session ID associated with the user.

        Returns:
            Union[User, None]: The user instance or None if no user is found.
        """
        user = None
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session for a given user.

        This method invalidates a user's session by setting the session ID
        to None.

        Args:
            user_id (int): The ID of the user whose session is to be destroyed.

        Returns:
            None
        """
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a password reset token for the user.

        This method creates a reset token for the user, which can be
        used to reset their password.

        Args:
            email (str): The user's email.

        Raises:
            ValueError: If the user is not found.

        Returns:
            str: The reset token.
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError("User not found")
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates the user's password using a reset token.

        This method updates the user's password if the provided reset
        token is valid.

        Args:
            reset_token (str): The password reset token.
            password (str): The new plain text password.

        Raises:
            ValueError: If the reset token is invalid.

        Returns:
            None
        """
        user = None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError("Invalid reset token")
        new_password_hash = _hash_password(password)
        self._db.update_user(
            user.id,
            hashed_password=new_password_hash,
            reset_token=None,
        )
