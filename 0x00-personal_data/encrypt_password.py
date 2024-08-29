#!/usr/bin/env python3
"""
Encrypting passwords.

This module provides two functions to handle password encryption and validation
using the bcrypt library. The primary operations are hashing a password and
verifying if a given password matches a hashed password.

Functions:
- hash_password: Hashes a password using bcrypt with a salt.
- is_valid: Validates a password against a hashed password.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt with a salt.

    Args:
        password (str): The plain text password to be hashed.

    Returns:
        bytes: The salted, hashed password as a byte string.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against a hashed password.

    This function checks if the provided plain text password matches the
    hashed password.

    Args:
        hashed_password (bytes): The hashed password to be compared.
        password (str): The plain text password to validate.

    Returns:
        bool: True if the password matches the hashed password, False otherwise
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
