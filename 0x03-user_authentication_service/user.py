#!/usr/bin/env python3
"""
The `user` model's module.

This module defines the User class, which represents a record in the `users`
table within a relational database. SQLAlchemy is used for object-relational
mapping (ORM) to interact with the database. The `User` class is mapped to the
`users` table and defines various attributes such as `id`, `email`,
`hashed_password`, `session_id`, and `reset_token`.
"""

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

# `Base` is the base class for all models in SQLAlchemy. It allows us to define
# classes that
# map to database tables.
Base = declarative_base()


class User(Base):
    """
    Represents a record from the `users` table.

    This class maps to a database table called `users`. Each instance of the
    `User` class corresponds to a row in the table. The class defines several
    fields that represent the columns in the table:

    Attributes:
        id (int): The primary key of the `users` table, unique for each record.
        email (str): The email address of the user, stored as a string with a
        max length of 250 characters. This field is required (nullable=False).
        hashed_password (str): The hashed version of the user's password,
        stored as a string with a max length of 250 characters. This field is
        required (nullable=False).
        session_id (str): Optional. Represents the session ID for the user,
        used to track user sessions. It has a max length of 250 characters and
        can be `null` (nullable=True).
        reset_token (str): Optional. Represents a token used to reset the
        user's password. It has a max length of 250 characters and can be
        `null` (nullable=True).
    """

    # The name of the database table that this model maps to.
    __tablename__ = "users"

    # The `id` column, which is an integer and the primary key for the table.
    # `primary_key=True` ensures that each row will have a unique `id`.
    id = Column(Integer, primary_key=True)

    # The `email` column, which is a string with a maximum length of 250
    # characters.
    # This field is required, so `nullable=False` is set.
    email = Column(String(250), nullable=False)

    # The `hashed_password` column, which is a string with a maximum length of
    # 250 characters.
    # This is used to store the hashed password of the user, and it is required
    # (`nullable=False`).
    hashed_password = Column(String(250), nullable=False)

    # The `session_id` column, which is an optional string (can be `null`). It
    # stores the user's session ID for tracking user sessions in the
    # application.
    session_id = Column(String(250), nullable=True)

    # The `reset_token` column, which is also an optional string (can be
    # null`). It is used to store a token that allows users to reset their
    # password.
    reset_token = Column(String(250), nullable=True)
