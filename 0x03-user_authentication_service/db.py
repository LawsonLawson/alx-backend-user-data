#!/usr/bin/env python3
"""DB module.

This module defines a DB class that provides basic database operations
for interacting with a SQLite database using SQLAlchemy. It includes
methods for adding, finding, and updating users.
"""
from sqlalchemy import create_engine, tuple_
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session

from user import Base, User


class DB:
    """DB class for interacting with the database.

    This class provides methods to add, find, and update users
    in a SQLite database using SQLAlchemy ORM.
    """

    def __init__(self) -> None:
        """Initialize a new DB instance.

        This method initializes the database engine and creates
        all the required tables defined in the Base metadata.
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object.

        Returns a SQLAlchemy session if one is not already created.
        If a session exists, it returns the existing session.

        Returns:
            Session: A SQLAlchemy session bound to the engine.
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Adds a new user to the database.

        This method creates a new User instance with the provided
        email and hashed password and commits it to the database.

        Args:
            email (str): The email address of the user.
            hashed_password (str): The hashed password of the user.

        Returns:
            User: The newly added user or None if the operation fails.
        """
        try:
            new_user = User(email=email, hashed_password=hashed_password)
            self._session.add(new_user)
            self._session.commit()
        except Exception:
            self._session.rollback()
            new_user = None
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Finds a user based on a set of filters.

        This method queries the database to find a user based on the
        provided keyword arguments (filters). If no user is found or
        an invalid filter is provided, an appropriate exception is raised.

        Args:
            **kwargs: Arbitrary keyword arguments representing the fields
                      and their values to filter by.

        Raises:
            InvalidRequestError: If an invalid filter key is provided.
            NoResultFound: If no user is found with the provided filters.

        Returns:
            User: The user that matches the given filters.
        """
        fields, values = [], []
        for key, value in kwargs.items():
            if hasattr(User, key):
                fields.append(getattr(User, key))
                values.append(value)
            else:
                raise InvalidRequestError()
        result = self._session.query(User).filter(
            tuple_(*fields).in_([tuple(values)])
        ).first()
        if result is None:
            raise NoResultFound()
        return result

    def update_user(self, user_id: int, **kwargs) -> None:
        """Updates a user based on a given user ID.

        This method updates the attributes of an existing user
        with the given keyword arguments.

        Args:
            user_id (int): The ID of the user to be updated.
            **kwargs: Arbitrary keyword arguments representing
                      the fields and their new values.

        Raises:
            ValueError: If an invalid field is provided.

        Returns:
            None
        """
        user = self.find_user_by(id=user_id)
        if user is None:
            return
        update_source = {}
        for key, value in kwargs.items():
            if hasattr(User, key):
                update_source[getattr(User, key)] = value
            else:
                raise ValueError()
        self._session.query(User).filter(User.id == user_id).update(
            update_source,
            synchronize_session=False,
        )
        self._session.commit()
