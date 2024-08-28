#!/usr/bin/env python3
"""
A module for filtering logs.

This script sets up a logging system that handles sensitive user data.
It filters out Personally Identifiable Information (PII) from logs,
ensuring that sensitive data such as names, emails, phone numbers,
social security numbers, and passwords are redacted.

Key Functions:
- filter_datum: Filters sensitive information from a log message.
- get_logger: Creates and configures a logger for user data.
- get_db: Establishes a connection to a MySQL database.
- main: Logs user data from a database, ensuring that sensitive information is
redacted.

Classes:
- RedactingFormatter: A custom logging formatter that redacts sensitive data in
log messages.
"""

import os
import re
import logging
import mysql.connector
from typing import List


# Patterns used for filtering and replacing sensitive data
patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}

# Fields that contain Personally Identifiable Information (PII)
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str, separator:
                 str) -> str:
    """
    Filters a log line by redacting sensitive information.

    Args:
        fields (List[str]): The list of fields to redact.
        redaction (str): The string to replace the sensitive information with.
        message (str): The log message to filter.
        separator (str): The character that separates fields in the log message

    Returns:
        str: The filtered log message with sensitive information redacted.
    """
    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """
    Creates a new logger for user data.

    This logger will handle logs that involve sensitive user information and
    ensures that such information is redacted before logging.

    Returns:
        logging.Logger: A configured logger instance for user data.
    """
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Creates a connector to a MySQL database.

    The connection parameters are retrieved from environment variables.

    Returns:
        mysql.connector.connection.MySQLConnection: A MySQL database
        connection object.
    """
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    connection = mysql.connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return connection


def main():
    """
    Logs the information about user records in a table.

    This function retrieves user data from the 'users' table in the database,
    and logs each record while redacting sensitive information.
    """
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()

    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()

        for row in rows:
            record = map(lambda x: '{}={}'.format(x[0], x[1]), zip(columns,
                         row))
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class.

    This custom formatter redacts sensitive information from log messages
    before they are outputted.
    """
    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initializes the RedactingFormatter.

        Args:
            fields (List[str]): The list of fields to redact.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Formats a log record by redacting sensitive information.

        Args:
            record (logging.LogRecord): The log record to format.

        Returns:
            str: The formatted log message with sensitive information redacted.
        """
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt


if __name__ == "__main__":
    main()
