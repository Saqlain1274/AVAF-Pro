"""
===============================================================================
SQL Injection Indicators

Contains SQL error signatures used by the SQL Injection detector.

Responsibilities
----------------
✔ Database error signatures
✔ Error-based detection patterns

Never
-----
✘ HTTP requests
✘ Payload generation
✘ Validation
===============================================================================
"""

from __future__ import annotations


DATABASE_ERRORS = {

    "mysql": (

        "SQL syntax",

        "You have an error in your SQL syntax",

        "mysql_fetch",

        "mysqli",

        "MySQL server version",

    ),

    "postgresql": (

        "PostgreSQL",

        "pg_query",

        "pg_fetch",

        "ERROR: syntax error",

    ),

    "mssql": (

        "Microsoft SQL Server",

        "ODBC SQL Server Driver",

        "Unclosed quotation mark",

        "SQLServerException",

    ),

    "oracle": (

        "ORA-",

        "Oracle error",

        "OCIError",

    ),

    "sqlite": (

        "SQLite",

        "sqlite3.OperationalError",

        "SQLite.Exception",

    ),

    "mariadb": (

        "MariaDB",

        "MariaDB server version",

    ),

    "generic": (

        "PDOException",

        "SQLSTATE",

        "syntax error",

        "database error",

    ),
}