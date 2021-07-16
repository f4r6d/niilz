import os

from cs50 import SQL


# Configure CS50 Library to use SQLite database
uri = os.environ.get("DATABASE_URL")
uri = uri.replace("postgres://", "postgresql://", 1)
db = SQL(uri)


db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, hash TEXT NOT NULL, cash NUMERIC NOT NULL DEFAULT 10000.00)")

db.execute("CREATE TABLE trans (user_id INTEGER, symbol TEXT NOT NULL, shares NUMERIC NOT NULL, price NUMERIC NOT NULL DEFAULT 0, ts  TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))")