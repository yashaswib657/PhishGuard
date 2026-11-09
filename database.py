
import sqlite3

DB_NAME = "phishguard.db"


def create_database():

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            score INTEGER,
            risk TEXT,
            findings TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_analysis(email, result):

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO history
        (email, score, risk, findings)
        VALUES (?, ?, ?, ?)
    """, (
        email,
        result["score"],
        result["risk"],
        "\n".join(result["findings"])
    ))

    connection.commit()
    connection.close()


def get_history():

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM history")

    records = cursor.fetchall()

    connection.close()

    return records
