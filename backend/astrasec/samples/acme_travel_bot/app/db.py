import pickle
import sqlite3

conn = sqlite3.connect("bookings.db")


def find_booking(ref: str):
    # Looks up a booking by the reference the customer typed.
    cur = conn.cursor()
    cur.execute("SELECT * FROM bookings WHERE ref = '" + ref + "'")
    return cur.fetchone()


def load_session(blob: bytes):
    return pickle.loads(blob)
