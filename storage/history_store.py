"""SQLite-based history store for Aegis-SOC alerts."""

import sqlite3
import os

# Database path in project root
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "aegis_history.db")


def get_connection():
	"""Create and return a database connection."""
	return sqlite3.connect(DB_PATH)


def init_db():
	"""Initialize the database and create alert_history table if it doesn't exist."""
	with get_connection() as conn:
		cursor = conn.cursor()
		cursor.execute(
			"""
			CREATE TABLE IF NOT EXISTS alert_history (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				source_ip TEXT,
				alert_type TEXT,
				attempt_count INTEGER,
				timestamp TEXT
			)
			"""
		)
		conn.commit()


def save_alerts(alerts):
	"""Insert alerts into the alert_history table."""
	if not alerts:
		return

	with get_connection() as conn:
		cursor = conn.cursor()
		for alert in alerts:
			cursor.execute(
				"""
				INSERT INTO alert_history (source_ip, alert_type, attempt_count, timestamp)
				VALUES (?, ?, ?, ?)
				""",
				(
					alert.get("source_ip"),
					alert.get("alert_type"),
					alert.get("attempt_count"),
					alert.get("timestamp"),
				),
			)
		conn.commit()


def get_historical_data():
	"""Retrieve all rows from alert_history as a list of dicts."""
	with get_connection() as conn:
		conn.row_factory = sqlite3.Row
		cursor = conn.cursor()
		cursor.execute(
			"SELECT source_ip, alert_type, attempt_count, timestamp FROM alert_history"
		)
		rows = cursor.fetchall()
		return [dict(row) for row in rows]


# Initialize database on module import
init_db()
