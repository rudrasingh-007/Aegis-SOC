import os
import json
from datetime import datetime
import sqlite3


DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "aegis_history.db")


def get_connection():
	return sqlite3.connect(DB_PATH)


def init_tickets_db():
	try:
		with get_connection() as conn:
			cursor = conn.cursor()
			cursor.execute(
				"""
				CREATE TABLE IF NOT EXISTS fp_tickets (
					ticket_id TEXT PRIMARY KEY,
					alert_id TEXT,
					source_ip TEXT,
					alert_type TEXT,
					severity TEXT,
					status TEXT,
					created_at TEXT,
					updated_at TEXT,
					closed_at TEXT,
					closure_reason TEXT,
					notes TEXT
				)
				"""
			)
			conn.commit()
	except Exception as error:
		print(f"Error initializing tickets database: {error}")


def create_ticket(alert):
	try:
		alert_id = str(alert.get("alert_id", ""))
		current_time = datetime.utcnow().isoformat()
		ticket = {
			"ticket_id": f"TICKET-{alert_id}",
			"alert_id": alert_id,
			"source_ip": alert.get("source_ip", ""),
			"alert_type": alert.get("alert_type", ""),
			"severity": alert.get("severity", ""),
			"status": "OPEN",
			"created_at": current_time,
			"updated_at": current_time,
			"closed_at": "",
			"closure_reason": "",
			"notes": "",
		}

		with get_connection() as conn:
			cursor = conn.cursor()
			cursor.execute(
				"""
				INSERT INTO fp_tickets (
					ticket_id, alert_id, source_ip, alert_type, severity, status,
					created_at, updated_at, closed_at, closure_reason, notes
				)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				""",
				(
					ticket["ticket_id"],
					ticket["alert_id"],
					ticket["source_ip"],
					ticket["alert_type"],
					ticket["severity"],
					ticket["status"],
					ticket["created_at"],
					ticket["updated_at"],
					ticket["closed_at"],
					ticket["closure_reason"],
					ticket["notes"],
				),
			)
			conn.commit()
		return ticket
	except Exception as error:
		print(f"Error creating ticket: {error}")
		return None


def get_all_tickets():
	try:
		with get_connection() as conn:
			conn.row_factory = sqlite3.Row
			cursor = conn.cursor()
			cursor.execute("SELECT * FROM fp_tickets")
			rows = cursor.fetchall()
			return [dict(row) for row in rows]
	except Exception as error:
		print(f"Error getting all tickets: {error}")
		return []


def get_open_tickets():
	try:
		with get_connection() as conn:
			conn.row_factory = sqlite3.Row
			cursor = conn.cursor()
			cursor.execute("SELECT * FROM fp_tickets WHERE status = ?", ("OPEN",))
			rows = cursor.fetchall()
			return [dict(row) for row in rows]
	except Exception as error:
		print(f"Error getting open tickets: {error}")
		return []


def close_ticket(ticket_id, closure_reason):
	try:
		current_time = datetime.utcnow().isoformat()
		with get_connection() as conn:
			cursor = conn.cursor()
			cursor.execute(
				"""
				UPDATE fp_tickets
				SET status = ?, closed_at = ?, closure_reason = ?, updated_at = ?
				WHERE ticket_id = ?
				""",
				("CLOSED", current_time, closure_reason, current_time, ticket_id),
			)
			conn.commit()
			return cursor.rowcount > 0
	except Exception as error:
		print(f"Error closing ticket {ticket_id}: {error}")
		return False


def update_ticket_status(ticket_id, status, notes):
	try:
		current_time = datetime.utcnow().isoformat()
		with get_connection() as conn:
			cursor = conn.cursor()
			cursor.execute(
				"""
				UPDATE fp_tickets
				SET status = ?, notes = ?, updated_at = ?
				WHERE ticket_id = ?
				""",
				(status, notes, current_time, ticket_id),
			)
			conn.commit()
			return cursor.rowcount > 0
	except Exception as error:
		print(f"Error updating ticket {ticket_id}: {error}")
		return False


init_tickets_db()