import os
import sqlite3
import hashlib
from datetime import datetime


DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "aegis_history.db")


def hash_password(password):
	return hashlib.sha256(password.encode()).hexdigest()


def get_connection():
	return sqlite3.connect(DB_PATH)


def init_users_db():
	try:
		with get_connection() as conn:
			cursor = conn.cursor()
			cursor.execute(
				"""
				CREATE TABLE IF NOT EXISTS dashboard_users (
					username TEXT PRIMARY KEY,
					password_hash TEXT,
					role TEXT,
					created_at TEXT
				)
				"""
			)
			conn.commit()
	except Exception as error:
		print(f"Error initializing users database: {error}")


def create_user(username, password, role):
	try:
		password_hash = hash_password(password)
		created_at = datetime.utcnow().isoformat()

		with get_connection() as conn:
			cursor = conn.cursor()
			cursor.execute(
				"""
				INSERT INTO dashboard_users (username, password_hash, role, created_at)
				VALUES (?, ?, ?, ?)
				""",
				(username, password_hash, role, created_at),
			)
			conn.commit()
		return True
	except sqlite3.IntegrityError:
		return False
	except Exception as error:
		print(f"Error creating user {username}: {error}")
		return False


def authenticate_user(username, password):
	try:
		password_hash = hash_password(password)

		with get_connection() as conn:
			conn.row_factory = sqlite3.Row
			cursor = conn.cursor()
			cursor.execute(
				"SELECT username, password_hash, role FROM dashboard_users WHERE username = ?",
				(username,),
			)
			row = cursor.fetchone()
			if row and row["password_hash"] == password_hash:
				return {"username": row["username"], "role": row["role"]}
			return None
	except Exception as error:
		print(f"Error authenticating user {username}: {error}")
		return None


def get_all_users():
	try:
		with get_connection() as conn:
			conn.row_factory = sqlite3.Row
			cursor = conn.cursor()
			cursor.execute("SELECT username, role, created_at FROM dashboard_users")
			rows = cursor.fetchall()
			return [dict(row) for row in rows]
	except Exception as error:
		print(f"Error getting all users: {error}")
		return []


def delete_user(username):
	try:
		with get_connection() as conn:
			conn.row_factory = sqlite3.Row
			cursor = conn.cursor()
			cursor.execute("SELECT username, role FROM dashboard_users WHERE username = ?", (username,))
			user = cursor.fetchone()
			if not user:
				return False

			if user["role"] == "admin":
				cursor.execute("SELECT COUNT(*) AS admin_count FROM dashboard_users WHERE role = 'admin'")
				admin_count = cursor.fetchone()["admin_count"]
				if admin_count <= 1:
					return False

			cursor.execute("DELETE FROM dashboard_users WHERE username = ?", (username,))
			conn.commit()
			return cursor.rowcount > 0
	except Exception as error:
		print(f"Error deleting user {username}: {error}")
		return False


def create_default_admin():
	try:
		admin_username = os.environ.get("DASHBOARD_USERNAME", "admin")
		admin_password = os.environ.get("DASHBOARD_PASSWORD", "aegis123")

		with get_connection() as conn:
			cursor = conn.cursor()
			cursor.execute("SELECT COUNT(*) FROM dashboard_users")
			user_count = cursor.fetchone()[0]
			if user_count == 0:
				create_user(admin_username, admin_password, "admin")
	except Exception as error:
		print(f"Error creating default admin: {error}")


init_users_db()
create_default_admin()