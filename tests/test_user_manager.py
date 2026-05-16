"""Tests for the auth user manager module."""

import pytest

import auth.user_manager as user_manager
from auth.user_manager import (
	create_user,
	authenticate_user,
	get_all_users,
	delete_user,
	init_users_db,
)


@pytest.fixture
def temp_users_db(tmp_path, monkeypatch):
	"""Create a temporary SQLite database for testing."""
	temp_db_path = str(tmp_path / "test_aegis_history.db")
	monkeypatch.setattr(user_manager, "DB_PATH", temp_db_path)
	init_users_db()
	return temp_db_path


def make_user(username="analyst1", password="pass123", role="analyst"):
	"""Return a minimal user definition for testing."""
	return {
		"username": username,
		"password": password,
		"role": role,
	}


def test_create_user_returns_true_for_new_user(temp_users_db):
	user = make_user()
	assert create_user(user["username"], user["password"], user["role"]) is True
	assert any(entry["username"] == user["username"] for entry in get_all_users())


def test_create_user_returns_false_for_duplicate_username(temp_users_db):
	user = make_user()
	assert create_user(user["username"], user["password"], user["role"]) is True
	assert create_user(user["username"], "different-pass", "admin") is False


def test_authenticate_user_returns_user_dict_for_valid_credentials(temp_users_db):
	user = make_user(role="analyst")
	assert create_user(user["username"], user["password"], user["role"]) is True

	authenticated = authenticate_user(user["username"], user["password"])

	assert authenticated == {"username": user["username"], "role": user["role"]}


def test_authenticate_user_returns_none_for_invalid_password(temp_users_db):
	user = make_user()
	assert create_user(user["username"], user["password"], user["role"]) is True

	assert authenticate_user(user["username"], "wrong-password") is None


def test_delete_user_returns_false_for_last_admin(temp_users_db):
	assert create_user("admin", "aegis123", "admin") is True

	assert delete_user("admin") is False