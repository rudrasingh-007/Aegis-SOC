import os
import sqlite3
import tempfile

import pytest

from storage import history_store


@pytest.fixture
def temp_history_db():
	"""Use a temporary SQLite database path for each test."""
	original_db_path = history_store.DB_PATH
	temp_file = tempfile.NamedTemporaryFile(delete=False)
	temp_db_path = temp_file.name
	temp_file.close()

	history_store.DB_PATH = temp_db_path
	history_store.init_db()

	try:
		yield temp_db_path
	finally:
		history_store.DB_PATH = original_db_path
		if os.path.exists(temp_db_path):
			try:
				os.remove(temp_db_path)
			except (OSError, PermissionError):
				pass


def test_init_db_creates_table(temp_history_db):
	with sqlite3.connect(temp_history_db) as conn:
		cursor = conn.cursor()
		cursor.execute(
			"SELECT name FROM sqlite_master WHERE type='table' AND name='alert_history'"
		)
		result = cursor.fetchone()

	assert result is not None
	assert result[0] == "alert_history"


def test_save_alerts_persists_data(temp_history_db):
	alerts = [
		{
			"source_ip": "10.0.0.1",
			"alert_type": "port_scan",
			"attempt_count": 5,
			"timestamp": "2026-05-02 10:00:00",
		}
	]

	history_store.save_alerts(alerts)
	rows = history_store.get_historical_data()

	assert len(rows) == 1
	assert rows[0]["source_ip"] == "10.0.0.1"
	assert rows[0]["alert_type"] == "port_scan"
	assert rows[0]["attempt_count"] == 5
	assert rows[0]["timestamp"] == "2026-05-02 10:00:00"


def test_save_alerts_empty_list(temp_history_db):
	history_store.save_alerts([])


def test_get_historical_data_returns_correct_fields(temp_history_db):
	alerts = [
		{
			"source_ip": "10.0.0.2",
			"alert_type": "failed_login",
			"attempt_count": 2,
			"timestamp": "2026-05-02 11:00:00",
		}
	]

	history_store.save_alerts(alerts)
	rows = history_store.get_historical_data()

	assert len(rows) == 1
	assert set(rows[0].keys()) == {
		"source_ip",
		"alert_type",
		"attempt_count",
		"timestamp",
	}


def test_save_multiple_alerts(temp_history_db):
	alerts = [
		{
			"source_ip": "10.0.0.1",
			"alert_type": "port_scan",
			"attempt_count": 1,
			"timestamp": "2026-05-02 12:00:00",
		},
		{
			"source_ip": "10.0.0.2",
			"alert_type": "brute_force",
			"attempt_count": 7,
			"timestamp": "2026-05-02 12:01:00",
		},
		{
			"source_ip": "10.0.0.3",
			"alert_type": "malware_detected",
			"attempt_count": 3,
			"timestamp": "2026-05-02 12:02:00",
		},
	]

	history_store.save_alerts(alerts)
	rows = history_store.get_historical_data()

	assert len(rows) == 3
