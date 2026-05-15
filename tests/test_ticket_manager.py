"""Tests for the ticket manager module."""

import pytest
from pathlib import Path

from ticketing.ticket_manager import (
    create_ticket,
    get_all_tickets,
    get_open_tickets,
    close_ticket,
    init_tickets_db,
)


@pytest.fixture
def temp_ticket_db(tmp_path, monkeypatch):
    """Create a temporary SQLite database for testing."""
    temp_db_path = str(tmp_path / "test_aegis_history.db")
    
    # Monkeypatch the DB_PATH in the ticket_manager module
    import ticketing.ticket_manager
    monkeypatch.setattr(ticketing.ticket_manager, "DB_PATH", temp_db_path)
    
    # Initialize the temporary database
    init_tickets_db()
    
    return temp_db_path


def make_alert():
    """Return a minimal alert dict for testing."""
    return {
        "alert_id": "ALERT-001",
        "source_ip": "192.168.1.100",
        "alert_type": "SSH_BRUTE_FORCE",
        "severity": "HIGH",
    }


def test_create_ticket_returns_open_status(temp_ticket_db):
    """Test that create_ticket() returns a ticket with status OPEN."""
    alert = make_alert()
    ticket = create_ticket(alert)
    
    assert ticket is not None
    assert ticket["status"] == "OPEN"


def test_create_ticket_sets_ticket_id(temp_ticket_db):
    """Test that create_ticket() sets ticket_id as TICKET-{alert_id}."""
    alert = make_alert()
    ticket = create_ticket(alert)
    
    assert ticket is not None
    assert ticket["ticket_id"] == "TICKET-ALERT-001"


def test_get_all_tickets_returns_created_ticket(temp_ticket_db):
    """Test that get_all_tickets() returns the created ticket."""
    alert = make_alert()
    created_ticket = create_ticket(alert)
    
    all_tickets = get_all_tickets()
    
    assert len(all_tickets) == 1
    assert all_tickets[0]["ticket_id"] == created_ticket["ticket_id"]
    assert all_tickets[0]["alert_id"] == alert["alert_id"]


def test_close_ticket_changes_status_to_closed(temp_ticket_db):
    """Test that close_ticket() changes status to CLOSED and returns True."""
    alert = make_alert()
    ticket = create_ticket(alert)
    ticket_id = ticket["ticket_id"]
    
    result = close_ticket(ticket_id, "Confirmed as false positive")
    
    assert result is True
    
    # Verify the ticket status was updated
    all_tickets = get_all_tickets()
    closed_ticket = next((t for t in all_tickets if t["ticket_id"] == ticket_id), None)
    assert closed_ticket is not None
    assert closed_ticket["status"] == "CLOSED"
    assert closed_ticket["closure_reason"] == "Confirmed as false positive"


def test_get_open_tickets_filters_by_status(temp_ticket_db):
    """Test that get_open_tickets() returns only OPEN tickets, not CLOSED ones."""
    alert1 = make_alert()
    alert2 = {
        "alert_id": "ALERT-002",
        "source_ip": "192.168.1.101",
        "alert_type": "PORT_SCAN",
        "severity": "MEDIUM",
    }
    
    ticket1 = create_ticket(alert1)
    ticket2 = create_ticket(alert2)
    
    # Close the first ticket
    close_ticket(ticket1["ticket_id"], "False positive")
    
    # Get only open tickets
    open_tickets = get_open_tickets()
    
    assert len(open_tickets) == 1
    assert open_tickets[0]["ticket_id"] == ticket2["ticket_id"]
    assert open_tickets[0]["status"] == "OPEN"
