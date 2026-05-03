"""Log parser module for Aegis-SOC."""

from .auth_log_parser import parse_auth_log, parse_auth_log_content

__all__ = ['parse_auth_log', 'parse_auth_log_content']
