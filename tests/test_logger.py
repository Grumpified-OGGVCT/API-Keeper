"""Tests for the logger module."""

import os
import tempfile
from pathlib import Path

import pytest

from api_keeper.logger import AuditLogger


class TestAuditLogger:
    """Tests for the AuditLogger class."""
    
    @pytest.fixture
    def temp_log_dir(self):
        """Create a temporary log directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def logger(self, temp_log_dir):
        """Create a logger instance."""
        return AuditLogger(log_dir=temp_log_dir)
    
    def test_creates_log_directory(self, temp_log_dir):
        """Should create log directory if it doesn't exist."""
        log_dir = os.path.join(temp_log_dir, "new_logs")
        logger = AuditLogger(log_dir=log_dir)
        
        assert os.path.exists(log_dir)
    
    def test_log_info(self, logger, temp_log_dir):
        """Should log info messages."""
        logger.log_info("Test message", key1="value1")
        
        logs = logger.get_recent_logs()
        assert any("Test message" in log for log in logs)
        assert any("key1=value1" in log for log in logs)
    
    def test_log_warning(self, logger, temp_log_dir):
        """Should log warning messages."""
        logger.log_warning("Warning message")
        
        logs = logger.get_recent_logs()
        assert any("WARNING" in log for log in logs)
    
    def test_log_error(self, logger, temp_log_dir):
        """Should log error messages."""
        logger.log_error("Error message")
        
        logs = logger.get_recent_logs()
        assert any("ERROR" in log for log in logs)
    
    def test_log_scan_start(self, logger, temp_log_dir):
        """Should log scan start."""
        logger.log_scan_start("/path/to/scan", patterns_count=10)
        
        logs = logger.get_recent_logs()
        assert any("SCAN_START" in log for log in logs)
    
    def test_log_scan_complete(self, logger, temp_log_dir):
        """Should log scan completion."""
        logger.log_scan_complete("/path", files_scanned=100, keys_found=5, duration_seconds=2.5)
        
        logs = logger.get_recent_logs()
        assert any("SCAN_COMPLETE" in log for log in logs)
    
    def test_log_key_stored(self, logger, temp_log_dir):
        """Should log key storage."""
        logger.log_key_stored(key_id=1, service="aws")
        
        logs = logger.get_recent_logs()
        assert any("KEY_STORED" in log for log in logs)
    
    def test_log_key_retrieved(self, logger, temp_log_dir):
        """Should log key retrieval."""
        logger.log_key_retrieved(key_id=1, service="aws")
        
        logs = logger.get_recent_logs()
        assert any("KEY_RETRIEVED" in log for log in logs)
    
    def test_log_key_deleted(self, logger, temp_log_dir):
        """Should log key deletion."""
        logger.log_key_deleted(key_id=1, service="aws")
        
        logs = logger.get_recent_logs()
        assert any("KEY_DELETED" in log for log in logs)
    
    def test_log_backup_created(self, logger, temp_log_dir):
        """Should log backup creation."""
        logger.log_backup_created("/path/to/backup.db")
        
        logs = logger.get_recent_logs()
        assert any("BACKUP_CREATED" in log for log in logs)
    
    def test_log_authentication(self, logger, temp_log_dir):
        """Should log authentication attempts."""
        logger.log_authentication(success=True)
        
        logs = logger.get_recent_logs()
        assert any("AUTH_SUCCESS" in log for log in logs)
        
        logger.log_authentication(success=False)
        logs = logger.get_recent_logs()
        assert any("AUTH_FAILURE" in log for log in logs)
    
    def test_log_rotation_reminder(self, logger, temp_log_dir):
        """Should log rotation reminders."""
        logger.log_rotation_reminder(key_id=1, service="aws", days_old=100)
        
        logs = logger.get_recent_logs()
        assert any("ROTATION_REMINDER" in log for log in logs)
    
    def test_get_log_files(self, logger, temp_log_dir):
        """Should return list of log files."""
        logger.log_info("Test")
        
        log_files = logger.get_log_files()
        
        assert len(log_files) > 0
        assert all(f.suffix == ".log" for f in log_files)
    
    def test_get_recent_logs_empty(self, temp_log_dir):
        """Should handle empty logs gracefully."""
        # Create logger but don't log anything
        log_dir = os.path.join(temp_log_dir, "empty_logs")
        os.makedirs(log_dir)
        
        logger = AuditLogger(log_dir=log_dir)
        
        # The logger initialization logs a message, so we need to check for that
        logs = logger.get_recent_logs()
        assert isinstance(logs, list)
