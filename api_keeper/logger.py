"""
Audit Logger Module - Logging activities for auditing purposes.

Provides comprehensive logging of all key management operations including
scans, extractions, storage, retrievals, and modifications.
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


class AuditLogger:
    """
    Handles audit logging for all API key management activities.
    
    Logs are stored in a secure location and include timestamps,
    operation types, and relevant metadata for compliance and auditing.
    """
    
    def __init__(
        self,
        log_dir: Optional[str] = None,
        log_level: int = logging.INFO,
        console_output: bool = False
    ):
        """
        Initialize the audit logger.
        
        Args:
            log_dir: Directory to store log files. Defaults to ~/.api_keeper/logs
            log_level: Logging level (default: INFO)
            console_output: Whether to also output to console
        """
        if log_dir is None:
            log_dir = os.path.join(os.path.expanduser("~"), ".api_keeper", "logs")
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Set restrictive permissions on log directory
        try:
            os.chmod(self.log_dir, 0o700)
        except OSError:
            pass  # May fail on some systems, continue anyway
        
        # Configure logger
        self.logger = logging.getLogger("api_keeper.audit")
        self.logger.setLevel(log_level)
        self.logger.handlers = []  # Clear any existing handlers
        
        # File handler - daily rotation
        log_file = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(log_level)
        
        # Format with timestamp, level, and message
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Optional console output
        if console_output:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(log_level)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        self.log_info("Audit logger initialized")
    
    def log_info(self, message: str, **kwargs) -> None:
        """Log an informational message."""
        extra_info = self._format_extra(kwargs)
        self.logger.info(f"{message}{extra_info}")
    
    def log_warning(self, message: str, **kwargs) -> None:
        """Log a warning message."""
        extra_info = self._format_extra(kwargs)
        self.logger.warning(f"{message}{extra_info}")
    
    def log_error(self, message: str, **kwargs) -> None:
        """Log an error message."""
        extra_info = self._format_extra(kwargs)
        self.logger.error(f"{message}{extra_info}")
    
    def log_scan_start(self, path: str, patterns_count: int) -> None:
        """Log the start of a file scan operation."""
        self.log_info(
            "SCAN_START",
            path=path,
            patterns_count=patterns_count
        )
    
    def log_scan_complete(
        self,
        path: str,
        files_scanned: int,
        keys_found: int,
        duration_seconds: float
    ) -> None:
        """Log completion of a file scan operation."""
        self.log_info(
            "SCAN_COMPLETE",
            path=path,
            files_scanned=files_scanned,
            keys_found=keys_found,
            duration_seconds=round(duration_seconds, 2)
        )
    
    def log_scan_error(self, path: str, error: str) -> None:
        """Log a scan error."""
        self.log_error("SCAN_ERROR", path=path, error=error)
    
    def log_key_extracted(
        self,
        service: str,
        source_file: str,
        confidence: float
    ) -> None:
        """Log a key extraction event (without logging the actual key)."""
        self.log_info(
            "KEY_EXTRACTED",
            service=service,
            source_file=source_file,
            confidence=round(confidence, 2)
        )
    
    def log_key_stored(self, key_id: int, service: str) -> None:
        """Log a key storage event."""
        self.log_info("KEY_STORED", key_id=key_id, service=service)
    
    def log_key_retrieved(self, key_id: int, service: str) -> None:
        """Log a key retrieval event."""
        self.log_info("KEY_RETRIEVED", key_id=key_id, service=service)
    
    def log_key_updated(self, key_id: int, service: str, fields: list) -> None:
        """Log a key update event."""
        self.log_info(
            "KEY_UPDATED",
            key_id=key_id,
            service=service,
            fields_updated=",".join(fields)
        )
    
    def log_key_deleted(self, key_id: int, service: str) -> None:
        """Log a key deletion event."""
        self.log_info("KEY_DELETED", key_id=key_id, service=service)
    
    def log_backup_created(self, backup_path: str) -> None:
        """Log a backup creation event."""
        self.log_info("BACKUP_CREATED", backup_path=backup_path)
    
    def log_backup_restored(self, backup_path: str) -> None:
        """Log a backup restoration event."""
        self.log_info("BACKUP_RESTORED", backup_path=backup_path)
    
    def log_authentication(self, success: bool) -> None:
        """Log an authentication attempt."""
        if success:
            self.log_info("AUTH_SUCCESS")
        else:
            self.log_warning("AUTH_FAILURE")
    
    def log_rotation_reminder(self, key_id: int, service: str, days_old: int) -> None:
        """Log a rotation reminder event."""
        self.log_info(
            "ROTATION_REMINDER",
            key_id=key_id,
            service=service,
            days_old=days_old
        )
    
    def _format_extra(self, kwargs: dict) -> str:
        """Format extra keyword arguments for logging."""
        if not kwargs:
            return ""
        parts = [f" | {k}={v}" for k, v in kwargs.items()]
        return "".join(parts)
    
    def get_log_files(self) -> list:
        """Get list of all log files."""
        return sorted(self.log_dir.glob("audit_*.log"))
    
    def get_recent_logs(self, lines: int = 100) -> list:
        """Get the most recent log entries."""
        log_files = self.get_log_files()
        if not log_files:
            return []
        
        # Read from the most recent log file
        recent_file = log_files[-1]
        try:
            with open(recent_file, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                return all_lines[-lines:]
        except (OSError, IOError):
            return []
