"""
Manager Module - High-level API key management operations.

Provides a unified interface for scanning, extracting, storing,
and managing API keys with backup and rotation support.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from api_keeper.scanner import KeyScanner, ScanResult
from api_keeper.extractor import KeyExtractor, ExtractedKey
from api_keeper.storage import SecureStorage, StorageError, AuthenticationError
from api_keeper.logger import AuditLogger


class KeyManager:
    """
    High-level API key management interface.
    
    Combines scanning, extraction, and storage into a unified workflow
    with support for backup, rotation reminders, and auditing.
    """
    
    def __init__(
        self,
        storage_dir: Optional[str] = None,
        log_dir: Optional[str] = None
    ):
        """
        Initialize the key manager.
        
        Args:
            storage_dir: Directory for encrypted storage
            log_dir: Directory for audit logs
        """
        self.logger = AuditLogger(log_dir=log_dir)
        self.scanner = KeyScanner(logger=self.logger)
        self.extractor = KeyExtractor(logger=self.logger)
        self.storage = SecureStorage(storage_dir=storage_dir, logger=self.logger)
        
        self._authenticated = False
    
    def authenticate(self, password: str) -> bool:
        """
        Authenticate with the master password.
        
        Creates new storage if it doesn't exist.
        
        Args:
            password: Master password
            
        Returns:
            True if this is a new storage, False if existing
            
        Raises:
            AuthenticationError: If password is incorrect
        """
        is_new = self.storage.initialize(password)
        self._authenticated = True
        return is_new
    
    def is_authenticated(self) -> bool:
        """Check if manager is authenticated."""
        return self._authenticated and self.storage.is_initialized()
    
    def _require_auth(self) -> None:
        """Ensure manager is authenticated."""
        if not self.is_authenticated():
            raise AuthenticationError("Not authenticated. Call authenticate() first.")
    
    # === Scanning Operations ===
    
    def scan_directory(
        self,
        directory: str,
        recursive: bool = True,
        min_confidence: float = 0.3
    ) -> list[ExtractedKey]:
        """
        Scan a directory for API keys.
        
        Args:
            directory: Path to directory to scan
            recursive: Whether to scan subdirectories
            min_confidence: Minimum confidence threshold for results
            
        Returns:
            List of extracted keys found
        """
        self.logger.log_info(f"Starting scan of {directory}")
        
        scan_results = list(self.scanner.scan_directory(directory, recursive))
        extracted = self.extractor.extract_all(scan_results)
        
        if min_confidence > 0:
            extracted = self.extractor.filter_by_confidence(extracted, min_confidence)
        
        return extracted
    
    def scan_file(self, filepath: str) -> list[ExtractedKey]:
        """
        Scan a single file for API keys.
        
        Args:
            filepath: Path to file to scan
            
        Returns:
            List of extracted keys found
        """
        scan_results = self.scanner.scan_file(filepath)
        return self.extractor.extract_all(scan_results)
    
    def scan_and_store(
        self,
        directory: str,
        recursive: bool = True,
        min_confidence: float = 0.5,
        auto_backup: bool = True
    ) -> dict:
        """
        Scan a directory and automatically store found keys.
        
        Args:
            directory: Path to directory to scan
            recursive: Whether to scan subdirectories
            min_confidence: Minimum confidence threshold
            auto_backup: Whether to create backup before storing
            
        Returns:
            Dictionary with scan results and stored key IDs
        """
        self._require_auth()
        
        # Create backup before adding new keys
        backup_path = None
        if auto_backup:
            try:
                backup_path = self.storage.create_backup()
            except Exception as e:
                self.logger.log_warning(f"Backup failed: {e}")
        
        # Scan and extract
        extracted = self.scan_directory(directory, recursive, min_confidence)
        
        # Store keys
        stored_ids = []
        for key in extracted:
            try:
                key_id = self.storage.store_key(key)
                stored_ids.append(key_id)
            except StorageError as e:
                self.logger.log_error(f"Failed to store key: {e}")
        
        return {
            "keys_found": len(extracted),
            "keys_stored": len(stored_ids),
            "stored_ids": stored_ids,
            "backup_path": backup_path,
        }
    
    # === Key Management Operations ===
    
    def add_key(
        self,
        key_value: str,
        service: str,
        notes: Optional[str] = None,
        source: Optional[str] = None,
        rotation_days: int = 90
    ) -> int:
        """
        Manually add a new API key.
        
        Args:
            key_value: The API key value
            service: Service name (e.g., 'aws', 'openai')
            notes: Optional notes about the key
            source: Optional source description
            rotation_days: Days until rotation reminder
            
        Returns:
            ID of the stored key
        """
        self._require_auth()
        
        extracted = ExtractedKey(
            key_value=key_value,
            service=service.lower(),
            source_file=source or "manual_entry",
            line_number=0,
            context="",
            confidence=1.0,
            entropy=self.scanner.calculate_entropy(key_value),
            pattern_name="manual",
            metadata={"notes": notes} if notes else {}
        )
        
        key_id = self.storage.store_key(extracted)
        
        if notes:
            self.storage.update_key(key_id, notes=notes)
        
        if rotation_days != 90:
            self.storage.update_key(key_id, rotation_reminder_days=rotation_days)
        
        return key_id
    
    def get_key(self, key_id: int) -> Optional[dict]:
        """
        Get a key by ID.
        
        Args:
            key_id: The key ID
            
        Returns:
            Key dictionary or None if not found
        """
        self._require_auth()
        return self.storage.get_key(key_id)
    
    def list_keys(
        self,
        service: Optional[str] = None,
        include_values: bool = False
    ) -> list[dict]:
        """
        List all stored keys.
        
        Args:
            service: Filter by service name (optional)
            include_values: Whether to include decrypted values
            
        Returns:
            List of key dictionaries
        """
        self._require_auth()
        return self.storage.list_keys(service=service, include_values=include_values)
    
    def search_keys(self, query: str) -> list[dict]:
        """
        Search keys by service, notes, or source.
        
        Args:
            query: Search query
            
        Returns:
            List of matching key dictionaries
        """
        self._require_auth()
        return self.storage.search_keys(query)
    
    def update_key(
        self,
        key_id: int,
        new_value: Optional[str] = None,
        notes: Optional[str] = None,
        service: Optional[str] = None,
        rotation_days: Optional[int] = None
    ) -> bool:
        """
        Update a key's properties.
        
        Args:
            key_id: The key ID
            new_value: New key value (rotates the key)
            notes: Updated notes
            service: Updated service name
            rotation_days: Updated rotation reminder days
            
        Returns:
            True if update was successful
        """
        self._require_auth()
        return self.storage.update_key(
            key_id,
            new_value=new_value,
            notes=notes,
            service=service,
            rotation_reminder_days=rotation_days
        )
    
    def delete_key(self, key_id: int) -> bool:
        """
        Delete a key by ID.
        
        Args:
            key_id: The key ID
            
        Returns:
            True if deletion was successful
        """
        self._require_auth()
        return self.storage.delete_key(key_id)
    
    def rotate_key(self, key_id: int, new_value: str) -> bool:
        """
        Rotate a key with a new value.
        
        Args:
            key_id: The key ID
            new_value: New key value
            
        Returns:
            True if rotation was successful
        """
        self._require_auth()
        return self.storage.update_key(key_id, new_value=new_value)
    
    def get_services(self) -> list[str]:
        """Get list of all stored services."""
        self._require_auth()
        return self.storage.get_services()
    
    def get_stats(self) -> dict:
        """Get storage statistics."""
        self._require_auth()
        return self.storage.get_stats()
    
    # === Backup Operations ===
    
    def create_backup(self, name: Optional[str] = None) -> str:
        """
        Create a backup of the key store.
        
        Args:
            name: Optional backup name
            
        Returns:
            Path to the backup file
        """
        self._require_auth()
        return self.storage.create_backup(backup_name=name)
    
    def list_backups(self) -> list[dict]:
        """List available backups."""
        return self.storage.list_backups()
    
    def restore_backup(self, backup_path: str) -> bool:
        """
        Restore from a backup.
        
        Note: After restore, re-authentication is required.
        
        Args:
            backup_path: Path to backup file
            
        Returns:
            True if restore was successful
        """
        result = self.storage.restore_backup(backup_path)
        self._authenticated = False
        return result
    
    # === Rotation Management ===
    
    def get_rotation_reminders(self, days: Optional[int] = None) -> list[dict]:
        """
        Get keys that need rotation.
        
        Args:
            days: Override default rotation check days
            
        Returns:
            List of keys needing rotation
        """
        self._require_auth()
        return self.storage.get_keys_needing_rotation(days)
    
    def check_rotation_due(self, key_id: int) -> dict:
        """
        Check if a specific key is due for rotation.
        
        Args:
            key_id: The key ID
            
        Returns:
            Dictionary with rotation status
        """
        self._require_auth()
        key = self.storage.get_key(key_id)
        
        if not key:
            return {"error": "Key not found"}
        
        # Handle None vs 0 - use 90 only if None, not if 0
        reminder_days = key.get('rotation_reminder_days')
        if reminder_days is None:
            reminder_days = 90
        
        last_date_str = key.get('last_rotated') or key.get('created_at')
        last_date = datetime.fromisoformat(last_date_str)
        
        days_old = (datetime.now() - last_date).days
        
        return {
            "key_id": key_id,
            "service": key['service'],
            "days_since_rotation": days_old,
            "reminder_days": reminder_days,
            "is_due": days_old >= reminder_days,
        }
    
    # === Password Management ===
    
    def change_password(self, old_password: str, new_password: str) -> bool:
        """
        Change the master password.
        
        Args:
            old_password: Current password
            new_password: New password
            
        Returns:
            True if password was changed
        """
        self._require_auth()
        return self.storage.change_password(old_password, new_password)
    
    # === Audit Log Access ===
    
    def get_recent_logs(self, lines: int = 100) -> list[str]:
        """
        Get recent audit log entries.
        
        Args:
            lines: Number of log lines to retrieve
            
        Returns:
            List of log lines
        """
        return self.logger.get_recent_logs(lines)
    
    def get_log_files(self) -> list[Path]:
        """Get list of log files."""
        return self.logger.get_log_files()
    
    # === Pattern Management ===
    
    def add_scan_pattern(self, name: str, pattern: str) -> None:
        """
        Add a custom scan pattern.
        
        Args:
            name: Pattern name
            pattern: Regex pattern
        """
        self.scanner.add_pattern(name, pattern)
        self.logger.log_info(f"Added custom pattern: {name}")
    
    def remove_scan_pattern(self, name: str) -> bool:
        """
        Remove a scan pattern.
        
        Args:
            name: Pattern name
            
        Returns:
            True if pattern was removed
        """
        result = self.scanner.remove_pattern(name)
        if result:
            self.logger.log_info(f"Removed pattern: {name}")
        return result
    
    def list_scan_patterns(self) -> dict:
        """Get all scan patterns."""
        return self.scanner.patterns.copy()
