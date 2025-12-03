"""
Storage Module - Encrypted storage for API keys.

Provides secure, encrypted SQLite-based storage for API keys with
self-organizing categories, metadata, and backup capabilities.
"""

import base64
import hashlib
import json
import os
import shutil
import sqlite3
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from api_keeper.extractor import ExtractedKey
from api_keeper.logger import AuditLogger


class StorageError(Exception):
    """Base exception for storage errors."""
    pass


class AuthenticationError(StorageError):
    """Raised when authentication fails."""
    pass


class SecureStorage:
    """
    Provides encrypted SQLite storage for API keys.
    
    Features:
    - AES-256 encryption using Fernet
    - PBKDF2 key derivation from master password
    - Automatic categorization by service
    - Metadata tracking (source, date, confidence)
    - Backup and restore functionality
    """
    
    # Database schema version for migrations
    SCHEMA_VERSION = 1
    
    def __init__(
        self,
        storage_dir: Optional[str] = None,
        logger: Optional[AuditLogger] = None
    ):
        """
        Initialize secure storage.
        
        Args:
            storage_dir: Directory for database and backups. 
                        Defaults to ~/.api_keeper
            logger: AuditLogger instance for logging
        """
        if storage_dir is None:
            storage_dir = os.path.join(os.path.expanduser("~"), ".api_keeper")
        
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Set restrictive permissions on storage directory
        try:
            os.chmod(self.storage_dir, 0o700)
        except OSError:
            pass  # May fail on some systems
        
        self.db_path = self.storage_dir / "keystore.db"
        self.backup_dir = self.storage_dir / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logger or AuditLogger()
        self._fernet: Optional[Fernet] = None
        self._initialized = False
    
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: Master password
            salt: Random salt for key derivation
            
        Returns:
            32-byte derived key suitable for Fernet
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,  # OWASP recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    @staticmethod
    def _hash_password(password: str, salt: bytes) -> bytes:
        """Create a hash of the password for verification."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            iterations=480000
        )
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_database(self, password: str) -> None:
        """Initialize the database schema."""
        # Generate salt for this storage
        salt = os.urandom(32)
        password_hash = self._hash_password(password, salt)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Store salt and password hash for verification
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auth (
                    id INTEGER PRIMARY KEY,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                INSERT INTO auth (salt, password_hash, created_at)
                VALUES (?, ?, ?)
            """, (salt, password_hash, datetime.now().isoformat()))
            
            # Schema version tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                )
            """)
            cursor.execute("INSERT INTO schema_version (version) VALUES (?)", 
                          (self.SCHEMA_VERSION,))
            
            # Main keys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    encrypted_key BLOB NOT NULL,
                    source_file TEXT,
                    line_number INTEGER,
                    confidence REAL,
                    entropy REAL,
                    pattern_name TEXT,
                    metadata TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_rotated TEXT,
                    rotation_reminder_days INTEGER DEFAULT 90,
                    notes TEXT
                )
            """)
            
            # Index for faster queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_keys_service ON keys(service)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_keys_created ON keys(created_at)")
            
            conn.commit()
        
        # Set restrictive permissions on database file
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass
    
    def _verify_password(self, password: str) -> bytes:
        """
        Verify password and return salt if valid.
        
        Raises:
            AuthenticationError: If password is incorrect
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT salt, password_hash FROM auth LIMIT 1")
            row = cursor.fetchone()
            
            if not row:
                raise StorageError("Storage not initialized")
            
            salt = row['salt']
            stored_hash = row['password_hash']
            
            computed_hash = self._hash_password(password, salt)
            
            if computed_hash != stored_hash:
                self.logger.log_authentication(success=False)
                raise AuthenticationError("Invalid master password")
            
            self.logger.log_authentication(success=True)
            return salt
    
    def initialize(self, password: str) -> bool:
        """
        Initialize storage with a master password.
        
        Creates the database if it doesn't exist, or authenticates
        if it already exists.
        
        Args:
            password: Master password for encryption
            
        Returns:
            True if storage was newly created, False if it already existed
            
        Raises:
            AuthenticationError: If password is incorrect for existing storage
        """
        is_new = not self.db_path.exists()
        
        if is_new:
            self._init_database(password)
            salt = self._verify_password(password)
        else:
            salt = self._verify_password(password)
        
        # Set up Fernet for encryption/decryption
        key = self._derive_key(password, salt)
        self._fernet = Fernet(key)
        self._initialized = True
        
        return is_new
    
    def is_initialized(self) -> bool:
        """Check if storage is initialized and authenticated."""
        return self._initialized and self._fernet is not None
    
    def _require_init(self) -> None:
        """Ensure storage is initialized."""
        if not self.is_initialized():
            raise StorageError("Storage not initialized. Call initialize() first.")
    
    def _encrypt(self, data: str) -> bytes:
        """Encrypt string data."""
        if self._fernet is None:
            raise StorageError("Storage not initialized. Call initialize() first.")
        return self._fernet.encrypt(data.encode())
    
    def _decrypt(self, data: bytes) -> str:
        """Decrypt data to string."""
        if self._fernet is None:
            raise StorageError("Storage not initialized. Call initialize() first.")
        try:
            return self._fernet.decrypt(data).decode()
        except InvalidToken:
            raise StorageError("Failed to decrypt data - corrupted or wrong key")
    
    def store_key(self, extracted_key: ExtractedKey) -> int:
        """
        Store an extracted key in encrypted storage.
        
        Args:
            extracted_key: The ExtractedKey to store
            
        Returns:
            The ID of the stored key
        """
        self._require_init()
        
        encrypted_key = self._encrypt(extracted_key.key_value)
        now = datetime.now().isoformat()
        
        metadata = json.dumps(extracted_key.metadata) if extracted_key.metadata else "{}"
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO keys (
                    service, encrypted_key, source_file, line_number,
                    confidence, entropy, pattern_name, metadata,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                extracted_key.service,
                encrypted_key,
                extracted_key.source_file,
                extracted_key.line_number,
                extracted_key.confidence,
                extracted_key.entropy,
                extracted_key.pattern_name,
                metadata,
                now,
                now
            ))
            key_id = cursor.lastrowid
            conn.commit()
        
        if key_id is not None:
            self.logger.log_key_stored(key_id, extracted_key.service)
            return key_id
        raise StorageError("Failed to store key")
    
    def store_keys(self, extracted_keys: list[ExtractedKey]) -> list[int]:
        """Store multiple keys."""
        return [self.store_key(key) for key in extracted_keys]
    
    def get_key(self, key_id: int) -> Optional[dict]:
        """
        Retrieve a key by ID.
        
        Args:
            key_id: The ID of the key to retrieve
            
        Returns:
            Dictionary with key data including decrypted key value,
            or None if not found
        """
        self._require_init()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM keys WHERE id = ?", (key_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            result = dict(row)
            result['key_value'] = self._decrypt(row['encrypted_key'])
            del result['encrypted_key']
            
            if result.get('metadata'):
                result['metadata'] = json.loads(result['metadata'])
            
            self.logger.log_key_retrieved(key_id, result['service'])
            return result
    
    def list_keys(
        self,
        service: Optional[str] = None,
        include_values: bool = False
    ) -> list[dict]:
        """
        List stored keys with optional filtering.
        
        Args:
            service: Filter by service name (optional)
            include_values: Whether to include decrypted key values
            
        Returns:
            List of key dictionaries
        """
        self._require_init()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if service:
                cursor.execute(
                    "SELECT * FROM keys WHERE service = ? ORDER BY created_at DESC",
                    (service,)
                )
            else:
                cursor.execute("SELECT * FROM keys ORDER BY created_at DESC")
            
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                
                if include_values:
                    result['key_value'] = self._decrypt(row['encrypted_key'])
                
                del result['encrypted_key']
                
                if result.get('metadata'):
                    result['metadata'] = json.loads(result['metadata'])
                
                results.append(result)
            
            return results
    
    def search_keys(self, query: str) -> list[dict]:
        """
        Search keys by service name or notes.
        
        Args:
            query: Search query string
            
        Returns:
            List of matching key dictionaries
        """
        self._require_init()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM keys 
                WHERE service LIKE ? OR notes LIKE ? OR source_file LIKE ?
                ORDER BY created_at DESC
            """, (f"%{query}%", f"%{query}%", f"%{query}%"))
            
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                del result['encrypted_key']
                
                if result.get('metadata'):
                    result['metadata'] = json.loads(result['metadata'])
                
                results.append(result)
            
            return results
    
    def update_key(
        self,
        key_id: int,
        new_value: Optional[str] = None,
        notes: Optional[str] = None,
        service: Optional[str] = None,
        rotation_reminder_days: Optional[int] = None
    ) -> bool:
        """
        Update a stored key.
        
        Args:
            key_id: The ID of the key to update
            new_value: New key value (optional)
            notes: Notes to attach (optional)
            service: New service name (optional)
            rotation_reminder_days: Days until rotation reminder (optional)
            
        Returns:
            True if key was updated
        """
        self._require_init()
        
        updates = []
        params = []
        fields_updated = []
        
        if new_value is not None:
            updates.append("encrypted_key = ?")
            params.append(self._encrypt(new_value))
            updates.append("last_rotated = ?")
            params.append(datetime.now().isoformat())
            fields_updated.extend(["key_value", "last_rotated"])
        
        if notes is not None:
            updates.append("notes = ?")
            params.append(notes)
            fields_updated.append("notes")
        
        if service is not None:
            updates.append("service = ?")
            params.append(service)
            fields_updated.append("service")
        
        if rotation_reminder_days is not None:
            updates.append("rotation_reminder_days = ?")
            params.append(rotation_reminder_days)
            fields_updated.append("rotation_reminder_days")
        
        if not updates:
            return False
        
        updates.append("updated_at = ?")
        params.append(datetime.now().isoformat())
        params.append(key_id)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get current service for logging
            cursor.execute("SELECT service FROM keys WHERE id = ?", (key_id,))
            row = cursor.fetchone()
            if not row:
                return False
            
            service_name = service or row['service']
            
            cursor.execute(
                f"UPDATE keys SET {', '.join(updates)} WHERE id = ?",
                params
            )
            conn.commit()
            
            if cursor.rowcount > 0:
                self.logger.log_key_updated(key_id, service_name, fields_updated)
                return True
            return False
    
    def delete_key(self, key_id: int) -> bool:
        """
        Delete a key by ID.
        
        Args:
            key_id: The ID of the key to delete
            
        Returns:
            True if key was deleted
        """
        self._require_init()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get service for logging
            cursor.execute("SELECT service FROM keys WHERE id = ?", (key_id,))
            row = cursor.fetchone()
            if not row:
                return False
            
            service = row['service']
            
            cursor.execute("DELETE FROM keys WHERE id = ?", (key_id,))
            conn.commit()
            
            if cursor.rowcount > 0:
                self.logger.log_key_deleted(key_id, service)
                return True
            return False
    
    def get_services(self) -> list[str]:
        """Get list of all unique services."""
        self._require_init()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT service FROM keys ORDER BY service")
            return [row['service'] for row in cursor.fetchall()]
    
    def get_stats(self) -> dict:
        """Get storage statistics."""
        self._require_init()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) as total FROM keys")
            total = cursor.fetchone()['total']
            
            cursor.execute("""
                SELECT service, COUNT(*) as count 
                FROM keys GROUP BY service 
                ORDER BY count DESC
            """)
            by_service = {row['service']: row['count'] for row in cursor.fetchall()}
            
            return {
                "total_keys": total,
                "by_service": by_service,
                "services_count": len(by_service),
            }
    
    def create_backup(self, backup_name: Optional[str] = None) -> str:
        """
        Create a backup of the encrypted database.
        
        Args:
            backup_name: Optional name for the backup file
            
        Returns:
            Path to the created backup
        """
        self._require_init()
        
        if backup_name is None:
            backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        
        backup_path = self.backup_dir / backup_name
        shutil.copy2(self.db_path, backup_path)
        
        # Set restrictive permissions
        try:
            os.chmod(backup_path, 0o600)
        except OSError:
            pass
        
        self.logger.log_backup_created(str(backup_path))
        return str(backup_path)
    
    def list_backups(self) -> list[dict]:
        """List available backups."""
        backups = []
        for backup_file in sorted(self.backup_dir.glob("*.db"), reverse=True):
            stat = backup_file.stat()
            backups.append({
                "name": backup_file.name,
                "path": str(backup_file),
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
        return backups
    
    def restore_backup(self, backup_path: str) -> bool:
        """
        Restore from a backup.
        
        Args:
            backup_path: Path to the backup file
            
        Returns:
            True if restore was successful
        """
        backup = Path(backup_path)
        if not backup.exists():
            raise StorageError(f"Backup not found: {backup_path}")
        
        # Create a backup of current state first
        if self.db_path.exists():
            pre_restore_backup = self.backup_dir / f"pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            shutil.copy2(self.db_path, pre_restore_backup)
        
        # Restore
        shutil.copy2(backup, self.db_path)
        
        # Reset authentication state
        self._fernet = None
        self._initialized = False
        
        self.logger.log_backup_restored(backup_path)
        return True
    
    def get_keys_needing_rotation(self, days: Optional[int] = None) -> list[dict]:
        """
        Get keys that need rotation based on their reminder settings.
        
        Args:
            days: Override default rotation days check
            
        Returns:
            List of keys needing rotation
        """
        self._require_init()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, service, created_at, last_rotated, rotation_reminder_days
                FROM keys
            """)
            
            results = []
            now = datetime.now()
            
            for row in cursor.fetchall():
                # Handle days override, then check for None vs 0 in database
                if days is not None:
                    reminder_days = days
                elif row['rotation_reminder_days'] is not None:
                    reminder_days = row['rotation_reminder_days']
                else:
                    reminder_days = 90
                
                # Use last_rotated if available, otherwise created_at
                last_date_str = row['last_rotated'] or row['created_at']
                last_date = datetime.fromisoformat(last_date_str)
                
                days_old = (now - last_date).days
                
                if days_old >= reminder_days:
                    results.append({
                        "id": row['id'],
                        "service": row['service'],
                        "days_since_rotation": days_old,
                        "reminder_days": reminder_days,
                    })
                    self.logger.log_rotation_reminder(
                        row['id'], row['service'], days_old
                    )
            
            return results
    
    def change_password(self, old_password: str, new_password: str) -> bool:
        """
        Change the master password.
        
        Re-encrypts all keys with the new password.
        
        Args:
            old_password: Current master password
            new_password: New master password
            
        Returns:
            True if password was changed successfully
        """
        # Verify old password
        old_salt = self._verify_password(old_password)
        old_key = self._derive_key(old_password, old_salt)
        old_fernet = Fernet(old_key)
        
        # Generate new salt and key
        new_salt = os.urandom(32)
        new_key = self._derive_key(new_password, new_salt)
        new_fernet = Fernet(new_key)
        new_hash = self._hash_password(new_password, new_salt)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get all encrypted keys
            cursor.execute("SELECT id, encrypted_key FROM keys")
            rows = cursor.fetchall()
            
            # Re-encrypt each key
            for row in rows:
                decrypted = old_fernet.decrypt(row['encrypted_key'])
                re_encrypted = new_fernet.encrypt(decrypted)
                cursor.execute(
                    "UPDATE keys SET encrypted_key = ? WHERE id = ?",
                    (re_encrypted, row['id'])
                )
            
            # Update auth info
            cursor.execute("""
                UPDATE auth SET salt = ?, password_hash = ?
            """, (new_salt, new_hash))
            
            conn.commit()
        
        # Update current session
        self._fernet = new_fernet
        
        self.logger.log_info("Password changed successfully")
        return True
