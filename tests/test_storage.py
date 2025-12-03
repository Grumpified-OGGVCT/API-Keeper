"""Tests for the storage module."""

import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from api_keeper.storage import SecureStorage, StorageError, AuthenticationError
from api_keeper.extractor import ExtractedKey


class TestSecureStorage:
    """Tests for the SecureStorage class."""
    
    @pytest.fixture
    def temp_storage_dir(self):
        """Create a temporary storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def storage(self, temp_storage_dir):
        """Create and initialize a storage instance."""
        storage = SecureStorage(storage_dir=temp_storage_dir)
        storage.initialize("test_password")
        return storage
    
    @pytest.fixture
    def sample_key(self):
        """Create a sample ExtractedKey."""
        return ExtractedKey(
            key_value="test-api-key-12345678901234567890",
            service="test_service",
            source_file="/path/to/file.py",
            line_number=10,
            context="some context",
            confidence=0.85,
            entropy=4.2,
            pattern_name="test_pattern",
            metadata={"test": "value"}
        )
    
    def test_initialize_creates_new_storage(self, temp_storage_dir):
        """Initialize should create new storage."""
        storage = SecureStorage(storage_dir=temp_storage_dir)
        is_new = storage.initialize("test_password")
        
        assert is_new is True
        assert storage.is_initialized()
        assert (Path(temp_storage_dir) / "keystore.db").exists()
    
    def test_initialize_existing_storage(self, temp_storage_dir):
        """Initialize should authenticate with existing storage."""
        # Create storage
        storage1 = SecureStorage(storage_dir=temp_storage_dir)
        storage1.initialize("test_password")
        
        # Reopen with correct password
        storage2 = SecureStorage(storage_dir=temp_storage_dir)
        is_new = storage2.initialize("test_password")
        
        assert is_new is False
        assert storage2.is_initialized()
    
    def test_wrong_password_raises_error(self, temp_storage_dir):
        """Wrong password should raise AuthenticationError."""
        # Create storage
        storage1 = SecureStorage(storage_dir=temp_storage_dir)
        storage1.initialize("correct_password")
        
        # Try to open with wrong password
        storage2 = SecureStorage(storage_dir=temp_storage_dir)
        with pytest.raises(AuthenticationError):
            storage2.initialize("wrong_password")
    
    def test_store_and_retrieve_key(self, storage, sample_key):
        """Should store and retrieve a key."""
        key_id = storage.store_key(sample_key)
        
        assert key_id is not None
        assert key_id > 0
        
        retrieved = storage.get_key(key_id)
        
        assert retrieved is not None
        assert retrieved['key_value'] == sample_key.key_value
        assert retrieved['service'] == sample_key.service
        assert retrieved['source_file'] == sample_key.source_file
    
    def test_store_multiple_keys(self, storage, sample_key):
        """Should store multiple keys."""
        ids = storage.store_keys([sample_key, sample_key])
        
        assert len(ids) == 2
        assert ids[0] != ids[1]
    
    def test_list_keys(self, storage, sample_key):
        """Should list all stored keys."""
        storage.store_key(sample_key)
        storage.store_key(sample_key)
        
        keys = storage.list_keys()
        
        assert len(keys) == 2
    
    def test_list_keys_by_service(self, storage):
        """Should filter keys by service."""
        key1 = ExtractedKey(
            key_value="key1",
            service="service_a",
            source_file="file.py",
            line_number=1,
            context="",
            confidence=0.9,
            entropy=4.0,
            pattern_name="pattern"
        )
        key2 = ExtractedKey(
            key_value="key2",
            service="service_b",
            source_file="file.py",
            line_number=1,
            context="",
            confidence=0.9,
            entropy=4.0,
            pattern_name="pattern"
        )
        
        storage.store_key(key1)
        storage.store_key(key2)
        
        keys = storage.list_keys(service="service_a")
        
        assert len(keys) == 1
        assert keys[0]['service'] == "service_a"
    
    def test_search_keys(self, storage, sample_key):
        """Should search keys by service or notes."""
        storage.store_key(sample_key)
        
        results = storage.search_keys("test")
        
        assert len(results) > 0
    
    def test_update_key(self, storage, sample_key):
        """Should update key properties."""
        key_id = storage.store_key(sample_key)
        
        success = storage.update_key(
            key_id,
            notes="Updated notes",
            service="new_service"
        )
        
        assert success is True
        
        updated = storage.get_key(key_id)
        assert updated['notes'] == "Updated notes"
        assert updated['service'] == "new_service"
    
    def test_update_key_value(self, storage, sample_key):
        """Should update key value (rotation)."""
        key_id = storage.store_key(sample_key)
        
        new_value = "new-rotated-key-value-1234567890"
        success = storage.update_key(key_id, new_value=new_value)
        
        assert success is True
        
        updated = storage.get_key(key_id)
        assert updated['key_value'] == new_value
        assert updated['last_rotated'] is not None
    
    def test_delete_key(self, storage, sample_key):
        """Should delete a key."""
        key_id = storage.store_key(sample_key)
        
        success = storage.delete_key(key_id)
        
        assert success is True
        assert storage.get_key(key_id) is None
    
    def test_delete_nonexistent_key(self, storage):
        """Deleting nonexistent key should return False."""
        success = storage.delete_key(99999)
        assert success is False
    
    def test_get_services(self, storage):
        """Should return list of unique services."""
        key1 = ExtractedKey(
            key_value="key1",
            service="aws",
            source_file="file.py",
            line_number=1,
            context="",
            confidence=0.9,
            entropy=4.0,
            pattern_name="pattern"
        )
        key2 = ExtractedKey(
            key_value="key2",
            service="github",
            source_file="file.py",
            line_number=1,
            context="",
            confidence=0.9,
            entropy=4.0,
            pattern_name="pattern"
        )
        
        storage.store_key(key1)
        storage.store_key(key2)
        
        services = storage.get_services()
        
        assert "aws" in services
        assert "github" in services
    
    def test_get_stats(self, storage, sample_key):
        """Should return storage statistics."""
        storage.store_key(sample_key)
        storage.store_key(sample_key)
        
        stats = storage.get_stats()
        
        assert stats['total_keys'] == 2
        assert 'by_service' in stats
        assert stats['services_count'] == 1
    
    def test_create_backup(self, storage, sample_key, temp_storage_dir):
        """Should create a backup file."""
        storage.store_key(sample_key)
        
        backup_path = storage.create_backup()
        
        assert os.path.exists(backup_path)
        assert "backup_" in backup_path
    
    def test_list_backups(self, storage, temp_storage_dir):
        """Should list available backups."""
        storage.create_backup("test_backup_1.db")
        storage.create_backup("test_backup_2.db")
        
        backups = storage.list_backups()
        
        assert len(backups) >= 2
        assert any("test_backup_1" in b['name'] for b in backups)
    
    def test_restore_backup(self, storage, sample_key, temp_storage_dir):
        """Should restore from backup."""
        # Store a key and backup
        key_id = storage.store_key(sample_key)
        backup_path = storage.create_backup("pre_change.db")
        
        # Delete the key
        storage.delete_key(key_id)
        assert storage.get_key(key_id) is None
        
        # Restore backup
        storage.restore_backup(backup_path)
        
        # Re-authenticate
        storage.initialize("test_password")
        
        # Key should be back
        assert storage.get_key(key_id) is not None
    
    def test_change_password(self, storage, sample_key, temp_storage_dir):
        """Should change master password."""
        key_id = storage.store_key(sample_key)
        
        success = storage.change_password("test_password", "new_password")
        
        assert success is True
        
        # Verify old password doesn't work
        storage2 = SecureStorage(storage_dir=temp_storage_dir)
        with pytest.raises(AuthenticationError):
            storage2.initialize("test_password")
        
        # Verify new password works
        storage3 = SecureStorage(storage_dir=temp_storage_dir)
        storage3.initialize("new_password")
        
        # Verify key is still accessible
        retrieved = storage3.get_key(key_id)
        assert retrieved['key_value'] == sample_key.key_value
    
    def test_operations_require_init(self, temp_storage_dir, sample_key):
        """Operations should require initialization."""
        storage = SecureStorage(storage_dir=temp_storage_dir)
        
        with pytest.raises(StorageError):
            storage.store_key(sample_key)
        
        with pytest.raises(StorageError):
            storage.get_key(1)
        
        with pytest.raises(StorageError):
            storage.list_keys()


class TestRotationReminders:
    """Tests for rotation reminder functionality."""
    
    @pytest.fixture
    def temp_storage_dir(self):
        """Create a temporary storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def storage(self, temp_storage_dir):
        """Create and initialize a storage instance."""
        storage = SecureStorage(storage_dir=temp_storage_dir)
        storage.initialize("test_password")
        return storage
    
    def test_get_keys_needing_rotation(self, storage):
        """Should identify keys needing rotation."""
        key = ExtractedKey(
            key_value="old-key",
            service="test",
            source_file="file.py",
            line_number=1,
            context="",
            confidence=0.9,
            entropy=4.0,
            pattern_name="pattern"
        )
        
        key_id = storage.store_key(key)
        
        # Set rotation_reminder_days to 0, meaning key is immediately due
        storage.update_key(key_id, rotation_reminder_days=0)
        
        # A key created just now has days_old=0, and with reminder_days=0
        # the check is 0 >= 0 which is True
        reminders = storage.get_keys_needing_rotation()
        
        assert len(reminders) > 0
        assert any(r['id'] == key_id for r in reminders)
