"""Tests for the manager module."""

import os
import tempfile
from pathlib import Path

import pytest

from api_keeper.manager import KeyManager
from api_keeper.storage import AuthenticationError


class TestKeyManager:
    """Tests for the KeyManager class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def manager(self, temp_dir):
        """Create and authenticate a manager instance."""
        manager = KeyManager(storage_dir=temp_dir, log_dir=temp_dir)
        manager.authenticate("test_password")
        return manager
    
    def test_authenticate_new_storage(self, temp_dir):
        """Should create new storage on first authentication."""
        manager = KeyManager(storage_dir=temp_dir)
        is_new = manager.authenticate("test_password")
        
        assert is_new is True
        assert manager.is_authenticated()
    
    def test_authenticate_existing_storage(self, temp_dir):
        """Should authenticate with existing storage."""
        # Create storage
        manager1 = KeyManager(storage_dir=temp_dir)
        manager1.authenticate("test_password")
        
        # Reopen
        manager2 = KeyManager(storage_dir=temp_dir)
        is_new = manager2.authenticate("test_password")
        
        assert is_new is False
        assert manager2.is_authenticated()
    
    def test_wrong_password(self, temp_dir):
        """Should reject wrong password."""
        manager1 = KeyManager(storage_dir=temp_dir)
        manager1.authenticate("correct")
        
        manager2 = KeyManager(storage_dir=temp_dir)
        with pytest.raises(AuthenticationError):
            manager2.authenticate("wrong")
    
    def test_add_key_manually(self, manager):
        """Should add a key manually."""
        key_id = manager.add_key(
            key_value="test-api-key-1234567890",
            service="test_service",
            notes="Test key",
            rotation_days=30
        )
        
        assert key_id > 0
        
        key = manager.get_key(key_id)
        assert key['service'] == "test_service"
        assert key['key_value'] == "test-api-key-1234567890"
    
    def test_list_keys(self, manager):
        """Should list stored keys."""
        manager.add_key("key1", "service_a")
        manager.add_key("key2", "service_b")
        
        keys = manager.list_keys()
        
        assert len(keys) == 2
    
    def test_list_keys_by_service(self, manager):
        """Should filter keys by service."""
        manager.add_key("key1", "service_a")
        manager.add_key("key2", "service_b")
        
        keys = manager.list_keys(service="service_a")
        
        assert len(keys) == 1
        assert keys[0]['service'] == "service_a"
    
    def test_search_keys(self, manager):
        """Should search keys."""
        manager.add_key("key1", "openai", notes="GPT key")
        
        results = manager.search_keys("openai")
        
        assert len(results) > 0
    
    def test_update_key(self, manager):
        """Should update key properties."""
        key_id = manager.add_key("key1", "test")
        
        success = manager.update_key(
            key_id,
            notes="Updated notes",
            service="new_service"
        )
        
        assert success is True
        
        key = manager.get_key(key_id)
        assert key['notes'] == "Updated notes"
        assert key['service'] == "new_service"
    
    def test_rotate_key(self, manager):
        """Should rotate key with new value."""
        key_id = manager.add_key("old_key", "test")
        
        success = manager.rotate_key(key_id, "new_key")
        
        assert success is True
        
        key = manager.get_key(key_id)
        assert key['key_value'] == "new_key"
        assert key['last_rotated'] is not None
    
    def test_delete_key(self, manager):
        """Should delete a key."""
        key_id = manager.add_key("key1", "test")
        
        success = manager.delete_key(key_id)
        
        assert success is True
        assert manager.get_key(key_id) is None
    
    def test_get_services(self, manager):
        """Should get list of services."""
        manager.add_key("key1", "aws")
        manager.add_key("key2", "github")
        
        services = manager.get_services()
        
        assert "aws" in services
        assert "github" in services
    
    def test_get_stats(self, manager):
        """Should get storage statistics."""
        manager.add_key("key1", "aws")
        manager.add_key("key2", "aws")
        manager.add_key("key3", "github")
        
        stats = manager.get_stats()
        
        assert stats['total_keys'] == 3
        assert stats['services_count'] == 2
        assert stats['by_service']['aws'] == 2
    
    def test_backup_and_restore(self, manager, temp_dir):
        """Should backup and restore."""
        key_id = manager.add_key("key1", "test")
        backup_path = manager.create_backup()
        
        # Delete key
        manager.delete_key(key_id)
        assert manager.get_key(key_id) is None
        
        # Restore
        manager.restore_backup(backup_path)
        manager.authenticate("test_password")
        
        # Key should be back
        assert manager.get_key(key_id) is not None
    
    def test_change_password(self, manager, temp_dir):
        """Should change password."""
        manager.add_key("key1", "test")
        
        success = manager.change_password("test_password", "new_password")
        
        assert success is True
        
        # Verify new password works
        manager2 = KeyManager(storage_dir=temp_dir)
        manager2.authenticate("new_password")
        
        keys = manager2.list_keys()
        assert len(keys) == 1
    
    def test_rotation_reminders(self, manager):
        """Should get rotation reminders."""
        # Add a key with a short rotation period
        key_id = manager.add_key("key1", "test", rotation_days=1)
        
        # For newly created keys, check using 0 days override
        reminders = manager.get_rotation_reminders(days=0)
        
        # A key created just now with days_old=0 and reminder_days=0 should trigger
        assert len(reminders) > 0
        assert any(r['id'] == key_id for r in reminders)
    
    def test_check_rotation_due(self, manager):
        """Should check if specific key is due for rotation."""
        # Add a key with 0 rotation days (immediately due)
        key_id = manager.add_key("key1", "test", rotation_days=0)
        
        status = manager.check_rotation_due(key_id)
        
        # A key with rotation_reminder_days=0 should be due immediately
        # since days_old (0) >= reminder_days (0)
        assert status['key_id'] == key_id
        assert status['is_due'] is True


class TestScanning:
    """Tests for scanning functionality through manager."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def manager(self, temp_dir):
        """Create a manager instance."""
        storage_dir = os.path.join(temp_dir, "storage")
        return KeyManager(storage_dir=storage_dir, log_dir=temp_dir)
    
    def test_scan_directory_finds_keys(self, manager, temp_dir):
        """Should find keys in scanned directory."""
        # Create test file with API key
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        
        extracted = manager.scan_directory(temp_dir)
        
        assert len(extracted) > 0
        assert any("AKIAIOSFODNN7" in k.key_value for k in extracted)
    
    def test_scan_file(self, manager, temp_dir):
        """Should scan single file."""
        test_file = Path(temp_dir) / "secrets.env"
        test_file.write_text('GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
        
        extracted = manager.scan_file(str(test_file))
        
        assert len(extracted) > 0
    
    def test_scan_and_store(self, manager, temp_dir):
        """Should scan and store keys."""
        manager.authenticate("test_password")
        
        # Create test file
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        
        result = manager.scan_and_store(
            temp_dir,
            min_confidence=0.1,
            auto_backup=False
        )
        
        assert result['keys_found'] > 0
        assert result['keys_stored'] > 0
        assert len(result['stored_ids']) == result['keys_stored']


class TestPatternManagement:
    """Tests for pattern management."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def manager(self, temp_dir):
        """Create a manager instance."""
        return KeyManager(storage_dir=temp_dir, log_dir=temp_dir)
    
    def test_add_scan_pattern(self, manager):
        """Should add custom scan pattern."""
        manager.add_scan_pattern("custom", r"CUSTOM_[A-Z]{10}")
        
        patterns = manager.list_scan_patterns()
        
        assert "custom" in patterns
    
    def test_remove_scan_pattern(self, manager):
        """Should remove scan pattern."""
        manager.add_scan_pattern("to_remove", r"REMOVE_[A-Z]+")
        
        success = manager.remove_scan_pattern("to_remove")
        
        assert success is True
        assert "to_remove" not in manager.list_scan_patterns()
