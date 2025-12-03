"""Tests for the scanner module."""

import os
import tempfile
from pathlib import Path

import pytest

from api_keeper.scanner import KeyScanner, ScanResult


class TestEntropyCalculation:
    """Tests for entropy calculation."""
    
    def test_empty_string_entropy(self):
        """Empty string should have zero entropy."""
        assert KeyScanner.calculate_entropy("") == 0.0
    
    def test_single_char_entropy(self):
        """Single character string should have zero entropy."""
        assert KeyScanner.calculate_entropy("a") == 0.0
        assert KeyScanner.calculate_entropy("aaaa") == 0.0
    
    def test_high_entropy_string(self):
        """Random-looking strings should have high entropy."""
        # A typical API key has high entropy
        high_entropy = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW"
        entropy = KeyScanner.calculate_entropy(high_entropy)
        assert entropy > 3.5
    
    def test_low_entropy_string(self):
        """Repetitive strings should have low entropy."""
        low_entropy = "password123"
        entropy = KeyScanner.calculate_entropy(low_entropy)
        assert entropy < 3.5


class TestKeyScanner:
    """Tests for the KeyScanner class."""
    
    @pytest.fixture
    def scanner(self):
        """Create a scanner instance."""
        return KeyScanner()
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory with test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_default_patterns_loaded(self, scanner):
        """Default patterns should be loaded."""
        assert len(scanner.patterns) > 0
        assert "aws_access_key" in scanner.patterns
        assert "github_token" in scanner.patterns
    
    def test_add_custom_pattern(self, scanner):
        """Should be able to add custom patterns."""
        scanner.add_pattern("custom_test", r"TEST_[A-Z]{10}")
        assert "custom_test" in scanner.patterns
    
    def test_remove_pattern(self, scanner):
        """Should be able to remove patterns."""
        scanner.add_pattern("to_remove", r"REMOVE_ME")
        assert scanner.remove_pattern("to_remove")
        assert "to_remove" not in scanner.patterns
    
    def test_remove_nonexistent_pattern(self, scanner):
        """Removing nonexistent pattern should return False."""
        assert not scanner.remove_pattern("nonexistent")
    
    def test_scan_file_with_aws_key(self, scanner, temp_dir):
        """Should detect AWS access key pattern."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        
        results = scanner.scan_file(str(test_file))
        
        assert len(results) > 0
        assert any("AKIAIOSFODNN7EXAMPLE" in r.key_value for r in results)
    
    def test_scan_file_with_github_token(self, scanner, temp_dir):
        """Should detect GitHub token pattern."""
        test_file = Path(temp_dir) / "config.env"
        test_file.write_text('GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
        
        results = scanner.scan_file(str(test_file))
        
        assert len(results) > 0
        assert any("ghp_" in r.key_value for r in results)
    
    def test_scan_nonexistent_file(self, scanner):
        """Should handle nonexistent files gracefully."""
        results = scanner.scan_file("/nonexistent/file.txt")
        assert len(results) == 0
    
    def test_scan_empty_file(self, scanner, temp_dir):
        """Should handle empty files."""
        test_file = Path(temp_dir) / "empty.txt"
        test_file.write_text("")
        
        results = scanner.scan_file(str(test_file))
        assert len(results) == 0
    
    def test_scan_directory(self, scanner, temp_dir):
        """Should scan directory recursively."""
        # Create nested structure
        subdir = Path(temp_dir) / "subdir"
        subdir.mkdir()
        
        # File in root
        (Path(temp_dir) / "root.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"')
        
        # File in subdir
        (subdir / "nested.py").write_text('TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"')
        
        results = list(scanner.scan_directory(temp_dir))
        
        assert len(results) >= 2
    
    def test_skip_large_files(self, scanner, temp_dir):
        """Should skip files larger than max_file_size."""
        scanner.max_file_size = 100  # 100 bytes
        
        test_file = Path(temp_dir) / "large.txt"
        test_file.write_text("A" * 200 + 'KEY = "AKIAIOSFODNN7EXAMPLE"')
        
        results = scanner.scan_file(str(test_file))
        assert len(results) == 0
    
    def test_skip_ignored_directories(self, scanner, temp_dir):
        """Should skip directories in skip_dirs."""
        node_modules = Path(temp_dir) / "node_modules"
        node_modules.mkdir()
        (node_modules / "config.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"')
        
        results = list(scanner.scan_directory(temp_dir))
        
        # Should not find key in node_modules
        assert not any("node_modules" in r.source_file for r in results)
    
    def test_context_extraction(self, scanner, temp_dir):
        """Should extract context around matched keys."""
        test_file = Path(temp_dir) / "config.py"
        content = """# Configuration file
import os

# AWS Configuration
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_REGION = "us-east-1"

# End of config
"""
        test_file.write_text(content)
        
        results = scanner.scan_file(str(test_file))
        
        assert len(results) > 0
        assert "AWS" in results[0].context


class TestScanResult:
    """Tests for ScanResult dataclass."""
    
    def test_repr_masks_key(self):
        """Repr should mask the key value."""
        result = ScanResult(
            key_value="AKIAIOSFODNN7EXAMPLE1234567890",
            source_file="/path/to/file.py",
            line_number=10,
            context="some context",
            entropy=4.5,
            pattern_name="aws_access_key"
        )
        
        repr_str = repr(result)
        
        # Full key should not be in repr
        assert "AKIAIOSFODNN7EXAMPLE1234567890" not in repr_str
        # But partial should be visible
        assert "AKIA" in repr_str
