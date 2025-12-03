"""Tests for the extractor module."""

import pytest

from api_keeper.scanner import ScanResult
from api_keeper.extractor import KeyExtractor, ExtractedKey


class TestKeyExtractor:
    """Tests for the KeyExtractor class."""
    
    @pytest.fixture
    def extractor(self):
        """Create an extractor instance."""
        return KeyExtractor()
    
    def test_identify_aws_from_pattern(self, extractor):
        """Should identify AWS from pattern name."""
        scan_result = ScanResult(
            key_value="AKIAIOSFODNN7EXAMPLE",
            source_file="/path/config.py",
            line_number=10,
            context="aws_access_key = 'AKIAIOSFODNN7EXAMPLE'",
            entropy=4.0,
            pattern_name="aws_access_key"
        )
        
        service, confidence = extractor.identify_service(scan_result)
        
        assert service == "aws"
        assert confidence >= 0.5  # Pattern + context should give good confidence
    
    def test_identify_github_from_pattern(self, extractor):
        """Should identify GitHub from pattern name."""
        scan_result = ScanResult(
            key_value="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            source_file="/path/config.py",
            line_number=10,
            context="GITHUB_TOKEN = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
            entropy=4.0,
            pattern_name="github_token"
        )
        
        service, confidence = extractor.identify_service(scan_result)
        
        assert service == "github"
        assert confidence >= 0.9
    
    def test_identify_from_context_keywords(self, extractor):
        """Should identify service from context keywords."""
        scan_result = ScanResult(
            key_value="sk-random-key-value-1234567890abcdefg",
            source_file="/path/config.py",
            line_number=10,
            context="# OpenAI API key for GPT model\nOPENAI_API_KEY = 'sk-random-key-value-1234567890abcdefg'",
            entropy=4.0,
            pattern_name="generic_api_key"
        )
        
        service, confidence = extractor.identify_service(scan_result)
        
        assert service == "openai"
        assert confidence > 0.5
    
    def test_identify_from_env_var_name(self, extractor):
        """Should identify service from environment variable names."""
        scan_result = ScanResult(
            key_value="some-api-key-value-1234567890",
            source_file="/path/.env",
            line_number=5,
            context="STRIPE_API_KEY=some-api-key-value-1234567890",
            entropy=4.0,
            pattern_name="generic_api_key"
        )
        
        service, confidence = extractor.identify_service(scan_result)
        
        assert service == "stripe"
    
    def test_extract_creates_extracted_key(self, extractor):
        """Should create ExtractedKey from ScanResult."""
        scan_result = ScanResult(
            key_value="AKIAIOSFODNN7EXAMPLE",
            source_file="/path/config.py",
            line_number=10,
            context="AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
            entropy=4.0,
            pattern_name="aws_access_key"
        )
        
        extracted = extractor.extract(scan_result)
        
        assert isinstance(extracted, ExtractedKey)
        assert extracted.key_value == "AKIAIOSFODNN7EXAMPLE"
        assert extracted.service == "aws"
        assert extracted.source_file == "/path/config.py"
        assert extracted.confidence >= 0.5  # Should have reasonable confidence
    
    def test_extract_all_deduplicates(self, extractor):
        """Should deduplicate keys from same file."""
        scan_results = [
            ScanResult(
                key_value="AKIAIOSFODNN7EXAMPLE",
                source_file="/path/config.py",
                line_number=10,
                context="context1",
                entropy=4.0,
                pattern_name="aws_access_key"
            ),
            ScanResult(
                key_value="AKIAIOSFODNN7EXAMPLE",
                source_file="/path/config.py",
                line_number=20,
                context="context2",
                entropy=4.0,
                pattern_name="aws_access_key"
            ),
        ]
        
        extracted = extractor.extract_all(scan_results)
        
        assert len(extracted) == 1
    
    def test_filter_by_confidence(self, extractor):
        """Should filter keys by confidence threshold."""
        keys = [
            ExtractedKey(
                key_value="key1",
                service="aws",
                source_file="file1.py",
                line_number=1,
                context="",
                confidence=0.9,
                entropy=4.0,
                pattern_name="aws_access_key"
            ),
            ExtractedKey(
                key_value="key2",
                service="unknown",
                source_file="file2.py",
                line_number=1,
                context="",
                confidence=0.2,
                entropy=4.0,
                pattern_name="generic"
            ),
        ]
        
        filtered = extractor.filter_by_confidence(keys, min_confidence=0.5)
        
        assert len(filtered) == 1
        assert filtered[0].service == "aws"
    
    def test_filter_by_service(self, extractor):
        """Should filter keys by service name."""
        keys = [
            ExtractedKey(
                key_value="key1",
                service="aws",
                source_file="file1.py",
                line_number=1,
                context="",
                confidence=0.9,
                entropy=4.0,
                pattern_name="pattern"
            ),
            ExtractedKey(
                key_value="key2",
                service="github",
                source_file="file2.py",
                line_number=1,
                context="",
                confidence=0.9,
                entropy=4.0,
                pattern_name="pattern"
            ),
        ]
        
        filtered = extractor.filter_by_service(keys, "aws")
        
        assert len(filtered) == 1
        assert filtered[0].service == "aws"
    
    def test_group_by_service(self, extractor):
        """Should group keys by service."""
        keys = [
            ExtractedKey(
                key_value="key1",
                service="aws",
                source_file="file1.py",
                line_number=1,
                context="",
                confidence=0.9,
                entropy=4.0,
                pattern_name="pattern"
            ),
            ExtractedKey(
                key_value="key2",
                service="aws",
                source_file="file2.py",
                line_number=1,
                context="",
                confidence=0.9,
                entropy=4.0,
                pattern_name="pattern"
            ),
            ExtractedKey(
                key_value="key3",
                service="github",
                source_file="file3.py",
                line_number=1,
                context="",
                confidence=0.9,
                entropy=4.0,
                pattern_name="pattern"
            ),
        ]
        
        grouped = extractor.group_by_service(keys)
        
        assert len(grouped) == 2
        assert len(grouped["aws"]) == 2
        assert len(grouped["github"]) == 1


class TestExtractedKey:
    """Tests for ExtractedKey dataclass."""
    
    def test_repr_masks_key(self):
        """Repr should mask the key value."""
        key = ExtractedKey(
            key_value="super-secret-api-key-value-1234567890",
            service="aws",
            source_file="/path/file.py",
            line_number=10,
            context="context",
            confidence=0.9,
            entropy=4.0,
            pattern_name="pattern"
        )
        
        repr_str = repr(key)
        
        assert "super-secret-api-key-value-1234567890" not in repr_str
        assert "supe" in repr_str  # First 4 chars
