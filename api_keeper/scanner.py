"""
Scanner Module - Local file scanning for API keys.

Provides functionality to scan directories for files containing potential
API keys using regex patterns and entropy analysis.
"""

import math
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from api_keeper.logger import AuditLogger


@dataclass
class ScanResult:
    """Represents a potential API key found during scanning."""
    
    key_value: str
    source_file: str
    line_number: int
    context: str
    entropy: float
    pattern_name: str
    detected_at: datetime = field(default_factory=datetime.now)
    
    def __repr__(self) -> str:
        # Don't expose the full key in repr for security
        masked_key = self.key_value[:4] + "..." + self.key_value[-4:] if len(self.key_value) > 8 else "***"
        return f"ScanResult(key={masked_key}, file={self.source_file}, line={self.line_number})"


class KeyScanner:
    """
    Scans local files for potential API keys using pattern matching
    and entropy analysis.
    """
    
    # Common API key patterns for various services
    DEFAULT_PATTERNS = {
        "aws_access_key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "aws_secret_key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
        "openai_key": r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
        "openai_key_new": r"sk-(?:proj-)?[a-zA-Z0-9_-]{40,}",
        "github_token": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        "github_oauth": r"gho_[A-Za-z0-9]{36}",
        "stripe_key": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
        "google_api_key": r"AIza[0-9A-Za-z_-]{35}",
        "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z]{24}",
        "slack_webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "twilio_key": r"SK[0-9a-fA-F]{32}",
        "sendgrid_key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "mailgun_key": r"key-[0-9a-zA-Z]{32}",
        "heroku_key": r"(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
        "generic_api_key": r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?",
        "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "jwt_token": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        "high_entropy_string": r"['\"][a-zA-Z0-9+/=_-]{32,}['\"]",
    }
    
    # File extensions to scan by default
    DEFAULT_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
        ".env", ".yaml", ".yml", ".json", ".xml", ".ini", ".cfg", ".conf",
        ".properties", ".txt", ".md", ".sh", ".bash", ".zsh", ".config",
        ".toml", ".tf", ".tfvars", ".hcl", ".sql", ".cs", ".cpp", ".c",
        ".h", ".hpp", ".rs", ".swift", ".kt", ".scala", ".gradle"
    }
    
    # Directories to skip by default
    DEFAULT_SKIP_DIRS = {
        ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv",
        "venv", "env", ".env", "vendor", "target", "build", "dist",
        ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".cache",
        "site-packages", ".idea", ".vscode", "bin", "obj"
    }
    
    # Maximum file size to scan (10MB by default)
    DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024
    
    # Minimum entropy threshold for high-entropy detection
    DEFAULT_MIN_ENTROPY = 3.5
    
    def __init__(
        self,
        patterns: Optional[dict] = None,
        extensions: Optional[set] = None,
        skip_dirs: Optional[set] = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        min_entropy: float = DEFAULT_MIN_ENTROPY,
        logger: Optional[AuditLogger] = None
    ):
        """
        Initialize the key scanner.
        
        Args:
            patterns: Custom regex patterns to use (defaults to DEFAULT_PATTERNS)
            extensions: File extensions to scan (defaults to DEFAULT_EXTENSIONS)
            skip_dirs: Directories to skip (defaults to DEFAULT_SKIP_DIRS)
            max_file_size: Maximum file size in bytes to scan
            min_entropy: Minimum Shannon entropy for high-entropy detection
            logger: AuditLogger instance for logging
        """
        self.patterns = patterns or self.DEFAULT_PATTERNS.copy()
        self.extensions = extensions or self.DEFAULT_EXTENSIONS.copy()
        self.skip_dirs = skip_dirs or self.DEFAULT_SKIP_DIRS.copy()
        self.max_file_size = max_file_size
        self.min_entropy = min_entropy
        self.logger = logger or AuditLogger()
        
        # Compile regex patterns for performance
        self._compiled_patterns = {
            name: re.compile(pattern)
            for name, pattern in self.patterns.items()
        }
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """
        Calculate Shannon entropy of a string.
        
        Higher entropy indicates more randomness, which is typical of API keys.
        
        Args:
            data: String to analyze
            
        Returns:
            Shannon entropy value (bits per character)
        """
        if not data:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _should_scan_file(self, filepath: Path) -> bool:
        """Check if a file should be scanned based on extension and size."""
        # Check extension
        if self.extensions and filepath.suffix.lower() not in self.extensions:
            # Also check for dotfiles like .env
            if filepath.name.lower() not in {".env", ".envrc"}:
                return False
        
        # Check file size
        try:
            if filepath.stat().st_size > self.max_file_size:
                return False
        except OSError:
            return False
        
        return True
    
    def _should_skip_dir(self, dirpath: Path) -> bool:
        """Check if a directory should be skipped."""
        return dirpath.name in self.skip_dirs
    
    def _get_context(self, lines: list, line_idx: int, context_lines: int = 3) -> str:
        """Get surrounding context for a match."""
        start = max(0, line_idx - context_lines)
        end = min(len(lines), line_idx + context_lines + 1)
        return "\n".join(lines[start:end])
    
    def _scan_file_content(
        self,
        filepath: Path,
        content: str
    ) -> Generator[ScanResult, None, None]:
        """Scan file content for potential API keys."""
        lines = content.splitlines()
        
        for pattern_name, compiled_pattern in self._compiled_patterns.items():
            for match in compiled_pattern.finditer(content):
                matched_text = match.group(0)
                
                # For patterns with groups, use the first group if available
                if match.groups():
                    matched_text = match.group(1) or matched_text
                
                # Strip quotes if present
                matched_text = matched_text.strip("'\"")
                
                # Skip very short matches (likely false positives)
                if len(matched_text) < 16:
                    continue
                
                # Calculate entropy
                entropy = self.calculate_entropy(matched_text)
                
                # Skip low-entropy matches for high_entropy_string pattern
                if pattern_name == "high_entropy_string" and entropy < self.min_entropy:
                    continue
                
                # Find line number
                match_start = match.start()
                line_number = content[:match_start].count('\n') + 1
                
                # Get context
                context = self._get_context(lines, line_number - 1)
                
                yield ScanResult(
                    key_value=matched_text,
                    source_file=str(filepath),
                    line_number=line_number,
                    context=context,
                    entropy=entropy,
                    pattern_name=pattern_name
                )
    
    def scan_file(self, filepath: str) -> list[ScanResult]:
        """
        Scan a single file for potential API keys.
        
        Args:
            filepath: Path to the file to scan
            
        Returns:
            List of ScanResult objects for potential keys found
        """
        path = Path(filepath)
        results = []
        
        if not path.exists():
            self.logger.log_error("File not found", path=str(path))
            return results
        
        if not path.is_file():
            self.logger.log_error("Not a file", path=str(path))
            return results
        
        if not self._should_scan_file(path):
            return results
        
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for result in self._scan_file_content(path, content):
                results.append(result)
                
        except PermissionError:
            self.logger.log_error("Permission denied", path=str(path))
        except OSError as e:
            self.logger.log_error("Error reading file", path=str(path), error=str(e))
        
        return results
    
    def scan_directory(
        self,
        directory: str,
        recursive: bool = True
    ) -> Generator[ScanResult, None, None]:
        """
        Scan a directory for potential API keys.
        
        Args:
            directory: Path to the directory to scan
            recursive: Whether to scan subdirectories
            
        Yields:
            ScanResult objects for potential keys found
        """
        import time
        start_time = time.time()
        
        dir_path = Path(directory)
        
        if not dir_path.exists():
            self.logger.log_error("Directory not found", path=str(dir_path))
            return
        
        if not dir_path.is_dir():
            self.logger.log_error("Not a directory", path=str(dir_path))
            return
        
        self.logger.log_scan_start(str(dir_path), len(self.patterns))
        
        files_scanned = 0
        keys_found = 0
        
        try:
            if recursive:
                walker = os.walk(dir_path)
            else:
                walker = [(str(dir_path), [], [f.name for f in dir_path.iterdir() if f.is_file()])]
            
            for root, dirs, files in walker:
                root_path = Path(root)
                
                # Filter out directories to skip
                dirs[:] = [d for d in dirs if not self._should_skip_dir(Path(d))]
                
                for filename in files:
                    filepath = root_path / filename
                    
                    if not self._should_scan_file(filepath):
                        continue
                    
                    files_scanned += 1
                    
                    for result in self.scan_file(str(filepath)):
                        keys_found += 1
                        yield result
                        
        except PermissionError:
            self.logger.log_error("Permission denied on directory", path=str(dir_path))
        except OSError as e:
            self.logger.log_error("Error scanning directory", path=str(dir_path), error=str(e))
        
        duration = time.time() - start_time
        self.logger.log_scan_complete(str(dir_path), files_scanned, keys_found, duration)
    
    def add_pattern(self, name: str, pattern: str) -> None:
        """Add a custom regex pattern for detection."""
        self.patterns[name] = pattern
        self._compiled_patterns[name] = re.compile(pattern)
    
    def remove_pattern(self, name: str) -> bool:
        """Remove a pattern by name."""
        if name in self.patterns:
            del self.patterns[name]
            del self._compiled_patterns[name]
            return True
        return False
