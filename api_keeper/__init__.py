"""
API Keeper - Secure Local API Key Management Tool

A Python tool for scanning, extracting, and securely storing API keys
from local files with encryption, backup, and audit capabilities.
"""

__version__ = "1.0.0"
__author__ = "API Keeper Team"

from api_keeper.scanner import KeyScanner
from api_keeper.extractor import KeyExtractor
from api_keeper.storage import SecureStorage
from api_keeper.manager import KeyManager
from api_keeper.logger import AuditLogger

__all__ = [
    "KeyScanner",
    "KeyExtractor", 
    "SecureStorage",
    "KeyManager",
    "AuditLogger",
]
