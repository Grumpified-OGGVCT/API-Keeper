"""
Extractor Module - Key extraction and service identification.

Provides functionality to extract API keys from scan results and
identify associated services using context analysis.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from api_keeper.scanner import ScanResult
from api_keeper.logger import AuditLogger


@dataclass
class ExtractedKey:
    """Represents an extracted and identified API key."""
    
    key_value: str
    service: str
    source_file: str
    line_number: int
    context: str
    confidence: float
    entropy: float
    pattern_name: str
    extracted_at: datetime = field(default_factory=datetime.now)
    metadata: dict = field(default_factory=dict)
    
    def __repr__(self) -> str:
        # Don't expose the full key in repr for security
        masked = self.key_value[:4] + "..." + self.key_value[-4:] if len(self.key_value) > 8 else "***"
        return f"ExtractedKey(service={self.service}, key={masked}, confidence={self.confidence:.2f})"


class KeyExtractor:
    """
    Extracts and identifies API keys from scan results.
    
    Uses context analysis, pattern matching, and heuristics to determine
    the service associated with each key.
    """
    
    # Service identification keywords and patterns
    SERVICE_KEYWORDS = {
        "aws": {
            "keywords": ["aws", "amazon", "s3", "ec2", "lambda", "dynamodb", "sqs", "sns", "iam"],
            "env_vars": ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SECRET_ACCESS_KEY"],
            "file_patterns": [".aws", "aws-credentials", "aws.json", "aws.yaml"],
        },
        "openai": {
            "keywords": ["openai", "gpt", "chatgpt", "davinci", "curie", "ada", "babbage"],
            "env_vars": ["OPENAI_API_KEY", "OPENAI_KEY"],
            "file_patterns": [".openai", "openai.json"],
        },
        "github": {
            "keywords": ["github", "gh", "octokit", "repository", "repo", "actions"],
            "env_vars": ["GITHUB_TOKEN", "GH_TOKEN", "GITHUB_API_KEY"],
            "file_patterns": [".github", "github-token"],
        },
        "stripe": {
            "keywords": ["stripe", "payment", "subscription", "customer"],
            "env_vars": ["STRIPE_KEY", "STRIPE_SECRET_KEY", "STRIPE_API_KEY"],
            "file_patterns": ["stripe.json", ".stripe"],
        },
        "google": {
            "keywords": ["google", "gcp", "firebase", "bigquery", "cloud", "maps", "youtube"],
            "env_vars": ["GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "GCP_KEY"],
            "file_patterns": ["google-credentials.json", "service-account.json", ".gcp"],
        },
        "slack": {
            "keywords": ["slack", "slackbot", "webhook", "channel", "workspace"],
            "env_vars": ["SLACK_TOKEN", "SLACK_API_TOKEN", "SLACK_WEBHOOK"],
            "file_patterns": [".slack", "slack.json"],
        },
        "twilio": {
            "keywords": ["twilio", "sms", "messaging", "phone", "voice"],
            "env_vars": ["TWILIO_AUTH_TOKEN", "TWILIO_API_KEY", "TWILIO_SID"],
            "file_patterns": ["twilio.json", ".twilio"],
        },
        "sendgrid": {
            "keywords": ["sendgrid", "email", "mail", "smtp"],
            "env_vars": ["SENDGRID_API_KEY", "SENDGRID_KEY"],
            "file_patterns": ["sendgrid.json"],
        },
        "mailgun": {
            "keywords": ["mailgun", "email", "mail"],
            "env_vars": ["MAILGUN_API_KEY", "MAILGUN_KEY"],
            "file_patterns": ["mailgun.json"],
        },
        "heroku": {
            "keywords": ["heroku", "dyno", "buildpack"],
            "env_vars": ["HEROKU_API_KEY", "HEROKU_TOKEN"],
            "file_patterns": ["heroku.json", ".heroku"],
        },
        "azure": {
            "keywords": ["azure", "microsoft", "cosmos", "blob", "function"],
            "env_vars": ["AZURE_API_KEY", "AZURE_SUBSCRIPTION_KEY"],
            "file_patterns": ["azure.json", ".azure"],
        },
        "datadog": {
            "keywords": ["datadog", "dd", "monitoring", "metrics"],
            "env_vars": ["DD_API_KEY", "DATADOG_API_KEY"],
            "file_patterns": ["datadog.json"],
        },
        "mongodb": {
            "keywords": ["mongodb", "mongo", "atlas"],
            "env_vars": ["MONGODB_URI", "MONGO_URL"],
            "file_patterns": ["mongodb.json"],
        },
        "postgresql": {
            "keywords": ["postgres", "postgresql", "pg", "database"],
            "env_vars": ["DATABASE_URL", "POSTGRES_PASSWORD"],
            "file_patterns": [],
        },
        "redis": {
            "keywords": ["redis", "cache", "celery"],
            "env_vars": ["REDIS_URL", "REDIS_PASSWORD"],
            "file_patterns": [],
        },
        "jwt": {
            "keywords": ["jwt", "token", "bearer", "auth"],
            "env_vars": ["JWT_SECRET", "JWT_KEY"],
            "file_patterns": [],
        },
        "npm": {
            "keywords": ["npm", "registry", "publish"],
            "env_vars": ["NPM_TOKEN", "NPM_AUTH_TOKEN"],
            "file_patterns": [".npmrc"],
        },
        "docker": {
            "keywords": ["docker", "registry", "container"],
            "env_vars": ["DOCKER_PASSWORD", "DOCKER_TOKEN"],
            "file_patterns": [".docker"],
        },
        "digitalocean": {
            "keywords": ["digitalocean", "droplet", "spaces"],
            "env_vars": ["DO_API_KEY", "DIGITALOCEAN_TOKEN"],
            "file_patterns": [],
        },
        "cloudflare": {
            "keywords": ["cloudflare", "cdn", "dns"],
            "env_vars": ["CLOUDFLARE_API_KEY", "CF_API_KEY"],
            "file_patterns": [],
        },
    }
    
    # Pattern-based service detection
    PATTERN_SERVICE_MAP = {
        "aws_access_key": "aws",
        "aws_secret_key": "aws",
        "openai_key": "openai",
        "openai_key_new": "openai",
        "github_token": "github",
        "github_oauth": "github",
        "stripe_key": "stripe",
        "google_api_key": "google",
        "slack_token": "slack",
        "slack_webhook": "slack",
        "twilio_key": "twilio",
        "sendgrid_key": "sendgrid",
        "mailgun_key": "mailgun",
        "heroku_key": "heroku",
        "jwt_token": "jwt",
    }
    
    def __init__(self, logger: Optional[AuditLogger] = None):
        """
        Initialize the key extractor.
        
        Args:
            logger: AuditLogger instance for logging
        """
        self.logger = logger or AuditLogger()
    
    def _identify_from_pattern(self, pattern_name: str) -> tuple[str, float]:
        """
        Identify service from the pattern that matched.
        
        Returns:
            Tuple of (service_name, confidence)
        """
        if pattern_name in self.PATTERN_SERVICE_MAP:
            return self.PATTERN_SERVICE_MAP[pattern_name], 0.9
        return "unknown", 0.0
    
    def _identify_from_context(self, context: str) -> tuple[str, float]:
        """
        Identify service from surrounding context.
        
        Returns:
            Tuple of (service_name, confidence)
        """
        context_lower = context.lower()
        best_match = ("unknown", 0.0)
        
        for service, info in self.SERVICE_KEYWORDS.items():
            score = 0.0
            matches = 0
            
            # Check keywords
            for keyword in info["keywords"]:
                if keyword in context_lower:
                    matches += 1
                    score += 0.2
            
            # Check environment variable names
            for env_var in info["env_vars"]:
                if env_var.lower() in context_lower:
                    matches += 1
                    score += 0.4
            
            # Normalize score
            if matches > 0:
                confidence = min(score, 0.85)  # Cap at 0.85 for context-only
                if confidence > best_match[1]:
                    best_match = (service, confidence)
        
        return best_match
    
    def _identify_from_filename(self, filepath: str) -> tuple[str, float]:
        """
        Identify service from the filename/path.
        
        Returns:
            Tuple of (service_name, confidence)
        """
        path = Path(filepath)
        filename_lower = path.name.lower()
        path_str_lower = str(path).lower()
        
        for service, info in self.SERVICE_KEYWORDS.items():
            for pattern in info.get("file_patterns", []):
                if pattern in filename_lower or pattern in path_str_lower:
                    return service, 0.7
        
        # Check for common config file patterns
        if ".env" in filename_lower:
            return "unknown", 0.3  # Could be any service
        
        return "unknown", 0.0
    
    def identify_service(self, scan_result: ScanResult) -> tuple[str, float]:
        """
        Identify the service associated with a scanned key.
        
        Uses multiple heuristics and combines confidence scores.
        
        Args:
            scan_result: The ScanResult to analyze
            
        Returns:
            Tuple of (service_name, confidence_score)
        """
        identifications = []
        
        # Try pattern-based identification first (most reliable)
        service, confidence = self._identify_from_pattern(scan_result.pattern_name)
        if confidence > 0:
            identifications.append((service, confidence))
        
        # Try context-based identification
        service, confidence = self._identify_from_context(scan_result.context)
        if confidence > 0:
            identifications.append((service, confidence))
        
        # Try filename-based identification
        service, confidence = self._identify_from_filename(scan_result.source_file)
        if confidence > 0:
            identifications.append((service, confidence))
        
        if not identifications:
            return "unknown", 0.1
        
        # Combine identifications
        # If multiple methods agree, boost confidence
        service_votes = {}
        for svc, conf in identifications:
            if svc != "unknown":
                if svc not in service_votes:
                    service_votes[svc] = []
                service_votes[svc].append(conf)
        
        if not service_votes:
            return "unknown", 0.2
        
        # Pick the service with highest combined confidence
        best_service = "unknown"
        best_score = 0.0
        
        for svc, confidences in service_votes.items():
            # Average confidence with bonus for multiple sources
            avg_conf = sum(confidences) / len(confidences)
            bonus = min(0.1 * (len(confidences) - 1), 0.15)
            combined = min(avg_conf + bonus, 0.99)
            
            if combined > best_score:
                best_service = svc
                best_score = combined
        
        return best_service, best_score
    
    def extract(self, scan_result: ScanResult) -> ExtractedKey:
        """
        Extract and identify a key from a scan result.
        
        Args:
            scan_result: The ScanResult to process
            
        Returns:
            ExtractedKey with service identification
        """
        service, confidence = self.identify_service(scan_result)
        
        extracted = ExtractedKey(
            key_value=scan_result.key_value,
            service=service,
            source_file=scan_result.source_file,
            line_number=scan_result.line_number,
            context=scan_result.context,
            confidence=confidence,
            entropy=scan_result.entropy,
            pattern_name=scan_result.pattern_name,
            extracted_at=scan_result.detected_at,
            metadata={
                "pattern_matched": scan_result.pattern_name,
            }
        )
        
        self.logger.log_key_extracted(
            service=service,
            source_file=scan_result.source_file,
            confidence=confidence
        )
        
        return extracted
    
    def extract_all(self, scan_results: list[ScanResult]) -> list[ExtractedKey]:
        """
        Extract and identify all keys from scan results.
        
        Args:
            scan_results: List of ScanResult objects to process
            
        Returns:
            List of ExtractedKey objects
        """
        extracted_keys = []
        seen_keys = set()  # Deduplicate
        
        for result in scan_results:
            # Skip duplicates
            key_hash = hash((result.key_value, result.source_file))
            if key_hash in seen_keys:
                continue
            seen_keys.add(key_hash)
            
            extracted = self.extract(result)
            extracted_keys.append(extracted)
        
        return extracted_keys
    
    def filter_by_confidence(
        self,
        extracted_keys: list[ExtractedKey],
        min_confidence: float = 0.5
    ) -> list[ExtractedKey]:
        """Filter extracted keys by minimum confidence threshold."""
        return [k for k in extracted_keys if k.confidence >= min_confidence]
    
    def filter_by_service(
        self,
        extracted_keys: list[ExtractedKey],
        service: str
    ) -> list[ExtractedKey]:
        """Filter extracted keys by service name."""
        return [k for k in extracted_keys if k.service.lower() == service.lower()]
    
    def group_by_service(
        self,
        extracted_keys: list[ExtractedKey]
    ) -> dict[str, list[ExtractedKey]]:
        """Group extracted keys by their identified service."""
        grouped = {}
        for key in extracted_keys:
            if key.service not in grouped:
                grouped[key.service] = []
            grouped[key.service].append(key)
        return grouped
