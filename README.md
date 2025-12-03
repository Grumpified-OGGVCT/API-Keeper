# API-Keeper

A secure, local API key management tool in Python that provides automated scanning, extraction, encrypted storage, and management of API keys with backup and rotation support.

## Features

- **Local Search and Scanning**: Scan directories for files containing potential API keys using regex patterns and entropy analysis
- **Extraction and Identification**: Automatically extract detected keys and identify associated services (AWS, OpenAI, GitHub, Stripe, etc.) via context analysis
- **Self-Organizing Storage**: Categorize and store keys by service with encrypted SQLite storage using AES-256 encryption
- **Safe Retrieval and Management**: CLI interface for searching, viewing, updating, or deleting keys with master password protection
- **Backup and Restore**: Prevent key loss with encrypted backups
- **Key Rotation Reminders**: Get notified when keys need rotation
- **Audit Logging**: Comprehensive logging of all activities

## Installation

```bash
# Clone the repository
git clone https://github.com/Grumpified-OGGVCT/API-Keeper.git
cd API-Keeper

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Quick Start

```bash
# Scan a directory for API keys
api-keeper scan ~/projects

# Store found keys (will prompt for master password)
api-keeper scan ~/projects --store

# List all stored keys
api-keeper list

# Get a specific key by ID
api-keeper get 1

# Add a key manually
api-keeper add --service openai --notes "Production key"

# Search for keys
api-keeper search aws

# Check for keys needing rotation
api-keeper rotation-check

# Create a backup
api-keeper backup
```

## Usage

### Scanning for API Keys

```bash
# Scan a directory recursively (default)
api-keeper scan /path/to/directory

# Scan without recursion
api-keeper scan /path/to/directory --no-recursive

# Scan and automatically store found keys
api-keeper scan /path/to/directory --store

# Set minimum confidence threshold (default: 0.3)
api-keeper scan /path/to/directory --min-confidence 0.5
```

### Managing Keys

```bash
# List all keys
api-keeper list

# List keys for a specific service
api-keeper list --service aws

# Show key values (decrypted)
api-keeper list --show-values

# Get a specific key
api-keeper get <key_id>

# Add a new key manually
api-keeper add --service <service_name> --key <key_value>
api-keeper add --service openai --notes "Development key" --rotation-days 30

# Update a key
api-keeper update <key_id> --notes "Updated notes"
api-keeper update <key_id> --service new_service
api-keeper update <key_id> --rotate  # Rotate key value

# Delete a key
api-keeper delete <key_id>
api-keeper delete <key_id> --force  # Skip confirmation

# Search keys
api-keeper search <query>
```

### Backup and Restore

```bash
# Create a backup
api-keeper backup
api-keeper backup --name my_backup.db

# List available backups
api-keeper list-backups

# Restore from backup
api-keeper restore /path/to/backup.db
```

### Key Rotation

```bash
# Check for keys needing rotation
api-keeper rotation-check

# Override default rotation days
api-keeper rotation-check --days 30

# Rotate a specific key
api-keeper update <key_id> --rotate
```

### Security Management

```bash
# Change master password
api-keeper change-password

# View audit logs
api-keeper logs
api-keeper logs --lines 100

# View storage statistics
api-keeper stats

# List all services
api-keeper services
```

### Pattern Management

```bash
# List all scan patterns
api-keeper patterns

# Add a custom pattern
api-keeper patterns --add custom_pattern "CUSTOM_[A-Z]{10}"

# Remove a pattern
api-keeper patterns --remove custom_pattern
```

## Python API

```python
from api_keeper import KeyManager

# Initialize manager
manager = KeyManager()

# Authenticate (creates storage if new)
is_new = manager.authenticate("master_password")

# Scan and store keys
result = manager.scan_and_store(
    "/path/to/scan",
    recursive=True,
    min_confidence=0.5
)

# Add a key manually
key_id = manager.add_key(
    key_value="sk-xxx...",
    service="openai",
    notes="Production key",
    rotation_days=90
)

# List keys
keys = manager.list_keys(service="openai")

# Get a specific key
key = manager.get_key(key_id)

# Search keys
results = manager.search_keys("openai")

# Rotate a key
manager.rotate_key(key_id, "new_key_value")

# Get rotation reminders
reminders = manager.get_rotation_reminders()

# Create backup
backup_path = manager.create_backup()

# Get statistics
stats = manager.get_stats()
```

## Supported Services

API-Keeper can automatically identify keys for the following services:

- AWS (Access Keys, Secret Keys)
- OpenAI
- GitHub (PAT, OAuth tokens)
- Stripe (Test and Live keys)
- Google Cloud Platform
- Slack (Bot tokens, Webhooks)
- Twilio
- SendGrid
- Mailgun
- Heroku
- Azure
- Datadog
- MongoDB
- PostgreSQL
- Redis
- Docker
- DigitalOcean
- Cloudflare
- NPM
- And more...

## Security

- **Encryption**: All keys are encrypted using AES-256 (Fernet) before storage
- **Key Derivation**: Master password is processed using PBKDF2 with 480,000 iterations
- **Local Storage**: All data is stored locally in `~/.api_keeper/`
- **File Permissions**: Database and backup files are created with restrictive permissions (600)
- **No Plaintext**: Keys are never stored in plaintext

## Configuration

Default storage location: `~/.api_keeper/`

You can override this with the `--storage-dir` option:

```bash
api-keeper --storage-dir /custom/path scan ~/projects
```

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=api_keeper --cov-report=term-missing
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
