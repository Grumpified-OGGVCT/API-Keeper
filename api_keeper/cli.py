"""
CLI Module - Command-line interface for API Key Manager.

Provides a user-friendly command-line interface for all key management
operations including scanning, storage, retrieval, and backup.
"""

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import Optional

from api_keeper.manager import KeyManager
from api_keeper.storage import AuthenticationError, StorageError


def get_password(prompt: str = "Master password: ") -> str:
    """Securely get password from user."""
    return getpass.getpass(prompt)


def mask_key(key: str, visible_chars: int = 4) -> str:
    """Mask a key showing only first and last few characters."""
    if len(key) <= visible_chars * 2:
        return "*" * len(key)
    return key[:visible_chars] + "*" * (len(key) - visible_chars * 2) + key[-visible_chars:]


def format_table(headers: list, rows: list) -> str:
    """Format data as a simple table."""
    if not rows:
        return "No data to display."
    
    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    
    # Build table
    lines = []
    
    # Header
    header_line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    lines.append(header_line)
    lines.append("-" * len(header_line))
    
    # Rows
    for row in rows:
        row_line = " | ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))
        lines.append(row_line)
    
    return "\n".join(lines)


class CLI:
    """Command-line interface for API Key Manager."""
    
    def __init__(self):
        """Initialize CLI."""
        self.manager: Optional[KeyManager] = None
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            prog="api-keeper",
            description="Secure local API key management tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  api-keeper scan ~/projects              # Scan directory for API keys
  api-keeper list                         # List all stored keys
  api-keeper get 1                        # Get key by ID
  api-keeper add --service openai         # Add a new key manually
  api-keeper search aws                   # Search for keys
  api-keeper backup                       # Create a backup
  api-keeper rotation-check               # Check for keys needing rotation
            """
        )
        
        parser.add_argument(
            "--storage-dir",
            help="Storage directory (default: ~/.api_keeper)",
            default=None
        )
        
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        
        # === Scan command ===
        scan_parser = subparsers.add_parser("scan", help="Scan for API keys")
        scan_parser.add_argument("path", help="Directory or file to scan")
        scan_parser.add_argument(
            "--recursive", "-r",
            action="store_true",
            default=True,
            help="Scan recursively (default: true)"
        )
        scan_parser.add_argument(
            "--no-recursive",
            action="store_true",
            help="Don't scan recursively"
        )
        scan_parser.add_argument(
            "--store",
            action="store_true",
            help="Store found keys automatically"
        )
        scan_parser.add_argument(
            "--min-confidence",
            type=float,
            default=0.3,
            help="Minimum confidence threshold (default: 0.3)"
        )
        
        # === List command ===
        list_parser = subparsers.add_parser("list", help="List stored keys")
        list_parser.add_argument(
            "--service", "-s",
            help="Filter by service name"
        )
        list_parser.add_argument(
            "--show-values",
            action="store_true",
            help="Show decrypted key values"
        )
        
        # === Get command ===
        get_parser = subparsers.add_parser("get", help="Get a specific key")
        get_parser.add_argument("id", type=int, help="Key ID")
        
        # === Add command ===
        add_parser = subparsers.add_parser("add", help="Add a new key manually")
        add_parser.add_argument(
            "--service", "-s",
            required=True,
            help="Service name (e.g., aws, openai, github)"
        )
        add_parser.add_argument(
            "--key", "-k",
            help="API key value (will prompt if not provided)"
        )
        add_parser.add_argument(
            "--notes", "-n",
            help="Notes about this key"
        )
        add_parser.add_argument(
            "--rotation-days",
            type=int,
            default=90,
            help="Days until rotation reminder (default: 90)"
        )
        
        # === Update command ===
        update_parser = subparsers.add_parser("update", help="Update a key")
        update_parser.add_argument("id", type=int, help="Key ID")
        update_parser.add_argument("--service", "-s", help="New service name")
        update_parser.add_argument("--notes", "-n", help="New notes")
        update_parser.add_argument("--rotate", action="store_true", help="Rotate key value")
        update_parser.add_argument("--rotation-days", type=int, help="New rotation reminder days")
        
        # === Delete command ===
        delete_parser = subparsers.add_parser("delete", help="Delete a key")
        delete_parser.add_argument("id", type=int, help="Key ID")
        delete_parser.add_argument(
            "--force", "-f",
            action="store_true",
            help="Skip confirmation"
        )
        
        # === Search command ===
        search_parser = subparsers.add_parser("search", help="Search keys")
        search_parser.add_argument("query", help="Search query")
        
        # === Backup command ===
        backup_parser = subparsers.add_parser("backup", help="Create a backup")
        backup_parser.add_argument("--name", help="Backup name")
        
        # === List backups command ===
        subparsers.add_parser("list-backups", help="List available backups")
        
        # === Restore command ===
        restore_parser = subparsers.add_parser("restore", help="Restore from backup")
        restore_parser.add_argument("backup_path", help="Path to backup file")
        
        # === Rotation check command ===
        rotation_parser = subparsers.add_parser(
            "rotation-check",
            help="Check for keys needing rotation"
        )
        rotation_parser.add_argument(
            "--days",
            type=int,
            help="Override default rotation days"
        )
        
        # === Stats command ===
        subparsers.add_parser("stats", help="Show storage statistics")
        
        # === Services command ===
        subparsers.add_parser("services", help="List all services")
        
        # === Change password command ===
        subparsers.add_parser("change-password", help="Change master password")
        
        # === Logs command ===
        logs_parser = subparsers.add_parser("logs", help="View audit logs")
        logs_parser.add_argument(
            "--lines", "-n",
            type=int,
            default=50,
            help="Number of lines to show (default: 50)"
        )
        
        # === Patterns command ===
        patterns_parser = subparsers.add_parser("patterns", help="Manage scan patterns")
        patterns_parser.add_argument(
            "--add",
            nargs=2,
            metavar=("NAME", "PATTERN"),
            help="Add a custom pattern"
        )
        patterns_parser.add_argument(
            "--remove",
            metavar="NAME",
            help="Remove a pattern"
        )
        
        return parser
    
    def _init_manager(self, storage_dir: Optional[str] = None) -> None:
        """Initialize the key manager."""
        self.manager = KeyManager(storage_dir=storage_dir)
    
    def _authenticate(self) -> bool:
        """Authenticate with the key manager."""
        if self.manager is None:
            return False
        
        password = get_password()
        try:
            is_new = self.manager.authenticate(password)
            if is_new:
                print("New key storage created successfully.")
                # Confirm password for new storage
                confirm = get_password("Confirm password: ")
                if confirm != password:
                    print("Error: Passwords don't match.")
                    return False
            return True
        except AuthenticationError:
            print("Error: Invalid password.")
            return False
    
    def cmd_scan(self, args: argparse.Namespace) -> int:
        """Handle scan command."""
        if self.manager is None:
            return 1
        
        path = os.path.expanduser(args.path)
        recursive = args.recursive and not args.no_recursive
        
        if args.store:
            if not self._authenticate():
                return 1
            
            result = self.manager.scan_and_store(
                path,
                recursive=recursive,
                min_confidence=args.min_confidence
            )
            
            print(f"\nScan complete:")
            print(f"  Keys found: {result['keys_found']}")
            print(f"  Keys stored: {result['keys_stored']}")
            if result['backup_path']:
                print(f"  Backup created: {result['backup_path']}")
        else:
            extracted = self.manager.scan_directory(
                path,
                recursive=recursive,
                min_confidence=args.min_confidence
            )
            
            if not extracted:
                print("No potential API keys found.")
                return 0
            
            print(f"\nFound {len(extracted)} potential API key(s):\n")
            
            headers = ["#", "Service", "Key (masked)", "Confidence", "Source"]
            rows = []
            for i, key in enumerate(extracted, 1):
                rows.append([
                    i,
                    key.service,
                    mask_key(key.key_value),
                    f"{key.confidence:.2f}",
                    os.path.basename(key.source_file)
                ])
            
            print(format_table(headers, rows))
            print("\nUse 'api-keeper scan --store' to save these keys.")
        
        return 0
    
    def cmd_list(self, args: argparse.Namespace) -> int:
        """Handle list command."""
        if self.manager is None or not self._authenticate():
            return 1
        
        keys = self.manager.list_keys(
            service=args.service,
            include_values=args.show_values
        )
        
        if not keys:
            print("No keys stored.")
            return 0
        
        headers = ["ID", "Service", "Source", "Created", "Confidence"]
        if args.show_values:
            headers.append("Key")
        
        rows = []
        for key in keys:
            row = [
                key['id'],
                key['service'],
                os.path.basename(key.get('source_file', 'N/A')),
                key['created_at'][:10],
                f"{key.get('confidence', 0):.2f}"
            ]
            if args.show_values:
                row.append(mask_key(key.get('key_value', '')))
            rows.append(row)
        
        print(format_table(headers, rows))
        return 0
    
    def cmd_get(self, args: argparse.Namespace) -> int:
        """Handle get command."""
        if self.manager is None or not self._authenticate():
            return 1
        
        key = self.manager.get_key(args.id)
        
        if not key:
            print(f"Key with ID {args.id} not found.")
            return 1
        
        print(f"\nKey ID: {key['id']}")
        print(f"Service: {key['service']}")
        print(f"Key Value: {key['key_value']}")
        print(f"Source: {key.get('source_file', 'N/A')}")
        print(f"Created: {key['created_at']}")
        print(f"Last Rotated: {key.get('last_rotated', 'Never')}")
        print(f"Rotation Reminder: {key.get('rotation_reminder_days', 90)} days")
        print(f"Notes: {key.get('notes', 'None')}")
        
        return 0
    
    def cmd_add(self, args: argparse.Namespace) -> int:
        """Handle add command."""
        if self.manager is None or not self._authenticate():
            return 1
        
        key_value = args.key
        if not key_value:
            key_value = getpass.getpass("Enter API key: ")
            if not key_value:
                print("Error: Key value cannot be empty.")
                return 1
        
        key_id = self.manager.add_key(
            key_value=key_value,
            service=args.service,
            notes=args.notes,
            rotation_days=args.rotation_days
        )
        
        print(f"Key added successfully with ID: {key_id}")
        return 0
    
    def cmd_update(self, args: argparse.Namespace) -> int:
        """Handle update command."""
        if self.manager is None or not self._authenticate():
            return 1
        
        new_value = None
        if args.rotate:
            new_value = getpass.getpass("Enter new API key value: ")
            if not new_value:
                print("Error: Key value cannot be empty.")
                return 1
        
        success = self.manager.update_key(
            key_id=args.id,
            new_value=new_value,
            notes=args.notes,
            service=args.service,
            rotation_days=args.rotation_days
        )
        
        if success:
            print(f"Key {args.id} updated successfully.")
            return 0
        else:
            print(f"Key {args.id} not found or no changes made.")
            return 1
    
    def cmd_delete(self, args: argparse.Namespace) -> int:
        """Handle delete command."""
        if self.manager is None or not self._authenticate():
            return 1
        
        if not args.force:
            confirm = input(f"Are you sure you want to delete key {args.id}? [y/N]: ")
            if confirm.lower() != 'y':
                print("Deletion cancelled.")
                return 0
        
        if self.manager.delete_key(args.id):
            print(f"Key {args.id} deleted successfully.")
            return 0
        else:
            print(f"Key {args.id} not found.")
            return 1
    
    def cmd_search(self, args: argparse.Namespace) -> int:
        """Handle search command."""
        if self.manager is None or not self._authenticate():
            return 1
        
        results = self.manager.search_keys(args.query)
        
        if not results:
            print(f"No keys found matching '{args.query}'.")
            return 0
        
        headers = ["ID", "Service", "Source", "Created"]
        rows = []
        for key in results:
            rows.append([
                key['id'],
                key['service'],
                os.path.basename(key.get('source_file', 'N/A')),
                key['created_at'][:10]
            ])
        
        print(format_table(headers, rows))
        return 0
    
    def cmd_backup(self, args: argparse.Namespace) -> int:
        """Handle backup command."""
        if self.manager is None or not self._authenticate():
            return 1
        
        backup_path = self.manager.create_backup(name=args.name)
        print(f"Backup created: {backup_path}")
        return 0
    
    def cmd_list_backups(self, args: argparse.Namespace) -> int:
        """Handle list-backups command."""
        if self.manager is None:
            return 1
        
        backups = self.manager.list_backups()
        
        if not backups:
            print("No backups available.")
            return 0
        
        headers = ["Name", "Size", "Created"]
        rows = []
        for backup in backups:
            rows.append([
                backup['name'],
                f"{backup['size'] / 1024:.1f} KB",
                backup['created'][:19]
            ])
        
        print(format_table(headers, rows))
        return 0
    
    def cmd_restore(self, args: argparse.Namespace) -> int:
        """Handle restore command."""
        if self.manager is None:
            return 1
        
        confirm = input(f"Restore from {args.backup_path}? This will replace current data. [y/N]: ")
        if confirm.lower() != 'y':
            print("Restore cancelled.")
            return 0
        
        try:
            if self.manager.restore_backup(args.backup_path):
                print("Backup restored successfully.")
                print("Please re-authenticate with your password.")
                return 0
        except StorageError as e:
            print(f"Error: {e}")
            return 1
        
        return 1
    
    def cmd_rotation_check(self, args: argparse.Namespace) -> int:
        """Handle rotation-check command."""
        if self.manager is None or not self._authenticate():
            return 1
        
        reminders = self.manager.get_rotation_reminders(days=args.days)
        
        if not reminders:
            print("No keys need rotation.")
            return 0
        
        print(f"\n{len(reminders)} key(s) due for rotation:\n")
        
        headers = ["ID", "Service", "Days Since Rotation", "Reminder Days"]
        rows = []
        for r in reminders:
            rows.append([
                r['id'],
                r['service'],
                r['days_since_rotation'],
                r['reminder_days']
            ])
        
        print(format_table(headers, rows))
        return 0
    
    def cmd_stats(self, args: argparse.Namespace) -> int:
        """Handle stats command."""
        if self.manager is None or not self._authenticate():
            return 1
        
        stats = self.manager.get_stats()
        
        print("\nStorage Statistics:")
        print(f"  Total keys: {stats['total_keys']}")
        print(f"  Services: {stats['services_count']}")
        print("\nKeys by service:")
        for service, count in stats['by_service'].items():
            print(f"  {service}: {count}")
        
        return 0
    
    def cmd_services(self, args: argparse.Namespace) -> int:
        """Handle services command."""
        if self.manager is None or not self._authenticate():
            return 1
        
        services = self.manager.get_services()
        
        if not services:
            print("No services stored.")
            return 0
        
        print("Stored services:")
        for service in services:
            print(f"  - {service}")
        
        return 0
    
    def cmd_change_password(self, args: argparse.Namespace) -> int:
        """Handle change-password command."""
        if self.manager is None:
            return 1
        
        old_password = get_password("Current password: ")
        try:
            self.manager.authenticate(old_password)
        except AuthenticationError:
            print("Error: Invalid current password.")
            return 1
        
        new_password = get_password("New password: ")
        confirm = get_password("Confirm new password: ")
        
        if new_password != confirm:
            print("Error: Passwords don't match.")
            return 1
        
        if self.manager.change_password(old_password, new_password):
            print("Password changed successfully.")
            return 0
        else:
            print("Error: Failed to change password.")
            return 1
    
    def cmd_logs(self, args: argparse.Namespace) -> int:
        """Handle logs command."""
        if self.manager is None:
            return 1
        
        logs = self.manager.get_recent_logs(lines=args.lines)
        
        if not logs:
            print("No logs available.")
            return 0
        
        print("Recent audit logs:\n")
        for log in logs:
            print(log.rstrip())
        
        return 0
    
    def cmd_patterns(self, args: argparse.Namespace) -> int:
        """Handle patterns command."""
        if self.manager is None:
            return 1
        
        if args.add:
            name, pattern = args.add
            self.manager.add_scan_pattern(name, pattern)
            print(f"Pattern '{name}' added.")
            return 0
        
        if args.remove:
            if self.manager.remove_scan_pattern(args.remove):
                print(f"Pattern '{args.remove}' removed.")
            else:
                print(f"Pattern '{args.remove}' not found.")
            return 0
        
        # List patterns
        patterns = self.manager.list_scan_patterns()
        print("Scan patterns:\n")
        for name, pattern in patterns.items():
            print(f"  {name}:")
            print(f"    {pattern[:60]}{'...' if len(pattern) > 60 else ''}")
        
        return 0
    
    def run(self, args: Optional[list] = None) -> int:
        """
        Run the CLI.
        
        Args:
            args: Command-line arguments (uses sys.argv if None)
            
        Returns:
            Exit code
        """
        parsed = self.parser.parse_args(args)
        
        if not parsed.command:
            self.parser.print_help()
            return 0
        
        # Initialize manager
        self._init_manager(storage_dir=parsed.storage_dir)
        
        # Route to command handler
        command_handlers = {
            "scan": self.cmd_scan,
            "list": self.cmd_list,
            "get": self.cmd_get,
            "add": self.cmd_add,
            "update": self.cmd_update,
            "delete": self.cmd_delete,
            "search": self.cmd_search,
            "backup": self.cmd_backup,
            "list-backups": self.cmd_list_backups,
            "restore": self.cmd_restore,
            "rotation-check": self.cmd_rotation_check,
            "stats": self.cmd_stats,
            "services": self.cmd_services,
            "change-password": self.cmd_change_password,
            "logs": self.cmd_logs,
            "patterns": self.cmd_patterns,
        }
        
        handler = command_handlers.get(parsed.command)
        if handler:
            try:
                return handler(parsed)
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                return 130
            except Exception as e:
                print(f"Error: {e}")
                return 1
        
        self.parser.print_help()
        return 0


def main() -> int:
    """Main entry point."""
    cli = CLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
