#!/usr/bin/env python
"""
Setup script for the Sliver C2 Dashboard Plugin
Run this script to initialize the Sliver integration after installation
"""

import os
import sys
import django
from pathlib import Path

def setup_sliver():
    """Initialize Sliver plugin with migrations and default templates"""

    # Setup Django environment
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyber_pen_test.settings')

    # Add current directory to Python path if needed
    current_dir = Path(__file__).resolve().parent
    cyber_test_dir = current_dir / 'cyber_pen_test'

    if str(current_dir) not in sys.path:
        sys.path.insert(0, str(current_dir))
    if str(cyber_test_dir) not in sys.path:
        sys.path.insert(0, str(cyber_test_dir))

    try:
        django.setup()

        from django.core.management import execute_from_command_line
        from django.db import connection

        print("🚀 Starting Sliver C2 Dashboard Plugin Setup...")
        print("=" * 60)

        # Test database connection
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            print("✅ Database connection successful")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            print("Please ensure your database is running and configured correctly.")
            return False

        # Make migrations
        print("\n📦 Creating database migrations...")
        try:
            execute_from_command_line(['manage.py', 'makemigrations', 'sliver'])
            print("✅ Migrations created successfully")
        except Exception as e:
            print(f"❌ Failed to create migrations: {e}")
            return False

        # Run migrations
        print("\n🗃️  Running database migrations...")
        try:
            execute_from_command_line(['manage.py', 'migrate', 'sliver'])
            print("✅ Database migrations applied successfully")
        except Exception as e:
            print(f"❌ Failed to apply migrations: {e}")
            return False

        # Create default templates
        print("\n📋 Creating default templates...")
        try:
            execute_from_command_line(['manage.py', 'create_default_templates'])
            print("✅ Default templates created successfully")
        except Exception as e:
            print(f"❌ Failed to create default templates: {e}")
            return False

        print("\n" + "=" * 60)
        print("🎉 Sliver C2 Dashboard Plugin setup completed successfully!")
        print("\nNext steps:")
        print("1. Configure teamserver connections in Django admin")
        print("2. Start Celery worker: celery -A cyber_pen_test worker --loglevel=info")
        print("3. Start Django server: python cyber_pen_test/manage.py runserver")
        print("4. Access the Sliver dashboard at: http://localhost:8000/sliver/")
        print("\n📖 For full documentation, see the Sliver integration docs.")
        print("=" * 60)

        return True

    except Exception as e:
        print(f"❌ Setup failed: {e}")
        print("\nTroubleshooting:")
        print("1. Ensure your database is running and accessible")
        print("2. Check your settings.py configuration")
        print("3. Make sure all dependencies are installed")
        print("4. Check Python path and run this from the project root")
        return False

if __name__ == '__main__':
    success = setup_sliver()
    sys.exit(0 if success else 1)
