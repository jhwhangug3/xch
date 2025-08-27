#!/usr/bin/env python3
"""
Database Migration Script for Adding Location Column
This script adds the 'location' column to the user_profiles table if it doesn't exist.

Usage:
    python migrate_add_location.py

This script is designed to be run as a build command on Render before the application starts.
"""

import os
import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

def get_database_url():
    """Get database URL from environment or use default"""
    # Default Render Postgres URL (fallback)
    default_url = (
        'postgresql://database_db_81rr_user:'
        'N5xaJ1T1sZ1SwnaQYHS8JheZGt0qZpsm'
        '@dpg-d2m7qimr433s73cqvdg0-a.singapore-postgres.render.com/database_db_81rr'
    )
    
    database_url = os.environ.get('DATABASE_URL', default_url)
    
    # Ensure SSL for Render Postgres
    if 'sslmode=' not in database_url:
        connector = '&' if '?' in database_url else '?'
        database_url = f"{database_url}{connector}sslmode=require"
    
    return database_url

def parse_database_url(url):
    """Parse database URL to extract connection parameters"""
    # Remove postgresql:// prefix
    if url.startswith('postgresql://'):
        url = url[13:]
    
    # Remove query parameters (like ?sslmode=require)
    if '?' in url:
        url = url.split('?')[0]
    
    # Split into user:pass@host:port/database
    if '@' in url:
        auth_part, rest = url.split('@', 1)
        if ':' in auth_part:
            username, password = auth_part.split(':', 1)
        else:
            username, password = auth_part, ''
    else:
        username, password = '', ''
    
    if '/' in rest:
        host_port, database = rest.split('/', 1)
    else:
        host_port, database = rest, ''
    
    if ':' in host_port:
        host, port = host_port.split(':', 1)
        port = int(port)
    else:
        host, port = host_port, 5432
    
    return {
        'host': host,
        'port': port,
        'database': database,
        'user': username,
        'password': password
    }

def check_column_exists(conn, table_name, column_name):
    """Check if a column exists in a table"""
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = %s 
                AND column_name = %s
            """, (table_name, column_name))
            return cursor.fetchone() is not None
    except Exception as e:
        print(f"❌ Error checking if column exists: {e}")
        return False

def add_location_column(conn):
    """Add location column to user_profiles table"""
    try:
        with conn.cursor() as cursor:
            # Check if the table exists first
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'user_profiles'
                )
            """)
            
            if not cursor.fetchone()[0]:
                print("❌ Table 'user_profiles' does not exist!")
                print("   This migration should run after the application creates the tables.")
                return False
            
            # Check if location column already exists
            if check_column_exists(conn, 'user_profiles', 'location'):
                print("✅ Column 'location' already exists in 'user_profiles' table")
                return True
            
            # Add the location column
            print("🔄 Adding 'location' column to 'user_profiles' table...")
            cursor.execute("""
                ALTER TABLE user_profiles 
                ADD COLUMN location VARCHAR(200) DEFAULT NULL
            """)
            
            # Verify the column was added
            if check_column_exists(conn, 'user_profiles', 'location'):
                print("✅ Successfully added 'location' column to 'user_profiles' table")
                return True
            else:
                print("❌ Failed to add 'location' column")
                return False
                
    except Exception as e:
        print(f"❌ Error adding location column: {e}")
        return False

def main():
    """Main migration function"""
    print("🚀 Starting database migration for location column...")
    
    try:
        # Get database connection parameters
        database_url = get_database_url()
        print(f"📡 Connecting to database...")
        
        # Parse connection parameters
        conn_params = parse_database_url(database_url)
        
        # Connect to database
        conn = psycopg2.connect(**conn_params)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        
        print(f"✅ Connected to database: {conn_params['database']} on {conn_params['host']}")
        
        # Run the migration
        success = add_location_column(conn)
        
        if success:
            print("🎉 Migration completed successfully!")
            print("   The 'location' column is now available in the user_profiles table.")
        else:
            print("⚠️  Migration completed with warnings.")
            print("   Some operations may have failed, but the application should still work.")
        
        # Close connection
        conn.close()
        print("🔌 Database connection closed")
        
        return 0 if success else 1
        
    except Exception as e:
        print(f"💥 Migration failed with error: {e}")
        print("   The application may not work properly without the required database schema.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
