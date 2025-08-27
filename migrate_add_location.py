#!/usr/bin/env python3
"""
Database Migration Script: Add location column to user_profiles table
Run this script on your production database to add the missing location column.
"""

import os
import sys
from sqlalchemy import create_engine, text

# Database configuration - use the same as your app
DATABASE_URL = os.environ.get('DATABASE_URL', 
    'postgresql+psycopg://database_db_81rr_user:N5xaJ1T1sZ1SwnaQYHS8JheZGt0qZpsm@dpg-d2m7qimr433s73cqvdg0-a.singapore-postgres.render.com/database_db_81rr')

def migrate_database():
    """Add location column to user_profiles table if it doesn't exist"""
    try:
        # Create engine
        engine = create_engine(DATABASE_URL)
        
        with engine.connect() as conn:
            # Check if location column already exists
            result = conn.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'user_profiles' 
                AND column_name = 'location'
            """))
            
            if result.fetchone():
                print("✅ Location column already exists in user_profiles table")
                return
            
            # Add the location column
            print("🔄 Adding location column to user_profiles table...")
            conn.execute(text("""
                ALTER TABLE user_profiles 
                ADD COLUMN location VARCHAR(200)
            """))
            
            # Commit the transaction
            conn.commit()
            print("✅ Successfully added location column to user_profiles table")
            
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("🚀 Starting database migration...")
    migrate_database()
    print("🎉 Migration completed successfully!")
