#!/usr/bin/env python3
"""
Test script to verify the database migration works correctly
Run this to test if the location column exists and can be accessed
"""

import os
import sys
from sqlalchemy import create_engine, text

# Database configuration - use the same as your app
DATABASE_URL = os.environ.get('DATABASE_URL', 
    'postgresql+psycopg://database_db_81rr_user:N5xaJ1T1sZ1SwnaQYHS8JheZGt0qZpsm@dpg-d2m7qimr433s73cqvdg0-a.singapore-postgres.render.com/database_db_81rr')

def test_database():
    """Test if the location column exists and can be accessed"""
    try:
        # Create engine
        engine = create_engine(DATABASE_URL)
        
        with engine.connect() as conn:
            # Test 1: Check if location column exists
            print("🔍 Testing if location column exists...")
            result = conn.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'user_profiles' 
                AND column_name = 'location'
            """))
            
            if result.fetchone():
                print("✅ Location column exists in user_profiles table")
            else:
                print("❌ Location column does NOT exist in user_profiles table")
                return False
            
            # Test 2: Try to query the location column
            print("🔍 Testing if location column can be queried...")
            result = conn.execute(text("""
                SELECT id, user_id, location 
                FROM user_profiles 
                LIMIT 1
            """))
            
            print("✅ Location column can be queried successfully")
            return True
            
    except Exception as e:
        print(f"❌ Error testing database: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Testing database migration...")
    success = test_database()
    if success:
        print("🎉 Database migration test passed!")
    else:
        print("💥 Database migration test failed!")
        sys.exit(1)
