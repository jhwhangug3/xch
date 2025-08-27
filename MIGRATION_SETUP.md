# Database Migration Setup for Render

## Problem

The profile system is encountering `UndefinedColumn` errors because the `location` column is missing from the `user_profiles` table in the production database.

## Solution

We need to run a database migration script **before** the application starts to ensure the required database schema exists.

## Setup Instructions

### 1. Configure Render Build Command

In your Render dashboard, go to your service settings and set the **Build Command** to:

```bash
pip install -r requirements-migration.txt && python migrate_add_location.py
```

### 2. What This Does

- **First**: Installs `psycopg2-binary` (required for PostgreSQL connections)
- **Then**: Runs the migration script to add the missing `location` column
- **Finally**: The application starts normally

### 3. Migration Script Details

The `migrate_add_location.py` script:

- Connects to your PostgreSQL database
- Checks if the `location` column exists in `user_profiles` table
- Adds the column if it's missing
- Provides detailed logging of the process
- Handles errors gracefully

### 4. Expected Output

When the build command runs, you should see:

```
🚀 Starting database migration for location column...
📡 Connecting to database...
✅ Connected to database: database_db_81rr on dpg-d2m7qimr433s73cqvdg0-a.singapore-postgres.render.com
🔄 Adding 'location' column to 'user_profiles' table...
✅ Successfully added 'location' column to 'user_profiles' table
🎉 Migration completed successfully!
   The 'location' column is now available in the user_profiles table.
🔌 Database connection closed
```

### 5. Alternative Build Commands

If you prefer, you can also use:

**Option A (Recommended):**

```bash
pip install psycopg2-binary && python migrate_add_location.py
```

**Option B (Full requirements):**

```bash
pip install -r requirements.txt && python migrate_add_location.py
```

### 6. What Happens After Migration

- The `location` column will be available in the database
- Profile editing will work normally
- All profile fields (including location and timezone) will save correctly
- No more "failed to save" errors

### 7. Troubleshooting

If the migration fails:

1. Check the build logs in Render dashboard
2. Ensure your `DATABASE_URL` environment variable is set correctly
3. Verify the database is accessible from Render's build environment
4. The migration script will provide detailed error messages

### 8. Manual Migration (if needed)

If you need to run the migration manually:

```bash
# Install dependencies
pip install psycopg2-binary

# Run migration
python migrate_add_location.py
```

## Important Notes

- **This migration is safe** - it only adds a column if it doesn't exist
- **The column is nullable** - existing data won't be affected
- **SSL is enforced** - the script automatically adds SSL requirements for Render
- **Error handling** - the script provides detailed feedback and graceful failure

After setting up the build command, deploy your application and the profile system should work correctly!
