import sqlite3

# Connect to your existing database
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Create the saved_colleges table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS saved_colleges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        college_name TEXT,
        state TEXT,
        stream TEXT,
        rank INTEGER,
        tlr REAL,
        placement REAL,
        perception REAL
    )
''')

conn.execute('''
    CREATE TABLE IF NOT EXISTS saved_colleges_dashboard (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        college_name TEXT,
        state TEXT,
        stream TEXT,
        rating REAL,
        academic REAL,
        accommodation REAL,
        faculty REAL,
        infrastructure REAL,
        placement REAL,
        social_life REAL
    )
''')

conn.commit()
conn.close()
print("saved_colleges table created!")

