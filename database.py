
import sqlite3

DATABASE_NAME = "dashboard.db"

def get_connection():
  """Provides a connection to the SQLite database"""
  return sqlite3.connect(DATABASE_NAME)

def init_db():
  """Initializes the database tables if they do not exist"""
  conn = get_connection()
  cursor = conn.cursor()

  # Core users table
  cursor.execute("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)""")

  conn.commit()
  conn.close()

def get_user(username: str):
  """Fetches a user profile tuple by username"""
  conn = get_connection()
  cursor = conn.cursor()
  cursor.execute("""SELECT username,password FROM users WHERE username = ?""", (username,))
  user = cursor.fetchone()
  conn.close()
  return user

def create_user(username: str, hashed_pass: str):
  """Inserts a new user in to the database"""
  conn = get_connection()
  cursor= conn.cursor()
  try:
    cursor.execute("INSERT INTO users(username,password) VALUES (?,?)",(username,hashed_pass))
    conn.commit()
    return True
  except sqlite3.IntegrityError:
    return False
  finally: 
    conn.close()