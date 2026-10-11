import pickle
import sqlite3
import subprocess

# ---- Secrets
api_key = "sk-test-123456789"           # BAD: hardcoded secret
password = "changeme"                    # placeholder: should NOT be reported
token = "aaaaaaaaaa"                     # low entropy: should NOT be reported

user_input = input()

# ---- Dangerous functions
eval(user_input)                                   # BAD
subprocess.run("ls " + user_input, shell=True)     # BAD
pickle.loads(user_input.encode())                  # BAD

# ---- SQL Injection
conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
name = user_input

cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")        # BAD
cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")   # BAD
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)      # BAD
cursor.execute("SELECT * FROM users WHERE name = ?", (name,))       # SAFE

query = "SELECT * FROM users WHERE name = '" + name + "'"
cursor.execute(query)                                               # BAD (variable)

# ---- New rules
import os
os.system("say hello")                                   # MEDIUM
os.system("ls " + user_input)                            # BAD
script = f'tell application "Messages" to send "{user_input}"'   # AppleScript injection
app.run(host="0.0.0.0", debug=True)                      # Flask debug

safe_script = f'tell application "{escape(user_input)}" to quit'   # escaped: LOW

def run_server(host: str = "0.0.0.0", port: int = 5005):         # default parameter
    app.run(host=host, port=port, debug=False)
