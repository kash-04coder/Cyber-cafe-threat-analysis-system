import sqlite3
import random
from datetime import datetime, timedelta

conn = sqlite3.connect("cyber_cafe.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT, password TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS login_attempts(
attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT,
ip_address TEXT,
device_id TEXT,
attempt_status TEXT,
attempt_time TEXT,
failure_reason TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS suspicious_ips(
ip_address TEXT,
threat_level TEXT,
first_detected TEXT,
last_detected TEXT,
status TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS blocked_systems(
ip_address TEXT,
reason TEXT,
blocked_time TEXT,
blocked_by TEXT,
status TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS attack_logs(
attack_id INTEGER PRIMARY KEY AUTOINCREMENT,
ip_address TEXT,
attack_type TEXT,
severity TEXT,
severity_score INTEGER,
attack_time TEXT
)
""")


users = [f"user{i}" for i in range(1,21)]

for user in users:
    cursor.execute(
        "INSERT INTO users(username) VALUES(?)",
        (user,)
    )

ips = [f"192.168.1.{i}" for i in range(1,21)]

failure_reasons = ["Wrong Password", "Invalid Device", "Blocked IP", "Timeout"]

for i in range(100):
    cursor.execute("""
    INSERT INTO login_attempts
    (username, ip_address, device_id, attempt_status, attempt_time, failure_reason)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        random.choice(users),
        random.choice(ips),
        f"DEV-{random.randint(100,999)}",
        status := random.choice(["Success","Failed","Blocked"]),
        str(datetime.now()-timedelta(hours=random.randint(1,100))),
        None if status == "Success" else random.choice(failure_reasons)
    ))

attacks = [
    "Brute Force",
    "Credential Stuffing",
    "SQL Injection",
    "DDoS"
]

for i in range(30):
    cursor.execute("""
    INSERT INTO attack_logs
    (ip_address,attack_type,severity,
    severity_score,attack_time)
    VALUES(?,?,?,?,?)
    """,(
        random.choice(ips),
        random.choice(attacks),
        random.choice(["Low","Medium","High"]),
        random.randint(1,10),
        str(datetime.now())
    ))

for i in range(10):
    cursor.execute("""
    INSERT INTO suspicious_ips
    VALUES(?,?,?,?,?)
    """,(
        random.choice(ips),
        random.choice(["Low","Medium","High"]),
        str(datetime.now()),
        str(datetime.now()),
        "Active"
    ))

for i in range(5):
    cursor.execute("""
    INSERT INTO blocked_systems
    VALUES(?,?,?,?,?)
    """,(
        random.choice(ips),
        "Repeated Failed Login",
        str(datetime.now()),
        "Admin",
        "Blocked"
    ))

conn.commit()
conn.close()

print("Database Ready")
