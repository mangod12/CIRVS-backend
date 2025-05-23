# database.py
import sqlite3

def init_db():
    conn = sqlite3.connect('vuln.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS reported_vulns (
                    cve TEXT PRIMARY KEY,
                    product_name TEXT,
                    oem_name TEXT,
                    severity_level TEXT,
                    vulnerability TEXT,
                    mitigation_strategy TEXT,
                    published_date TEXT
                )''')
    conn.commit()
    conn.close()

def is_duplicate(cve_id):
    conn = sqlite3.connect('vuln.db')
    c = conn.cursor()
    c.execute('SELECT 1 FROM reported_vulns WHERE cve=?', (cve_id,))
    result = c.fetchone()
    conn.close()
    return result is not None

def save_vuln(vuln):
    """Save vulnerability data to database."""
    conn = sqlite3.connect('vuln.db')
    c = conn.cursor()
    try:
        c.execute('''INSERT INTO reported_vulns (cve, product_name, oem_name, severity_level, vulnerability, mitigation_strategy, published_date)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (vuln.get('Unique ID', 'NA'), 
                   vuln.get('Product Name', 'NA'), 
                   vuln.get('OEM Name', 'NA'), 
                   vuln.get('Severity Level', 'NA'), 
                   vuln.get('Vulnerability', 'NA'), 
                   vuln.get('Mitigation Strategy', 'NA'), 
                   vuln.get('Published Date', 'NA')))
        conn.commit()
    except Exception as e:
        raise RuntimeError(f"Failed to save vulnerability to database: {e}")
    finally:
        conn.close()
