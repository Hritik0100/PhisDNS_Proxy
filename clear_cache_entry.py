import sqlite3

db_path = 'phishblock_cache.db'
domain_to_delete = '8ujoo-4.pages.dev'

conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute("DELETE FROM domain_cache WHERE domain = ?", (domain_to_delete,))
conn.commit()
deleted = cursor.rowcount
conn.close()

if deleted:
    print(f"Deleted cache entry for {domain_to_delete}")
else:
    print(f"No cache entry found for {domain_to_delete}")