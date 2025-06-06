from sqlalchemy import create_engine, text
from dotenv import load_dotenv
import os

load_dotenv()

engine = create_engine(os.getenv("DB_URL"))

# Test connection
with engine.connect() as conn:
    result = conn.execute(text("SELECT NOW()"))
    print("DB Connected, time:", result.fetchone()[0])
