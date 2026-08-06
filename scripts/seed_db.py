#!/usr/bin/env python3
"""
Seed script to initialize PostgreSQL database schema if available.
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio
from guardian.db.session import init_db

async def main():
    print("Initializing Database...")
    success = await init_db()
    if success:
        print("✅ Database initialized successfully.")
    else:
        print("⚠️ Database initialization skipped (PostgreSQL unavailable or failed).")

if __name__ == "__main__":
    asyncio.run(main())
