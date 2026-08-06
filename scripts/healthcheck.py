#!/usr/bin/env python3
"""
Health check script to verify connections to local backing services.
"""
import sys
import socket
import os
from urllib.parse import urlparse

def check_port(host, port, service_name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host, port))
        print(f"✅ {service_name} is UP on {host}:{port}")
        return True
    except (socket.timeout, ConnectionRefusedError):
        print(f"❌ {service_name} is DOWN (could not connect to {host}:{port})")
        return False
    finally:
        s.close()

def main():
    print("--- AI Code Guardian v3 Local Health Check ---")
    
    # Check Postgres
    db_url = os.getenv("DATABASE_URL", "postgresql+asyncpg://guardian:guardian_pass@localhost:5432/guardian_db")
    parsed_db = urlparse(db_url)
    db_host = parsed_db.hostname or 'localhost'
    db_port = parsed_db.port or 5432
    postgres_up = check_port(db_host, db_port, "PostgreSQL")

    # Check Redis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    parsed_redis = urlparse(redis_url)
    redis_host = parsed_redis.hostname or 'localhost'
    redis_port = parsed_redis.port or 6379
    redis_up = check_port(redis_host, redis_port, "Redis")

    # Check Neo4j
    neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    parsed_neo4j = urlparse(neo4j_uri)
    neo4j_host = parsed_neo4j.hostname or 'localhost'
    neo4j_port = parsed_neo4j.port or 7687
    neo4j_up = check_port(neo4j_host, neo4j_port, "Neo4j")

    # Qdrant is embedded
    qdrant_loc = os.getenv("QDRANT_LOCATION", "./qdrant_data")
    if qdrant_loc == ":memory:":
        print("✅ Qdrant will run in-memory (Embedded mode)")
    elif qdrant_loc.startswith("http"):
        parsed_qdrant = urlparse(qdrant_loc)
        qdrant_host = parsed_qdrant.hostname or 'localhost'
        qdrant_port = parsed_qdrant.port or 6333
        check_port(qdrant_host, qdrant_port, "Qdrant (Remote)")
    else:
        print(f"✅ Qdrant will run in embedded file-backed mode (Path: {qdrant_loc})")

    if not all([postgres_up, redis_up, neo4j_up]):
        print("\n⚠️ WARNING: Not all backing services are UP.")
        print("The system will gracefully degrade (using in-memory fallbacks/disabling features).")
        print("For full functionality, start the missing services. See docs/LOCAL_SETUP.md for instructions.")
        sys.exit(1)
    
    print("\nAll local services are healthy! 🚀")
    sys.exit(0)

if __name__ == "__main__":
    main()
