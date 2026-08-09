import asyncio
import time
import httpx
from pathlib import Path

from guardian.ust import USTBuilder, UST
from guardian.evidence import EvidenceStore, Evidence, EvidenceType

BASE_URL = "http://localhost:8000"

def test_ust_builder_and_caching():
    print("\n--- 1. Testing USTBuilder & Redis Serialization ---")
    repo_root = Path.cwd() / "guardian" / "ust"
    builder = USTBuilder()
    
    # Measure initial parse
    t0 = time.time()
    ust1 = builder.build_repository(repo_root, list(repo_root.rglob("*.py")))
    t1 = time.time()
    print(f"Parsed {len(ust1.files)} files into UST in {round(t1 - t0, 3)}s")
    
    # Test Cache Serialization & Deserialization
    cache_dict = ust1.to_cache_dict()
    assert "files" in cache_dict
    
    t2 = time.time()
    ust2 = UST.from_cache_dict(cache_dict)
    t3 = time.time()
    print(f"Deserialized UST from cache dict in {round((t3 - t2) * 1000, 2)}ms")
    assert len(ust2.files) == len(ust1.files)
    print("UST Deserialization Check: PASSED")

def test_evidence_store():
    print("\n--- 2. Testing Evidence Store & Immutable IDs ---")
    store = EvidenceStore(id_prefix="E")
    e1 = store.add(Evidence(
        type=EvidenceType.VULNERABILITY_PATTERN,
        file="test.py",
        line=10,
        snippet="cursor.execute(query)",
        source="security_engine",
        symbol="execute",
        operation="query"
    ))
    assert e1.id == "E1"
    assert e1.snippet == "cursor.execute(query)"
    
    # Adding duplicate fingerprint returns same evidence ID
    e2 = store.add(Evidence(
        type=EvidenceType.VULNERABILITY_PATTERN,
        file="test.py",
        line=10,
        snippet="cursor.execute(query)",
        source="security_engine",
        symbol="execute",
        operation="query"
    ))
    assert e2.id == "E1"
    print("Evidence Store Immutable ID Check: PASSED (ID:", e1.id, ")")

async def test_files_api():
    print("\n--- 3. Testing Files API Wiring ---")
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        # Trigger a scan first
        res = await client.post("/api/v1/scans", json={
            "source_type": "local",
            "target_path": str(Path.cwd() / "guardian" / "ust"),
            "enable_ai": False
        })
        assert res.status_code == 200
        scan_id = res.json()["scan_id"]
        
        # Test File Tree endpoint
        tree_res = await client.get(f"/api/v1/files/tree?scan_id={scan_id}")
        assert tree_res.status_code == 200
        tree = tree_res.json()
        assert tree["name"] == "ust"
        assert "children" in tree
        print("File Tree Endpoint Check: PASSED (Root:", tree["name"], ")")

        # Test File Content endpoint
        content_res = await client.get(f"/api/v1/files/content?scan_id={scan_id}&path=builder.py")
        assert content_res.status_code == 200
        content = content_res.json()
        assert "class USTBuilder:" in content["content"]
        print("File Content Endpoint Check: PASSED")

if __name__ == "__main__":
    test_ust_builder_and_caching()
    test_evidence_store()
    asyncio.run(test_files_api())
