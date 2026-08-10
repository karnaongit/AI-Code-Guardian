import asyncio
import httpx
import tempfile
import zipfile
from pathlib import Path

BASE_URL = "http://localhost:8000"

async def run_tests():
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=60.0) as client:
        print("\n--- 1. Testing Local Directory Scan ---")
        local_req = {
            "source_type": "local",
            "target_path": str(Path.cwd() / "guardian"),
            "enable_ai": False,
            "scan_mode": "precision"
        }
        res1 = await client.post("/api/v1/scans", json=local_req)
        print("Local Scan HTTP Status:", res1.status_code)
        if res1.status_code == 200:
            print("Local Scan Result:", res1.json().get("status"), "Scan ID:", res1.json().get("scan_id"))
        else:
            print("Local Scan Error:", res1.text)

        print("\n--- 2. Testing GitHub Repo Scan ---")
        github_req = {
            "source_type": "github",
            "repo_url": "https://github.com/octocat/Hello-World",
            "enable_ai": False,
            "scan_mode": "precision"
        }
        res2 = await client.post("/api/v1/scans", json=github_req)
        print("GitHub Scan HTTP Status:", res2.status_code)
        if res2.status_code == 200:
            print("GitHub Scan Result:", res2.json().get("status"), "Scan ID:", res2.json().get("scan_id"))
        else:
            print("GitHub Scan Error:", res2.text)

        print("\n--- 3. Testing ZIP Upload Scan ---")
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp_zip:
            tmp_zip_path = Path(tmp_zip.name)
            with zipfile.ZipFile(tmp_zip_path, "w") as zf:
                zf.writestr("test_vulnerable.py", "import os\nos.system(input('Enter cmd: '))\n")
            
        with open(tmp_zip_path, "rb") as f:
            files = {"file": ("sample_repo.zip", f, "application/zip")}
            data = {"scan_mode": "precision", "enable_ai": "false"}
            res3 = await client.post("/api/v1/scans/upload", files=files, data=data)
            
        print("ZIP Upload Scan HTTP Status:", res3.status_code)
        if res3.status_code == 200:
            print("ZIP Scan Result:", res3.json().get("status"), "Scan ID:", res3.json().get("scan_id"))
        else:
            print("ZIP Scan Error:", res3.text)

if __name__ == "__main__":
    asyncio.run(run_tests())
