import asyncio
import httpx
import uuid
from pathlib import Path

BASE_URL = "http://localhost:8000"

async def test_chat_pipeline():
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=60.0) as client:
        print("\n--- 1. Trigger Scan & Register Context ---")
        scan_res = await client.post("/api/v1/scans", json={
            "source_type": "local",
            "target_path": str(Path.cwd() / "guardian" / "ust"),
            "enable_ai": False
        })
        if scan_res.status_code != 200:
            print("Scan status code:", scan_res.status_code, "Text:", scan_res.text)
        assert scan_res.status_code == 200
        scan_data = scan_res.json()["result"]
        assert "repo_overview" in scan_data
        overview = scan_data["repo_overview"]
        print("Repo Overview Generated:", overview["summary"])
        print("Primary Languages:", overview["primary_languages"])

        thread_id = str(uuid.uuid4())

        print("\n--- 2. Turn 1: Initial Query ---")
        messages = [{"role": "user", "content": "what is this repository about and are there any findings?"}]
        res1 = await client.post("/api/v1/chat/completions", json={
            "messages": messages,
            "persona": "Developer",
            "temperature": 0.2,
            "thread_id": thread_id
        })
        assert res1.status_code == 200
        data1 = res1.json()
        print("Tools Used:", data1.get("tools_used"))
        assert "get_repo_overview" in data1.get("tools_used", [])
        print("Reply 1 Output:\n", data1["reply"][:300], "...")

        print("\n--- 3. Turn 2: Follow-up Query ---")
        messages.append({"role": "assistant", "content": data1["reply"]})
        messages.append({"role": "user", "content": "how can we fix the security issues?"})
        
        res2 = await client.post("/api/v1/chat/completions", json={
            "messages": messages,
            "persona": "Developer",
            "temperature": 0.2,
            "thread_id": thread_id
        })
        assert res2.status_code == 200
        data2 = res2.json()
        print("Reply 2 Output:\n", data2["reply"][:300], "...")
        print("\nALL CONTEXT & CHATBOT TESTS PASSED!")

if __name__ == "__main__":
    asyncio.run(test_chat_pipeline())
