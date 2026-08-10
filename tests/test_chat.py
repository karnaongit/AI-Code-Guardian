import uuid
import pytest
from httpx import AsyncClient, ASGITransport

from backend.app.main import app


async def test_chat():
    thread_id = str(uuid.uuid4())
    print(f"Thread ID: {thread_id}")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", timeout=60.0) as client:
        # Trigger a scan so _ACTIVE_FINDINGS is populated (enable_ai=False avoids NVIDIA key requirement)
        scan_req = {
            "target_path": "/tmp",
            "scan_mode": "precision",
            "enable_ai": False,
        }
        scan_res = await client.post("/api/v1/scans", json=scan_req)
        print("SCAN RESPONSE:", scan_res.status_code)

        # Turn 1
        req1 = {
            "messages": [{"role": "user", "content": "list all the critical findings"}],
            "persona": "Developer",
            "temperature": 0.2,
            "thread_id": thread_id,
        }
        res1 = await client.post("/api/v1/chat/completions", json=req1)
        assert res1.status_code == 200
        print("\nTURN 1 RESPONSE:", res1.json())

        # Turn 2
        req2 = {
            "messages": [
                {"role": "user", "content": "list all the critical findings"},
                {"role": "assistant", "content": res1.json().get("reply", "...")},
                {"role": "user", "content": "ok what are the ways we can fix this"},
            ],
            "persona": "Developer",
            "temperature": 0.2,
            "thread_id": thread_id,
        }
        res2 = await client.post("/api/v1/chat/completions", json=req2)
        assert res2.status_code == 200
        print("\nTURN 2 RESPONSE:", res2.json())

        # Turn 3
        req3 = {
            "messages": [
                {"role": "user", "content": "list all the critical findings"},
                {"role": "assistant", "content": res1.json().get("reply", "...")},
                {"role": "user", "content": "ok what are the ways we can fix this"},
                {"role": "assistant", "content": res2.json().get("reply", "...")},
                {"role": "user", "content": "ok"},
            ],
            "persona": "Developer",
            "temperature": 0.2,
            "thread_id": thread_id,
        }
        res3 = await client.post("/api/v1/chat/completions", json=req3)
        assert res3.status_code == 200
        print("\nTURN 3 RESPONSE:", res3.json())


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_chat())
