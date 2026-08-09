import httpx
import uuid
import asyncio

async def test_chat():
    thread_id = str(uuid.uuid4())
    print(f"Thread ID: {thread_id}")
    
    async with httpx.AsyncClient(base_url="http://localhost:8002", timeout=60.0) as client:
        # Register some fake findings so _ACTIVE_FINDINGS isn't completely empty
        # If it is empty, it'll hit NVIDIA which we might not have a key for.
        # But wait, let's just trigger a dummy scan if possible.
        scan_req = {
            "target_path": "/tmp",
            "scan_mode": "precision",
            "enable_ai": False
        }
        scan_res = await client.post("/api/v1/scans", json=scan_req)
        print("SCAN RESPONSE:", scan_res.status_code, scan_res.text)
        
        # Turn 1
        req1 = {
            "messages": [{"role": "user", "content": "list all the critical findings"}],
            "persona": "Developer",
            "temperature": 0.2,
            "thread_id": thread_id
        }
        res1 = await client.post("/api/v1/chat/completions", json=req1)
        print("\nTURN 1 RESPONSE:")
        print(res1.json())
        
        # Turn 2
        req2 = {
            "messages": [
                {"role": "user", "content": "list all the critical findings"},
                {"role": "assistant", "content": res1.json().get("reply", "...")},
                {"role": "user", "content": "ok what are the ways we can fix this"}
            ],
            "persona": "Developer",
            "temperature": 0.2,
            "thread_id": thread_id
        }
        res2 = await client.post("/api/v1/chat/completions", json=req2)
        print("\nTURN 2 RESPONSE:")
        print(res2.json())
        
        req3 = {
            "messages": [
                {"role": "user", "content": "list all the critical findings"},
                {"role": "assistant", "content": res1.json().get("reply", "...")},
                {"role": "user", "content": "ok what are the ways we can fix this"},
                {"role": "assistant", "content": res2.json().get("reply", "...")},
                {"role": "user", "content": "ok"}
            ],
            "persona": "Developer",
            "temperature": 0.2,
            "thread_id": thread_id
        }
        res3 = await client.post("/api/v1/chat/completions", json=req3)
        print("\nTURN 3 RESPONSE:")
        print(res3.json())

if __name__ == "__main__":
    asyncio.run(test_chat())
