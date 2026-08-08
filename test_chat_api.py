import requests

# This script simulates what the user is trying to do via the FastAPI endpoints.

print("--- Testing /chat API endpoint ---")

# First, ensure you are passing the repo_name in the chat payload so the backend knows which index to load!
payload = {
    "repo_name": "sidgulmire1/AI-Code-Guardian",
    "question": "Summarize this repository in 5 sentences."
}

try:
    response = requests.post("http://127.0.0.1:8000/analysis/chat", json=payload)
    if response.status_code == 200:
        print("\nSUCCESS!")
        print(response.json())
    else:
        print("\nERROR:")
        print(response.text)
except requests.exceptions.ConnectionError:
    print("Could not connect to FastAPI server. Please ensure 'uvicorn main:app' is running.")
