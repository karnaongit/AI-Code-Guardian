from scanner.parser import UniversalParser

parser = UniversalParser()
with open('rag/faiss_manager.py', 'r') as f:
    source = f.read()
    
parsed = parser.parse(source, 'rag/faiss_manager.py')

for call in parsed.calls:
    print(f"Call: {call.name}, Receiver: {call.context.get('receiver')}")
