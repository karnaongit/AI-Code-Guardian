from rag.retriever import Retriever
r = Retriever()
r.load_index("fportantier_vulpy")
results = r.search("summerize it in two lines and tell me about vulnerabilities", top_k=5)
print(results)
