from pipeline import RAGPipeline

finding = {
    "category": "Command Injection",
    "severity": "High",
    "language": "Python",
    "snippet": "os.system(user_input)"
}

pipeline = RAGPipeline()

result = pipeline.enhance(finding)

print(result)