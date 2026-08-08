from scanner.language_learning.nemotron_llm import NemotronLLM

llm = NemotronLLM()

response = llm.generate("""
You are generating Tree-sitter queries for AI-Code Guardian.

Use ONLY the following capture names:

@function
@class
@method
@import
@call
@variable
@constant

Never invent new capture names.

Do not use:
@function.name
@class.name
@definition
@body
@parameters

Return only valid .scm.
""")

print(response)