# from scanner.parser import UniversalParser

# code = """
# import os
# from pathlib import Path

# x = 10

# class Test:

#     def hello(self):
#         print("Hello")

# hello()
# """

# parser = UniversalParser()

# result = parser.parse(
#     code,
#     "test.py"
# )

# print(result.functions)
# print(result.classes)
# print(result.imports)
# print(result.variables)
# print(result.calls)
# print(result.metrics)
# from scanner.language_learning.manager import LanguageLearningManager

# print("Import OK")
import os

def hello():
    eval("print(123)")