# from sentence_transformers import SentenceTransformer


# class Embedder:

#     def __init__(self):
#         self.model = SentenceTransformer(
#             "all-MiniLM-L6-v2"
#         )

from sentence_transformers import SentenceTransformer

model = SentenceTransformer("all-MiniLM-L6-v2")
print("Model loaded successfully!")