# 03_search_qdrant.py
import sys
import config
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient

QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION_NAME = "mitre-attack-vectors"


def search_knn(query_text, client, model):
    print(f"Searching for: '{query_text}'")

    query_vector = model.encode(query_text, normalize_embeddings=True).tolist()

    try:
        search_results = client.search(
            collection_name=COLLECTION_NAME,
            query_vector=query_vector,
            limit=5,
            with_payload=True
        )
        return search_results
    except Exception as e:
        print(f"Error during search: {e}")
        return []


def print_result(hit, index):
    payload = hit.payload

    obj_type = payload.get("type", "unknown")
    name = payload.get("name", "N/A")
    mitre_id = payload.get("mitre_id", "N/A")
    description = payload.get("description", "")
    short_desc = (description[:180] + "...") if len(description) > 180 else description

    print(f"\n{index}. [{obj_type.upper()}]  {name}")
    print(f"   MITRE ID: {mitre_id}")
    print(f"   Score: {hit.score:.4f}")
    print(f"   Description: {short_desc}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python 03_search_qdrant.py \"Your search query here\"")
        return

    query_text = " ".join(sys.argv[1:])

    print(f"Loading model: {config.MODEL_NAME}...")
    model = SentenceTransformer(config.MODEL_NAME)

    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

    results = search_knn(query_text, client, model)

    print("\n--- Search Results ---")

    if not results:
        print("No results found.")
        return

    for i, hit in enumerate(results, start=1):
        print_result(hit, i)


if __name__ == "__main__":
    main()
