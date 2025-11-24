# 02_ingest_qdrant.py
import config
from stix2 import MemoryStore, Filter
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams, PointStruct
from tqdm import tqdm
import warnings
import uuid

warnings.filterwarnings("ignore", module="stix2.properties")

QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION_NAME = "mitre-attack-vectors"

# -------------------------------
# Helper: split list into batches
# -------------------------------
def chunk_list(data, size=200):
    for i in range(0, len(data), size):
        yield data[i:i + size]

# -------------------------------
# Normalize payload content by type
# -------------------------------
def create_text_for_embedding(obj):
    obj_type = obj.get("type", "")
    # helper to safely get fields
    def g(k, default=""):
        return obj.get(k, default) or ""

    # Base fields
    name = g("name")
    desc = g("description")
    ext = obj.get("external_references", [{}])
    url = ext[0].get("url", "") if ext else ""

    if obj_type == "attack-pattern":
        tactics = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])] if obj.get("kill_chain_phases") else []
        parts = [
            f"Type: Attack-Pattern",
            f"Name: {name}",
            f"Description: {desc}",
            f"Tactics: {', '.join(tactics)}",
            f"Platforms: {', '.join(obj.get('x_mitre_platforms', []))}",
            f"Detection: {obj.get('x_mitre_detection','')}"
        ]
        return ". ".join([p for p in parts if p.split(":")[-1].strip()])

    if obj_type == "course-of-action":
        parts = [
            "Type: Mitigation",
            f"Name: {name}",
            f"Description: {desc}",
            "Purpose: mitigation / remediation"
        ]
        return ". ".join([p for p in parts if p.split(":")[-1].strip()])

    if obj_type == "x-mitre-data-source":
        parts = [
            "Type: Data-Source",
            f"Name: {name}",
            f"Description: {desc}",
            f"Contributors: {', '.join(obj.get('x_mitre_contributors', [])) if obj.get('x_mitre_contributors') else ''}"
        ]
        return ". ".join([p for p in parts if p.split(":")[-1].strip()])

    if obj_type == "relationship":
        parts = [
            "Type: Relationship",
            f"Rel_Type: {obj.get('relationship_type','')}",
            f"Source: {obj.get('source_ref','')}",
            f"Target: {obj.get('target_ref','')}",
            f"Description: {desc}"
        ]
        return ". ".join([p for p in parts if p.split(":")[-1].strip()])

    # fallback - generic
    return f"Type: {obj_type}. Name: {name}. Description: {desc or obj.get('text','') or ''}"

# -------------------------------
# Decide priority (smaller = higher priority)
# -------------------------------
def priority_for_type(obj_type):
    mapping = {
        "course-of-action": 1,   # mitigation highest
        "attack-pattern": 2,     # technique
        "x-mitre-data-source": 3,
        "software": 3,
        "relationship": 5,
    }
    return mapping.get(obj_type, 4)

# -------------------------------
# MAIN
# -------------------------------
def main():
    print(f"Loading SentenceTransformer model: {config.MODEL_NAME}...")
    model = SentenceTransformer(config.MODEL_NAME)

    print(f"Loading STIX data from {config.STIX_FILE_PATH}...")
    store = MemoryStore()
    store.load_from_file(config.STIX_FILE_PATH)

    # query types we care about (extendable)
    types_to_query = [
        "attack-pattern",
        "x-mitre-data-source",
        "course-of-action",
        "relationship",
        # include software/intrusion-set if present in your STIX
        "malware",
        "tool",
        "campaign",
        "intrusion-set",
    ]

    all_objects = []
    for t in types_to_query:
        try:
            objs = store.query([Filter("type", "=", t)])
            all_objects.extend(objs)
        except Exception:
            # some types may not exist in the bundle
            continue

    print(f"Total STIX objects to ingest: {len(all_objects)}")

    # Connect to Qdrant
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
    client.recreate_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(
            size=config.VECTOR_DIMS,
            distance=Distance.COSINE,
        )
    )
    print(f"Collection '{COLLECTION_NAME}' created successfully")

    # Build points
    points_to_ingest = []
    print("Generating vectors and payloads...")

    for obj in tqdm(all_objects, desc="Encoding"):
        obj_type = obj.get("type", "")
        ext = obj.get("external_references", [{}])
        mitre_id = ext[0].get("external_id", "") if ext else ""
        url = ext[0].get("url", "") if ext else ""

        # normalized content used for embed and search context
        text_content = create_text_for_embedding(obj)
        vector = model.encode(text_content, normalize_embeddings=True).tolist()

        payload = {
            "type": obj_type,
            "mitre_id": mitre_id,
            "name": obj.get("name", "") or obj.get("x_mitre_name", ""),
            "description": obj.get("description", "") or "",
            "url": url,
            "text_content": text_content,
            "priority": priority_for_type(obj_type),
        }

        # include any other useful STIX fields for later use (safe to add)
        if obj_type == "attack-pattern":
            payload["tactics"] = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])] if obj.get("kill_chain_phases") else []
            payload["platforms"] = obj.get("x_mitre_platforms", [])

        points_to_ingest.append(
            PointStruct(
                id=str(uuid.uuid4()),
                vector=vector,
                payload=payload
            )
        )

    # Upsert in chunks
    print("Uploading data in batches to Qdrant...")
    batch_size = 200
    for batch in chunk_list(points_to_ingest, batch_size):
        client.upsert(
            collection_name=COLLECTION_NAME,
            points=batch,
            wait=True
        )

    print(f"Ingest completed: {len(points_to_ingest)} objects uploaded.")


if __name__ == "__main__":
    main()
