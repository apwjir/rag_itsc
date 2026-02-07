import os
import time
from dotenv import load_dotenv
from stix2 import MemoryStore, Filter
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams, PointStruct
from tqdm import tqdm
import warnings
import uuid
from langchain_openai import OpenAIEmbeddings

warnings.filterwarnings("ignore", module="stix2.properties")

load_dotenv()
STIX_FILE_PATH = os.getenv("STIX_FILE_PATH")
QDRANT_HOST = os.getenv("QDRANT_HOST")
QDRANT_PORT = os.getenv("QDRANT_PORT")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")
VECTOR_DIMS = int(os.getenv("VECTOR_DIMS"))
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


EMBEDDING_MODEL_NAME = "text-embedding-3-large"

embeddings = OpenAIEmbeddings(
    model=EMBEDDING_MODEL_NAME,
    api_key=OPENAI_API_KEY,
    dimensions=VECTOR_DIMS
)

# -------------------------------
# Helper: Batch Embedding Function
# -------------------------------
def embed_batch(texts):
    """
    รับ list ของ text แล้วส่งไป embed ทีเดียว
    """
    try:
        # LangChain รองรับการส่ง list เข้าไป embed_documents
        return embeddings.embed_documents(texts)
    except Exception as e:
        print(f"Error embedding batch: {e}")
        # ถ้า error ให้ return list ว่าง หรือจัดการ retry ตามสมควร
        return []

# -------------------------------
# Helper: split list into batches
# -------------------------------
def chunk_list(data, size=100):
    for i in range(0, len(data), size):
        yield data[i:i + size]

# -------------------------------
# Normalize payload content
# -------------------------------
def create_text_for_embedding(obj):
    obj_type = obj.get("type", "")
    def g(k, default=""):
        return obj.get(k, default) or ""

    name = g("name")
    desc = g("description")
    
    # Custom logic for types
    if obj_type == "attack-pattern":
        tactics = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])] if obj.get("kill_chain_phases") else []
        return f"Type: Attack-Pattern. Name: {name}. Description: {desc}. Tactics: {', '.join(tactics)}"
    
    if obj_type == "course-of-action":
        return f"Type: Mitigation. Name: {name}. Description: {desc}. Purpose: mitigation"
    
    # Default fallback
    return f"Type: {obj_type}. Name: {name}. Description: {desc}"

# -------------------------------
# Priority Logic
# -------------------------------
def priority_for_type(obj_type):
    mapping = {"course-of-action": 1, "attack-pattern": 2, "x-mitre-data-source": 3}
    return mapping.get(obj_type, 4)

# -------------------------------
# MAIN
# -------------------------------
def main():
    print(f"Using Google Embedding Model (LangChain): {EMBEDDING_MODEL_NAME}")
    
    # ** CHECK VECTOR DIMS **
    # text-embedding-004 ปกติ output dimension คือ 768
    # แต่ถ้าคุณใช้ Gecko รุ่นเก่าอาจจะเป็น 1024 หรือ 1536
    # แนะนำให้ลอง print(len(embed_batch(["test"])[0])) เพื่อเช็คก่อนสร้าง Collection ก็ดีครับ
    
    print(f"Loading STIX data from {STIX_FILE_PATH}...")
    store = MemoryStore()
    store.load_from_file(STIX_FILE_PATH)

    types_to_query = ["attack-pattern", "course-of-action", "x-mitre-data-source", "intrusion-set", "malware", "tool"]
    all_objects = []
    for t in types_to_query:
        try:
            objs = store.query([Filter("type", "=", t)])
            all_objects.extend(objs)
        except: continue

    print(f"Total objects found: {len(all_objects)}")

    # Connect Qdrant
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
    
    # Check if collection exists properly (using newer method logic if needed)
    # For simplicity, we recreate
    client.recreate_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=VECTOR_DIMS, distance=Distance.COSINE)
    )
    print(f"Collection '{COLLECTION_NAME}' (re)created.")

    # Prepare Data List first
    print("Preparing data for batch processing...")
    prepared_data = []
    for obj in all_objects:
        text_content = create_text_for_embedding(obj)
        payload = {
            "type": obj.get("type"),
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "text_content": text_content,
            "priority": priority_for_type(obj.get("type")),
            # Add other fields as needed
        }
        prepared_data.append({"text": text_content, "payload": payload})

    # Process in Batches (Embedding + Upsert)
    # Batch size สำหรับ Embedding API (Google รับได้ประมาณ 100 ต่อ call กำลังดี)
    EMBED_BATCH_SIZE = 50
    
    print(f"Starting Ingestion in batches of {EMBED_BATCH_SIZE}...")
    
    total_ingested = 0
    
    for batch in tqdm(chunk_list(prepared_data, EMBED_BATCH_SIZE), total=len(prepared_data)//EMBED_BATCH_SIZE):
        # 1. Extract texts
        texts_to_embed = [item["text"] for item in batch]
        
        # 2. Call Google API (Batch Embed)
        try:
            vectors = embed_batch(texts_to_embed)
        except Exception as e:
            print(f"Skipping batch due to error: {e}")
            continue

        if not vectors:
            continue
            
        # 3. Prepare Points for Qdrant
        points = []
        for i, item in enumerate(batch):
            points.append(PointStruct(
                id=str(uuid.uuid4()),
                vector=vectors[i],
                payload=item["payload"]
            ))
        
        # 4. Upsert to Qdrant
        client.upsert(
            collection_name=COLLECTION_NAME,
            points=points
        )
        
        total_ingested += len(points)
        
        # ** สำคัญ **: ใส่ Delay นิดหน่อยเพื่อไม่ให้ชน Rate Limit ของ Free Tier
        time.sleep(1) 

    print(f"Done! Ingested {total_ingested} objects.")

if __name__ == "__main__":
    main()