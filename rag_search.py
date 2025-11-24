# rag_search.py
import sys
import config
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
import google.generativeai as genai # <-- Import Gemini
import warnings

# ปิด Warning ที่ไม่จำเป็น
warnings.filterwarnings("ignore", category=UserWarning, module="google.generativeai")

# --------------------
# 1. ตั้งค่า Qdrant (เหมือนเดิม)
# --------------------
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION_NAME = "mitre-attack-vectors"

def search_knn(query_text, client, model):
    """
    (R) - Retrieval: ค้นหาใน Qdrant
    """
    
    # (เรา "ไม่" สร้าง query_vector เองแล้ว)
    # query_vector = model.encode(query_text, normalize_embeddings=True).tolist()
    
    try:
        # (ใช้ .query และส่ง query_text)
        search_results = client.query(
            collection_name=COLLECTION_NAME,
            query_text=query_text, # <--- **จุดสำคัญคือบรรทัดนี้**
            with_payload=True,
            limit=3
        )
        return search_results
    except Exception as e:
        print(f"Error during Qdrant search: {e}")
        return []

# --------------------
# 2. (ใหม่) ส่วนของ "G" - Generation
# --------------------
def generate_answer(query_text, search_results):
    """
    (G) - Generation: นำผลลัพธ์ไปให้ Gemini เรียบเรียง
    """
    print("\n--- 🤖 Calling Gemini API ---")
    
    # 1. เตรียม Context (ข้อมูลดิบที่ค้นเจอ)
    context = ""
    if not search_results:
        print("No context found from Qdrant.")
        return "ฉันไม่พบข้อมูลที่เกี่ยวข้องในฐานข้อมูล MITRE ATT&CK ครับ"

    print("Context retrieved from Qdrant:")
    for i, hit in enumerate(search_results):
        payload = hit.payload
        context += f"Result {i+1} (ID: {payload['mitre_id']}):\n"
        context += f"Name: {payload['mitre_name']}\n"
        context += f"Description: {payload['description']}\n---\n"
        print(f"- {payload['mitre_id']}: {payload['mitre_name']}")

    # 2. สร้าง Prompt ที่สมบูรณ์
    # นี่คือการบอกให้ LLM ตอบโดยอ้างอิงจากข้อมูลที่เราหามาให้
    prompt_template = f"""
    คุณคือผู้ช่วย AI ด้าน Cybersecurity ที่เชี่ยวชาญ MITRE ATT&CK
    จงตอบคำถามต่อไปนี้ โดยใช้ *เฉพาะ* ข้อมูลใน 'บริบท' ที่กำหนดให้เท่านั้น
    ห้ามใช้ความรู้เดิมของตัวเองในการตอบ ให้สรุปและอ้างอิงจากบริบท

    **บริบท (Context) ที่ค้นหามาได้:**
    {context}

    **คำถามจากผู้ใช้ (Query):**
    "{query_text}"

    **คำตอบ:**
    """
    
    # 3. เรียก Gemini API
    try:
        genai.configure(api_key=config.GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-1.0-pro')
        response = model.generate_content(prompt_template)
        return response.text
    except Exception as e:
        if "API_KEY_INVALID" in str(e):
            return "Error: Gemini API Key ไม่ถูกต้อง กรุณาตรวจสอบใน config.py"
        else:
            return f"Error calling Gemini API: {e}"

# --------------------
# 3. Main (ส่วนควบคุมหลัก)
# --------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python 04_rag_search.py \"Your search query here\"")
        return

    query_text = " ".join(sys.argv[1:])
    print(f"--- ❓ Query: \"{query_text}\" ---")

    # ----- (R) Retrieval -----
    # 1. โหลด Model (สำหรับค้นหา)
    print("Loading SentenceTransformer model...")
    embedding_model = None
    
    # 2. เชื่อมต่อ Qdrant
    qdrant_client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
    
    # 3. ค้นหา Context
    print("--- 🔍 Retrieving from Qdrant ---")
    search_results = search_knn(query_text, qdrant_client, None)

    # ----- (G) Generation -----
    # 4. ส่ง Context และ Query ให้ LLM สร้างคำตอบ
    rag_answer = generate_answer(query_text, search_results)
    
    # 5. แสดงผลลัพธ์
    print("\n--- 💡 RAG Answer ---")
    print(rag_answer)

if __name__ == "__main__":
    main()