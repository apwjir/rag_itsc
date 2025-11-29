import sys
import pandas as pd
import json
import config
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
import google.generativeai as genai
import warnings
import re
import uuid
from tqdm import tqdm
from datetime import datetime

warnings.filterwarnings("ignore", category=UserWarning, module="google.generativeai")

# ==========================================
# ⚙️ CONFIGURATION
# ==========================================
INPUT_CSV_FILE = "csvFile/log_test.csv"
current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_JSON_FILE = f"incident_analysis_{current_time}.json"
# ==========================================

QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION_NAME = "mitre-attack-vectors"

def search_and_rerank(query_text, client, model, top_k=20, final_k=6):
    try:
        qv = model.encode(query_text, normalize_embeddings=True).tolist()
        hits = client.search(collection_name=COLLECTION_NAME, query_vector=qv, limit=top_k, with_payload=True)
    except Exception:
        return []
    
    boosted = []
    for h in hits:
        p = h.payload or {}
        score = getattr(h, "score", 0.0)
        boost_factor = 1.0
        if p.get("type") == "course-of-action": boost_factor = 1.4
        elif p.get("type") == "attack-pattern": boost_factor = 1.2
        combined = score * boost_factor + (1.0 / (p.get("priority", 4) + 0.1)) * 0.15
        boosted.append((combined, h))
    
    boosted_sorted = sorted(boosted, key=lambda x: x[0], reverse=True)
    return [item[1] for item in boosted_sorted[:final_k]]

def build_context_from_hits(hits):
    lines = []
    for i, h in enumerate(hits, 1):
        p = h.payload
        desc = (p.get("description") or "").replace("\n", " ")[:800]
        lines.append(f"Result {i}: type={p.get('type')}, id={p.get('mitre_id')}, name={p.get('name')}, desc={desc}")
    return "\n".join(lines)

def generate_mitigation_json(query_text, context_text):
    prompt = f"""
    คุณเป็นผู้เชี่ยวชาญด้าน Cybersecurity
    จงตอบเป็นภาษาไทยทั้งหมด และใช้ข้อมูลจาก CONTEXT ด้านล่างเท่านั้น

    เป้าหมาย: เสนอแผน Mitigation 3 วิธีการ (3 Alternative Methods) ที่แตกต่างกัน
    เน้นการดำเนินการทางเทคนิค (Technical Actions)

    Context: {context_text}
    Incident: "{query_text}"

    Format Output (JSON Array):
    [
      {{
        "method_id": 1,
        "action": "วิธีที่ 1: [Action]",
        "reason": "เหตุผล (อ้างอิงจาก Context Result ไหน)"
      }},
      {{
        "method_id": 2,
        "action": "...",
        "reason": "..."
      }},
      {{
        "method_id": 3,
        "action": "...",
        "reason": "..."
      }}
    ]
    """
    try:
        genai.configure(api_key=config.GEMINI_API_KEY)
        model = genai.GenerativeModel("models/gemini-2.5-flash")
        resp = model.generate_content(prompt)
        text_resp = resp.text if hasattr(resp, "text") else str(resp)
        text_resp = text_resp.replace("```json", "").replace("```", "").strip()
        return json.loads(text_resp)
    except Exception as e:
        return [{"method_id": 0, "action": "Error", "reason": str(e)}]

def main():
    print(f"--- 📂 Loading CSV: {INPUT_CSV_FILE} ---")
    try:
        df = pd.read_csv(INPUT_CSV_FILE)
    except FileNotFoundError:
        return

    df_filtered = df[df['CategoryEN'] != 'Admin Information Sharing'].copy()
    print(f"Processing {len(df_filtered)} incidents...")

    model = SentenceTransformer(config.MODEL_NAME)
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

    json_output = []

    for _, row in tqdm(df_filtered.iterrows(), total=len(df_filtered)):
        inc_id = row.get('IncidentsId')
        cat = str(row.get('CategoryEN', 'Unknown'))
        subj = str(row.get('IncidentSubject', ''))
        msg = str(row.get('IncidentMessage', ''))
        
        query = f"Category: {cat} | Subject: {subj} | Detail: {msg}"
        hits = search_and_rerank(query, client, model)
        
        related_threats = []
        if hits:
            context = build_context_from_hits(hits)
            mitigation_plan = generate_mitigation_json(query, context)
            
            for i, h in enumerate(hits, 1):
                p = h.payload
                related_threats.append({
                    "ref_result": f"Result {i}",
                    "mitre_id": p.get("mitre_id"),
                    "name": p.get("name"),
                    "type": p.get("type")
                })
        else:
            mitigation_plan = []

        # 🟢 จุดแก้ไข: ย้าย uid มาไว้ข้างนอก
        record = {
            "uid": str(uuid.uuid4()),  # <--- อยู่ระดับบนสุดแล้ว
            "metadata": {
                "original_id": int(inc_id) if pd.notna(inc_id) else None,
                "ticket_id": str(row.get('TicketId', '')),
                "timestamp": str(row.get('CreateDate', ''))
            },
            "incident_details": {
                "category": cat,
                "subject": subj,
                "message": msg
            },
            "ai_analysis": {
                "mitigation_plan": mitigation_plan,
                "related_threats": related_threats
            }
        }
        
        json_output.append(record)

    print(f"\n--- 💾 Saving JSON to: {OUTPUT_JSON_FILE} ---")
    with open(OUTPUT_JSON_FILE, 'w', encoding='utf-8') as f:
        json.dump(json_output, f, ensure_ascii=False, indent=4)
    
    print("Done!")

if __name__ == "__main__":
    main()