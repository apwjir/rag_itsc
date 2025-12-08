import json
import os
from dotenv import load_dotenv
from qdrant_client import QdrantClient
import google.generativeai as genai
import warnings
from qdrant_client.models import SearchRequest

# โหลดตัวแปรจาก .env
load_dotenv()

# ปิด Warning
warnings.filterwarnings("ignore", category=UserWarning, module="google.generativeai")

class AIEngine:
    def __init__(self):
        # Config ค่าต่างๆ จาก Environment Variable
        self.qdrant_host = os.getenv("QDRANT_HOST", "localhost")
        self.qdrant_port = int(os.getenv("QDRANT_PORT", 6333))
        self.collection_name = os.getenv("COLLECTION_NAME", "mitre-attack-vectors")
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        
        # ชื่อโมเดล Embedding (ต้องตรงกับตอน Ingest)
        self.embedding_model = "models/text-embedding-004"
        self.generation_model = "models/gemini-2.5-flash"

        self.client = None

    def init_models(self):
        """โหลด Qdrant Client และ Config Gemini"""
        print("--- 🤖 Connecting to AI Services... ---")
        
        # 1. Config Gemini
        if not self.gemini_api_key:
            raise ValueError("❌ GEMINI_API_KEY not found in .env")
        genai.configure(api_key=self.gemini_api_key)
        
        # 2. Connect Qdrant (ไม่ต้องโหลด SentenceTransformer แล้ว)
        self.client = QdrantClient(host=self.qdrant_host, port=self.qdrant_port)
        
        print(f"--- ✅ AI Ready (Embed: {self.embedding_model} | Gen: {self.generation_model}) ---")

    def get_embedding(self, text):
        """ฟังก์ชันแปลงข้อความให้เป็น Vector โดยใช้ Gemini"""
        try:
            # ใช้ task_type="retrieval_query" เพราะเรากำลังเอาไปค้นหา
            result = genai.embed_content(
                model=self.embedding_model,
                content=text,
                task_type="retrieval_query" 
            )
            return result['embedding']
        except Exception as e:
            print(f"Embedding Error: {e}")
            return []

    def search_and_rerank(self, query_text, top_k=20, final_k=6):
        qv = self.get_embedding(query_text)
        if not qv:
            return []

        try:
            hits = self.client.search(
                collection_name=self.collection_name,
                query_vector=qv,
                limit=top_k,
                with_payload=True
            )
        except Exception as e:
            print(f"Qdrant Error: {e}")
            return []

        boosted = []
        for h in hits:
            p = h.payload or {}
            score = getattr(h, "score", 0.0)

            boost_factor = 1.0
            if p.get("type") == "course-of-action":
                boost_factor = 1.4
            elif p.get("type") == "attack-pattern":
                boost_factor = 1.2

            combined = score * boost_factor + (1.0 / (p.get("priority", 4) + 0.1)) * 0.15
            boosted.append((combined, h))

        boosted_sorted = sorted(boosted, key=lambda x: x[0], reverse=True)
        return [item[1] for item in boosted_sorted[:final_k]]



    def build_context_from_hits(self, hits):
        lines = []
        for i, h in enumerate(hits, 1):
            p = h.payload
            desc = (p.get("description") or "").replace("\n", " ")[:800]
            lines.append(f"Result {i}: type={p.get('type')}, id={p.get('mitre_id')}, name={p.get('name')}, desc={desc}")
        return "\n".join(lines)

    def generate_mitigation_json(self, query_text, context_text):
        prompt = f"""
        คุณเป็นผู้เชี่ยวชาญด้าน Cybersecurity (Security Analyst).
        จงวิเคราะห์และตอบเป็น JSON เท่านั้น ห้ามมี Markdown (```json) ครอบ

        Context ข้อมูลภัยคุกคามที่พบ:
        {context_text}

        เหตุการณ์ที่เกิดขึ้น (Incident): "{query_text}"

        คำสั่ง: สร้างแผนการรับมือ (Mitigation Plan) 3 วิธี โดยอ้างอิงข้อมูลจาก Context เป็นหลัก
        Output Format:
        [
            {{
                "method_id": 1,
                "action": "ชื่อวิธีดำเนินการ (กระชับ)",
                "detail": "รายละเอียดทางเทคนิคที่ต้องทำ",
                "reason": "เหตุผลที่เลือกวิธีนี้ (อ้างอิงจาก Result ไหนใน context)"
            }},
            {{ "method_id": 2, ... }},
            {{ "method_id": 3, ... }}
        ]
        """
        try:
            # ใช้ Gemini 1.5 Flash (ตัว 2.5 ยังไม่ออกเป็นทางการ อาจจะ Error ได้)
            model = genai.GenerativeModel(self.generation_model)
            resp = model.generate_content(prompt)
            
            text_resp = resp.text if hasattr(resp, "text") else str(resp)
            # Clean Markdown formatting (กันเหนียว)
            text_resp = text_resp.replace("```json", "").replace("```", "").strip()
            return json.loads(text_resp)
        except Exception as e:
            print(f"Gemini Generate Error: {e}")
            # Return Fallback JSON กรณี Error
            return [{"method_id": 0, "action": "System Error", "detail": "AI generation failed", "reason": str(e)}]

    def analyze_incident(self, cat, subj, msg):
        """ฟังก์ชันหลักที่ API จะเรียกใช้"""
        query = f"Category: {cat} | Subject: {subj} | Detail: {msg}"
        print(f"Processing Query: {query[:50]}...")
        
        # 1. Search RAG
        hits = self.search_and_rerank(query)
        
        mitigation_plan = []
        related_threats = []

        if hits:
            # 2. Build Context
            context = self.build_context_from_hits(hits)
            
            # 3. Generate with Gemini
            mitigation_plan = self.generate_mitigation_json(query, context)
            
            # 4. Format Related Threats for Frontend
            for i, h in enumerate(hits, 1):
                p = h.payload
                related_threats.append({
                    "ref_result": f"Result {i}",
                    "mitre_id": p.get("mitre_id"),
                    "name": p.get("name"),
                    "type": p.get("type"),
                    "score": f"{h.score:.4f}" # เพิ่ม Score ให้ดู Debug ง่ายขึ้น
                })
        
        return {
            "mitigation_plan": mitigation_plan,
            "related_threats": related_threats
        }

# สร้าง Instance ไว้รอให้ API import
ai_engine_instance = AIEngine()