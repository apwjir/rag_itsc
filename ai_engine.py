import json
import config
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
import google.generativeai as genai
import warnings

# ปิด Warning
warnings.filterwarnings("ignore", category=UserWarning, module="google.generativeai")

class AIEngine:
    def __init__(self):
        self.model = None
        self.client = None
        self.collection_name = "mitre-attack-vectors"
        self.qdrant_host = "localhost"
        self.qdrant_port = 6333

    def init_models(self):
        """โหลด Model และเชื่อมต่อ Database (ทำครั้งเดียวตอน Start Server)"""
        print("--- 🤖 Loading AI Models... ---")
        self.model = SentenceTransformer(config.MODEL_NAME)
        self.client = QdrantClient(host=self.qdrant_host, port=self.qdrant_port)
        genai.configure(api_key=config.GEMINI_API_KEY)
        print("--- ✅ AI Models Loaded ---")

    def search_and_rerank(self, query_text, top_k=20, final_k=6):
        try:
            qv = self.model.encode(query_text, normalize_embeddings=True).tolist()
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
            if p.get("type") == "course-of-action": boost_factor = 1.4
            elif p.get("type") == "attack-pattern": boost_factor = 1.2
            
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
        คุณเป็นผู้เชี่ยวชาญด้าน Cybersecurity
        จงตอบเป็นภาษาไทยทั้งหมด และใช้ข้อมูลจาก CONTEXT ด้านล่างเท่านั้น

        เป้าหมาย: เสนอแผน Mitigation 3 วิธีการ (3 Alternative Methods) ที่แตกต่างกัน
        เน้นการดำเนินการทางเทคนิค (Technical Actions)

        Context: {context_text}
        Incident: "{query_text}"

        Format Output (JSON Array Only, No Markdown):
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
            model = genai.GenerativeModel("models/gemini-2.5-flash")
            resp = model.generate_content(prompt)
            text_resp = resp.text if hasattr(resp, "text") else str(resp)
            # Clean Markdown formatting
            text_resp = text_resp.replace("```json", "").replace("```", "").strip()
            return json.loads(text_resp)
        except Exception as e:
            print(f"Gemini Error: {e}")
            return [{"method_id": 0, "action": "Error Generating Plan", "reason": str(e)}]

    def analyze_incident(self, cat, subj, msg):
        """ฟังก์ชันหลักที่ API จะเรียกใช้"""
        query = f"Category: {cat} | Subject: {subj} | Detail: {msg}"
        
        # 1. Search RAG
        hits = self.search_and_rerank(query)
        
        mitigation_plan = []
        related_threats = []

        if hits:
            # 2. Build Context
            context = self.build_context_from_hits(hits)
            
            # 3. Generate with Gemini
            mitigation_plan = self.generate_mitigation_json(query, context)
            
            # 4. Format Related Threats
            for i, h in enumerate(hits, 1):
                p = h.payload
                related_threats.append({
                    "ref_result": f"Result {i}",
                    "mitre_id": p.get("mitre_id"),
                    "name": p.get("name"),
                    "type": p.get("type")
                })
        
        return {
            "mitigation_plan": mitigation_plan,
            "related_threats": related_threats
        }

# สร้าง Instance ไว้รอให้ API import
ai_engine_instance = AIEngine()