import json
import os
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from qdrant_client.models import SearchRequest
from app.services.models import get_model, ModelProvider, find_model_by_display_name
from langchain_core.messages import HumanMessage
from langchain_google_genai import GoogleGenerativeAIEmbeddings

# โหลดตัวแปรจาก .env
load_dotenv()

class AIEngine:
    def __init__(self):
        # Config ค่าต่างๆ จาก Environment Variable
        self.qdrant_host = os.getenv("QDRANT_HOST", "localhost")
        self.qdrant_port = int(os.getenv("QDRANT_PORT", 6333))
        self.collection_name = os.getenv("COLLECTION_NAME", "mitre-attack-vectors")
        # Support both keys but prefer GOOGLE_API_KEY for consistency with models.py
        self.google_api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        
        # ชื่อโมเดล Embedding (ต้องตรงกับตอน Ingest)
        # FIXED: Only use models/text-embedding-004 by Google
        self.embedding_model_name = "models/text-embedding-004"
        
        # Default generation model
        self.generation_model_name = "gemini-2.0-flash-exp"
        self.generation_provider = ModelProvider.GOOGLE

        # Override with model from (.env) by Display Name if present
        target_display_name = os.getenv("GENERATION_MODEL_DISPLAY_NAME")
        if target_display_name:
            found_model = find_model_by_display_name(target_display_name)
            if found_model:
                print(f"--- ⚙️ Using Model from ENV: {found_model.display_name} ({found_model.model_name}) ---")
                self.generation_model_name = found_model.model_name
                self.generation_provider = found_model.provider
            else:
                print(f"--- ⚠️ Warning: Model '{target_display_name}' not found. Using default: {self.generation_model_name} ---")

        self.client = None
        self.llm = None
        self.embeddings = None

    def init_models(self):
        """โหลด Qdrant Client และ Config Gemini"""
        print("--- 🤖 Connecting to AI Services... ---")
        
        if not self.google_api_key:
            raise ValueError("❌ GOOGLE_API_KEY or GEMINI_API_KEY not found in .env")
        
        # 1. Initialize LangChain Chat Model
        self.llm = get_model(
            model_name=self.generation_model_name,
            model_provider=self.generation_provider,
            api_keys={"GOOGLE_API_KEY": self.google_api_key}
        )
        
        # 2. Initialize LangChain Embeddings
        # task_type="retrieval_query" is often supported by the underlying API, 
        # but LangChain's wrapper might treat it differently. 
        # For text-embedding-004, it usually auto-handles or we pass arguments if needed.
        self.embeddings = GoogleGenerativeAIEmbeddings(
            model=self.embedding_model_name,
            google_api_key=self.google_api_key,
            task_type="retrieval_query"
        )

        # 3. Connect Qdrant (ไม่ต้องโหลด SentenceTransformer แล้ว)
        self.client = QdrantClient(host=self.qdrant_host, port=self.qdrant_port)
        
        print(f"--- ✅ AI Ready (Embed: {self.embedding_model_name} | Gen: {self.generation_model_name}) ---")

    def get_embedding(self, text):
        """ฟังก์ชันแปลงข้อความให้เป็น Vector โดยใช้ LangChain Embeddings"""
        try:
            if not self.embeddings:
                self.init_models()
                
            return self.embeddings.embed_query(text)
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
                "reason": "เขียน reason โดยอ้างอิงข้อมูลจาก context ที่ให้ไว้
                            - ห้ามแสดงคำว่า Result, Reference, Source หรือหมายเลขใด ๆ
                            - ให้สรุปเหตุผลเป็นข้อความธรรมดา
                            - หากมีหลายแหล่งข้อมูล ให้รวมเหตุผลเข้าด้วยกันโดยไม่ระบุที่มาเป็นชื่อ
                            "
            }},
            {{ "method_id": 2, ... }},
            {{ "method_id": 3, ... }}
        ]
        """
        try:
            # ใช้ LangChain model ที่ init ไว้
            if not self.llm:
                 # Fallback/Lazy init if needed
                 self.init_models()
            
            response = self.llm.invoke(prompt)
            text_resp = response.content
            
            # Clean Markdown formatting (กันเหนียว)
            text_resp = text_resp.replace("```json", "").replace("```", "").strip()
            return json.loads(text_resp)
        except Exception as e:
            print(f"LLM Generate Error: {e}")
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
            
            # 3. Generate with LLM
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