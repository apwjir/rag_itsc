# app/services/ai_engine.py

import json
import os
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from app.services.models import get_model, ModelProvider, find_model_by_display_name
from langchain_google_genai import GoogleGenerativeAIEmbeddings

# โหลดตัวแปรจาก .env
load_dotenv()


# ------------------------------
# ✅ Custom Exceptions
# ------------------------------
class AIEngineError(Exception):
    def __init__(self, code: str, message: str, provider_message: str = ""):
        super().__init__(message)
        self.code = code
        self.provider_message = provider_message


class AIEngine:
    def __init__(self):
        # Config ค่าต่างๆ จาก Environment Variable
        self.qdrant_host = os.getenv("QDRANT_HOST", "localhost")
        self.qdrant_port = int(os.getenv("QDRANT_PORT", 6333))
        self.collection_name = os.getenv("COLLECTION_NAME", "mitre-attack-vectors")

        # Support both keys but prefer GOOGLE_API_KEY for consistency
        self.google_api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")

        # ชื่อโมเดล Embedding (ต้องตรงกับตอน Ingest)
        self.embedding_model_name = "models/text-embedding-004"

        # Default generation model
        self.generation_model_name = "gemini-2.0-flash-exp"
        self.generation_provider = ModelProvider.GOOGLE

        # Override with model from (.env) by Display Name if present
        target_display_name = os.getenv("GENERATION_MODEL_DISPLAY_NAME")
        if target_display_name:
            found_model = find_model_by_display_name(target_display_name)
            if found_model:
                print(
                    f"--- ⚙️ Using Model from ENV: {found_model.display_name} ({found_model.model_name}) ---"
                )
                self.generation_model_name = found_model.model_name
                self.generation_provider = found_model.provider
            else:
                print(
                    f"--- ⚠️ Warning: Model '{target_display_name}' not found. Using default: {self.generation_model_name} ---"
                )

        self.client = None
        self.llm = None
        self.embeddings = None

    # ------------------------------
    # ✅ Error classifier
    # ------------------------------
    def _raise_if_key_or_rate_error(self, e: Exception):
        s = str(e)

        # expired key patterns
        if "expired_api_key" in s:
            raise AIEngineError(
                code="EXPIRED_API_KEY",
                message="AI provider API key expired/invalid.",
                provider_message=s,
            )

        if ("Invalid API Key" in s or "invalid api key" in s.lower()) and (
            "401" in s or "Error code: 401" in s
        ):
            raise AIEngineError(
                code="EXPIRED_API_KEY",
                message="AI provider API key expired/invalid.",
                provider_message=s,
            )

        # rate limit patterns
        if "Error code: 429" in s or "429" in s or "rate limit" in s.lower():
            raise AIEngineError(
                code="RATE_LIMIT",
                message="AI provider rate limited.",
                provider_message=s,
            )

    def init_models(self):
        """โหลด Qdrant Client และ Config Gemini"""
        print("--- 🤖 Connecting to AI Services... ---")

        if not self.google_api_key:
            raise AIEngineError(
                code="EXPIRED_API_KEY",
                message="GOOGLE_API_KEY / GEMINI_API_KEY not found in .env",
                provider_message="Missing GOOGLE_API_KEY/GEMINI_API_KEY",
            )

        # 1) Initialize LangChain Chat Model
        self.llm = get_model(
            model_name=self.generation_model_name,
            model_provider=self.generation_provider,
            api_keys={"GOOGLE_API_KEY": self.google_api_key},
        )

        # 2) Initialize LangChain Embeddings
        self.embeddings = GoogleGenerativeAIEmbeddings(
            model=self.embedding_model_name,
            google_api_key=self.google_api_key,
            task_type="retrieval_query",
        )

        # 3) Connect Qdrant
        self.client = QdrantClient(host=self.qdrant_host, port=self.qdrant_port)

        print(
            f"--- ✅ AI Ready (Embed: {self.embedding_model_name} | Gen: {self.generation_model_name}) ---"
        )

    def get_embedding(self, text: str):
        """แปลงข้อความเป็น vector (ถ้า key หมดต้อง throw)"""
        try:
            if not self.embeddings:
                self.init_models()
            return self.embeddings.embed_query(text)
        except Exception as e:
            # ✅ ถ้า key/rate error -> throw แบบรู้รหัส
            self._raise_if_key_or_rate_error(e)

            # ✅ อื่น ๆ -> throw เป็น embedding error
            raise AIEngineError(
                code="EMBEDDING_ERROR",
                message="Embedding generation failed.",
                provider_message=str(e),
            )

    def search_and_rerank(self, query_text: str, top_k: int = 20, final_k: int = 6):
        """ค้น Qdrant + boost score (ถ้า embedding/key fail ต้อง throw)"""
        qv = self.get_embedding(query_text)  # ถ้า key หมด จะ raise ไปแล้ว

        if not qv:
            raise AIEngineError(
                code="EMBEDDING_ERROR",
                message="Empty embedding returned.",
                provider_message="embed_query returned empty vector",
            )

        try:
            if not self.client:
                self.init_models()

            hits = self.client.search(
                collection_name=self.collection_name,
                query_vector=qv,
                limit=top_k,
                with_payload=True,
            )
        except Exception as e:
            raise AIEngineError(
                code="QDRANT_ERROR",
                message="Vector search failed.",
                provider_message=str(e),
            )

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
            p = h.payload or {}
            desc = (p.get("description") or "").replace("\n", " ")[:800]
            lines.append(
                f"Result {i}: type={p.get('type')}, id={p.get('mitre_id')}, name={p.get('name')}, desc={desc}"
            )
        return "\n".join(lines)

    def generate_mitigation_json(self, query_text: str, context_text: str):
            prompt = f"""
        คุณเป็นผู้เชี่ยวชาญด้าน Cybersecurity (SOC / Incident Response Analyst)

        หน้าที่ของคุณคือ:
        เสนอ "ตัวเลือกการรับมือ" ที่ทีม SOC สามารถเลือกไปใช้งานจริงได้
        ไม่จำเป็นต้องดีที่สุดทุกวิธี แต่ต้อง "ทำได้จริง" และ "เลือกได้"

        ข้อกำหนดสำคัญ:
        - ตอบเป็น JSON เท่านั้น
        - ห้ามใช้ Markdown หรือ ```json
        - ห้ามใส่คำว่า Result, Reference, Source หรือหมายเลขอ้างอิงใด ๆ

        Context ข้อมูลภัยคุกคาม:
        {context_text}

        Incident:
        "{query_text}"

        คำสั่ง:
        สร้าง Mitigation Plan จำนวน 3 วิธี
        โดยแต่ละวิธีต้อง "แตกต่างกันชัดเจน" และอยู่คนละแนวทางดังนี้เท่านั้น:
        1) Containment — ลดผลกระทบในทันที (quick win / stop the bleeding)
        2) Eradication & Recovery — แก้ root cause และกู้ระบบกลับสู่สภาพปกติ
        3) Prevention / Hardening — ป้องกันไม่ให้เหตุการณ์ลักษณะนี้เกิดซ้ำ
        ห้ามสร้างวิธีที่ซ้ำแนวคิดกัน

        ข้อกำหนดโครงสร้างแต่ละวิธี:
        1) action: ชื่อสั้น กระชับ สื่อชัดว่า SOC จะต้องทำอะไร (ภาษาไทย)
        2) detail: ต้องมีอย่างน้อย 3 ขั้น (Step 1/2/3) และทำตามได้จริง
        3) reason:
        - ต้องเป็นข้อความเดียว (ห้ามแยกหัวข้อ)
        - 3–5 ประโยค
        - ต้องมี 3 ส่วนต่อเนื่องกัน: Threat/Impact → Evidence (อย่างน้อย 2 fact จาก context) → Expected Outcome
        - ห้ามเขียนว่า Result/Reference/Source/หมายเลข

        Output Format (ต้องตรงนี้เท่านั้น):
        [
        {{
            "method_id": 1,
            "action": "...",
            "detail": "Step 1: ...\\nStep 2: ...\\nStep 3: ...",
            "reason": "..."
        }},
        {{
            "method_id": 2,
            "action": "...",
            "detail": "Step 1: ...\\nStep 2: ...\\nStep 3: ...",
            "reason": "..."
        }},
        {{
            "method_id": 3,
            "action": "...",
            "detail": "Step 1: ...\\nStep 2: ...\\nStep 3: ...",
            "reason": "..."
        }}
        ]
        """.strip()

            try:
                if not self.llm:
                    self.init_models()

                response = self.llm.invoke(prompt)
                text_resp = response.content.strip()
                text_resp = text_resp.replace("```json", "").replace("```", "").strip()

                data = json.loads(text_resp)
                if not isinstance(data, list) or len(data) != 3:
                    raise AIEngineError(
                        code="AI_PROCESSING_ERROR",
                        message="AI returned invalid JSON (expected list of 3 items).",
                        provider_message=text_resp,
                    )

                return data

            except AIEngineError:
                raise
            except Exception as e:
                self._raise_if_key_or_rate_error(e)
                raise AIEngineError(
                    code="AI_PROCESSING_ERROR",
                    message="AI generation failed.",
                    provider_message=str(e),
                )


    def analyze_incident(self, cat: str, subj: str, msg: str):
        """ฟังก์ชันหลักที่ API จะเรียกใช้"""
        query = f"Category: {cat} | Subject: {subj} | Detail: {msg}"
        print(f"Processing Query: {query[:80]}...")

        hits = self.search_and_rerank(query)

        # ถ้าไม่เจอ hits จะไม่ fail ก็ได้ (ตามดีไซน์)
        if not hits:
            return {"mitigation_plan": [], "related_threats": []}

        context = self.build_context_from_hits(hits)
        mitigation_plan = self.generate_mitigation_json(query, context)

        # Format Related Threats for Frontend
        related_threats = []
        for i, h in enumerate(hits, 1):
            p = h.payload or {}
            related_threats.append(
                {
                    "ref_result": f"Result {i}",
                    "mitre_id": p.get("mitre_id"),
                    "name": p.get("name"),
                    "type": p.get("type"),
                    "score": f"{getattr(h, 'score', 0.0):.4f}",
                }
            )

        return {"mitigation_plan": mitigation_plan, "related_threats": related_threats}


# สร้าง Instance ไว้รอให้ API import
ai_engine_instance = AIEngine()
