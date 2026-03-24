# ITSC Incident RAG Backend

**ITSC Incident RAG Backend** คือระบบ Backend API สำหรับงานวิเคราะห์ Incident Logs ด้วยแนวทาง Retrieval-Augmented Generation (RAG) โดยเชื่อม Elasticsearch (logs), Qdrant (knowledge vectors), และ PostgreSQL (users/settings) เพื่อช่วยทีม SOC วิเคราะห์เหตุการณ์และเลือกแนวทางตอบสนองได้เร็วขึ้น

ระบบรองรับการทำงานร่วมกับหลาย LLM providers (เช่น Ollama, Groq, OpenAI, Google, Anthropic) ผ่านการตั้งค่าโมเดลใน environment

- Backend repository: https://github.com/apwjir/rag_itsc
- Frontend repository: https://github.com/nathapatt/web-management-log.git
- Deploy repository: https://github.com/nathapatt/ticket-sys-deploy.git

---

## คุณสมบัติของระบบ (Key Features)

- **RAG-based Incident Analysis**: วิเคราะห์ incident แล้วจับคู่บริบทกับ MITRE ATT&CK knowledge base
- **AI Mitigation Plan Generation**: สร้าง mitigation methods สำหรับทีม SOC ใช้ตัดสินใจ
- **SOC Workflow APIs**: รองรับการเลือก action, rating, feedback และการติดตามสถานะ
- **Incident Search & Filtering**: ค้นหาและกรองข้อมูลจาก Elasticsearch ได้ละเอียด
- **Dashboard Metrics APIs**: ส่งข้อมูลสรุปเพื่อแสดงผลบน dashboard แบบ near real-time
- **Auth & User Management**: ระบบ login ด้วย JWT cookie และจัดการผู้ใช้งานใน PostgreSQL

---

## สมาชิกผู้พัฒนา

| ชื่อ                     | รหัสนักศึกษา |
| ---------------------  | ------------ |
| กัลป์กรณ์ จิรไชยหิรัญ        | 650610746    |
| จิรพัทธ์ พลรัฐ             | 650610752    |
| ณฐภัทร เนรังษี            | 650610758    |

---

## Technology Stack

| Tech | Description |
| ---- | ----------- |
| Python 3.11 | ภาษาหลักของ Backend |
| FastAPI | REST API Framework |
| SQLAlchemy | ORM สำหรับ PostgreSQL |
| PostgreSQL 17 | ข้อมูลผู้ใช้และ metadata |
| Elasticsearch | เก็บและค้นหา incident logs |
| Qdrant | Vector DB สำหรับ RAG retrieval |
| LangChain | LLM orchestration |
| OpenAI Embeddings | embedding model ที่ใช้ในปัจจุบัน |
| Docker / Docker Compose | Infrastructure และการ deploy |

---

## Environment Variables ที่สำคัญ

> สร้าง `.env` จาก `.env.example` ก่อนเริ่มใช้งาน

### RAG / Model
- `STIX_FILE_PATH`
- `VECTOR_DIMS`
- `COLLECTION_NAME`
- `OPENAI_API_KEY` (จำเป็นสำหรับ embeddings)
- `GENERATION_MODEL_DISPLAY_NAME` (เลือก generation model)
- `OLLAMA_BASE_URL` (กรณีใช้ Ollama)
- `GROQ_API_KEY`, `GOOGLE_API_KEY`, `ANTHROPIC_API_KEY` (ใส่เฉพาะ provider ที่ใช้)

### Databases / Search
- `ES_URL`, `ES_INDEX`
- `QDRANT_HOST`, `QDRANT_PORT`
- `DATABASE_URL`
- `POSTGRES_*`

### Auth / Runtime
- `SECRET_KEY`, `ALGORITHM`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `ALLOWED_ORIGINS`
- `ADMIN_USERNAME`, `ADMIN_PASSWORD`

---

## การตั้งค่าและเริ่มใช้งาน

### Prerequisites

- Python 3.11+
- Docker + Docker Compose

### ขั้นตอนการรันสำหรับพัฒนา

1. **Clone repository**
   ```bash
   git clone https://github.com/apwjir/rag_itsc
   cd rag_itsc
   ```

2. **ตั้งค่า environment**
   ```bash
   cp .env.example .env
   ```

3. **เริ่ม infrastructure ที่จำเป็น**
   ```bash
   docker-compose up -d
   ```

4. **ติดตั้ง dependencies**
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

5. **Initialize ระบบครั้งแรก (แนะนำวิธีนี้)**
   ```bash
   ./init_project.sh
   ```

   สคริปต์นี้จะทำให้อัตโนมัติ:
   - สร้าง Elasticsearch index (`init_es_index.py`)
   - Ingest MITRE ATT&CK ลง Qdrant (`ingest_data.py`)
   - สร้างตาราง PostgreSQL (`app/create_db.py`)
   - Seed บัญชี Admin (`app/seed_admin.py`)

6. **รัน API server**
   ```bash
   python -m uvicorn app.main:app --reload
   ```

### วิธี manual (ถ้าไม่ใช้สคริปต์รวม)

```bash
python init_es_index.py
python ingest_data.py
python app/create_db.py
python app/seed_admin.py
```

---

## การเข้าถึงระบบ

- API Base URL: `http://localhost:8000`
- API Docs (Swagger): `http://localhost:8000/docs`
- Elasticsearch: `http://localhost:9200`
- Qdrant: `http://localhost:6333`

---

## API Modules หลัก

- `auth` - login/logout/me
- `logs` - upload, search, summary, analyzed/unanalyzed lists
- `ai` - วิเคราะห์ incident และ generate suggestion
- `dashboard` - metrics/threat/severity/trends
- `soc_action` - บันทึกการเลือก action
- `summary` - สรุปข้อมูลเวลาและประสิทธิภาพ
- `users` - จัดการผู้ใช้งาน
- `auto_analyze` - ตั้งค่า auto analysis

---

## หมายเหตุการตั้งค่า LLM

- ค่า `GENERATION_MODEL_DISPLAY_NAME` ต้องตรงกับรายการที่ระบบรองรับใน `app/services/api_models.json`
- ถึงแม้เลือก generation ผ่าน Ollama/Groq ได้ แต่ embedding ในโค้ดปัจจุบันยังใช้ OpenAI (`OPENAI_API_KEY`)
