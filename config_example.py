# config.py

# --------------------
# การตั้งค่าข้อมูล
# --------------------
# (ดาวน์โหลดไฟล์นี้จาก https://github.com/mitre/cti/blob/master/enterprise-attack/enterprise-attack.json)
STIX_FILE_PATH = "data/enterprise-attack.json"

# --------------------
# การตั้งค่า Embedding Model
# --------------------
# (ชื่อ Model จาก SentenceTransformers)
MODEL_NAME = 'all-MiniLM-L6-v2' 

# (จำนวนมิติของ Vector ที่ Model นี้สร้าง)
# all-MiniLM-L6-v2 = 384 มิติ
VECTOR_DIMS = 384

# --------------------
# การตั้งค่า Gemini API
# --------------------
# *** วาง Key ที่คัดลอกมาจาก Google AI Studio ตรงนี้ ***
GEMINI_API_KEY = "YOUR_API_KEY"

# --------------------
# (เพิ่มใหม่) การตั้งค่า Qdrant (ฐานข้อมูล Vector)
# --------------------
# (นี่คือค่า Default จาก docker-compose.yml)
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION_NAME = "mitre-attack-vectors"
