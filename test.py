import sys
import os
import pandas as pd
import re
import math
import warnings
import nltk
import time
from collections import Counter
from nltk.corpus import stopwords

# ปิด Warning
warnings.filterwarnings('ignore')

# --- Setup NLTK ---
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpus/stopwords')
except LookupError:
    print("⬇️ Downloading NLTK data...")
    nltk.download('punkt')
    nltk.download('stopwords')

# --- 1. Setup Path AI Engine ---
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app.services.ai_engine import ai_engine_instance
    print("✅ AI Engine Loaded Successfully.")
except Exception as e:  # <--- เปลี่ยนเป็น Exception as e
    print(f"❌ Real Import Error: {e}")  # <--- ให้มันปริ้นท์ความจริงออกมา
    import traceback
    traceback.print_exc()
    sys.exit(1)

# --- Config ---
INCIDENT_FILE = 'CSD-CMU_Incident_081225.xlsx'
RESPONSE_FILE = 'incident_response.csv'
SAMPLE_SIZE = 10

# --- 2. ฟังก์ชันโหลดข้อมูล (Smart Filter) ---
def load_and_merge_data():
    if not os.path.exists(INCIDENT_FILE) or not os.path.exists(RESPONSE_FILE):
        return pd.DataFrame()

    try:
        df_inc = pd.read_excel(INCIDENT_FILE)
        df_res = pd.read_csv(RESPONSE_FILE) 
    except Exception as e:
        print(f"❌ Read File Error: {e}")
        return pd.DataFrame()

    # Clean IDs
    df_inc['IncidentsId'] = df_inc['IncidentsId'].astype(str).str.split('.').str[0].str.strip()
    df_res['Incident_id'] = df_res['Incident_id'].astype(str).str.split('.').str[0].str.strip()

    # Smart Filter Logic
    def is_useful(text):
        if not isinstance(text, str): return False
        text_clean = text.strip().lower()
        
        if len(text_clean) < 4: return False

        # Whitelist Actions (เก็บไว้เสมอถ้ามี Action)
        action_keywords = [
            "block", "ban", "firewall", "isolate", "quarantine", 
            "check", "ตรวจสอบ", "reset", "change", "update",
            "source", "ip", "url", "account", "log", "scan", "patch"
        ]
        
        for action in action_keywords:
            if action in text_clean:
                return True 

        # Blacklist Noise
        noise_keywords = [
            "รับทราบ", "รอดำเนินการ", "กำลังตรวจสอบ", "ขอบคุณ", "เรียบร้อย", "test",
            "แก้ไขแล้ว", "ดำเนินการแล้ว", "ประสานงาน", "ปิดเคส", "close", "done",
            "ผู้ดูแล", "already", "fixed", "monitor", "เฝ้าระวัง"
        ]
        
        for w in noise_keywords:
            if w in text_clean:
                return False
                
        return True
    
    # Apply Filter
    df_res.dropna(subset=['ReplyMessage'], inplace=True)
    df_res = df_res[df_res['ReplyMessage'].apply(is_useful)]

    merged = pd.merge(
        df_inc[['IncidentsId', 'IncidentSubject', 'IncidentMessage']],
        df_res[['Incident_id', 'ReplyMessage']],
        left_on='IncidentsId',
        right_on='Incident_id',
        how='inner'
    )

    grouped = merged.groupby('IncidentsId').agg({
        'IncidentSubject': 'first',
        'IncidentMessage': 'first',
        # 'ReplyMessage': lambda x: ' | '.join(list(set([str(i) for i in x])))
        'ReplyMessage': 'last'
    }).reset_index()

    print(f"✅ Data Ready: {len(grouped)} valid cases loaded.")
    return grouped

# --- 3. ฟังก์ชัน Normalization (No Whitelist / Use Stopwords) ---
# def normalize_and_tokenize(text):
#     text = str(text).lower()

#     # URL Cleaner: แปลงชื่อเว็บยาวๆ ให้เป็นคำว่า "url" เพื่อให้ Match กับ AI เพิ่มส่วนนี้มาวันที่ 15/2/2026
#     text = re.sub(r'[a-zA-Z0-9.-]+\.[a-z]{2,}(/[a-zA-Z0-9./?=&_%+-]*)?', ' url ', text)
#     text = re.sub(r'/[a-zA-Z0-9./?=&_%+-]+', ' url ', text)
    
#     # 1. Synonym Mapping (แปลงทุกอย่างเป็นมาตรฐาน)
#     text = re.sub(r'(block|ban|deny|firewall|drop|reject|บล็อก|ปิดกั้น|ระงับ|หยุด|blacklist|black list|สกัดกั้น)', ' block ', text)
#     text = re.sub(r'(isolate|disconnect|quarantine|shutdown|disable|ตัดการเชื่อมต่อ|แยกเครื่อง|ถอดสาย|จำกัดการเข้าถึง|ปิดระบบ|กักกัน|ตัดเน็ต)', ' isolate ', text)
#     text = re.sub(r'(notify|alert|email|contact|inform|report|call|message|mail|แจ้ง|ประสาน|ติดต่อ|ส่งอีเมล|โทร|รับเรื่อง|ตอบกลับ|เตือน|เรียน)', ' notify ', text)
#     text = re.sub(r'(check|examine|investigate|verify|analyze|assess|scan|monitor|ตรวจสอบ|วิเคราะห์|หา|ดู|สแกน|เฝ้าระวัง|เก็บหลักฐาน|สืบหา)', ' check ', text)
#     text = re.sub(r'(reset|change|update|restore|force change|เปลี่ยน|รีเซ็ต|ตั้งใหม่|แก้ไข)', ' reset ', text)
    
#     # 2. Object Mapping
#     text = re.sub(r'(source|src|attacker|origin|malicious ip|threat actor|ต้นทาง|ผู้ส่ง|แหล่งที่มา|ตัวการ|ที่มา|แหล่งโจมตี|แหล่งโจมตี|แหล่งสแกน|แหล่ง)', ' source ', text)
#     text = re.sub(r'(destination|dest|dst|victim|target|internal|local|client|host|endpoint|node|ปลายทาง|เป้าหมาย|เหยื่อ|เครื่อง|ลูกข่าย|ผู้ใช้|ผู้ใช้งาน)', ' destination ', text)
#     text = re.sub(r'(ip address|ip|ipv4|ไอพี)', ' ip ', text)
#     text = re.sub(r'(password|credential|account|user|username|login|auth|รหัสผ่าน|พาสเวิร์ด|บัญชี|ชื่อผู้ใช้)', ' account ', text)
#     text = re.sub(r'(malware|virus|trojan|webshell|script|file|มัลแวร์|ไวรัส|ไฟล์อันตราย)', ' malware ', text)
#     text = re.sub(r'(server|vm|เซิร์ฟเวอร์)', ' server ', text)
#     text = re.sub(r'(url|domain|website|web|site|link|เว็บ|ลิงก์|โดเมน)', ' url ', text)

#     # 4. ลบตัวเลขและอักขระพิเศษ
#     text = re.sub(r'[^a-z0-9]', ' ', text)

#     # 3. Auto-Fix Phrases
#     text = re.sub(r'\bip\s+source\b', ' source ip ', text)          
#     text = re.sub(r'\bip\s+destination\b', ' destination ip ', text) 
#     text = re.sub(r'\baccount\s+reset\b', ' reset account ', text)

#     tokens = text.split()
    
#     # 🔥 5. Stopwords Filter (ใช้แทน Whitelist)
#     # เราจะเก็บทุกคำ ยกเว้นคำพวกนี้
    
#     # 5.1 คำเชื่อมภาษาอังกฤษมาตรฐาน
#     eng_stops = set(stopwords.words('english'))
    
#     # 5.2 คำขยะภาษาไทย + คำฟุ่มเฟือยในงาน SOC
#     thai_stops = {
#         "การ", "ความ", "ระบบ", "ข้อมูล", "รายละเอียด", "ขั้นตอน", "วิธีการ", "ข้อ", "เสนอแนะ", 
#         "สิ่งที่", "ควร", "ดำเนินการ", "ใน", "ทันที", "หมายเลข", "จำนวน", "มาก", "น้อย", "ระบุ", "พบ", 
#         "ว่าเป็น", "เกี่ยวข้อง", "เข้าข่าย", "ทราบ", "อยาก", "ต้องการ", "ช่วย", "แนะนำ",
#         "ครับ", "ค่ะ", "นะ", "นั้น", "นี้", "ที่", "ซึ่ง", "อัน", "ของ", "สำหรับ", "โดย", "และ", "หรือ", "แต่",
#         "จากนั้นให้", "ให้", "เพื่อ", "ไป", "ยัง", "เป็น", "ทำการ", "ต้อง", "สั่ง", "และทำการ", "และสั่ง",
#         "โดยทันที", "ออกจากระบบโดยทันที", "ปลายทางที่", "ที่เป็นอันตรายที่", "ตรวจสอบเพิ่มเติม", "มองว่าเป็น",
#         "จำนวนมาก", "จาก", "ไปยัง", "พยายาม", "โจมตี", "ผู้ดูแล", "ทีมงาน", "เบื้องต้น", "กล่าว", "ดัง", "แล้ว",
#         "step", "1", "2", "3", "4", "5", "etc", "use", "using", "used", "via", "through"
#     }
    
#     all_stops = eng_stops.union(thai_stops)
    
#     clean_tokens = [t for t in tokens if t not in all_stops and len(t) > 1]

#     # 6. Unique Filter
#     unique_tokens = []
#     if clean_tokens:
#         unique_tokens.append(clean_tokens[0])
#         for i in range(1, len(clean_tokens)):
#             if clean_tokens[i] != clean_tokens[i-1]:
#                 unique_tokens.append(clean_tokens[i])
    
#     return unique_tokens

# --- 3. ฟังก์ชัน Normalization (No Whitelist / Use Stopwords) ---
def normalize_and_tokenize(text):
    text = str(text).lower()

    # 🔥 0. ดักจับ Email และ IP Address ให้เป็นคำมาตรฐานก่อน (ป้องกันการถูกหั่น)
    text = re.sub(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', ' account ', text)
    text = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', ' ip ', text)

    # URL Cleaner: แปลงชื่อเว็บยาวๆ ให้เป็นคำว่า "url" 
    text = re.sub(r'\b(?:https?://|www\.)?[a-zA-Z0-9.-]+\.[a-z]{2,}(?:/[a-zA-Z0-9./?=&_%+-]*)?\b', ' url ', text)
    text = re.sub(r'/[a-zA-Z0-9./?=&_%+-]+', ' url ', text)
    
    # 1. Synonym Mapping (แปลงทุกอย่างเป็นมาตรฐาน - ใส่ \b ครอบคำอังกฤษ)
    text = re.sub(r'\b(block|ban|deny|firewall|drop|reject|blacklist|black list)\b|(บล็อก|ปิดกั้น|ระงับ|หยุด|สกัดกั้น|บล๊อก)', ' block ', text)
    text = re.sub(r'\b(isolate|disconnect|quarantine|shutdown|disable)\b|(ตัดการเชื่อมต่อ|แยกเครื่อง|ถอดสาย|จำกัดการเข้าถึง|ปิดระบบ|กักกัน|ตัดเน็ต|แยก)', ' isolate ', text)
    text = re.sub(r'\b(notify|alert|email|contact|inform|report|call|message|mail)\b|(แจ้ง|ประสาน|ติดต่อ|ส่งอีเมล|โทร|รับเรื่อง|ตอบกลับ|เตือน|เรียน)', ' notify ', text)
    text = re.sub(r'\b(check|examine|investigate|verify|analyze|assess|scan|monitor)\b|(ตรวจสอบ|วิเคราะห์|หา|ดู|สแกน|เฝ้าระวัง|เก็บหลักฐาน|สืบหา)', ' check ', text)
    text = re.sub(r'\b(reset|change|update|restore|force change)\b|(เปลี่ยน|รีเซ็ต|ตั้งใหม่|แก้ไข)', ' reset ', text)
    
    # 2. Object Mapping (ใส่ \b ครอบคำอังกฤษ และรวมคำไทยของคุณไว้ทั้งหมด)
    text = re.sub(r'\b(source|src|attacker|origin|malicious ip|threat actor)\b|(ต้นทาง|ผู้ส่ง|แหล่งที่มา|ตัวการ|ที่มา|แหล่งโจมตี|แหล่งสแกน|แหล่ง|เครื่องโจมตี|ผู้โจมตี)', ' source ', text)
    text = re.sub(r'\b(destination|dest|dst|victim|target|internal|local|client|host|endpoint|node)\b|(ปลายทาง|เป้าหมาย)', ' destination ', text)
    text = re.sub(r'\b(ip address|ip|ipv4)\b|(ไอพี)', ' ip ', text)
    text = re.sub(r'\b(account|user|username|login|password|credential|auth)\b|(บัญชี|ชื่อผู้ใช้|รหัสผ่าน|พาสเวิร์ด)', ' account ', text)
    text = re.sub(r'\b(malware|virus|trojan|webshell|script|file)\b|(มัลแวร์|ไวรัส|ไฟล์อันตราย)', ' malware ', text)
    text = re.sub(r'\b(server|vm)\b|(เซิร์ฟเวอร์)', ' server ', text)
    text = re.sub(r'\b(url|domain|website|web|site|link)\b|(เว็บ|ลิงก์|โดเมน)', ' url ', text)

    # 4. ลบตัวเลขและอักขระพิเศษ (ทำตรงนี้เพื่อให้เหลือแต่ตัวอักษร)
    text = re.sub(r'[^a-z0-9]', ' ', text)

    # 3. Auto-Fix Phrases
    text = re.sub(r'\bip\s+source\b', ' source ip ', text)          
    text = re.sub(r'\bip\s+destination\b', ' destination ip ', text) 
    text = re.sub(r'\baccount\s+reset\b', ' reset account ', text)

    tokens = text.split()
    
    # 🔥 5. Stopwords Filter (ใช้แทน Whitelist)
    # เราจะเก็บทุกคำ ยกเว้นคำพวกนี้
    
    # 5.1 คำเชื่อมภาษาอังกฤษมาตรฐาน
    eng_stops = set(stopwords.words('english'))
    
    # 5.2 คำขยะภาษาไทย + คำฟุ่มเฟือยในงาน SOC
    thai_stops = {
        "การ", "ความ", "ระบบ", "ข้อมูล", "รายละเอียด", "ขั้นตอน", "วิธีการ", "ข้อ", "เสนอแนะ", 
        "สิ่งที่", "ควร", "ดำเนินการ", "ใน", "ทันที", "หมายเลข", "จำนวน", "มาก", "น้อย", "ระบุ", "พบ", 
        "ว่าเป็น", "เกี่ยวข้อง", "เข้าข่าย", "ทราบ", "อยาก", "ต้องการ", "ช่วย", "แนะนำ",
        "ครับ", "ค่ะ", "นะ", "นั้น", "นี้", "ที่", "ซึ่ง", "อัน", "ของ", "สำหรับ", "โดย", "และ", "หรือ", "แต่",
        "จากนั้นให้", "ให้", "เพื่อ", "ไป", "ยัง", "เป็น", "ทำการ", "ต้อง", "สั่ง", "และทำการ", "และสั่ง",
        "โดยทันที", "ออกจากระบบโดยทันที", "ปลายทางที่", "ที่เป็นอันตรายที่", "ตรวจสอบเพิ่มเติม", "มองว่าเป็น",
        "จำนวนมาก", "จาก", "ไปยัง", "พยายาม", "โจมตี", "ผู้ดูแล", "ทีมงาน", "เบื้องต้น", "กล่าว", "ดัง", "แล้ว",
        "step", "1", "2", "3", "4", "5", "etc", "use", "using", "used", "via", "through"
    }
    
    all_stops = eng_stops.union(thai_stops)
    
    clean_tokens = [t for t in tokens if t not in all_stops and len(t) > 1]

    # 6. Unique Filter
    unique_tokens = []
    if clean_tokens:
        unique_tokens.append(clean_tokens[0])
        for i in range(1, len(clean_tokens)):
            if clean_tokens[i] != clean_tokens[i-1]:
                unique_tokens.append(clean_tokens[i])
    
    return unique_tokens

# --- 4. ฟังก์ชันคำนวณคะแนน ---
def get_ngrams(tokens, n):
    if len(tokens) < n: return []
    return [" ".join(tokens[i:i+n]) for i in range(len(tokens)-n+1)]

def calculate_recall_n(cand_toks, ref_toks, n):
    cand_grams = get_ngrams(cand_toks, n)
    ref_grams = get_ngrams(ref_toks, n)
    if not ref_grams: return 0.0
    cand_cnt = Counter(cand_grams)
    ref_cnt = Counter(ref_grams)
    overlap = 0
    for g in ref_cnt:
        overlap += min(ref_cnt[g], cand_cnt[g])
    return overlap / len(ref_grams)

# --- 5. Main Execution ---
def run_evaluation():
    df = load_and_merge_data()
    if df.empty: return

    test_df = df.sample(n=min(SAMPLE_SIZE, len(df)))
    
    # test_df = df

    print(f"\n🚀 Starting Evaluation (Full Context Mode - No Whitelist)...")
    print("(Metric: Weighted Average -> R1=0.4, R2=0.3, R3=0.3)\n")
    
    total_score = 0
    pass_count = 0  # <--- 1. เพิ่มตัวนับเคสที่ผ่าน
    threshold = 0.6000 # <--- 2. ตั้งเกณฑ์คะแนนที่ถือว่า "ผ่าน" (60%)

    valid_test_count = 0 # <--- เพิ่มตัวแปรนี้เข้ามาเพื่อนับเคสที่ API ทำงานสำเร็จ

    class_stats = {
        "class_1": {"total": 0, "pass": 0}, # กลุ่มคำเฉลย 1 คำ
        "class_2": {"total": 0, "pass": 0}, # กลุ่มคำเฉลย 2 คำ
        "class_3": {"total": 0, "pass": 0}  # กลุ่มคำเฉลย 3 คำขึ้นไป
    }

    total_cases = len(test_df) # หาจำนวนเคสทั้งหมด
    current_case = 0
    
    for i, row in test_df.iterrows():
        current_case += 1
        
        # 👇 ปริ้นท์บอกว่าตอนนี้รันอยู่เคสที่เท่าไหร่ จากทั้งหมดเท่าไหร่
        print(f"\n{'='*20} CASE {current_case}/{total_cases} (ID: {row['IncidentsId']}) {'='*20}")
        
        subject = str(row['IncidentSubject'])
        message = str(row['IncidentMessage'])
        ref_ans = str(row['ReplyMessage'])
        
        try:
            ai_output = ai_engine_instance.analyze_incident("General", subject, message)
            
            ai_text_parts = []
            steps = []
            
            # 1. พยายามดึง mitigation_plan ออกมา
            mitigation_data = ai_output.get("mitigation_plan")
            
            # 2. เช็คว่าเป็น List หรือ Dict
            if isinstance(mitigation_data, list):
                # กรณีเป็น List: แปลว่าไม่มี Severity/SLA แนบมา (เป็น Format เก่า)
                steps = mitigation_data
                severity = "N/A (AI returned List)"
                sla_time = "N/A (AI returned List)"
            elif isinstance(mitigation_data, dict):
                # กรณีเป็น Dict: แปลว่าน่าจะมี Severity (เป็น Format ใหม่)
                steps = mitigation_data.get("steps", [])
                severity = mitigation_data.get("severity", "N/A")
                sla_time = mitigation_data.get("total_estimated_time", "N/A")
            else:
                # กรณีไม่เจอข้อมูลเลย
                severity = "Error (Invalid Format)"
                sla_time = "Error"

            # 3. ตรวจสอบว่ามี Steps ไหม ถ้าไม่มีอาจจะอยู่ใน root ของ ai_output เลยก็ได้ (กันเหนียว)
            if not steps and "action" in str(ai_output):
                 # บางที AI อาจจะตอบ JSON ผิดโครงสร้างเล็กน้อย
                 pass 

            # ประกอบร่างคำตอบ AI
            for plan in steps:
                ai_text_parts.append(str(plan.get("action", "")))
                ai_text_parts.append(str(plan.get("detail", "")))
            
            ai_text = " ".join(ai_text_parts)
            
            # Tokenize & Deduplicate
            ref_toks = normalize_and_tokenize(ref_ans)
            cand_toks = normalize_and_tokenize(ai_text)
            
            #คำนวนคะแนนแบบ Dynamic Weighting
            try:
                # 1. คำนวณ Recall
                r1 = calculate_recall_n(cand_toks, ref_toks, 1)
                r2 = calculate_recall_n(cand_toks, ref_toks, 2)
                r3 = calculate_recall_n(cand_toks, ref_toks, 3)
                
                # 🔥 2. เช็คความยาวของคำตอบมนุษย์ (Dynamic Weighting)
                ref_len = len(ref_toks)
                
                if ref_len >= 3:
                    # ถ้าคำตอบยาว 3 คำขึ้นไป -> คิดเต็ม (R1=40%, R2=30%, R3=30%)
                    final_score = (r1 * 0.4) + (r2 * 0.3) + (r3 * 0.3)
                elif ref_len == 2:
                    # ถ้าคำตอบยาวแค่ 2 คำ -> คิดแค่ R1 และ R2 (R1=60%, R2=40%)
                    final_score = (r1 * 0.6) + (r2 * 0.4)
                elif ref_len == 1:
                    # ถ้าคำตอบยาวคำเดียว -> คิดแค่ R1 (R1=100%)
                    final_score = r1 * 1.0
                else:
                    final_score = 0.0
                
                # ... ส่วนแสดงผล print ต่างๆ ...
                # case_status = ""
                # if final_score >= threshold:
                #     pass_count += 1
                #     case_status = "✅ PASS"
                # else:
                #     case_status = "❌ FAIL"

                # 1. บันทึกว่าเคสนี้ตกอยู่ Class ไหน แล้วบวกจำนวน total เพิ่ม 1
                current_class = None
                if ref_len >= 3:
                    current_class = "class_3"
                elif ref_len == 2:
                    current_class = "class_2"
                elif ref_len == 1:
                    current_class = "class_1"
                
                if current_class:
                    class_stats[current_class]["total"] += 1

                # 2. เช็คว่าผ่านไหม ถ้าผ่านให้บวก pass ของคลาสนั้นๆ เพิ่ม 1
                if final_score >= threshold:
                    pass_count += 1
                    case_status = "✅ PASS"
                    if current_class:
                        class_stats[current_class]["pass"] += 1
                else:
                    case_status = "❌ FAIL"

            except Exception as e:  # <--- ต้องมีบรรทัดนี้ปิดท้ายเสมอ
                print(f"⚠️ Error during Score Calculation: {e}")
                final_score = 0.0
                case_status = "❌ ERROR"

            # 3. แสดงผล (ปรับการโชว์ผลให้สอดคล้องกัน)
            print(f"\n{'='*20} CASE {row['IncidentsId']} {'='*20}")
            print(f"📝 Subject: {subject[:80]}...")
            if severity != "N/A":
                print(f"🚨 Severity: {severity} | ⏳ SLA: {sla_time}")

            print(f"\n👤 [REF] Human Answer:\n{ref_ans.strip()}")
            print(f"\n🤖 [AI] Generated Answer:\n{ai_text.strip()}")
            
            print(f"\n🔹 Human Tokens: {ref_toks}")
            print(f"🔸 AI Tokens:    {cand_toks}") 
            
            print(f"\n✅ Matched:      {set(ref_toks) & set(cand_toks)}")
            # แสดงทศนิยม 4 ตำแหน่งสำหรับ Final Score และ 2 ตำแหน่งสำหรับ R ต่างๆ
            print(f"📊 Dynamic Weighting Score: {final_score:.4f} (R1={r1:.2f}, R2={r2:.2f}, R3={r3:.2f})")

            total_score += final_score
            valid_test_count += 1
            time.sleep(2)
            
        except Exception as e:
            print(f"⚠️ Error {row['IncidentsId']}: {e}")
            final_score = 0.0
            case_status = "❌ ERROR"
            
            # ถ้ามี Error ควรพักนานขึ้นหน่อยก่อนไปข้อถัดไป
            time.sleep(5)

    # --- 4. สรุปผลภาพรวม (Overall Result) ---
    # num_test = len(test_df)
    # avg_score = total_score / num_test if num_test > 0 else 0
    # success_rate = (pass_count / num_test) * 100 if num_test > 0 else 0

    # print("\n" + "="*60)
    # print(f"🏆 EVALUATION SUMMARY")
    # print(f"   - Average Score: {avg_score:.4f}")
    # print(f"   - Success Rate:  {success_rate:.2f}% ({pass_count}/{num_test} cases passed)")
    
# --- 4. สรุปผลภาพรวม (Overall Result) ---
    # num_test = len(test_df)
    # 👇 เปลี่ยนจาก len(test_df) มาใช้ valid_test_count แทน
    num_test = valid_test_count
    avg_score = total_score / num_test if num_test > 0 else 0
    success_rate = (pass_count / num_test) * 100 if num_test > 0 else 0

    # 👇 --- [เพิ่มจุดที่ 3] คำนวณเปอร์เซ็นต์แยกคลาส ---
    def calc_acc(c_pass, c_total):
        return (c_pass / c_total) * 100 if c_total > 0 else 0

    acc_class_1 = calc_acc(class_stats["class_1"]["pass"], class_stats["class_1"]["total"])
    acc_class_2 = calc_acc(class_stats["class_2"]["pass"], class_stats["class_2"]["total"])
    acc_class_3 = calc_acc(class_stats["class_3"]["pass"], class_stats["class_3"]["total"])
    # 👆 ------------------------------------------

    print("\n" + "="*60)
    print(f"🏆 EVALUATION SUMMARY")
    print(f"   - Valid Cases:   {num_test} / {len(test_df)} (Skipped {len(test_df) - num_test} errors)")
    print(f"   - Average Score: {avg_score:.4f}")
    print(f"   - Overall Success: {success_rate:.2f}% ({pass_count}/{num_test} cases passed)")
    
    # 👇 --- ปริ้นท์โชว์แยกคลาส ---
    print(f"\n📊 ACCURACY BY CLASS (Reference Length):")
    print(f"   - Class 1 (1 word)   : {acc_class_1:.2f}% ({class_stats['class_1']['pass']}/{class_stats['class_1']['total']})")
    print(f"   - Class 2 (2 words)  : {acc_class_2:.2f}% ({class_stats['class_2']['pass']}/{class_stats['class_2']['total']})")
    print(f"   - Class 3 (3+ words) : {acc_class_3:.2f}% ({class_stats['class_3']['pass']}/{class_stats['class_3']['total']})")
    print("-" * 60)
    
    # สรุปผลว่าผ่านเกณฑ์ 60% ของคุณหรือไม่
    if success_rate >= 60:
        print(f"🌟 OVERALL STATUS: PASSED (Target 60% Met!)")
    else:
        print(f"⚠️ OVERALL STATUS: FAILED (Target 60% Not Met)")
    print("="*60)

if __name__ == "__main__":
    run_evaluation()