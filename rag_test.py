# rag_test.py (updated)
import sys
import config
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
import google.generativeai as genai
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="google.generativeai")

QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION_NAME = "mitre-attack-vectors"

# --------------------
# Retrieval (multi-hit, then re-rank)
# --------------------
def search_and_rerank(query_text, client, model, top_k=20, final_k=6):
    qv = model.encode(query_text, normalize_embeddings=True).tolist()

    try:
        # get more hits initially (we'll re-rank)
        hits = client.search(
            collection_name=COLLECTION_NAME,
            query_vector=qv,
            limit=top_k,
            with_payload=True
        )
    except Exception as e:
        print(f"Qdrant search error: {e}")
        return []

    # apply priority + type boosting
    boosted = []
    for h in hits:
        p = h.payload or {}
        pr = p.get("priority", 4)
        typ = p.get("type", "")
        score = getattr(h, "score", 0.0) or 0.0
        # boost mitigations & techniques a bit
        boost_factor = 1.0
        if typ == "course-of-action":
            boost_factor = 1.4
        elif typ == "attack-pattern":
            boost_factor = 1.2
        elif typ == "x-mitre-data-source":
            boost_factor = 1.05
        # combine: lower priority (1) => higher rank, so invert
        combined = score * boost_factor + (1.0 / (pr + 0.1)) * 0.15
        boosted.append((combined, h))

    # sort by combined score desc
    boosted_sorted = sorted(boosted, key=lambda x: x[0], reverse=True)
    # take top final_k hits
    top_hits = [item[1] for item in boosted_sorted[:final_k]]
    return top_hits

# --------------------
# Build context: group by priority and show Result numbers
# --------------------
def build_context_from_hits(hits):
    # group hits by priority (lower number = higher priority)
    hits_sorted = sorted(hits, key=lambda h: h.payload.get("priority", 4))
    context_lines = []
    for i, hit in enumerate(hits_sorted, start=1):
        p = hit.payload or {}
        mitre_id = p.get("mitre_id", "N/A")
        name = p.get("name", "N/A")
        typ = p.get("type", "N/A")
        desc = (p.get("description") or p.get("text_content") or "").strip().replace("\n", " ")
        if len(desc) > 800:
            desc = desc[:800] + "..."
        context_lines.append(f"Result {i}:\n  type: {typ}\n  mitre_id: {mitre_id}\n  name: {name}\n  description: {desc}\n")
    return "\n".join(context_lines)

# --------------------
# Gemini call (Thai mitigation-focused)
# --------------------
def generate_answer_with_gemini(query_text, context_text):
    prompt = f"""
คุณเป็นผู้เชี่ยวชาญด้าน Cybersecurity ที่เชี่ยวชาญ MITRE ATT&CK และการ Mitigation

จงตอบเป็นภาษาไทยทั้งหมด และใช้ข้อมูลจาก CONTEXT ด้านล่างเท่านั้น (ห้ามเติมความรู้ภายนอก)
เป้าหมาย: ให้คำแนะนำด้าน Mitigation (การยับยั้งเหตุการณ์) แบบขั้นตอนสั้น ๆ
แต่ละขั้นต้องมี:
- Action: สิ่งที่ต้องทำ (1-2 บรรทัด)
- Reason: เหตุผลสั้น ๆ อ้างอิง "Result X" จาก CONTEXT

รูปแบบ:
- 3–6 ขั้นตอน
- กระชับ ตรงประเด็น
- ห้ามเกิน 300 คำ
- หาก CONTEXT ไม่มี mitigation ที่ชัดเจน ให้ระบุ "ไม่มีข้อมูล mitigation ใน context"

CONTEXT:
{context_text}

คำถามจากผู้ใช้:
\"{query_text}\"

คำตอบ:
"""
    try:
        genai.configure(api_key=config.GEMINI_API_KEY)
        model = genai.GenerativeModel("models/gemini-2.5-flash")
        response = model.generate_content(prompt)
        # SDK may present text in .text
        if hasattr(response, "text") and response.text:
            return response.text
        if hasattr(response, "output_text"):
            return response.output_text
        return str(response)
    except Exception as e:
        raise RuntimeError(f"Gemini API error: {e}")

# --------------------
# Local fallback (Thai mitigation steps) if Gemini fails
# --------------------
def local_fallback_answer(query_text, hits):
    # produce 4 concise mitigation steps referencing results
    lines = []
    lines.append("Mitigation (fallback):")
    # Try to include mitigation-first (course-of-action) if present
    coas = [h for h in hits if h.payload.get("type") == "course-of-action"]
    if coas:
        for i, c in enumerate(coas[:2], start=1):
            p = c.payload
            lines.append(f"{i}. Action: พิจารณาใช้มาตรการจาก {p.get('name','(Unnamed mitigation)')}.")
            lines.append(f"   Reason: อ้างอิงจาก Result (mitigation) {p.get('mitre_id','')}")
    # generic recommendations
    lines.append("3. Action: แยกโฮสต์ที่ถูกระบุออกจากเครือข่ายทันที (isolate).")
    lines.append("   Reason: ลดการสื่อสาร C2 และการแพร่กระจาย (อ้างอิง Result 1/Result 2).")
    lines.append("4. Action: บล็อก IP ปลายทางที่เป็นอันตรายที่ตรวจพบที่ไฟร์วอลล์.")
    lines.append("   Reason: ยับยั้งการสื่อสาร C2 ตามข้อมูลใน context.")
    return "\n".join(lines)

# --------------------
# Main
# --------------------
def main():
    if len(sys.argv) < 2:
        print('Usage: python rag_test.py "your alert description or query"')
        return

    query_text = " ".join(sys.argv[1:])
    print(f"--- ❓ Query: \"{query_text}\" ---")

    print("Loading embedding model...")
    embedding_model = SentenceTransformer(config.MODEL_NAME)

    qdrant_client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

    print("--- 🔍 Retrieving from Qdrant ---")
    hits = search_and_rerank(query_text, qdrant_client, embedding_model, top_k=20, final_k=6)

    if not hits:
        print("No hits from Qdrant. Exiting.")
        return

    context_text = build_context_from_hits(hits)
    print("\nContext extracted from Qdrant:")
    print(context_text)

    try:
        print("\n--- 🤖 Calling Gemini API ---")
        rag_answer = generate_answer_with_gemini(query_text, context_text)
    except Exception as e:
        print(f"Gemini failed: {e}")
        print("Using local fallback generation.")
        rag_answer = local_fallback_answer(query_text, hits)

    print("\n--- 💡 RAG Answer ---")
    print(rag_answer)


if __name__ == "__main__":
    main()
