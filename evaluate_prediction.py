#!/usr/bin/env python3
"""
evaluate_prediction.py
======================
Evaluates the precision of the `generate_suggestion` threat-prediction function
by running 3 back-tests:

  2022 logs  →  LLM prediction  →  compare with real 2023 data
  2023 logs  →  LLM prediction  →  compare with real 2024 data
  2024 logs  →  LLM prediction  →  compare with real 2025 data

Metrics (multi-label, set-based):
  Precision  = |predicted ∩ real| / |predicted|
  Recall     = |predicted ∩ real| / |real|
  F1 Score   = 2 * P * R / (P + R)

Usage:
  cd /path/to/rag_itsc
  source venv/bin/activate
  python evaluate_prediction.py
"""

import os
import sys
import re
from dotenv import load_dotenv
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt
import numpy as np

# ---------------------------------------------------------------------------
# Load .env so AIEngine can find API keys
# ---------------------------------------------------------------------------
load_dotenv()

# ---------------------------------------------------------------------------
# Category definitions
# All known CategoryEN values + Thai/English keyword patterns for LLM parsing
# ---------------------------------------------------------------------------
CATEGORIES = [
    {
        "name": "Unauthorized Access",
        "keywords_en": ["unauthorized access", "unauthorized", "brute force", "credential", "login attempt"],
        "keywords_th": ["การเข้าถึงโดยไม่ได้รับอนุญาต", "บุกรุก", "แฮก", "เข้าถึงระบบ", "ล็อกอิน", "รหัสผ่าน", "brute force"],
    },
    {
        "name": "Web Application Threat",
        "keywords_en": ["web application", "sql injection", "xss", "web attack", "web threat", "injection"],
        "keywords_th": ["เว็บแอปพลิเคชัน", "เว็บไซต์", "sql injection", "xss", "ช่องโหว่เว็บ", "โจมตีเว็บ"],
    },
    {
        "name": "Malware",
        "keywords_en": ["malware", "ransomware", "trojan", "virus", "worm", "backdoor"],
        "keywords_th": ["มัลแวร์", "ransomware", "แรนซัมแวร์", "ไวรัส", "โทรจัน", "เวิร์ม", "backdoor"],
    },
    {
        "name": "Network Scanning",
        "keywords_en": ["network scan", "port scan", "reconnaissance", "scanning"],
        "keywords_th": ["สแกนเครือข่าย", "สแกน", "reconnaissance", "สำรวจ", "ตรวจสอบพอร์ต"],
    },
    {
        "name": "Vulnerability",
        "keywords_en": ["vulnerability", "cve", "patch", "exploit", "zero-day", "zero day"],
        "keywords_th": ["ช่องโหว่", "cve", "แพตช์", "exploit", "zero-day", "เจาะระบบ"],
    },
    {
        "name": "Flood",
        "keywords_en": ["flood", "traffic flood", "bandwidth"],
        "keywords_th": ["ฟลัด", "flood", "ปริมาณการใช้งานสูง", "bandwidth"],
    },
    {
        "name": "Denial of Service",
        "keywords_en": ["denial of service", "dos", "ddos", "distributed denial"],
        "keywords_th": ["โจมตีแบบ dos", "ddos", "ปฏิเสธการให้บริการ", "dos attack"],
    },
    {
        "name": "Spyware",
        "keywords_en": ["spyware", "adware", "keylogger", "stalkerware"],
        "keywords_th": ["สปายแวร์", "spyware", "keylogger"],
    },
    {
        "name": "Email Alert",
        "keywords_en": ["phishing", "email", "spam", "social engineering"],
        "keywords_th": ["ฟิชชิ่ง", "phishing", "อีเมล", "อีเมลหลอกลวง", "spam"],
    },
    {
        "name": "Website Defacement",
        "keywords_en": ["defacement", "website defacement", "web defacement"],
        "keywords_th": ["เว็บไซต์ถูกแฮก", "defacement", "เปลี่ยนหน้าเว็บ", "ก่อกวนเว็บไซต์"],
    },
    {
        "name": "Malicious Redirects",
        "keywords_en": ["redirect", "malicious redirect", "drive-by"],
        "keywords_th": ["redirect", "เปลี่ยนเส้นทาง", "ลิงก์อันตราย"],
    },
    {
        "name": "Insecure Design",
        "keywords_en": ["insecure design", "misconfiguration", "misconfigured"],
        "keywords_th": ["การออกแบบที่ไม่ปลอดภัย", "misconfiguration", "ตั้งค่าผิดพลาด"],
    },
    {
        "name": "Admin Information Sharing",
        "keywords_en": ["information sharing", "advisory", "bulletin"],
        "keywords_th": ["แจ้งเตือน", "ข่าวสาร", "ประกาศ", "advisory"],
    },
]

CATEGORY_NAMES = [c["name"] for c in CATEGORIES]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_excel(path: str) -> pd.DataFrame:
    df = pd.read_excel(path)
    df["CreateDate"] = pd.to_datetime(df["CreateDate"])
    return df


def filter_by_year(df: pd.DataFrame, year: int) -> pd.DataFrame:
    return df[df["CreateDate"].dt.year == year].copy()


def format_log_text(df: pd.DataFrame) -> str:
    """
    Format logs for the LLM — mirrors the /generate-suggestion/ endpoint exactly:
      - Sort by CreateDate DESCENDING (most recent first)
      - Take the latest 100 records
      - Same field order and format string as the endpoint
    """
    # Sort descending, take top 100  (matches: sort=[{"CreateDate":"desc"}], size=100)
    df_sample = df.sort_values("CreateDate", ascending=False).head(100)

    lines = []
    for _, row in df_sample.iterrows():
        msg = str(row.get("IncidentMessage", ""))[:300]
        lines.append(
            f"[{row['CreateDate'].isoformat()}] "          # endpoint uses raw ISO string from ES
            f"Priority={row.get('PiorityEN', 'N/A')} | "
            f"Category={row.get('CategoryEN', 'N/A')} | "
            f"Subject={row.get('IncidentSubject', '')} | "
            f"Message={msg}"
        )
    return "\n".join(lines)


def extract_section2(llm_text: str) -> str:
    """Pull out the '2. ...' paragraph from the LLM's 3-paragraph output."""
    # Try to isolate paragraph starting with "2."
    match = re.search(r"2\.\s*(.*?)(?=3\.|$)", llm_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return llm_text  # fallback: use full text


def predict_categories(llm_text: str) -> set:
    """
    Given the full LLM output, extract section 2 and match keywords
    against known categories. Returns a set of matched CategoryEN names.
    """
    section = extract_section2(llm_text).lower()
    matched = set()
    for cat in CATEGORIES:
        for kw in cat["keywords_en"] + cat["keywords_th"]:
            if kw.lower() in section:
                matched.add(cat["name"])
                break
    return matched


def real_categories(df_year: pd.DataFrame, min_count: int = 1, min_pct: float = 0.0) -> set:
    """
    Return the set of CategoryEN values that appeared in the data for this year.
    Filters by min_count occurrences and optionally by min share percentage.
    """
    counts = df_year["CategoryEN"].value_counts()
    total = len(df_year)
    result = set()
    for cat, cnt in counts.items():
        if cnt >= min_count and (cnt / total * 100) >= min_pct:
            result.add(cat)
    return result


def compute_metrics(predicted: set, real: set):
    """Compute Precision, Recall, F1 for set-based multi-label evaluation."""
    tp = len(predicted & real)
    precision = tp / len(predicted) if predicted else 0.0
    recall    = tp / len(real)     if real      else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    return precision, recall, f1


def print_separator(char="=", width=70):
    print(char * width)


def print_year_result(
    train_year: int,
    test_year: int,
    llm_output: str,
    predicted: set,
    actual_all: set,
    actual_sig: set,
    precision_all: float, recall_all: float, f1_all: float,
    precision_sig: float, recall_sig: float, f1_sig: float,
    df_test: pd.DataFrame,
):
    print_separator()
    print(f"  EVALUATION: {train_year} → predict → {test_year}")
    print_separator()

    print(f"\n📋 LLM Prediction (Section 2 extract):")
    print("-" * 70)
    section2 = extract_section2(llm_output)
    for line in section2.split("  "):
        print(f"  {line.strip()}")

    print(f"\n🔮 Predicted threat categories ({len(predicted)}):")
    for c in sorted(predicted):
        marker = "✅" if c in actual_all else "❌"
        sig_tag = " [significant]" if c in actual_sig else ""
        print(f"  {marker} {c}{sig_tag}")
    if not predicted:
        print("  (none matched — prediction may be too vague)")

    print(f"\n📊 Real {test_year} threat distribution  (🎯 = LLM predicted it):")
    counts = df_test["CategoryEN"].value_counts()
    total  = len(df_test)
    for cat, cnt in counts.items():
        pct = cnt / total * 100
        sig_flag = " ★" if pct >= 5.0 else "  "
        marker   = "🎯" if cat in predicted else "  "
        print(f"  {marker}{sig_flag} {cat:<35} {cnt:>4}  ({pct:5.1f}%)")
    print(f"  (★ = significant threat ≥5% share, used for Sig-Only metrics)")

    tp_all = predicted & actual_all
    fp_all = predicted - actual_all
    fn_all = actual_all - predicted
    tp_sig = predicted & actual_sig
    fn_sig = actual_sig - predicted

    print(f"\n📈 Evaluation Metrics — [Full] all categories | [Sig-Only] ≥5% share:")
    print(f"  {'Metric':<15}   {'[Full]':>10}   {'[Sig-Only]':>12}")
    print(f"  {'-'*45}")
    print(f"  {'Precision':<15}   {precision_all:>10.4f}   {precision_sig:>12.4f}")
    print(f"  {'Recall':<15}   {recall_all:>10.4f}   {recall_sig:>12.4f}")
    print(f"  {'F1 Score':<15}   {f1_all:>10.4f}   {f1_sig:>12.4f}")
    print(f"  {'-'*45}")
    print(f"  [Full]     evaluated against all {len(actual_all)} categories in {test_year}")
    print(f"  [Sig-Only] evaluated against {len(actual_sig)} significant categories (≥5% share)")

    if fp_all:
        print(f"\n  ⚠️  False Positives (predicted but didn't happen): {sorted(fp_all)}")
    if fn_sig:
        print(f"  ⚠️  Significant threats missed: {sorted(fn_sig)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # --- Paths ---
    script_dir = os.path.dirname(os.path.abspath(__file__))
    excel_path = os.path.join(script_dir, "CSD-CMU_Incident_081225.xlsx")

    if not os.path.exists(excel_path):
        print(f"❌ Excel file not found: {excel_path}")
        sys.exit(1)

    # --- Load AI Engine ---
    print("🔌 Loading AI Engine...")
    try:
        from app.services.ai_engine import AIEngine
        engine = AIEngine()
        engine.init_models()
    except Exception as e:
        print(f"❌ Failed to initialise AI Engine: {e}")
        sys.exit(1)

    # --- Load data ---
    print(f"📂 Loading data from {os.path.basename(excel_path)}...")
    df = load_excel(excel_path)

    year_pairs = [(2022, 2023), (2023, 2024), (2024, 2025)]

    all_results = []

    for train_year, test_year in year_pairs:
        df_train = filter_by_year(df, train_year)
        df_test  = filter_by_year(df, test_year)

        if df_train.empty:
            print(f"⚠️  No data for {train_year}, skipping.")
            continue
        if df_test.empty:
            print(f"⚠️  No data for {test_year} (ground truth), skipping.")
            continue

        print(f"\n🚀 Running: {train_year} → {test_year}  "
              f"(train pool={len(df_train)}, logs sent to LLM={min(len(df_train), 100)}, "
              f"test={len(df_test)} records)")

        log_text = format_log_text(df_train)

        print(f"   Calling LLM...")
        try:
            llm_output = engine.generate_suggestion(log_text)
        except Exception as e:
            print(f"   ❌ LLM call failed: {e}")
            continue

        predicted   = predict_categories(llm_output)
        actual_all  = real_categories(df_test, min_count=1, min_pct=0.0)
        actual_sig  = real_categories(df_test, min_count=1, min_pct=5.0)

        precision_all, recall_all, f1_all = compute_metrics(predicted, actual_all)
        precision_sig, recall_sig, f1_sig = compute_metrics(predicted, actual_sig)

        all_results.append({
            "pair":          f"{train_year}→{test_year}",
            "precision_all": precision_all,
            "recall_all":    recall_all,
            "f1_all":        f1_all,
            "precision_sig": precision_sig,
            "recall_sig":    recall_sig,
            "f1_sig":        f1_sig,
        })

        print_year_result(
            train_year, test_year,
            llm_output, predicted,
            actual_all, actual_sig,
            precision_all, recall_all, f1_all,
            precision_sig, recall_sig, f1_sig,
            df_test,
        )

    # --- Summary table ---
    print("\n")
    print_separator("=")
    print("  OVERALL SUMMARY")
    print_separator("=")
    hdr = f"  {'Pair':<15} {'P[Full]':>9} {'R[Full]':>9} {'F1[Full]':>9}  {'P[Sig]':>8} {'R[Sig]':>8} {'F1[Sig]':>8}"
    print(hdr)
    print("-" * len(hdr))
    for r in all_results:
        print(
            f"  {r['pair']:<15}"
            f" {r['precision_all']:>9.4f} {r['recall_all']:>9.4f} {r['f1_all']:>9.4f}"
            f"  {r['precision_sig']:>8.4f} {r['recall_sig']:>8.4f} {r['f1_sig']:>8.4f}"
        )

    if all_results:
        def avg(key): return sum(r[key] for r in all_results) / len(all_results)
        print("-" * len(hdr))
        print(
            f"  {'Average':<15}"
            f" {avg('precision_all'):>9.4f} {avg('recall_all'):>9.4f} {avg('f1_all'):>9.4f}"
            f"  {avg('precision_sig'):>8.4f} {avg('recall_sig'):>8.4f} {avg('f1_sig'):>8.4f}"
        )

    print_separator("=")
    print()
    print("📌 Metric Interpretation:")
    print("  Precision  — of threats LLM predicted, how many actually occurred? (higher = fewer false alarms)")
    print("  Recall     — of threats that occurred, how many did LLM predict?  (higher = fewer misses)")
    print("  F1 Score   — harmonic mean of Precision & Recall (1.0 = perfect, 0.0 = no match)")
    print("  [Full]     — evaluated against ALL categories in target year (stricter)")
    print("  [Sig-Only] — evaluated against only major threats (≥5% of cases) (fairer for short LLM output)")
    # --- Generate chart (Sig-Only) ---
    if all_results:
        chart_path = os.path.join(script_dir, "prediction_evaluation.png")
        generate_chart(all_results, chart_path)


def generate_chart(results: list, save_path: str):
    """Generate a grouped bar chart for Sig-Only metrics only."""
    pairs     = [r["pair"] for r in results]
    precision = [r["precision_sig"] for r in results]
    recall    = [r["recall_sig"]    for r in results]
    f1        = [r["f1_sig"]        for r in results]

    x = np.arange(len(pairs))
    bar_width = 0.22

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    bars_p  = ax.bar(x - bar_width, precision, bar_width, label="Precision",  color="#00d2ff", edgecolor="#0a0a1a", linewidth=0.5)
    bars_r  = ax.bar(x,             recall,    bar_width, label="Recall",     color="#7b2ff7", edgecolor="#0a0a1a", linewidth=0.5)
    bars_f1 = ax.bar(x + bar_width, f1,        bar_width, label="F1 Score",   color="#ff6b6b", edgecolor="#0a0a1a", linewidth=0.5)

    # Value labels on each bar
    for bars in [bars_p, bars_r, bars_f1]:
        for bar in bars:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + 0.02,
                        f"{h:.2f}", ha="center", va="bottom",
                        fontsize=10, fontweight="bold", color="white")

    ax.set_xlabel("Year Pair", fontsize=12, color="white", labelpad=10)
    ax.set_ylabel("Score", fontsize=12, color="white", labelpad=10)
    ax.set_title("Threat Prediction Evaluation — Significant Categories (≥5%)",
                 fontsize=14, fontweight="bold", color="white", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(pairs, fontsize=11, color="white")
    ax.set_ylim(0, 1.15)
    ax.tick_params(colors="white")
    ax.legend(fontsize=11, loc="upper right",
              facecolor="#16213e", edgecolor="#444", labelcolor="white")

    # Grid
    ax.yaxis.grid(True, color="#333", linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)

    for spine in ax.spines.values():
        spine.set_color("#444")

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, facecolor=fig.get_facecolor())
    plt.close()
    print(f"\n📊 Chart saved to: {save_path}")


if __name__ == "__main__":
    main()
