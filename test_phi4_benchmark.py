#!/usr/bin/env python3
"""Benchmark phi-4 via Ollama — taux d'échec doit être < 20%.

Échec = erreur HTTP/timeout OU réponse < 5 caractères OU latence > 30s.
"""
import json
import time
import urllib.request

MODEL = "hf.co/mradermacher/Phi-4-Mini-Abliterated-GGUF:Q4_K_M"
URL = "http://127.0.0.1:11434/api/generate"

TESTS = [
    "What is the capital of France?",
    "Calculate 15% of 200.",
    "If A > B and B > C, is A > C?",
    "Write a Python function to reverse a string.",
    "What is a SQL injection attack?",
    "Explain what a firewall does.",
    "Who wrote '1984'?",
    "Solve: x + 5 = 12",
    "What year did WWII end?",
    "Explain everything about everything.",
]


def test(prompt):
    payload = json.dumps({
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 150},
    }).encode()
    req = urllib.request.Request(
        URL, data=payload, headers={"Content-Type": "application/json"}
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read().decode())
            return {
                "ok": True,
                "resp": d.get("response", "").strip(),
                "time": time.time() - start,
            }
    except Exception as e:
        return {"ok": False, "error": str(e), "time": time.time() - start}


def main():
    results = []
    for t in TESTS:
        r = test(t)
        failed = (
            not r["ok"]
            or len(r.get("resp", "")) < 5
            or r["time"] > 30
        )
        results.append({"fail": failed, "time": r["time"]})
        status = "FAIL" if failed else "OK  "
        excerpt = (r.get("resp") or r.get("error", ""))[:60].replace("\n", " ")
        print(f"[{status}] {r['time']:5.1f}s | {t[:45]:45s} | {excerpt}")

    fails = sum(1 for r in results if r["fail"])
    rate = fails / len(results) * 100
    print(f"\nTaux d'échec: {rate:.1f}% ({fails}/{len(results)})")
    print(f"{'PASS' if rate < 20 else 'FAIL'} — Seuil < 20%")
    return 0 if rate < 20 else 1


if __name__ == "__main__":
    raise SystemExit(main())
