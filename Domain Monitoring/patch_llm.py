"""
patch_llm.py
Run this from the project root to fix llm.py:
  python patch_llm.py
"""
import re

with open('brand_monitor/llm.py', 'r') as f:
    content = f.read()

old = """    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM did not return valid JSON: {e}\\nRaw: {raw}") from e"""

new = """    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Repair truncated JSON by closing open braces
    try:
        opens  = cleaned.count('{')
        closes = cleaned.count('}')
        if opens > closes:
            repaired = cleaned + ('}' * (opens - closes))
            return json.loads(repaired)
    except json.JSONDecodeError:
        pass
    # Final fallback — safe defaults so scan continues
    return {
        "classification":      "UNKNOWN",
        "confidence":          "LOW",
        "indicators":          ["LLM response could not be parsed"],
        "summary":             "Analysis incomplete — LLM returned malformed response.",
        "recommended_action":  "MONITOR",
        "risk_tier":           "MEDIUM",
        "risk_score":          5,
        "threat_type":         "UNKNOWN",
        "narrative":           "Risk synthesis incomplete due to LLM response error.",
        "recommended_actions": ["Manual review recommended"],
        "urgency":             "MONITOR",
    }"""

if old in content:
    content = content.replace(old, new)
    with open('brand_monitor/llm.py', 'w') as f:
        f.write(content)
    print("SUCCESS — llm.py patched")
else:
    print("NOT FOUND — the function text did not match")
    print("Try: notepad brand_monitor\\llm.py and edit manually")
