"""
patch_llm.py - Smart patcher for llm.py generate_json function
Run from project root: python patch_llm.py
"""

with open('brand_monitor/llm.py', 'r') as f:
    lines = f.readlines()

# Show current file so we can verify
print("Current llm.py lines:")
for i, line in enumerate(lines, 1):
    print(f"{i:3}: {line}", end="")

print("\n" + "="*50)

# Find the generate_json function
start = None
end   = None
for i, line in enumerate(lines):
    if 'def generate_json' in line:
        start = i
    if start is not None and i > start:
        # End of function = next def at same indent level or EOF
        if line.startswith('def ') or line.startswith('class '):
            end = i
            break

if start is None:
    print("ERROR: generate_json not found")
    exit(1)

if end is None:
    end = len(lines)

print(f"\nFound generate_json at lines {start+1} to {end}")
print("Current function:")
for line in lines[start:end]:
    print(repr(line))

# Replace with fixed version
new_function = '''def generate_json(prompt: str, system: str = None) -> dict:
    """Send a prompt expecting a JSON response and parse it.
    Strips markdown code fences before parsing since Llama3
    sometimes wraps JSON in ```json ... ``` blocks.
    Also repairs truncated JSON and provides safe fallback."""
    raw = generate(prompt, system=system, temperature=0.1)
    cleaned = re.sub(r"```(?:json)?\\s*|\\s*```", "", raw).strip()
    # Attempt 1 - parse as-is
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Attempt 2 - repair truncated JSON
    try:
        opens  = cleaned.count(\'{\')
        closes = cleaned.count(\'}\')
        if opens > closes:
            repaired = cleaned + (\'}\' * (opens - closes))
            return json.loads(repaired)
    except json.JSONDecodeError:
        pass
    # Fallback - safe defaults so scan continues
    print(f"  [WARN] LLM JSON parse failed - using safe defaults")
    return {
        "classification":      "UNKNOWN",
        "confidence":          "LOW",
        "indicators":          ["LLM response could not be parsed"],
        "summary":             "Analysis incomplete.",
        "recommended_action":  "MONITOR",
        "risk_tier":           "MEDIUM",
        "risk_score":          5,
        "threat_type":         "UNKNOWN",
        "narrative":           "Risk synthesis incomplete due to LLM response error.",
        "recommended_actions": ["Manual review recommended"],
        "urgency":             "MONITOR",
    }

'''

new_lines = lines[:start] + [new_function] + lines[end:]

with open('brand_monitor/llm.py', 'w') as f:
    f.writelines(new_lines)

print("\nSUCCESS - llm.py patched")
print("Verifying syntax...")
import py_compile
try:
    py_compile.compile('brand_monitor/llm.py', doraise=True)
    print("SYNTAX OK")
except py_compile.PyCompileError as e:
    print(f"SYNTAX ERROR: {e}")
