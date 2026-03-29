from __future__ import annotations
import typing
import os
import re
from dotenv import load_dotenv
from openai import OpenAI
load_dotenv("/root/FuzzAgent/sub_modules/HarnessReducer/.env")
from pathlib import Path
from harnessreducer.reducer_runner import (
    get_crash_tester_path,
    run_command
)
    
def llm_semantic_reduce(harness_code: str) -> str | None:
    """
    Use an LLM (via the official openai package) to perform semantic minimization on 
    the given C/C++ harness.
    """
    api_key = os.environ.get("OPENAI_API_KEY", None)
    base_url = os.environ.get("OPENAI_BASE_URL", None)
    model = os.environ.get("OPENAI_MODEL", None)
    if not api_key:
        print("[-] OPENAI_API_KEY not set. Skipping LLM reduction.")
        return None
    if not base_url:
        print("[-] OPENAI_BASE_URL not set. Skipping LLM reduction.")
        return None
    if not model:
        print("[-] OPENAI_MODEL not set. Skipping LLM reduction.")
        return None


    client = OpenAI(
        api_key=api_key,
        base_url=base_url
    )

    prompt = f"""You are an expert C/C++ programmer and security researcher.
The following code is a fuzzer harness returning a minimized PoC that has been reduced at the AST/syntax level.
However, it still contains structural redundancies. Your task is to further minimize this code structures while COMPLETELY preserving its semantic behavior and EXACT logic.

You should perform strict constant folding, redundant statement elimination, and control-flow flattening.
CRITICAL RULES for Constant Folding:
1. You MUST accurately evaluate modulo (`%`), bitwise, and other arithmetic expressions (e.g., `153 % 12` is `9`, so evaluate it as `9`).
2. Remove any redundant statements (unused variables or calls) that do not affect the final behavior. For example, if a variable is assigned a value that is never used, you can remove that assignment.
3. ONLY remove switch/if statements AFTER evaluating the exact condition based on earlier constant definitions. Retain the branch that is actually taken!
4. If a variable's value changes through an executed branch (e.g. `format = PNG_FORMAT_LINEAR_RGB_ALPHA;`), you MUST keep the updated value when replacing it. Do not carelessly use the initial value.
5. If MUST make sure your any removal are accurate. If you are not 100% sure about the value of a variable at a certain point, DO NOT remove the conditional branch that leads to it. This is especially important for cases where the variable's value is determined by an if/switch statement. You can only remove the branch that is actually taken based on the evaluated conditions.

For example:
```
png_uint_32 format = PNG_FORMAT_LINEAR_RGB_ALPHA;
png_uint_32 pixel_channels = 0;
if (format & PNG_FORMAT_FLAG_COLOR) {{
    pixel_channels = 3;
}}
```
Because if not know the definition of `format`, so you don't know if the condition is true or false, you cannot remove the if statement.


CRITICAL RULES for Code Alteration:
1. DO NOT alter the core API sequences, memory allocations (e.g., malloc sizes), or external function calls. They are needed for the crash.
2. Maintain exact variable types, sizes, and signs.
3. Remove redundant intermediate temporary variables ONLY if their exact final value is perfectly folded.




Return ONLY the fully minimized C/C++ code. Do not include any explanations. Wrap your code in a single ```cpp code block.

Here is the reduced harness:
```cpp
{harness_code}
```
"""

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a professional C/C++ security engineer."},
            {"role": "user", "content": prompt}
        ],
        temperature=1.0,
        extra_body={
            "chat_template_kwargs": {"thinking": True},
            "reasoning": {"enabled": True}
        }
    )

    content = response.choices[0].message.content
    if not content:
        return None
    output = content.strip()
    
    # Extract the code block if it is enclosed in markdown
    match = re.search(r"```(?:cpp|c|c\+\+)?\s*(.*?)\s*```", output, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()

    return output.strip()
    
def apply_llm_reduction(reduced_harness_path: str, crash_pattern: str, crash_input: str | None, extra_flags: str | None, fdp_trace_file: str) -> str:
    source = Path(reduced_harness_path).read_text(encoding="utf-8", errors="ignore")
    print("Applying LLM semantic reduction...")
    transformed = llm_semantic_reduce(source)
    print(f"LLM reduced harness length: {len(transformed) if transformed else 0}\n")
    
    if not transformed:
        print("[-] LLM semantic reduction failed.")
        return reduced_harness_path

    # Write to a secondary copy
    llm_reduced_path = str(Path(reduced_harness_path).with_suffix(".llm.cpp"))
    Path(llm_reduced_path).write_text(transformed, encoding="utf-8")
    
    print(f"LLM semantic reduction completed. Verifying crash preservation for {llm_reduced_path}")
    
    cmd = [
        get_crash_tester_path(),
        llm_reduced_path,
        crash_pattern,
        "--crash-input", crash_input or "",
        "--extra-flags", extra_flags or ""
    ]
    
    proc = run_command(cmd, "LLM reduction validation failed.", ignore_errors=True)
    if proc.returncode == 77:
        print("[+] LLM reduction succeeded and preserved the crash.")
        return llm_reduced_path
    else:
        print("[-] LLM reduction failed to preserve the crash. Falling back to earlier reduced version.")
        print(f"LLM reduced version for reference: \n{transformed}")
        return reduced_harness_path

if __name__ == "__main__":
    # For quick testing of the LLM reducer in isolation
    import argparse
    parser = argparse.ArgumentParser(description="Test LLM Reducer")
    parser.add_argument("source", help="Path to the reduced harness to further minimize with LLM")
    args = parser.parse_args()
    harness_path = args.source
    with open(harness_path, 'r', encoding='utf-8', errors='ignore') as f:
        harness_code = f.read()
    minimized_code = llm_semantic_reduce(harness_code)
    print("Minimized code:\n", minimized_code)
