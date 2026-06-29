# Function Extractor and LLM Risk Analyzer

This project contains a Clang LibTooling-based function extractor and a Python LLM analyzer.

The extractor reads a C/C++ source file, walks the AST, and emits one JSONL record per function. Each record includes function source, location, direct caller/callee context, and security-relevant signals. The analyzer sends those records to an OpenAI model and produces CVSS-oriented function risk reports.

## Repository Layout

```text
.
├── CMakeLists.txt          # CMake build definition for func_extractor
├── src/main.cpp            # Clang LibTooling function extractor
├── analyze_llm.py          # LLM-based risk analyzer
├── prompts/                # Prompt templates and prompt utilities
├── input/                  # Local test inputs and extracted JSONL files
└── outputs/                # Analyzer outputs and repeated-run summaries
```

## Requirements

### System Packages

Install CMake, a C++ compiler, LLVM, and Clang development libraries.

On Ubuntu/Debian-style systems:

```bash
sudo apt update
sudo apt install -y build-essential cmake llvm-dev clang libclang-dev
```

If you use the existing conda LLVM/Clang environment on this machine, activate it before configuring CMake:

```bash
conda activate <your-env-name>
```

This project expects LLVM/Clang packages that provide CMake config files such as `LLVMConfig.cmake` and `ClangConfig.cmake`. The current local environment has been used with LLVM/Clang 16.

### Python Packages

The analyzer requires Python 3 and these packages. `pydantic>=2` is required because the analyzer uses `model_dump()` and related v2 APIs.

```bash
python3 -m pip install --upgrade openai "pydantic>=2"
```

Set the OpenAI API key before running `analyze_llm.py`:

```bash
export OPENAI_API_KEY="YOUR_API_KEY"
```

## Quick Start

Run one sample case end-to-end:

```bash
# 1. Build the extractor
cd /home/sense/func-extractor
rm -rf build
cmake -S . -B build
cmake --build build -j

# 2. Set the OpenAI API key
export OPENAI_API_KEY="YOUR_API_KEY"

# 3. Extract function-level JSONL records
./build/func_extractor input/crash_in_A_rootcause_in_B.c -- \
  -std=c11 \
  -I"$(clang -print-resource-dir)/include" \
  > input/crash_in_A_rootcause_in_B-function-v2.jsonl

# 4. Run the LLM-based risk analyzer
python3 analyze_llm.py \
  --in input/crash_in_A_rootcause_in_B-function-v2.jsonl \
  --runs 5 \
  --out-dir outputs/crash_in_A_rootcause_in_B-v2 \
  --score-json outputs/crash_in_A_rootcause_in_B-v2/summary.json \
  --model gpt-5.5
```

## Build Steps

From this project directory:

```bash
cd /home/sense/func-extractor
```

Configure the build:

```bash
rm -rf build
cmake -S . -B build
```

If CMake cannot find LLVM or Clang automatically, pass the package config paths explicitly. For example:

```bash
rm -rf build
cmake -S . -B build \
  -DLLVM_DIR="$CONDA_PREFIX/lib/cmake/llvm" \
  -DClang_DIR="$CONDA_PREFIX/lib/cmake/clang"
```

Compile:

```bash
cmake --build build -j
```

The extractor binary will be generated at:

```bash
./build/func_extractor
```

## Basic Usage

Extract functions from a C file:

```bash
./build/func_extractor input/cve-2019-12982.c -- \
  -std=c11 \
  -I"$(clang -print-resource-dir)/include" \
  > input/cve-2019-12982-function.jsonl
```

Check the generated JSONL:

```bash
wc -l input/cve-2019-12982-function.jsonl
head -n 5 input/cve-2019-12982-function.jsonl
```

Run the LLM analyzer on all extracted functions:

```bash
python3 analyze_llm.py \
  --in input/cve-2019-12982-function.jsonl \
  --out outputs/cve-2019-12982/risk_report.jsonl \
  --score-json outputs/cve-2019-12982/summary.json \
  --model gpt-5.5
```

Analyze only the top-k baseline-ranked functions:

```bash
python3 analyze_llm.py \
  --in input/cve-2019-12982-function.jsonl \
  --out outputs/cve-2019-12982/risk_report.jsonl \
  --topk 20 \
  --model gpt-5.5
```

Run repeated analyses and generate aggregate summaries:

```bash
python3 analyze_llm.py \
  --in input/cve-2019-12982-function.jsonl \
  --runs 5 \
  --out-dir outputs/cve-2019-12982 \
  --score-json outputs/cve-2019-12982/summary.json \
  --model gpt-5.5
```

Important: `--out-dir` must be a directory path, not a `.jsonl` file path. For a single-run report file, use `--out`.

Repeated-run mode writes:

```text
outputs/<case>/run_001.jsonl
outputs/<case>/run_002.jsonl
outputs/<case>/...
outputs/<case>/runs.jsonl
outputs/<case>/baseline_summary.json
outputs/<case>/baseline_summary.md
outputs/<case>/summary.json
```

Resume an interrupted single-run output:

```bash
python3 analyze_llm.py \
  --in input/cve-2019-12982-function.jsonl \
  --out outputs/cve-2019-12982/risk_report.jsonl \
  --resume \
  --model gpt-5.5
```

## Notes for Real Target Code

The extractor forwards all arguments after `--` to Clang. For real projects, include the same defines and include paths used by the target project. Missing headers or missing macros may prevent Clang from building the AST correctly.

General pattern:

```bash
./build/func_extractor path/to/source.c -- \
  -std=c11 \
  -DPROJECT_DEFINE=1 \
  -I/path/to/project/include \
  -I"$(clang -print-resource-dir)/include" \
  > functions.jsonl
```

For conda LLVM/Clang 16, the Clang resource include path is commonly:

```bash
$(clang -print-resource-dir)/include
```

## Troubleshooting

If `find_package(LLVM)` or `find_package(Clang)` fails, check the package config locations:

```bash
find "${CONDA_PREFIX:-/usr}" \( -name LLVMConfig.cmake -o -name ClangConfig.cmake \)
```

Then rerun CMake with `-DLLVM_DIR=...` and `-DClang_DIR=...`.

If CMake reports that `CMakeCache.txt` was created in a different directory, remove the stale build directory and configure again:

```bash
rm -rf build
cmake -S . -B build
cmake --build build -j
```

If the extractor fails with missing system headers such as `stddef.h`, add the Clang resource include path after `--`:

```bash
-I"$(clang -print-resource-dir)/include"
```

If `analyze_llm.py` exits with `OPENAI_API_KEY not set`, export the API key in the current shell:

```bash
export OPENAI_API_KEY="YOUR_API_KEY"
```
