# run the project
```
cd ~/func-extractor
cmake --build build -j
./build/func_extractor test.c -- -std=c11 > functions.jsonl //抽出 function JSONL
./build/func_extractor test2.c -- -I/home/sense/miniconda3/lib/clang/16/include > functions.jsonl //給test2
head -n 5 functions.jsonl //你應該會看到像這樣（每行一筆 JSON）
export OPENAI_API_KEY=""
python3 analyze_llm.py --in functions.jsonl --out risk_report.jsonl //跑 LLM（全部 functions 都評）
python3 analyze_llm.py --in functions.jsonl --out risk_report.jsonl --topk 20 //只分析 Top-K（先用 baseline 做預篩）
python3 analyze_llm.py --in functions.jsonl --out risk_report.jsonl --git --repo . //加上 git commit message（file-level）一起給 LLM （如果你在別的 repo 做分析，就把 --repo 指到那個 repo 根。）
python3 analyze_llm.py --in functions.jsonl --out risk_report.jsonl // 目前 LLM 輸出採用估計的 CVSS v3.1 Base Score、Severity 與 CVSS vector
python3 analyze_llm.py --in functions.jsonl --runs 5 --out-dir outputs/baseline // 同一批 function 自動重跑 5 次
// outputs/baseline/run_001.jsonl ~ run_005.jsonl: 每次 run 的原始結果
// outputs/baseline/runs.jsonl: 所有 run 聚合結果
// outputs/baseline/baseline_summary.json: 每個 function 的平均分數、標準差、平均排名、排名波動
// outputs/baseline/baseline_summary.md: baseline summary table


```

//跑CVE_2013_2028 case
```
./build/func_extractor /home/sense/nginx-1.4.0/src/http/ngx_http_parse.c -- \
  -DNGX_LINUX=1 \
  -Wno-implicit-function-declaration \
  -include unistd.h \
  -I/home/sense/nginx-1.4.0/src/core \
  -I/home/sense/nginx-1.4.0/src/event \
  -I/home/sense/nginx-1.4.0/src/event/modules \
  -I/home/sense/nginx-1.4.0/src/os/unix \
  -I/home/sense/nginx-1.4.0/objs \
  -I/home/sense/nginx-1.4.0/src/http \
  -I/home/sense/nginx-1.4.0/src/http/modules \
  -I/home/sense/miniconda3/lib/clang/16/include > output.jsonl

  python3 analyze_llm.py --in output.jsonl --out nginx_report.jsonl --score-json scores.json
  python3 analyze_llm.py --in output.jsonl --runs 5 --out-dir outputs/cve-2013-2028_baseline --score-json outputs/cve-2013-2028_baseline/summary.json

```

// factor-based testing
```
python3 analyze_llm.py \
  --in output.jsonl \
  --runs 5 \
  --out-dir outputs/factor_cvss_test \
  --score-json outputs/factor_cvss_test/summary.json \
  --model gpt-4o-2024-08-06

```