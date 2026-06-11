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
python3 analyze_llm.py --in functions.jsonl --out risk_report.jsonl // 目前 LLM 輸出採用估計的 CVSS v3.1 Base Score、Severity 與 CVSS vector
python3 analyze_llm.py --in functions.jsonl --runs 5 --out-dir outputs/baseline // 同一批 function 自動重跑 5 次
// outputs/baseline/run_001.jsonl ~ run_005.jsonl: 每次 run 的原始結果
// outputs/baseline/runs.jsonl: 所有 run 聚合結果
// outputs/baseline/baseline_summary.json: 每個 function 的平均分數、標準差、平均排名、排名波動
// outputs/baseline/baseline_summary.md: baseline summary table
```

### Test Case - CVE-2013-2028
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


### Test Case - 2019-12982
```
cd /home/sense/func-extractor

./build/func_extractor input/cve-2019-12982.c -- \
  -std=c11 \
  -I/home/sense/libming/src \
  -I/home/sense/libming/util \
  -I/home/sense/libming/src/blocks \
  -I/home/sense/libming/ch/include \
  -I/home/sense/func-extractor/input \
  -I/home/sense/miniconda3/lib/clang/16/include \
  > input/cve-2019-12982-function.jsonl

python3 analyze_llm.py \
  --in input/cve-2019-12982-function.jsonl \
  --runs 2 \
  --out-dir outputs/cve-2019-12982 \
  --score-json outputs/cve-2019-12982/summary.json \
  --model gpt-4o-2024-08-0
```



### Test Case - CVE-2022-34526
```
cd /home/sense/func-extractor

./build/func_extractor input/cve-2022-34526.c -- \
  -std=c11 \
  -I/tmp/libtiff-cmake-for-ast/libtiff \
  -I/tmp/libtiff-cmake-for-ast \
  -I/home/sense/libtiff/libtiff \
  -I/home/sense/libtiff/port \
  -I/home/sense/libtiff/test \
  -I/home/sense/libtiff/contrib/tags \
  -I/home/sense/libtiff/contrib/stream \
  -I/home/sense/libtiff/contrib/addtiffo \
  -I/home/sense/libtiff/contrib/dbs/xtiff \
  -I/home/sense/libtiff/contrib/pds \
  -I/home/sense/libtiff/archive/tools \
  -I/home/sense/miniconda3/lib/clang/16/include \
  > input/cve-2022-34526-function.jsonl

 python3 analyze_llm.py \
  --in input/cve-2022-34526-function.jsonl \
  --runs 5 \
  --out-dir outputs/cve-2022-34526 \
  --score-json outputs/cve-2022-34526/summary.json \
  --model gpt-4o-2024-08-06

```

### Test Case - CVE-2021-29338
```
cd /home/sense/func-extractor

./build/func_extractor input/cve-2021-29338-decompress.c -- \
  -std=c11 \
  -I/home/sense/openjpeg/build/src/bin/common \
  -I/home/sense/openjpeg/build/src/lib/openjp2 \
  -I/home/sense/openjpeg/src/lib/openjp2 \
  -I/home/sense/openjpeg/src/bin/common \
  -I/home/sense/openjpeg/src/bin/jp2 \
  -I/home/sense/miniconda3/lib/clang/16/include \
  > input/cve-2021-29338-decompress-function.jsonl

python3 analyze_llm.py \
  --in input/cve-2021-29338-decompress-function.jsonl \
  --runs 5 \
  --out-dir outputs/cve-2021-29338-decpmpress \
  --score-json outputs/cve-2021-29338-decompress/summary.json \
  --model gpt-4o-2024-08-06


cd /home/sense/func-extractor
./build/func_extractor input/cve-2021-29338-compress.c -- \
  -std=c11 \
  -I/home/sense/openjpeg/build/src/bin/common \
  -I/home/sense/openjpeg/build/src/lib/openjp2 \
  -I/home/sense/openjpeg/src/lib/openjp2 \
  -I/home/sense/openjpeg/src/bin/common \
  -I/home/sense/openjpeg/src/bin/jp2 \
  -I/home/sense/miniconda3/lib/clang/16/include \
  > input/cve-2021-29338-compress-function.jsonl

python3 analyze_llm.py \
  --in input/cve-2021-29338-compress-function.jsonl \
  --runs 5 \
  --out-dir outputs/cve-2021-29338-compress \
  --score-json outputs/cve-2021-29338-compress/summary.json \
  --model gpt-4o-2024-08-06

```

## Across Function Cases
###  Test Case - CVE-2022-3602
```
cd /home/sense/func-extractor
./build/func_extractor input/cve-2022-3602.c -- \
  -std=c11 \
  -I/home/sense/openssl/include \
  -I/home/sense/miniconda3/lib/clang/16/include \
  > input/cve-2022-3602-function.jsonl

python3 analyze_llm.py \
  --in input/cve-2022-3602-function.jsonl \
  --runs 5 \
  --out-dir outputs/cve-2022-3602 \
  --score-json outputs/cve-2022-3602/summary.json \
  --model gpt-5.5
```

### Test Case - CVE-2022-37433
```
cd /home/sense/func-extractor
./build/func_extractor input/cve-2022-37434.c -- \
  -std=c11 \
  -I/home/sense/zlib \
  -I/home/sense/miniconda3/lib/clang/16/include \
  > input/cve-2022-37434-function.jsonl

python3 analyze_llm.py \
  --in input/cve-2022-37434-function.jsonl \
  --runs 5 \
  --out-dir outputs/cve-2022-37434 \
  --score-json outputs/cve-2022-37434/summary.json \
  --model gpt-5.5
```

### Test Case - CVE-2022-0185
```
cd /home/sense/func-extractor

./build/func_extractor input/cve-2022-0185.c -- \
  -std=gnu11 \
  -nostdinc \
  -I/usr/src/linux-headers-6.11.0-19-generic/arch/x86/include/generated \
  -I/usr/src/linux-headers-6.11.0-19-generic/arch/x86/include/generated/uapi \
  -I/usr/src/linux-headers-6.11.0-19-generic/include \
  -I/usr/src/linux-headers-6.11.0-19-generic/include/generated \
  -I/usr/src/linux-headers-6.11.0-19-generic/include/generated/uapi \
  -I/usr/src/linux-hwe-6.11-headers-6.11.0-19/arch/x86/include \
  -I/usr/src/linux-hwe-6.11-headers-6.11.0-19/arch/x86/include/uapi \
  -I/usr/src/linux-hwe-6.11-headers-6.11.0-19/include \
  -I/usr/src/linux-hwe-6.11-headers-6.11.0-19/include/uapi \
  -I/home/sense/linux/fs \
  -include /usr/src/linux-hwe-6.11-headers-6.11.0-19/include/linux/kconfig.h \
  -include /usr/src/linux-hwe-6.11-headers-6.11.0-19/include/linux/compiler-version.h \
  -include /usr/src/linux-hwe-6.11-headers-6.11.0-19/include/linux/compiler_types.h \
  -D__KERNEL__ \
  -DKBUILD_MODNAME='"fs_context"' \
  -I/home/sense/miniconda3/lib/clang/16/include \
  > input/cve-2022-0185-function.jsonl

python3 analyze_llm.py \
  --in input/cve-2022-0185-function.jsonl \
  --runs 5 \
  --out-dir outputs/cve-2022-0185 \
  --score-json outputs/cve-2022-0185/summary.json \
  --model gpt-5.5

```


### Test Case - CVE-2025-32463 (sudoers.c)
```
cd /home/sense/func-extractor

./build/func_extractor input/cve-2025-32463-sudoers.c -- \
  -std=gnu11 \
  -I/home/sense/sudo/build \
  -I/home/sense/cve-2025-32463/sudo/include \
  -I/home/sense/cve-2025-32463/sudo/lib/util \
  -I/home/sense/cve-2025-32463/sudo/lib/eventlog \
  -I/home/sense/cve-2025-32463/sudo/lib/iolog \
  -I/home/sense/cve-2025-32463/sudo/plugins/sudoers \
  -I/home/sense/cve-2025-32463/sudo/plugins/sudoers/. \
  -I/home/sense/miniconda3/lib/clang/16/include \
  -DLOCALEDIR='"/usr/share/locale"' \
  > input/cve-2025-32463-sudoers-function.jsonl

python3 analyze_llm.py \
  --in input/cve-2025-32463-sudoers-function_v2.jsonl \
  --runs 5 \
  --out-dir outputs/cve-2025-32463-sudoers-v2 \
  --score-json outputs/cve-2025-32463-sudoers-v2/summary.json \
  --model gpt-5.5

```
### Test Case - CVE-2019-16279
```
cd /home/sense/func-extractor

./build/func_extractor input/cve-2019-16279.c -- \
  -std=gnu11 \
  -D__linux__ \
  -I/home/sense/nostromo-1.9.6/src/nhttpd \
  -I/home/sense/nostromo-1.9.6/src/libmy \
  -I/home/sense/nostromo-1.9.6/src/libbsd \
  -I/home/sense/miniconda3/lib/clang/16/include \
  > input/cve-2019-16279-function.jsonl

python3 analyze_llm.py \
  --in input/cve-2019-16279-function.jsonl \
  --runs 1 \
  --out-dir outputs/cve-2019-16279-function \
  --score-json outputs/cve-2019-16279-function/summary.json \
  --model gpt-5.5  

```

### Test Case - CVE-2012-5533
```
cd /home/sense/func-extractor

./build/func_extractor input/cve-2012-5533.c -- \
  -std=gnu11 \
  -DHAVE_SOCKLEN_T=1 \
  -DHAVE_STDINT_H=1 \
  -I/home/sense/lighttpd-1.4.31/src \
  -I/home/sense/miniconda3/lib/clang/16/include \
  > input/cve-2012-5533-function.jsonl

python3 analyze_llm.py \
  --in input/cve-2012-5533-function.jsonl \
  --runs 5 \
  --out-dir outputs/cve-2012-5533-function \
  --score-json outputs/cve-2012-5533-function/summary.json \
  --model gpt-5.5  

```