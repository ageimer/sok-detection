---
jupyter:
  jupytext:
    formats: ipynb,md
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.14.4
  kernelspec:
    display_name: Python 3
    language: python
    name: python3
---

## Imports and settings

```python
import experiments as E
import xml.etree.ElementTree as ET
import os
import pandas as pd
import numpy as np
import toml           # needed for Binsec/Rel2 outputs
import csv            # needed for Binsec/Rel1 outputs
from datetime import timedelta, time
from typing import List

pd.set_option('styler.latex.hrules', True)
pd.set_option('styler.format.precision', 2)

```

## Common functions and values

```python
def load_text_output(path: str) -> List[str]:
    output = ""
    try: 
        with open(path, "r") as f:
            output = f.readlines()
    except OSError:
        return []
        
    return output

def init_dict(keys, value):
    return {k:v for (k,v) in zip(keys, [value for _ in range(len(keys))])}

BENCH_RES_DIR = "benchmarks-results"
VULN_RES_DIR = "vulns-results"

# experiment names in the order defined in experiments.py
binary_names = [b.name for benchmarks in E.all_bench for b in benchmarks]
vulns_names = [v.name for vulns in E.all_vuln for v in vulns]

print(binary_names)
print(vulns_names)

```

## ctgrind

ctgrind's outputs are in the form of one XML file per binary analyzed, listing vulnerabilities, their context and their origin *if* Valgrind is able to determine it. From this list of vulnerabilities we are interested in conditions and memory accesses computed using uninitialized memory, which comes from our call to `VALGRIND_MAKE_MEM_UNDEFINED` (so-called "client request").

For vulnerabilities whose origin *cannot* be traced by Valgrind, we can either choose to keep them (potentially adding false positives) or ignore them (potentially missing real vulnerabilities). By default **we keep these vulnerabilities**.

Additionnally, Valgrind reports a vulnerability if its instruction pointer *and* calling context are different. Thus a single leakage point can be reported multiple times. By defaut, **we filter out these duplicates**.

```python

MEMCHECK_COND = "UninitCondition"
MEMCHECK_VALUE = "UninitValue"
CLIENT_ORIGIN = "Uninitialised value was created by a client request"

def load_ctgrind_output(path: str):
    output = ""
    with open(path, "r") as f:
        output = f.readlines()
    
    root = ET.fromstringlist(output)
    return root

def ctgrind_vuln(root: ET.Element, keep_unknown_origins=True, filter_duplicates=True):
    elem_errors = root.findall("error")
    vulns = []

    for elem in elem_errors:
        kind = elem.findtext("kind")
        # only keep uninitialized memory errors
        if kind == MEMCHECK_COND or kind == MEMCHECK_VALUE:
            origin = elem.findtext("auxwhat")
            # keep errors coming from client requests
            # or of unknown origins *if* we keep them
            if origin == CLIENT_ORIGIN or (origin == None and keep_unknown_origins):
                error_ip = elem.find("stack").find("frame").findtext("ip")[2:]
                error_ip = hex(int(error_ip,16))
                if filter_duplicates:
                    if error_ip not in vulns: vulns.append(error_ip)
                else:
                    vulns.append(error_ip)
    return vulns

```

```python

RES_DIR = f"{BENCH_RES_DIR}/ctgrind"
ctgrind_vulns = init_dict(binary_names, "NaN")
ctgrind_secures = init_dict(binary_names, None)
ctgrind_times = init_dict(binary_names, "NaT")
stats = csv.DictReader(load_text_output(f"{RES_DIR}/benchmark_stats.csv"), delimiter=',')

for row in stats:
    name = row["name"]
    root = load_ctgrind_output(f"{RES_DIR}/{name}-ctgrind.txt")
    ctgrind_vulns[name] = len(ctgrind_vuln(root, True, True))
    ctgrind_times[name] = row["ctgrind_time"]
    ctgrind_secures[name] = None if ctgrind_vulns[name] == 0 else False
    
    print(f"{name}: {ctgrind_secures[name]}, {ctgrind_vulns[name]} in {ctgrind_times[name]}")
```

```python
RES_DIR = "vulns-results/ctgrind"
ctgrind_v_vulns = init_dict(vulns_names, "NaN")
ctgrind_v_times = init_dict(vulns_names, "NaT")
ctgrind_v_secures = init_dict(binary_names, None)
stats = csv.DictReader(load_text_output(f"{RES_DIR}/benchmark_stats.csv"), delimiter=',')

for row in stats:
    name = row["name"]
    root = load_ctgrind_output(f"{RES_DIR}/{name}-ctgrind.txt")
    ctgrind_v_vulns[name] = len(ctgrind_vuln(root))
    ctgrind_v_times[name] = row["ctgrind_time"]
    ctgrind_v_secures[name] = None if ctgrind_v_vulns[name] == 0 else False

    
    print(f"{name}: {ctgrind_v_secures[name]},{ctgrind_v_vulns[name]} in {ctgrind_v_times[name]}")
```

## Abacus

Abacus' outputs are in the form of simple plaintext files, listing the number of vulnerabilities and their addresses. The total running time of the analysis, as measured in our python script, is contained in `benchmark_stats.csv`

```python

def abacus_vuln(output: List[str]):
    preamble_end = output.index("DETAILS:\n")
    output = [line for line in output[0:preamble_end] if line.startswith("Address:")]
    return [hex(int(line.split(" ")[1],16)) for line in output]

```

```python
RES_DIR = f"{BENCH_RES_DIR}/abacus"
abacus_vulns = init_dict(binary_names, "NaN")
abacus_secures = init_dict(binary_names, None)
abacus_times = init_dict(binary_names, "NaT")

stats = csv.DictReader(load_text_output(f"{RES_DIR}/benchmark_stats.csv"), delimiter=',')

for row in stats:
    name = row["name"]
    # check if Abacus crashed or not
    if row["abacus_status"] != "0":
        abacus_times[name] = float(row["pin_time"]) + float(row["abacus_time"])
        abacus_vulns[name] = "NaN"
        abacus_secures[name] = None
    else:
        stdout = load_text_output(f"{RES_DIR}/{name}-abacus.txt")    # load Abacus output
        abacus_times[name] = float(row["pin_time"]) + float(row["abacus_time"])
        abacus_vulns[name] = len(abacus_vuln(stdout))
        abacus_secures[name] = None if abacus_vulns[name] == 0 else False

    
    print(f"{name}: {abacus_secures[name]}, {abacus_vulns[name]} in {abacus_times[name]}")
```

```python
RES_DIR = "vulns-results/abacus"
abacus_v_vulns = init_dict(vulns_names, "NaN")
abacus_v_times = init_dict(vulns_names, "NaT")
abacus_v_secures = init_dict(binary_names, None)

stats = csv.DictReader(load_text_output(f"{RES_DIR}/benchmark_stats.csv"), delimiter=',')

for row in stats:
    name = row["name"]
    if row["abacus_status"] != "0":
        abacus_v_times[name] = float(row["pin_time"]) + float(row["abacus_time"])
        abacus_v_vulns[name] = "NaN"
        abacus_v_secures[name] = None
    else:
        stdout = load_text_output(f"{RES_DIR}/{name}-abacus.txt")
        abacus_v_times[name] = float(row["pin_time"]) + float(row["abacus_time"])
        abacus_v_vulns[name] = len(abacus_vuln(stdout))
        abacus_v_secures[name] = None if abacus_v_vulns[name] == 0 else False
    
    print(f"{name}: {abacus_v_secures[name]},{abacus_v_vulns[name]} in {abacus_v_times[name]}")
```

## dudect

dudect outputs the result of its t-test score for each batch of measurements, and continues until either the score is too high ("probably not constant-time") or it is timed out by our python script. The total running time of the analysis, as measured in our python script, is appended at the end of the file. 

```python

def dudect_secure(output: List[str]):
    if output == []:
        # dudect couldn't produce an output before timeout
        return None
    
    result_line = output[-1].split(" ")
    if len(result_line) > 3 and result_line[-3] == "not":
        return False
    else:
        return None

def dudect_time(output: List[str]):
    # in any case, the analysis running time should be the only thing on the last line
    return timedelta(seconds=float(output[-1]))

```

```python

RES_DIR = f"{BENCH_RES_DIR}/dudect"
dudect_secures = init_dict(binary_names, None)
dudect_times = init_dict(binary_names, "Nat")

stats = csv.DictReader(load_text_output(f"{RES_DIR}/benchmark_stats.csv"), delimiter=',')

for row in stats:
    name = row["name"]
    stdout = load_text_output(f"{RES_DIR}/{name}-dudect.txt")
    
    dudect_secures[name] = dudect_secure(stdout)
    dudect_times[name] = row["dudect_time"]
    
    print(f"{name}: {dudect_secures[name]} in {dudect_times[name]}")

```

```python
RES_DIR = "vulns-results/dudect"
dudect_v_vulns = init_dict(vulns_names, None)
dudect_v_times = init_dict(vulns_names, "NaT")

stats = csv.DictReader(load_text_output(f"{RES_DIR}/benchmark_stats.csv"), delimiter=',')

for row in stats:
    name = row["name"]
    stdout = load_text_output(f"{RES_DIR}/{name}-dudect.txt")
    
    dudect_v_vulns[name] = dudect_secure(stdout)
    dudect_v_times[name] = row["dudect_time"]
    
    print(f"{name}: {dudect_v_vulns[name]} in {dudect_v_times[name]}")

```

# Binsec/Rel

Binsec/Rel outputs statistics for each benchmark in a single csv file. However, in cases where the analysis terminates with a fatal exception (e.g. an unsupported instruction), this file isn't written, so we have to also record each benchmark's stdout.

The total running time of the analysis, as measured in our python script, is appended at the end of the file.

```python
def rel_time_first(output: List[str]) -> pd.Timedelta:
    output = [line for line in output if line.startswith("[relse:result] Time:")]
    if output == []:
        # no vulnerability found
        return "NaT"
    else:
        # extracting time for the first vulnerability
        return output[0].split(" ")[2][:-2]

def rel_vuln(output: List[str]) -> List[str]:
    output = [line for line in output if line.startswith("[relse:result] Address")]
    if output == []:
        #no vulnerability found
        return []
    else:
        # extracting address of each vulnerability
        return [hex(int(line.split(" ")[2][1:-1],16)) for line in output]

def rel_secure(row):
    if row["rel1_status"] == "0":
        return True
    elif row["rel1_status"] == "7":
        return False
    else:
        return None
    
RES_DIR = f"{BENCH_RES_DIR}/binsec-rel"
rel_vulns = init_dict(binary_names, "NaN")
rel_times = init_dict(binary_names, "NaT")
rel_times_first = init_dict(binary_names, "NaT")
rel_secures = init_dict(binary_names, None)

stats = csv.DictReader(load_text_output(f"{RES_DIR}/benchmark_stats.csv"), delimiter=',')

for row in stats:
    name = row["name"]
    stdout = load_text_output(f"{RES_DIR}/{name}-binsec.txt")
    rel_times[name] = row["rel1_time"]
    rel_secures[name] = rel_secure(row)
    rel_times_first[name] = rel_time_first(stdout)
    rel_vulns[name] = len(rel_vuln(stdout))
    
    print(f"{name}: {rel_secures[name]}, {rel_vulns[name]} in {rel_times[name]}, {rel_times_first[name]}")

```

# Binsec/Rel2

```python

def rel2_vuln(root: dict):
    return [hex(int(v[2:], 16)) for v in root["CT report"]["Instructions status"]["insecure"]]

def rel2_time_first(output: List[str]):
    output = [line for line in output if line.startswith("[checkct:result] Instruction")]
    if output == []:
        return "NaT"
    else:
        return output[0].split("(")[1][:-3]
    
def rel2_secure(row):
    if row["rel2_status"] == "0":
        return True
    elif row["rel2_status"] == "7":
        return False
    else:
        return None
```

```python
RES_DIR = f"{BENCH_RES_DIR}/binsec-rel2"
rel2_vulns = init_dict(binary_names, "NaN")
rel2_times = init_dict(binary_names, "NaT")
rel2_times_first = init_dict(binary_names, "NaT")
rel2_secures = init_dict(binary_names, None)

stats = csv.DictReader(load_text_output(f"{RES_DIR}/benchmark_stats.csv"), delimiter=',')

for row in stats:
    name = row["name"]
    stdout = load_text_output(f"{RES_DIR}/{name}-binsec-rel2.txt")
    root = toml.load(f"{RES_DIR}/{name}-binsec-rel2.toml")

    rel2_times[name] = float(row["rel2_time"])
    rel2_secures[name] = rel2_secure(row)
    rel2_times_first[name] = rel2_time_first(stdout)
    rel2_vulns[name] = len(rel2_vuln(root))
    
    print(f"{name}: {rel2_secures[name]}, {rel2_vulns[name]} in {rel2_times[name]}, {rel2_times_first[name]}")

```

```python
RES_DIR = "vulns-results/binsec-rel2"
rel2_v_vulns = init_dict(vulns_names, "NaN")
rel2_v_times = init_dict(vulns_names, "NaT")
rel2_v_secures = init_dict(binary_names, None)

stats = csv.DictReader(load_text_output(f"{RES_DIR}/benchmark_stats.csv"), delimiter=',')

for row in stats:
    name = row["name"]
    if row["rel2_status"] == "2":
        stdout = load_text_output(f"{RES_DIR}/{name}-binsec-rel2.txt")

        rel2_v_times[name] = float(row["rel2_time"])
        rel2_v_vulns[name] = "NaN"
        rel2_v_secures[name] = None

    else:
        stdout = load_text_output(f"{RES_DIR}/{name}-binsec-rel2.txt")
        root = toml.load(f"{RES_DIR}/{name}-binsec-rel2.toml")
        
        rel2_v_times[name] = float(row["rel2_time"])
        rel2_v_vulns[name] = len(rel2_vuln(root))
        rel2_v_secures[name] = rel2_secure(row)

    print(f"{name}: {rel2_v_secures[name]},{rel2_v_vulns[name]} in {rel2_v_times[name]}")
        

```

# Generate latex tables

Table 2 and 3 are filled from the detection tools' outputs directly using this script. Some details must be filled manually however: core-dump initialization and early exits (table 2 and 3), and whether the right vulnerability was found (table 3). For these, a manual inspection of the output is needed.

```python
import experiments as E

# names used in the paper, in the order of experiment.py
table_names = ["AES-CBC-bearssl (T)", "AES-CBC-bearssl (BS)",
               "AES-GCM-bearssl (T)", "AES-GCM-bearssl (BS)",
               "AES-CBC-mbedtls (T)", "AES-GCM-mbedtls (T)",
               "AES-CBC-openssl (EVP)", "AES-GCM-openssl (EVP)",
               "AES-CBC-openssl (T)", "AES-CBC-openssl (VP)",
               "PolyChacha-bearssl (CT)", "PolyChacha-bearssl (SSE2)",
               "PolyChacha-mbedtls", "PolyChacha-openssl (EVP)",
               "Chacha20-openssl", "Poly1305-openssl", 
               "RSA-bearssl (OAEP)", "RSA-mbedtls (PKCS)",
               "RSA-mbedtls (OAEP)", "RSA-openssl (PKCS)",
               "RSA-openssl (OAEP)",
               "ECDSA-bearssl", "ECDSA-mbedtls", 
               "ECDSA-openssl", 
               "EdDSA-openssl"]

for i, b in enumerate(binary_names):
    # lambda to convert values into the strings used in the table
    si = lambda x: "\\crash" if x == "NaN" else x
    sb = lambda x: "\\true" if x is True else "\\false" if x is False else "\\unknown"
    st = lambda x: "--" if x == "NaT" else "\\timeout" if float(x) >= 3599 else str(np.format_float_positional(float(x), precision=2, fractional=True))
    row = (table_names[i] + " & " 
          f"{si(rel_vulns[b])} & {sb(rel_secures[b])} & {st(rel_times_first[b])} & {st(rel_times[b])} & "
          f"{si(rel2_vulns[b])} & {sb(rel2_secures[b])} & {st(rel2_times_first[b])} & {st(rel2_times[b])} & "
          f"{si(abacus_vulns[b])} & {sb(abacus_secures[b])} & {st(abacus_times[b])} & "
          f"{si(ctgrind_vulns[b])} & {sb(ctgrind_secures[b])} & {st(ctgrind_times[b])} & "
          f"{sb(dudect_secures[b])} & {st(dudect_times[b])} \\\\")
    print(row)
```

```python
import experiments as E

# names used in the paper, in the order of experiment.py
table_names = ["\\textbf{P256 sign (OpenSSL)}", "\\ wNAF mul. (OpenSSL)",
              "\\textbf{RSA valid. (MbedTLS)}", "\\ GCD (MbedTLS)", "\\ Mod. inv. (MbedTLS)",
              "\\textbf{RSA keygen (OpenSSL)}", "\\ GCD (OpenSSL)", "\\ Mod. exp. (OpenSSL)", "\\ Mod. inv. (OpenSSL)",
              "\\textbf{ECDH decrypt. (Libgcrypt)}", "\\ Mod. (Libgcrypt)"]

for i, b in enumerate(vulns_names):
    # lambda to convert values into the strings used in the table
    si = lambda x: "NA" if x == "NaN" else x
    sb = lambda x: "\\true" if x is True else ("\\false" if x is False else "\\unknown")
    st = lambda x: "--" if x == "NaT" else "\\timeout" if float(x) >= 3599 else str(np.format_float_positional(float(x), precision=2, fractional=True))
    row = (table_names[i] + " & " 
          f" & {si(rel2_v_vulns[b])} & {sb(rel2_v_secures[b])} & {st(rel2_v_times[b])} & "
          f" & {si(abacus_v_vulns[b])} & {sb(abacus_v_secures[b])} & {st(abacus_v_times[b])} & "
          f" & {si(ctgrind_v_vulns[b])} & {sb(ctgrind_v_secures[b])} & {st(ctgrind_v_times[b])} & "
          f"{sb(dudect_v_vulns[b])} & {st(dudect_v_times[b])} \\\\")
    print(row)
```

## Vulnerability details


```python
name = "gcm_starts-GCC9-O2"

# tools output for this binary
rel1_out = load_text_output(f"{BENCH_RES_DIR}/binsec-rel/{name}-binsec.txt")
rel2_out = toml.load(f"{BENCH_RES_DIR}/binsec-rel2/{name}-binsec-rel2.toml")
ctgrind_out = load_ctgrind_output(f"{BENCH_RES_DIR}/ctgrind/{name}-ctgrind.txt")
abacus_out = load_text_output(f"{BENCH_RES_DIR}/abacus/{name}-abacus.txt")

vuln_list = list(set(rel2_vuln(rel2_out)) | set(rel_vuln(rel1_out)) | set(abacus_vuln(abacus_out)) | set(ctgrind_vuln(ctgrind_out)))

rel2_list = np.array([(v in rel2_vuln(rel2_out)) for v in vuln_list])
rel_list = np.array([(v in rel_vuln(rel1_out)) for v in vuln_list])
abacus_list = np.array([(v in abacus_vuln(abacus_out)) for v in vuln_list])
ctgrind_list = np.array([(v in ctgrind_vuln(ctgrind_out)) for v in vuln_list])

print(len(rel_list[rel_list == True]))
print(len(rel2_list[rel2_list == True]))
print(len(abacus_list[abacus_list == True]))
print(len(ctgrind_list[ctgrind_list == True]))

df_vulns = pd.DataFrame(np.transpose([
    [(v in rel_vuln(rel1_out)) for v in vuln_list],
    [(v in rel2_vuln(rel2_out)) for v in vuln_list],
    [(v in abacus_vuln(abacus_out)) for v in vuln_list],
    [(v in ctgrind_vuln(ctgrind_out)) for v in vuln_list]]),
    index=vuln_list, columns=["Rel1", "Rel2", "Abacus", "ctgrind"])

with pd.option_context('display.max_rows', None, 'display.max_columns', None):
    print(df_vulns)

```

```python
name_pkcs = "RSA_private_decrypt_pkcs1_v15-GCC9-O2"
name_oaep = "RSA_private_decrypt_oaep-GCC9-O2"
RUN_NUMBER = 100

vulns_lists_pkcs = []
vulns_lists_oaep = []

for i in range(1,RUN_NUMBER):
    run = load_ctgrind_output(f"ctgrind-no-blinding/ctgrind{i}/{name_pkcs}-ctgrind.txt")
    vulns_lists_pkcs.append(ctgrind_vuln(run))
    run = load_ctgrind_output(f"ctgrind-no-blinding/ctgrind{i}/{name_oaep}-ctgrind.txt")
    vulns_lists_oaep.append(ctgrind_vuln(run))

```

```python
from functools import reduce

mean_pkcs = np.mean([len(l) for l in vulns_lists_pkcs])
mean_oaep = np.mean([len(l) for l in vulns_lists_oaep])

print(name_pkcs)

union_pkcs = reduce(np.union1d, vulns_lists_pkcs)
inter_pkcs = reduce(np.intersect1d, vulns_lists_pkcs)
print(f"total: {len(union_pkcs)}, common: {len(inter_pkcs)}, mean: {mean_pkcs}")
print(f"difference: {np.setdiff1d(union_pkcs, inter_pkcs)}")

print(name_pkcs)

union_oaep = reduce(np.union1d, vulns_lists_oaep)
inter_oaep = reduce(np.intersect1d, vulns_lists_oaep)
print(f"total: {len(union_oaep)}, common: {len(inter_oaep)}, mean: {mean_oaep}")
print(f"difference: {np.setdiff1d(union_oaep, inter_oaep)}")
```
