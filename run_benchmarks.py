#!/usr/bin/python3
import experiments as E
import detectiontools as T
from datetime import date
import argparse
import os
import csv

tool_switcher = {
    "binsec-rel": T.binsecrel,
    "binsec-rel2": T.binsecrel2,
    "abacus": T.abacus,
    "ctgrind": T.ctgrind,
    "dudect": T.dudect,
    "microwalk": T.microwalk
}

benchmark_switcher = {
    "all_bench": [bench for benchmarks in E.all_bench for bench in benchmarks],
    "all_vuln": [vuln for vulns in E.all_vuln for vuln in vulns],
    "aes": E.aes,
    "polychacha": E.polychacha,
    "rsa": E.rsa,
    "ecdsa": E.ecdsa,
    "eddsa": E.eddsa,
    "evp": E.evp,
    "aldayagt19": E.aldayagt19,
    "garciaht20": E.garciaht20,
    "genkinvy17": E.genkinvy17,
    "coredumps": E.ossl_coredumps
}

def run_benchmarks(data_list, tool_list, output, stats):
    os.makedirs(output, exist_ok=True)
    for t in tool_list:
        tool = tool_switcher.get(t)
        tool.prepare()
        for b in data_list:
            benchmarks = benchmark_switcher.get(b)
            for b in benchmarks:
                tool.run(b, output, stats)

    with open(f"{output}/benchmark_stats.csv", 'w', newline='') as f:
        fields = ["name"] + list(stats[list(stats)[0]])
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for name in list(stats):
            row = stats[name]
            row["name"] = name
            writer.writerow(row)
    
def main():
    parser = argparse.ArgumentParser(description='Run Binsec/RelSE experiments.')
    parser.add_argument('-t', '--tools', action='store', nargs="*",
                        help="Tools to use run (Binsec/Rel, Binsec/rel2, Abacus, ctgrind, dudect, Microwalk)")
    parser.add_argument('-b', '--benchmarks', action='store', nargs="*",
                        help="Dataset to run (see benchmark_switcher in run_benchmarks.py for datasets)")
    parser.add_argument('-o', "--out", action='store', nargs="?",
                        help="Name of the output folder", default='')

    args = parser.parse_args()


    print("[__________BEGIN__________]")
    if args.benchmarks is not None and len(args.benchmarks) > 0:
        benchmarks = args.benchmarks
        bench_list = [b.name for bench in benchmarks for b in benchmark_switcher[bench]]
        stats = {name: vals for (name, vals) in zip(bench_list, [dict() for _ in range(len(bench_list))])}
        
    else:
        print("Please, give me a benchmark to run with [-b].")
        exit(1)

    if args.tools is not None and len(args.tools) > 0:
        tools = args.tools

    else:
        print("Please, include a detection tool with [-t].")
        exit(1)

    if args.out != '':
        output = args.out
    else:
        output = f"results-{date.today()}"

    run_benchmarks(benchmarks, tools, output, stats)

    print("[__________End__________]")

main()
