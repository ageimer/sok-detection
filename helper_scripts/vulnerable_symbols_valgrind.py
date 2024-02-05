import sys
import os
sys.path.append(os.getcwd() + '/..')
os.chdir(os.getcwd() + '/..')

import experiments as E
import xml.etree.ElementTree as ET
import pandas as pd
import numpy as np
import toml           # needed for Binsec/Rel2 outputs
import csv            # needed for Binsec/Rel1 outputs
from datetime import timedelta, time
from typing import List


def load_text_output(path: str) -> List[str]:
    output = ""
    with open(path, "r") as f:
        output = f.readlines()

    return output


def init_dict(keys, value):
    return {k:v for (k,v) in zip(keys, [value for _ in range(len(keys))])}


# experiment names in the order defined in experiments.py
binary_names = [b.name for benchmarks in E.all_bench for b in benchmarks]
vulns_names = [v.name for vulns in E.all_vuln for v in vulns]

print(vulns_names)
print(binary_names)

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


def ctgrind_filter_errors(root: ET.Element, keep_unknown_origins=True, filter_duplicates=True):
    elem_errors = root.findall("error")
    elems = []
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
                    if error_ip not in vulns:
                        elems.append(elem)
                        vulns.append(error_ip)
                else:
                    elems.append(elem)
                    vulns.append(error_ip)
    return elems

def print_vulns(file):
    print(f"\n\n")
    RES_DIR = "benchmarks-results/ctgrind"
    root = load_ctgrind_output(f"{RES_DIR}/{file}-ctgrind.txt")
    vulns = ctgrind_filter_errors(root)
    for error in vulns:
        # Get vuln specific data
        unique = error.find('unique').text
        tid = error.find('tid').text
        kind = error.find('kind').text
        what = error.find('what').text

        # Get data from top frame
        top_frame = error.find('stack').find('frame')
        ip = top_frame.find('ip').text
        fn = top_frame.find('fn').text

        print(unique, tid, kind, what, ip, fn)


RES_DIR = "benchmarks-results/ctgrind"

ctgrind_vulns = init_dict(binary_names, "NaN")
ctgrind_times = init_dict(binary_names, "NaT")
stats = csv.DictReader(load_text_output(f"{RES_DIR}/benchmark_stats.csv"), delimiter=',')

for row in stats:
    name = row["name"]
    root = load_ctgrind_output(f"{RES_DIR}/{name}-ctgrind.txt")
    ctgrind_vulns[name] = len(ctgrind_vuln(root))
    ctgrind_times[name] = row["ctgrind_time"]

    print(f"\n\n===== {name}: {ctgrind_vulns[name]} in {ctgrind_times[name]}")
    if ctgrind_vulns[name] > 0:
        print_vulns(name)
    else:
        print(f"No vulnerabilities found")
