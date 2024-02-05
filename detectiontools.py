import experiments as E
import subprocess
import os
import shutil
import time
from datetime import date
import re

today = date.today()
PWD = "./"
DRY_RUN = False
TIMEOUT = 3600

#BINSEC = "binsec-rel"                                           # Binsec/Rel's docker container's name
#ABACUS = "crazy_lamport"                                        # Abacus' docker container's name
#CTGRIND = "valgrind"                                            # it's just valgrind 
#BINSEC_REL2 = "binsec"                                          # binsec ran from the command line, assume it is installed

BINSEC = "tools/binsec-rel"              # path to Binsec/Rel1 folder
ABACUS = "tools/Abacus"                 # path to Abacus folder
BINSEC_REL2 = "tools/relse2"             # path to Binsec/Rel2 folder

#########
# UTILS #
#########

def __clear_folder(folder: str):
    if os.path.isdir(folder):
        for myfile in os.listdir(folder):
            file_path = os.path.join(folder, myfile)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(e)


class DetectionTool:
    """Informal interface for detection tools"""

    def __init__(self, run, prepare):
        self.__run = run
        self.__prepare = prepare

    def run(self, exp: E.Experiment, output: str, stats):
        self.__run(exp, output, stats)

    def prepare(self):
        self.__prepare()

##############
# Binsec/Rel #
##############

# run script and parameters taken from https://github.com/binsec/rel_bench/blob/main/run.py

# Default values
DEF_DEBUG = 0
DEF_STORE = "rel"
DEF_PROP = "ct"
DEF_CANONICAL = True
DEF_MEMORY = "row-map"
DEF_TO = TIMEOUT
DEF_SOLVER_TO = 600    # 0
DEF_DEPTH = int(1e7)
DEF_PATHS = '0'        # 0
DEF_COUNT = 5
DEF_NC = True          # Nocomment
DEF_FP = 'instr'
DEF_DD = 1
DEF_SOLVER = 'boolector'
DEF_LEAKINFO = 'instr'  # {halt|instr|unique-leak}
DEF_PRINTMODEL = True
DEF_LOWDECL = False
DEF_OPTIMS = False
DEF_UNTAINTING = True  # Set untainting parameter
DEF_ENTRYPOINT = "main"

# Set parameters to run Binsec
class ParamsRel(object):

    def dated_output(self, prefix):
        self.output_file = prefix + "_" + str(today.isoformat())

    def __init__(self, output_file="", smtdir="", fp=DEF_FP, dd=DEF_DD, nc=DEF_NC,
                 timeout=DEF_TO, solver_timeout=DEF_SOLVER_TO, depth=DEF_DEPTH,
                 paths=DEF_PATHS, solver=DEF_SOLVER, leak_info=DEF_LEAKINFO,
                 print_model=DEF_PRINTMODEL, store=DEF_STORE, canonical=DEF_CANONICAL,
                 memory=DEF_MEMORY, debug=DEF_DEBUG, optims=DEF_OPTIMS,
                 untainting=DEF_UNTAINTING, low_decl=DEF_LOWDECL, trace="", prop=DEF_PROP,
                 entrypoint=DEF_ENTRYPOINT):
        self.fp = fp
        self.dd = dd
        if output_file == "":
            self.dated_output("results")
        else:
            self.output_file = output_file
        self.smtdir = smtdir
        self.nc = nc
        self.timeout = timeout
        self.solver_timeout = solver_timeout
        self.depth = depth
        self.paths = paths
        self.solver = solver
        self.leak_info = leak_info
        self.print_model = print_model
        self.debug = debug
        self.optims = optims
        self.trace = trace
        self.low_decl = low_decl
        self.untainting = untainting
        self.store = store
        self.canonical = canonical
        self.memory = memory
        self.prop = prop
        self.entrypoint = entrypoint
        
default_params = ParamsRel(output_file="binsec_stats")

def make_cmd_binsec(exp: E.Experiment, params: ParamsRel, output: str):
    prefix = exp.name
    path_to_bin = PWD + E.BIN_DIR + '/' + exp.folder + '/' + exp.name
    if params.smtdir != "" and not os.path.isdir(params.smtdir):
        os.makedirs(params.smtdir)
    if params.trace != "" and not os.path.isdir(params.trace):
        os.makedirs(params.trace)

    __clear_folder(params.smtdir + "/binsec_sse")
    __clear_folder(params.trace)

    high_syms_setting = "".join([" -relse-high-sym "+v for v in exp.high_sym])

    cmd = BINSEC + "/binsec" + ' -relse' + \
          ' -fml-solver-timeout ' + str(params.solver_timeout) + \
          (' -fml-optim-all' if params.optims else '') + \
          ' -relse-timeout ' + str(params.timeout) + \
          ' -relse-debug-level ' + str(params.debug) + \
          ' -sse-depth ' + str(params.depth) + \
          (' -sse-memory ' + exp.get_memory_file()
           if exp.memory_file != '' else '') + \
          ' -relse-paths ' + str(params.paths) + \
          (' -sse-comment' if not params.nc else '') + \
          ' -sse-load-ro-sections' + \
          (' -sse-load-sections ' + exp.sections if exp.sections != '' else '') + \
          ('' if exp.avoids == ''
           else ' -sse-no-explore ' + exp.avoids) + \
          (' -relse-stat-prefix ' + prefix if prefix != '' else '') + \
          (' -relse-stat-file ' + output + '/' + params.output_file + ".csv"
           if params.output_file != '' else '') + \
          (' -sse-smt-dir ' + params.smtdir
           if params.smtdir != '' else '') + \
          (' -fml-solver ') + params.solver + \
          (' -sse-address-trace-file ' + params.trace
           if params.trace != '' else '') + \
          ' -relse-store-type ' + params.store + \
          ' -relse-memory-type ' + params.memory + \
          ' -relse-property ' + params.prop + \
          ('' if exp.critical_func == ''
           else ' -relse-critical-func ' + exp.critical_func) + \
          (' -relse-no-canonical' if not params.canonical else '') + \
          (high_syms_setting if high_syms_setting != '' else '') + \
          ' -relse-dedup ' + str(params.dd) + \
          ' -relse-fp ' + str(params.fp) + \
          (' -relse-leak-info ' + params.leak_info if params.leak_info != '' else '') + \
          (' -relse-print-model' if params.print_model else '') + \
          (' -relse-low-decl' if params.low_decl else '') + \
          (' -relse-no-untainting ' if not params.untainting else '') + \
          ' -entrypoint ' + params.entrypoint + \
          ' -config ' + exp.get_script_file(1) + \
          ' ' + path_to_bin
    return cmd

def run_binsec(exp, output, stats, params=default_params):
    cmd = make_cmd_binsec(exp, params, output)

    if not DRY_RUN:
        print(f"Running Binsec/Rel1: {exp.name}")
        start = time.time()
        process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        delay = time.time() - start

        with open(os.path.join(output, f"{exp.name}-binsec.txt"), 'w') as f:
            f.write(process.stdout)

        stats[exp.name]["rel1_status"] = process.returncode
        stats[exp.name]["rel1_time"] = delay

    else:
        print(cmd)

def prepare_binsec(): pass

binsecrel = DetectionTool(run_binsec, prepare_binsec)

###############
# Binsec/Rel2 #
###############

# Default values
DEF2_DEBUG = 1
DEF2_DEPTH = int(1e7)
DEF2_TAINT = True
DEF2_CV = True
DEF2_RELSE = True
DEF2_LEAKINFO = 'instr'  # {instr|halt}
DEF2_TO = TIMEOUT
DEF2_SOLVER_TO = 600

class ParamsRel2(object):

    def dated_output(self, prefix):
        self.output_file = prefix + "_" + str(today.isoformat())

    def __init__(self, output_file="", use_taint=DEF2_TAINT, use_cv=DEF2_CV,
                 use_relse=DEF2_RELSE, timeout=DEF2_TO, solver_timeout=DEF2_SOLVER_TO,
                 depth=DEF2_DEPTH, debug=DEF2_DEBUG, leak_info=DEF2_LEAKINFO):
        if output_file == "":
            self.dated_output("results")
        else : 
            self.output_file = output_file
        self.use_taint = use_taint
        self.use_cv = use_cv
        self.use_relse = use_relse
        self.timeout = timeout
        self.solver_timeout = solver_timeout
        self.depth = depth
        self.debug = debug
        self.leak_info = leak_info

default_params_rel2 = ParamsRel2()        

def make_script_gdb(path_to_core, breakpoint):
    return '\n'.join(['set interactive-mode off',
                      'catch syscall set_thread_area',
                      f'break {breakpoint}',
                      'run',
                      'printf "gs_base<32> := %#x\\n", *($ebx + 4)',
                      'continue',
                      'continue',
                      'generate-core-file {}'.format(path_to_core),
                      'kill',
                      'quit'])

def run_gdb_core(exp: E.Experiment):
    path_to_bin = PWD + E.BIN_DIR + "/" + exp.folder + "/" + exp.name
    path_to_core = path_to_bin + ".core"

    process = subprocess.run("gdb --args {}".format(path_to_bin),
                             shell=True,
                             input=make_script_gdb(path_to_core, exp.core_break),
                             capture_output=True,
                             text=True)

    return re.search("gs_base<32> := 0x[0-9a-f]{1,8}", process.stdout).group(0)


def make_cmd_binsec_rel2(exp: E.Experiment, output, params: ParamsRel2):
    prefix = exp.name
    if exp.from_coredump:
        path_to_bin = PWD + E.BIN_DIR + "/" + exp.folder + "/" + exp.name + ".core"
    else:
        path_to_bin = PWD + E.BIN_DIR + "/" + exp.folder + "/" + exp.name

    cmd = BINSEC_REL2 + "/binsec" + ' -checkct' + \
        (' -checkct-no-taint' if not params.use_taint else '') +\
        (' -checkct-no-cv' if not params.use_cv else '') +\
        (' -checkct-no-relse' if not params.use_relse else '') +\
        ' -checkct-script ' + exp.get_script_file(2) +\
        ' -fml-solver-timeout ' + str(params.solver_timeout) + \
        ' -checkct-timeout ' + str(params.timeout) + \
        (' -checkct-debug-level ' + str(params.debug) \
         if params.debug >= 0 else '') + \
        ' -checkct-depth ' + str(params.depth) + \
        ' -checkct-leak-info ' + params.leak_info + \
        ' -checkct-stats-file ' + output + '/' + exp.name  + "-binsec-rel2.toml" +\
        ' ' + path_to_bin

    return cmd


def run_binsec_rel2(exp: E.Experiment, output, stats, params=default_params_rel2):
    params.dated_output("binsec-rel2")
    cmd = make_cmd_binsec_rel2(exp, output, params)
    path_to_tls = PWD + E.BIN_DIR + "/" + exp.folder + "/" + exp.name + ".tls"
    
    if not DRY_RUN:
        print(f"Running Binsec/Rel2: {exp.name}")
        start = time.time()
        if exp.from_coredump:
            tls = run_gdb_core(exp)
            with open(path_to_tls, 'w') as f:
                f.write(tls)

        process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        delay = time.time() - start
        
        with open(os.path.join(output, f"{exp.name}-binsec-rel2.txt"), 'w') as f:
            f.write(process.stdout)

        stats[exp.name]["rel2_status"] = process.returncode
        stats[exp.name]["rel2_time"] = delay
    else:
        print(cmd)

def prepare_binsec_rel2(): pass

binsecrel2 = DetectionTool(run_binsec_rel2, prepare_binsec_rel2)

##########
# Abacus #
##########

PIN_ROOT = "Intel-Pin-Archive"           # Pin archive pulled by Abacus during compilation
ABACUS_BINARY = "QIF-new"                # Name of Abacus' binary
PIN_DIR = "Pintools/obj-ia32"            # directory containing the pintools

# Pintool output files
INST_OUT = "Inst_data.txt"
FUNC_OUT = "Function.txt"

def make_cmd_pin(exp: E.Experiment):
    return [f"{ABACUS}/{PIN_ROOT}/pin", "-t", f"{ABACUS}/{PIN_DIR}/{exp.pintool}", "--", f"{E.BIN_DIR}/{exp.folder}/{exp.name}"]

def make_cmd_abacus(exp: E.Experiment, output: str):
    return [f"{ABACUS}/{ABACUS_BINARY}", f"./{INST_OUT}", "-f", f"{FUNC_OUT}", "-o", f"{output}/{exp.name}-abacus.txt"]

# copies the results of the benchmarks 
def copy_files_out(exp: E.Experiment, output: str):
    shutil.move(f"{FUNC_OUT}", f"{output}/{exp.name}-func.txt")
    shutil.move(f"{INST_OUT}", f"{output}/{exp.name}-inst.txt")

def prepare_abacus(): pass

def run_abacus(exp: E.Experiment, output: str, stats):
    pin_cmd = make_cmd_pin(exp)
    abacus_cmd = make_cmd_abacus(exp, output)

    if not DRY_RUN:
        print(f"Running Abacus: {exp.name}")
        start = time.time()
        try:
            process = subprocess.run(pin_cmd, shell=False, capture_output=True, timeout=TIMEOUT)
        except subprocess.TimeoutExpired as e:
            delay = time.time() - start
            stats[exp.name]["abacus_status"] = "NA"
            stats[exp.name]["abacus_time"] = "NA"
            stats[exp.name]["pin_status"] = 124
            stats[exp.name]["pin_time"] = delay
            # if crashing here, there's no files to copy so we exit immediately
            return
        else:
            delay = time.time() - start
            stats[exp.name]["pin_status"] = process.returncode
            stats[exp.name]["pin_time"] = delay
            
        start = time.time()
        try:
            process = subprocess.run(abacus_cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=TIMEOUT-delay)
        except subprocess.TimeoutExpired as e:
            delay = time.time() - start
            stats[exp.name]["abacus_status"] = 124
            stats[exp.name]["abacus_time"] = delay
            copy_files_out(exp, output)
        else:
            delay = time.time() - start
            stats[exp.name]["abacus_status"] = process.returncode
            stats[exp.name]["abacus_time"] = delay
            copy_files_out(exp, output)

    else:
        print(pin_cmd)
        print(abacus_cmd)


abacus = DetectionTool(run_abacus, prepare_abacus)

###########
# CTGRIND #
###########

DEF_NUMCALL=64

def make_cmd_ctgrind(exp: E.Experiment, output: str):
    path_to_bin = PWD + E.BIN_DIR + '/' + exp.folder + '/' + exp.name
    path_to_supp = (PWD + E.BIN_DIR + '/' + exp.folder + '/' + exp.suppfile if exp.suppfile != "" else "")
    
    cmd = f"valgrind -v --tool=memcheck --error-limit=no" + \
        f" --num-callers={DEF_NUMCALL}" + \
        f" --default-suppressions=yes" + \
        f" --suppressions=common.supp --suppressions=src/below_main_errors.supp" + \
        f" --track-origins=yes" + \
        f" --xml=yes" + \
        f" --xml-file={output}/{exp.name}-ctgrind.txt" + \
        (f" --suppressions={path_to_supp}" if path_to_supp != "" else "") + \
        " " + path_to_bin

    return cmd

def run_ctgrind(exp: E.Experiment, output: str, stats):
    ctgrind_cmd = make_cmd_ctgrind(exp, output)

    if not DRY_RUN:
        print(f"Running ctgrind: {exp.name}")
        start = time.time()
        try:
            process = subprocess.run(ctgrind_cmd, shell=True, capture_output=True, timeout=TIMEOUT)
        except subprocess.TimeoutExpired as e:
            delay = time.time() - start
            stats[exp.name]["ctgrind_status"] = 124
            stats[exp.name]["ctgrind_time"] = delay
        else:
            delay = time.time() - start
            stats[exp.name]["ctgrind_status"] = process.returncode
            stats[exp.name]["ctgrind_time"] = delay
            
    else:
        print(ctgrind_cmd)

def prepare_ctgrind(): pass

ctgrind = DetectionTool(run_ctgrind, prepare_ctgrind)

##########
# dudect #
##########

def run_dudect(exp: E.Experiment, output: str, stats):
    dudect_cmd = f"{E.BIN_DIR}/{exp.folder}/dut_{exp.name}"

    if not DRY_RUN:
        print(f"Running dudect: {exp.name}")
        start = time.time()
        try:
            process = subprocess.run(dudect_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=TIMEOUT)
        except subprocess.TimeoutExpired as e:
            delay = time.time() - start
            stats[exp.name]["dudect_status"] = 124
            stats[exp.name]["dudect_time"] = delay
            with open(os.path.join(output, f"{exp.name}-dudect.txt"), 'w') as f:
                # the exception returns stdout as a bytestring regardless of text=True
                # if the program didn't produce an output e.stdout is None
                f.write((e.stdout or b"").decode("utf-8"))
        else:
            delay = time.time() - start
            stats[exp.name]["dudect_status"] = process.returncode
            stats[exp.name]["dudect_time"] = delay
            with open(os.path.join(output, f"{exp.name}-dudect.txt"), 'w') as f:
                f.write(str(process.stdout))

    else:
        print(dudect_cmd) 

def prepare_dudect(): pass

dudect = DetectionTool(run_dudect, prepare_dudect)

#############
# Microwalk #
#############

def run_microwalk(exp: E.Experiment, output: str, stats):
    microwalk_cmd = f"docker run -it -v $(pwd)/build:/mw/library/build -v $(pwd)/src:/mw/library/src -v $(pwd)/{output}:/mw/work/persist ghcr.io/microwalk-project/microwalk:3.1.1-pin /bin/bash -c 'cd ../library; ./analyze.sh ../build/{exp.folder}/microwalk_{exp.name} {exp.inputs}'"

    if not DRY_RUN:
        print(f"Running Microwalk: {exp.name}")
        start = time.time()
        try:
            process = subprocess.run(microwalk_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, text=True, timeout=TIMEOUT)
        except subprocess.TimeoutExpired as e:
            delay = time.time() - start
            stats[exp.name]["microwalk_status"] = 124
            stats[exp.name]["microwalk_time"] = delay
            with open(os.path.join(output, f"{exp.name}-microwalk.txt"), 'w') as f:
                # the exception returns stdout as a bytestring regardless of text=True
                # if the program didn't produce an output e.stdout is None
                f.write((e.stdout or b"").decode("utf-8"))
        else:
            delay = time.time() - start
            stats[exp.name]["microwalk_status"] = process.returncode
            stats[exp.name]["microwalk_time"] = delay
            with open(os.path.join(output, f"{exp.name}-microwalk.txt"), 'w') as f:
                f.write(str(process.stdout))

    else:
        print(microwalk_cmd) 
    
def prepare_microwalk(): pass

microwalk = DetectionTool(run_microwalk, prepare_microwalk)
