from enum import Enum
import os

#################
#     UTILS
#################

BIN_DIR = "build"                       # location of benchmarks binaries
SRC_DIR = "src"
PWD = "./"
DEF_PINTOOL = "pintool.so"              # default pintool used by Abacus
DEF_SECTIONS = ".init,.text,.data,.rodata,.bss,.got.plt,.plt,.got,.data.rel.ro,.tdata"
DEF_REL1_MEM = f"{SRC_DIR}/relse1_memory.txt"
DEF_REL1_SCRIPT = f"{SRC_DIR}/relse1_script.ini"
DEF_REL2_MEM = f"{SRC_DIR}/relse2_script.ini"
DEF_REL2_CORE = f"{SRC_DIR}/relse2_script_coredump.ini"

class Status(Enum):
    TRUE = 1
    FALSE = 2
    UNKNOWN = 3

######################
#     EXPERIMENTS
######################

# not used: we use annotations instead
class TargetFunction(object):
    """Function used as entrypoint for Abacus"""
    def __init__(self, name: str, key_argpos: int, keylen: int):
        self.name = name                # Function name
        self.key_argpos = key_argpos    # Argument number for the pointer to the key
        self.keylen = keylen            # Length of the key in bytes


class Experiment(object):

    def __init__(self, folder, name, mem_file=None, script_file=None,
                 secure=Status.UNKNOWN, entrypoints='',
                 avoids='', high_sym='', suppfile='', spectre_secure=Status.TRUE,
                 critical_func='', target_func=None, pintool=DEF_PINTOOL, sections=DEF_SECTIONS,
                 from_coredump=False, core_break="main", inputs=None):
        self.folder = folder
        self.name = name
        self.entrypoints = entrypoints
        self.avoids = avoids
        self.high_sym = high_sym                # secret symbols list for Binsec/Rel 
        self.secure = secure
        self.spectre_secure = spectre_secure
        self.suppfile = suppfile                # Valgrind suppression file
        self.memory_file = mem_file             # Binsec/Rel1  memory file
        self.script_file = script_file          # Binsec/Rel script files
        self.critical_func = critical_func
        self.target_func = target_func          # Target function for Abacus
        self.pintool = pintool                  # pintool to use for Abacus
        self.sections = sections                # sections loaded by Binsec/Rel
        self.from_coredump = from_coredump      # whether Binsec/Rel2 starts from a coredump
        self.core_break = core_break            # Where to break in the coredump generation
        self.inputs = inputs                    # microwalk inputs
        
    def add_avoids(self, adr):
        self.avoids += "," + adr

    def set_memory_file(self, name):
        self.memory_file = name

    def get_memory_file(self):
        return PWD+self.memory_file

    def get_script_file(self, version):
        if (version == 1):
            return f"{PWD+SRC_DIR}/relse1_script.ini"
        elif (version == 2):
            common = f"{PWD+SRC_DIR}/relse2_script_coredump.ini" if self.from_coredump else f"{PWD+SRC_DIR}/relse2_script.ini"
            specific = f",{PWD+SRC_DIR}/{self.script_file}" if self.script_file != None else ""
            generated = f",{PWD+BIN_DIR}/{self.folder}/{self.name}.tls" if self.from_coredump else ""
            return common + specific + generated
        else:
            print(f'Unknown binsec version {str(version)}')
            exit(1)

def make_bench(folder, name, target_func, high_sym, mem=DEF_REL1_MEM, script2=None, supp=None, pintool=DEF_PINTOOL, from_coredump=False, core_break="main", inputs=None):
    for filename in os.listdir(os.path.join(PWD, BIN_DIR, folder)):
        if filename == name:
            mem_file = (mem if mem != None else f"memory_{filename}.txt")
            supp_file = (supp if supp != None else f"{filename}.supp")
            return Experiment(folder, filename, mem_file, script2, target_func=target_func, high_sym=high_sym, suppfile=supp_file, pintool=pintool, from_coredump=from_coredump, core_break=core_break, inputs=inputs)

################
#  BENCHMARKS  #
################

# AES-bearssl
brssl_aes_big_cbc = make_bench("AES-bearssl", "aes_big_cbc-GCC9-O2", None, ["skey"], script2="benchmark/secrets_aes.ini", inputs="src/testcases/target-symmetric")
brssl_aes_ct_cbc = make_bench("AES-bearssl", "aes_ct_cbc-GCC9-O2", None, ["skey"], script2="benchmark/secrets_aes.ini", inputs="src/testcases/target-symmetric")
brssl_aes_big_gcm = make_bench("AES-bearssl", "aes_big_gcm-GCC9-O2", None, ["skey"], script2="benchmark/secrets_gcm.ini", inputs="src/testcases/target-symmetric")
brssl_aes_ct_gcm = make_bench("AES-bearssl", "aes_ct_gcm-GCC9-O2", None, ["skey"], script2="benchmark/secrets_gcm.ini", inputs="src/testcases/target-symmetric")

# AES-mbedtls
mbed_aes_cbc = make_bench("AES-mbedtls", "aes_crypt_cbc-GCC9-O2", None, ["skey"], script2="benchmark/secrets_aes.ini", inputs="src/testcases/target-symmetric")
mbed_aes_gcm = make_bench("AES-mbedtls", "gcm_starts-GCC9-O2", None, ["skey"], script2="benchmark/secrets_gcm.ini", inputs="src/testcases/target-symmetric")

# AES-openssl
ossl_evp_aes = make_bench("AES-openssl", "evp_aes_cbc-GCC9-O2", None, ["skey"], script2="benchmark/secrets_aes.ini", from_coredump=True, inputs="src/testcases/target-symmetric")
ossl_evp_aes_gcm = make_bench("AES-openssl", "evp_aes_gcm-GCC9-O2", None, ["skey"], script2="benchmark/secrets_gcm.ini", from_coredump=True, inputs="src/testcases/target-symmetric")
ossl_aes_cbc = make_bench("AES-openssl", "aes_cbc_encrypt-GCC9-O2", None, ["skey"], script2="benchmark/secrets_aes.ini", inputs="src/testcases/target-symmetric")
ossl_vpaes_cbc = make_bench("AES-openssl", "vpaes_cbc_encrypt-GCC9-O2", None, ["skey"], script2="benchmark/secrets_aes.ini", from_coredump=True, inputs="src/testcases/target-symmetric")

aes = [brssl_aes_big_cbc, brssl_aes_ct_cbc, brssl_aes_big_gcm, brssl_aes_ct_gcm, mbed_aes_cbc, mbed_aes_gcm, ossl_evp_aes, ossl_evp_aes_gcm, ossl_aes_cbc, ossl_vpaes_cbc]

# Poly1305-bearssl
brssl_polychacha_ct = make_bench("Poly1305-bearssl", "poly1305_ctmul_chacha20_ct-GCC9-O2", None, ["skey"], script2="benchmark/secrets_keys32_iv12.ini", inputs="src/testcases/target-symmetric")
brssl_polychacha_sse2 = make_bench("Poly1305-bearssl", "poly1305_ctmul_chacha20_sse2-GCC9-O2", None, ["skey"], script2="benchmark/secrets_keys32_iv12.ini", inputs="src/testcases/target-symmetric")

# Poly1305-mbedtls
mbed_polychacha = make_bench("Poly1305-mbedtls", "mbedtls_chachapoly-GCC9-O2", None, ["skey"], script2="benchmark/secrets_keys32_iv12.ini", inputs="src/testcases/target-symmetric")

# Poly1305-openssl
ossl_evp_polychacha = make_bench("Poly1305-openssl", "evp_chacha20_poly1305-GCC9-O2", None, ["skey"], script2="benchmark/secrets_keys32_iv12.ini", from_coredump=True, inputs="src/testcases/target-symmetric")
ossl_chacha20 = make_bench("Poly1305-openssl", "chacha20_ctr32-GCC9-O2", None, ["skey"], script2="benchmark/secrets_chacha20.ini", inputs="src/testcases/target-symmetric")
ossl_poly1305 = make_bench("Poly1305-openssl", "poly1305_update-GCC9-O2", None, ["skey"], script2="benchmark/secrets_keys32.ini", from_coredump=True, inputs="src/testcases/target-symmetric")

polychacha = [brssl_polychacha_ct, brssl_polychacha_sse2, mbed_polychacha, ossl_evp_polychacha, ossl_chacha20, ossl_poly1305]

# RSA-bearssl
brssl_rsa_oaep = make_bench("RSA-bearssl", "rsa_i31_oaep_decrypt-GCC9-O2", None, ["RSA_P", "RSA_Q", "RSA_DP", "RSA_DQ", "RSA_QINV"], script2="benchmark/secrets_oaep.ini", inputs="src/testcases/target-oaep")

# RSA-mbedtls
mbed_rsa_pkcs = make_bench("RSA-mbedtls", "rsa_pkcs1_v15_decrypt-GCC9-O2", None, ["RSA_P", "RSA_Q", "RSA_D"], script2="benchmark/secrets_pkcs1_v15.ini", from_coredump=True, inputs="src/testcases/target-pkcs")
mbed_rsa_oaep = make_bench("RSA-mbedtls", "rsa_oaep_decrypt-GCC9-O2", None, ["RSA_P", "RSA_Q", "RSA_D"], script2="benchmark/secrets_oaep.ini", from_coredump=True, inputs="src/testcases/target-oaep")

# RSA-openssl
ossl_rsa_pkcs = make_bench("RSA-openssl", "RSA_private_decrypt_pkcs1_v15-GCC9-O2", None, ["RSA_P", "RSA_Q", "RSA_D", "RSA_DP", "RSA_DQ", "RSA_QINV"], script2="benchmark/secrets_pkcs1_v15.ini", from_coredump=True, inputs="src/testcases/target-pkcs")
ossl_rsa_oaep = make_bench("RSA-openssl", "RSA_private_decrypt_oaep-GCC9-O2", None, ["RSA_P", "RSA_Q", "RSA_D", "RSA_DP", "RSA_DQ", "RSA_QINV"], script2="benchmark/secrets_oaep.ini", from_coredump=True, inputs="src/testcases/target-oaep")

rsa = [brssl_rsa_oaep, mbed_rsa_pkcs, mbed_rsa_oaep, ossl_rsa_pkcs, ossl_rsa_oaep]

# ECDSA-bearssl
brssl_ecdsa_p256 = make_bench("ECDSA-bearssl", "ecdsa_i31_sign_p256-GCC9-O2", None, ["ECDSA_D"], script2="benchmark/secrets_ecdsa_p256.ini", inputs="src/testcases/target-ecdsa")

# ECDSA-mbedtls
mbed_ecdsa_p256 = make_bench("ECDSA-mbedtls", "ecdsa_sign_det_ext_p256-GCC9-O2", None, ["ECDSA_D"], script2="benchmark/secrets_ecdsa_p256.ini", from_coredump=True, inputs="src/testcases/target-ecdsa")

# ECDSA-openssl
ossl_ecdsa_p256 = make_bench("ECDSA-openssl", "ECDSA_do_sign_p256-GCC9-O2", None, ["ECDSA_D"], script2="benchmark/secrets_ecdsa_p256.ini", from_coredump=True, inputs="src/testcases/target-ecdsa")

ecdsa = [brssl_ecdsa_p256, mbed_ecdsa_p256, ossl_ecdsa_p256]

#EdDSA-openssl
ossl_ed25519 = make_bench("EdDSA-openssl", "ED25519_sign-GCC9-O2", None, ["Ed25519_D"], script2="benchmark/secrets_ed25519.ini", from_coredump=True, inputs="src/testcases/target-eddsa")

eddsa = [ossl_ed25519]

evp = [ossl_evp_aes, ossl_evp_aes_gcm, ossl_evp_polychacha]

all_bench = [aes,
             polychacha,
             rsa,
             ecdsa,
             eddsa]

##############################
#  VULNERABILITY VALIDATION  #
##############################

# Certified side-channels
ossl_ecdsa = make_bench("GarciaHT20", "ECDSA_do_sign-GCC9-O2", None, [], inputs="src/testcases/target-ecdsa")
ossl_wnaf_mul = make_bench("GarciaHT20", "ec_wnaf_mul-GCC9-O2", None, ["ECDSA_D"], script2="vuln_validation/secrets_ecdsa.ini", inputs="src/testcases/target-ecdsa")
mbed_rsa_complete = make_bench("GarciaHT20", "mbedtls_rsa_complete-GCC9-O2", None, ["RSA_P", "RSA_Q"], script2="vuln_validation/secrets_rsa.ini", inputs="src/testcases/target-oaep")
mbed_gcd = make_bench("GarciaHT20", "mbedtls_mpi_gcd-GCC9-O2", None, ["P_minus_one", "Q_minus_one"], script2="vuln_validation/secrets_gcd.ini", inputs="src/testcases/target-gcd")
mbed_mod_inv = make_bench("GarciaHT20", "mbedtls_mpi_inv_mod-GCC9-O2", None, ["lcm"], script2="vuln_validation/secrets_lcm.ini", inputs="src/testcases/target-lcm")

garciaht20 = [ossl_ecdsa, ossl_wnaf_mul, mbed_rsa_complete, mbed_gcd, mbed_mod_inv]

# Side-channel attacks on RSA key generation
ossl_rsa_keygen = make_bench("AldayaGT19", "RSA_key_generate_ex-GCC9-O2", None, [], inputs="src/testcases/target-gcd")
ossl_gcd = make_bench("AldayaGT19", "bn_gcd-GCC9-O2", None, ["P_minus_one"], script2="vuln_validation/secrets_gcd.ini", inputs="src/testcases/target-gcd")
ossl_mod_exp_mont = make_bench("AldayaGT19", "bn_mod_exp_mont-GCC9-O2", None, ["exponent"], script2="vuln_validation/secrets_modexp.ini", inputs="src/testcases/target-modexp")
ossl_mod_inv = make_bench("AldayaGT19", "bn_mod_inverse-GCC9-O2", None, ["P"], script2="vuln_validation/secrets_modinv.ini", inputs="src/testcases/target-modinv")

aldayagt19 = [ossl_rsa_keygen, ossl_gcd, ossl_mod_exp_mont, ossl_mod_inv]

# May the Fourth Be With You: A Microarchitectural Side Channel Attack on Several Real-World Applications of Curve25519
gcrypt_decrypt = make_bench("GenkinVY17", "gcry_pk_decrypt-GCC9-O2", None, ["Ed25519_D"], script2="vuln_validation/secrets_decrypt.ini", from_coredump=True, core_break="main_body", inputs="src/testcases/target-eddsa")
gcrypt_mod = make_bench("GenkinVY17", "gcry_mpi_mod-GCC9-O2", None, ["data"], script2="vuln_validation/secrets_mod.ini", from_coredump=True, core_break="main_body", inputs="src/testcases/target-mod")

genkinvy17 = [gcrypt_decrypt, gcrypt_mod]

ossl_coredumps = [ossl_vpaes_cbc, ossl_poly1305, ossl_rsa_oaep, ossl_rsa_pkcs, ossl_ecdsa_p256, ossl_ed25519]

all_vuln = [garciaht20, aldayagt19, genkinvy17]
