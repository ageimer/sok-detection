import sys
import os
import subprocess
import re

def parse_array(string):
    array = [[bytes.fromhex(b) for b in s[4:].split(":")] for s in string.split("\n")[:-1]]
    array = [item for sublist in array for item in sublist]
    if array[0] == b'\x00':
        # remove leading 00: https://crypto.stackexchange.com/questions/30608/leading-00-in-rsa-public-private-key-file
        return b''.join(array[1:])
    else:
        return b''.join(array)

assert len(sys.argv) >= 3

pem_file = sys.argv[2]
decoding_mode = sys.argv[1]
assert os.path.isfile(pem_file)

   
if decoding_mode == "RSA_OAEP":
    openssl_out = subprocess.run(f"openssl rsa -in {pem_file} -text -noout".split(), capture_output=True, text=True)
    output = openssl_out.stdout


    try: openssl_out.check_returncode()
    except CalledProcessError:
        print(f"Could not decode {pem_file}, check if it is a valid RSA key.") 
        exit()
 
    plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque sollicitudin ultrice"

    print(output)
    parse = re.search("Private-Key: \((\d+) bit, 2 primes\)\nmodulus:\n(?P<mod>.+)publicExponent:(?P<pubexp>.+)privateExponent:\n(?P<privexp>.+)prime1:\n(?P<p>.+)prime2:\n(?P<q>.+)exponent1:\n(?P<dp>.+)exponent2:\n(?P<dq>.+)coefficient:\n(?P<iq>.+)",output , re.DOTALL)

    mod = parse_array(parse.group("mod"))
    #print(parse_array(p.group("pubexp")))  only support 0x10001 as public exponent
    privexp = parse_array(parse.group("privexp"))
    p = parse_array(parse.group("p"))
    q = parse_array(parse.group("q"))
    dp = parse_array(parse.group("dp"))
    dq = parse_array(parse.group("dq"))
    iq = parse_array(parse.group("iq"))

    testcase_path = f"{os.path.splitext(pem_file)[0]}.testcase"

    openssl_out = subprocess.run(f"echo '{plaintext}' | openssl rsautl -encrypt -oaep -inkey {pem_file}", shell=True, capture_output=True)

    ciphertext = openssl_out.stdout
    print(ciphertext)
    
    #output_path = f"{os.path.splitext(pem_file)[0]}.enc"
    #with open(output_path, "xb") as f:
    #    f.write(openssl_out.stdout)
    with open(testcase_path, "xb") as f:
        f.write(mod+privexp+p+q+dp+dq+iq+ciphertext)

elif decoding_mode == "RSA_PKCS":
    openssl_out = subprocess.run(f"openssl rsa -in {pem_file} -text -noout".split(), capture_output=True, text=True)
    output = openssl_out.stdout

    try: openssl_out.check_returncode()
    except CalledProcessError:
        print(f"Could not decode {pem_file}, check if it is a valid RSA key.") 
        exit() 

    plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque sollicitudin ultrices enim. Aenean id odio imperdie";

    print(output)
    parse = re.search("Private-Key: \((\d+) bit, 2 primes\)\nmodulus:\n(?P<mod>.+)publicExponent:(?P<pubexp>.+)privateExponent:\n(?P<privexp>.+)prime1:\n(?P<p>.+)prime2:\n(?P<q>.+)exponent1:\n(?P<dp>.+)exponent2:\n(?P<dq>.+)coefficient:\n(?P<iq>.+)",output , re.DOTALL)

    mod = parse_array(parse.group("mod"))
    #print(parse_array(p.group("pubexp")))  only support 0x10001 as public exponent
    privexp = parse_array(parse.group("privexp"))
    p = parse_array(parse.group("p"))
    q = parse_array(parse.group("q"))
    dp = parse_array(parse.group("dp"))
    dq = parse_array(parse.group("dq"))
    iq = parse_array(parse.group("iq"))

    testcase_path = f"{os.path.splitext(pem_file)[0]}.testcase"

    openssl_out = subprocess.run(f"echo '{plaintext}' | openssl rsautl -encrypt -pkcs -inkey {pem_file}", shell=True, capture_output=True)

    ciphertext = openssl_out.stdout
    print(len(ciphertext))
    
    #output_path = f"{os.path.splitext(pem_file)[0]}.enc"
    #with open(output_path, "xb") as f:
    #    f.write(openssl_out.stdout)
    with open(testcase_path, "xb") as f:
        f.write(mod+privexp+p+q+dp+dq+iq+ciphertext)

elif decoding_mode == "ECDSA":
    openssl_out = subprocess.run(f"openssl ec -in {pem_file} -text -param_enc explicit -noout".split(), capture_output=True, text=True)
    output = openssl_out.stdout

    try: openssl_out.check_returncode()
    except CalledProcessError:
        print(f"Could not decode {pem_file}, check if it is a valid EC key.") 
        exit()

    parse = re.search("Private-Key: \(256 bit\)\npriv:\n(?P<priv>.+)pub:\n(?P<pub>.+)Field(?:.+)", output, re.DOTALL)
    
    pub = parse_array(parse.group("pub"))
    priv = parse_array(parse.group("priv"))

    print(pub)
    print(priv)

    testcase_path = f"{os.path.splitext(pem_file)[0]}.testcase"

    #output_path = f"{os.path.splitext(pem_file)[0]}.enc"
    #with open(output_path, "xb") as f:
    #    f.write(openssl_out.stdout)
    with open(testcase_path, "xb") as f:
        f.write(priv+pub)

elif decoding_mode == "EDDSA":
    openssl_out = subprocess.run(f"openssl ec -in {pem_file} -text -param_enc explicit -noout".split(), capture_output=True, text=True)
    output = openssl_out.stdout

    try: openssl_out.check_returncode()
    except CalledProcessError:
        print(f"Could not decode {pem_file}, check if it is a valid EC key.") 
        exit()

    parse = re.search("ED25519 Private-Key:\npriv:\n(?P<priv>.+)pub:\n(?P<pub>.+)", output, re.DOTALL)
    
    pub = parse_array(parse.group("pub"))
    priv = parse_array(parse.group("priv"))

    print(pub)
    print(priv)

    testcase_path = f"{os.path.splitext(pem_file)[0]}.testcase"

    #output_path = f"{os.path.splitext(pem_file)[0]}.enc"
    #with open(output_path, "xb") as f:
    #    f.write(openssl_out.stdout)
    with open(testcase_path, "xb") as f:
        f.write(priv+pub)
