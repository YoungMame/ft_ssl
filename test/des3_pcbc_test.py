import subprocess
import sys
import os

def build_encode_decode_test(test_file, key, iv):
    return ["./ft_ssl", "3des-pcbc", "-i", "test/files/" + test_file, "-o", "test/files/.out/" + test_file + "3pcbc_encrypted_ft_ssl", "-k", key, "-v", iv], \
           ["./ft_ssl", "3des-pcbc", "-d", "-i", "test/files/.out/" + test_file + "3pcbc_encrypted_ft_ssl", "-o", "test/files/.out/" + test_file + "3pcbc_decrypted_ft_ssl", "-k", key, "-v", iv], \

file_tests = [
    [ "binary", "0C871EEA3A53959353267524379562934659463564932562", "0C871EEA3AF7AAAA" ],
    [ "text", "0C871EEA3A53959353267524379562934659463564932562", "0C871EEA3AF7AAAA" ],
    [ "image.png", "0C871EEA3A53959353267524379562934659463564932562", "0C871EEA3AF7AAAA" ],
    [ "text", "0C871EEA3A53959353267524379562934659463564932562", "0000000000000000" ],
    [ "text", "0C871EEA3A53959353267524379562934659463564932562", "4242424242424242" ],
    [ "text", "424242424242424242424242424242424242424242424242", "0000000000000000" ],
    [ "text", "424242424242424242424242424242424242424242424242", "FFFFFFFFFFFFFFFF" ],
]

def run_cmd(cmd):
    if os.getenv("FT_SSL_TEST_DEBUG") == "1":
        print("Running command:", " ".join(cmd));
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False);
    return proc.stdout, proc.stderr;

def run_cmd_encode_decode(array):
    input_file = array[0][array[0].index("-i") + 1];
    encrypted_file = array[0][array[0].index("-o") + 1];
    decrypted_file = array[1][array[1].index("-o") + 1];

    out1, err1 = run_cmd(array[0]);
    out2, err2 = run_cmd(array[1]);

    diff = run_cmd(["diff", input_file, decrypted_file])[0]
    if diff:
        print("Output file mismatch: ", input_file, "and", decrypted_file);
        
        return 0;

    # os.remove(encrypted_file);
    # os.remove(decrypted_file);
    return 1;



def tests():
    os.makedirs("test/files/.out", exist_ok=True);
    for test_file, key, iv in file_tests:
        if not run_cmd_encode_decode(build_encode_decode_test(test_file, key, iv)):
            print("Test failed for file:", test_file)
            sys.exit(1)
        else:
            print("Test 3des-pcbc passed for file:", test_file)

    print("All 3des-pcbc tests passed.")

if __name__ == "__main__":
    tests()