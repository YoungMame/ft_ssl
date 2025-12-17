import subprocess
import sys
import os

def build_file_test(test_file, key, iv):
    return ["./ft_ssl", "3des-cbc", "-i", test_file, "-k", key, "-v", iv], \
           ["openssl", "des-ede3-cbc", "-in", test_file, "-K", key, "-iv", iv, "-provider", "default", "-provider", "legacy"]

def build_out_file_test(test_file, test_out_file, key, iv):
    return ["./ft_ssl", "3des-cbc", "-i", test_file, "-o", test_out_file + "_ft_ssl", "-k", key, "-v", iv], \
           ["openssl", "des-ede3-cbc", "-in", test_file, "-out", test_out_file + "_openssl", "-K", key, "-iv", iv, "-provider", "default", "-provider", "legacy"]
def build_encode_decode_cross_test(test_file, test_out_file, test_decrypted_file, key, iv):
    return ["./ft_ssl", "3des-cbc", "-i", test_file, "-o", test_out_file + "_ft_ssl", "-k", key, "-v", iv], \
           ["openssl", "des-ede3-cbc", "-in", test_file, "-out", test_out_file + "_openssl", "-K", key, "-iv", iv, "-provider", "default", "-provider", "legacy"], \
           ["./ft_ssl", "3des-cbc", "-d", "-i", test_out_file + "_openssl", "-o", test_decrypted_file + "_ft_ssl", "-k", key, "-v", iv], \
           ["openssl", "des-ede3-cbc", "-d", "-in", test_out_file + "_ft_ssl", "-out", test_decrypted_file + "_openssl", "-K", key, "-iv", iv, "-provider", "default", "-provider", "legacy"]

file_tests = [
    # [ "test/files/binary", "0C871EEA3AF7AAAA" ],
    [ "test/files/text", "0C871EEA3A53959353267524379562934659463564932562", "0C871EEA3AF7AAAA" ],
    [ "test/files/image.png", "0C871EEA3A53959353267524379562934659463564932562", "0C871EEA3AF7AAAA" ],
]

out_file_tests = [
    [ "test/files/text", "test/files/.out/des_ecb_test_output_text", "0C871EEA3A53959353267524379562934659463564932562", "0C871EEA3AF7AAAA" ],
    [ "test/files/binary", "test/files/.out/des_ecb_test_output_binary", "0C871EEA3A53959353267524379562934659463564932562", "0C871EEA3AF7AAAA" ],
    [ "test/files/image.png", "test/files/.out/des_ecb_test_output_image.png", "0C871EEA3A53959353267524379562934659463564932562", "0C871EEA3AF7AAAA" ],
]

encode_decode_cross_tests = [
    [ "test/files/text", "test/files/.out/text.encrypted", "test/files/.out/text.decrypted","0C871EEA3A53959353267524379562934659463564932562", "0C871EEA3AF7AAAA" ],
    [ "test/files/binary", "test/files/.out/binary.encrypted", "test/files/.out/binary.decrypted","0C871EEA3A53959353267524379562934659463564932562", "0C871EEA3AF7AAAA" ],
    [ "test/files/image.png", "test/files/.out/image.png.encrypted", "test/files/.out/image.png.decrypted","0C871EEA3A53959353267524379562934659463564932562", "0C871EEA3AF7AAAA" ],
]

def run_cmd(cmd):
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False);
    return proc.stdout, proc.stderr;

def run_cmd_out_pair(array):
    out1 = run_cmd(array[0]);
    out2 = run_cmd(array[1]);
    filename1 = array[0][array[0].index("-o") + 1];
    filename2 = array[1][array[1].index("-out") + 1];
    # open(filename1, "w").close();
    # open(filename2, "w").close();
    diff = run_cmd(["diff", filename1, filename2])[0]
    if diff:
        print("Output file mismatch: ", filename1, "and", filename2);
        
        return 0;
    os.remove(filename1);
    os.remove(filename2);
    return 1;

def run_cmd_pair(array):
    out1 = run_cmd(array[0]);
    out2 = run_cmd(array[1]);

    if out1 != out2:
        print("Output mismatch:");
        print("Cmd 1:", " ".join(array[0]));
        print("Cmd 2:", " ".join(array[1]));
        print("Output 1:", out1);
        print("Output 2:", out2);
        return 0;
    return 1;

def run_cmd_pair_x2(array):
    out1a = run_cmd(array[0]);
    out2a = run_cmd(array[1]);

    out1b = run_cmd(array[2]);
    out2b = run_cmd(array[3]);

    filename1 = array[2][array[0].index("-o") + 2];
    filename2 = array[3][array[1].index("-out") + 2];
    print ("Comparing decrypted files:", filename1, "and", filename2);
    diff = run_cmd(["diff", filename1, filename2])[0]
    
    if diff:
        print("Output file mismatch: ", filename1, "and", filename2);
        
        return 0;

    return 1;

def tests():
    os.makedirs("test/files/.out", exist_ok=True);
    for test_file, key, iv in file_tests:
        if not run_cmd_pair(build_file_test(test_file, key, iv)):
            print("Test failed for file:", test_file)
            sys.exit(1)
        else:
            print("Test des-cbc passed for file:", test_file)
    for test_file, test_out_file, key, iv in out_file_tests:
        if not run_cmd_out_pair(build_out_file_test(test_file, test_out_file, key, iv)):
            print("Out file test failed for file:", test_file, "->", test_out_file);
            sys.exit(1)
        else:
            print("Test des-cbc out file passed for file:", test_file, "->", test_out_file);
    for test_file, test_out_file, test_decrypted_file, key, iv in encode_decode_cross_tests:
        if not run_cmd_pair_x2(build_encode_decode_cross_test(test_file, test_out_file, test_decrypted_file, key, iv)):
            print("Encode-decode cross test failed for file:", test_file);
            sys.exit(1);
        else:
            print("Test des-cbc encode-decode cross passed for file:", test_file);

    print("All des-cbc tests passed.")

if __name__ == "__main__":
    tests()