import subprocess
import sys
import os

def build_file_test(test_file, key):
    return ["./ft_ssl", "des-ecb", "-i", test_file, "-k", key], \
           ["openssl", "des-ecb", "-in", test_file, "-K", key, "-provider", "default", "-provider", "legacy"]

def build_out_file_test(test_file, test_out_file, key):
    return ["./ft_ssl", "des-ecb", "-i", test_file, "-o", test_out_file + "_ft_ssl", "-k", key], \
           ["openssl", "des-ecb", "-in", test_file, "-out", test_out_file + "_openssl", "-K", key, "-provider", "default", "-provider", "legacy"]

def build_encode_decode_cross_test(test_file, test_out_file, test_decrypted_file, key):
    return ["./ft_ssl", "des-ecb", "-i", test_file, "-o", test_out_file + "_ft_ssl", "-k", key], \
           ["openssl", "des-ecb", "-in", test_file, "-out", test_out_file + "_openssl", "-K", key, "-provider", "default", "-provider", "legacy"], \
           ["./ft_ssl", "des-ecb", "-i", test_out_file + "_openssl", "-o", test_decrypted_file + "_ft_ssl", "-k", key], \
           ["openssl", "des-ecb", "-in", test_out_file + "_ft_ssl", "-out", test_decrypted_file + "_openssl", "-K", key, "-provider", "default", "-provider", "legacy"]

def build_file_password_salt_test(test_file, out_file, password, salt):
    return ["./ft_ssl", "des-ecb", "-i", test_file, "-o", out_file + "_ft_ssl", "-p", password, "-s", salt], \
           ["openssl", "des-ecb", '-pbkdf2', "-iter", "1000", "-in", test_file, "-out", out_file + "_openssl", "-k", password, "-S", salt, "-provider", "default", "-provider", "legacy"]

def build_pbkdf_test(password, salt):
    return ["./ft_ssl", "des-ecb", "-i", "test/files/text", "-p", password, "-s", salt, "-P"], \
           ["openssl", "des-ecb", '-pbkdf2', "-iter", "1000", "-in", "test/files/text", "-k", password, "-S", salt, "-P", "-provider", "default", "-provider", "legacy"]

file_tests = [
    # [ "test/files/binary", "0C871EEA3AF7AAAA" ],
    [ "test/files/text", "0C871EEA3AF7AAAA" ],
    [ "test/files/image.png", "0C871EEA3AF7AAAA" ],
]

out_file_tests = [
    [ "test/files/text", "test/files/.out/des_ecb_test_output_text", "0C871EEA3AF7AAAA" ],
    [ "test/files/binary", "test/files/.out/des_ecb_test_output_binary", "0C871EEA3AF7AAAA" ],
    [ "test/files/image.png", "test/files/.out/des_ecb_test_output_image.png", "0C871EEA3AF7AAAA" ],
]

encode_decode_cross_tests = [
    [ "test/files/text", "test/files/.out/text.encrypted", "test/files/.out/text.decrypted","0C871EEA3AF7AAAA" ],
    [ "test/files/binary", "test/files/.out/binary.encrypted", "test/files/.out/binary.decrypted","0C871EEA3AF7AAAA" ],
    [ "test/files/image.png", "test/files/.out/image.png.encrypted", "test/files/.out/image.png.decrypted","0C871EEA3AF7AAAA" ],
]

file_tests_password_salt = [
    [ "test/files/binary", "test/files/.out/des_ecb_test_pbkdf2.enc",  "MySecretPassword", "0C871EEA3AF7AAAA" ],
    [ "test/files/text", "test/files/.out/des_ecb_test_pbkdf2.enc", "MySecretPassword", "0C871EEA3AF7AAAA" ],
    [ "test/files/image.png", "test/files/.out/des_ecb_test_pbkdf2.enc", "MySecretPassword", "0C871EEA3AF7AAAA" ],
    [ "test/files/image.png", "test/files/.out/des_ecb_test_pbkdf2.enc", "smallPass", "0C871EEA3AF7AAAA" ],
    [ "test/files/image.png", "test/files/.out/des_ecb_test_pbkdf2.enc", "lonNNNNNNNNNNNNNNNNNNGGggggPaassss42gsduhgruiewhrewyiyghwreyghreitreiugh", "0C871EEA3AF7AAAA" ],
    [ "test/files/image.png", "test/files/.out/des_ecb_test_pbkdf2.enc", "lonNNNNNNNNNNNNNNNNNNGGggggPaassss42gsduhgruiewhrewyiyghwreyghreitreiugh", "0C871EEA3AF7AAAA" ],
]

pbkdf_tests = [
    [ "MySecretPassword", "0C871EEA3AF7AAAA" ],
    [ "smallPass", "0C871EEA3AF7AAAA" ],
    [ "lonNNNNNNNNNNNNNNNNNNGGggggPaassss42gsduhgruiewhrewyiyghwreyghreitreiugh", "0C871EEA3AF7AAAA" ],
]

def run_cmd(cmd):
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False);
    return proc.stdout, proc.stderr;

def run_cmd_out_pair(array):
    out1, err1 = run_cmd(array[0]);
    out2, err2 = run_cmd(array[1]);
    filename1 = array[0][array[0].index("-o") + 1];
    filename2 = array[1][array[1].index("-out") + 1];
    # open(filename1, "w").close();
    # open(filename2, "w").close();
    if err1:
        print("Cmd 1 stderr:", err1.decode(errors="ignore"));
    if err2:
        print("Cmd 2 stderr:", err2.decode(errors="ignore"));
    diff = run_cmd(["diff", filename1, filename2])[0]
    if diff:
        print("Output file mismatch: ", filename1, "and", filename2);
        print("Diff output:", diff);
        return 0;
    os.remove(filename1);
    os.remove(filename2);
    return 1;

def run_cmd_pair(array):
    out1, err1 = run_cmd(array[0]);
    out2, err2 = run_cmd(array[1]);
    if err1:
        print("Cmd 1 stderr:", err1.decode(errors="ignore"));
    if err2:
        print("Cmd 2 stderr:", err2.decode(errors="ignore"));
    if out1 != out2:
        print("Output mismatch:");
        print("Cmd 1:", " ".join(array[0]));
        print("Cmd 2:", " ".join(array[1]));
        print("Output 1:", out1);
        print("Output 2:", out2);
        return 0;
    return 1;

def run_cmd_pair_x2(array):
    out1a, err1a = run_cmd(array[0]);
    out2a, err2a = run_cmd(array[1]);
    if err1a or err2a:
        print("Error during command execution:");
        print("Cmd 1 stderr:", err1a.decode(errors="ignore"));
        print("Cmd 2 stderr:", err2a.decode(errors="ignore"));
        return 0;

    out1b, err1b = run_cmd(array[2]);
    out2b, err2b = run_cmd(array[3]);
    if err1b or err2b:
        print("Error during command execution:");
        print("Cmd 1 stderr:", err1b.decode(errors="ignore"));
        print("Cmd 2 stderr:", err2b.decode(errors="ignore"));
        return 0;

    filename1 = array[2][array[0].index("-o") + 1];
    filename2 = array[3][array[1].index("-out") + 1];
    print ("Comparing decrypted files:", filename1, "and", filename2);
    diff = run_cmd(["diff", filename1, filename2])[0]
    if diff:
        print("Output file mismatch: ", filename1, "and", filename2);
        print("Diff output:", diff);
        return 0;

    return 1;

def tests():
    os.makedirs("test/files/.out", exist_ok=True);
    for test_file, key in file_tests:
        if not run_cmd_pair(build_file_test(test_file, key)):
            print("Test failed for file:", test_file)
            sys.exit(1)
        else:
            print("Test des-ecb passed for file:", test_file)
    for test_file, test_out_file, key in out_file_tests:
        if not run_cmd_out_pair(build_out_file_test(test_file, test_out_file, key)):
            print("Out file test failed for file:", test_file, "->", test_out_file);
            sys.exit(1)
        else:
            print("Test des-ecb out file passed for file:", test_file, "->", test_out_file);
    for test_file, test_out_file, test_decrypted_file, key in encode_decode_cross_tests:
        if not run_cmd_pair_x2(build_encode_decode_cross_test(test_file, test_out_file, test_decrypted_file, key)):
            print("Encode-decode cross test failed for file:", test_file);
            sys.exit(1);
        else:
            print("Test des-ecb encode-decode cross passed for file:", test_file);
    # for test_file, out_file, password, salt in file_tests_password_salt:
    #     if not run_cmd_out_pair(build_file_password_salt_test(test_file, out_file, password, salt)):
    #         print("Test failed for file:", test_file);
    #         sys.exit(1);
    #     else:
    #         print("Test des-ecb passed for file:", test_file);
    for password, salt in pbkdf_tests:
        if not run_cmd_pair(build_pbkdf_test(password, salt)):
            print("PBKDF test failed for password:", password, "salt:", salt);
            sys.exit(1);
        else:
            print("Test des-ecb PBKDF passed for password:", password, "salt:", salt);
    print("All des-ecb tests passed.")

if __name__ == "__main__":
    tests()