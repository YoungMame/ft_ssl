import subprocess
import sys
import tempfile
from pathlib import Path

TEST_FILE = "test/files/text"
KEY = "0123456789ABCDEF"

FTSSL_CMD = ["./ft_ssl", "des-ecb", "-i", TEST_FILE, "-k", KEY]
OPENSSL_CMD = ["openssl", "des-ecb", "-in", TEST_FILE, "-K", KEY, "-provider", "default", "-provider", "legacy"]

def run_cmd(cmd):
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.returncode, proc.stdout, proc.stderr

def tests():
    rc1, out1, err1 = run_cmd(FTSSL_CMD)
    if rc1 != 0:
        print("ft_ssl failed:", err1.decode(errors="ignore"))
        sys.exit(1)

    rc2, out2, err2 = run_cmd(OPENSSL_CMD)
    if rc2 != 0:
        print("openssl failed:", err2.decode(errors="ignore"))
        sys.exit(1)

    if out1 == out2:
        print("Test des-ecb passed")
        return

    # Debug: dump to temp files and run diff for human-readable output
    with tempfile.NamedTemporaryFile(delete=False) as a, tempfile.NamedTemporaryFile(delete=False) as b:
        a.write(out1); a.flush()
        b.write(out2); b.flush()
        print("Outputs differ; written to:", a.name, b.name)
        # call system diff for nicer info
        subprocess.run(["diff", "-u", a.name, b.name])
    sys.exit(1)

if __name__ == "__main__":
    tests()