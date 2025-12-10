import subprocess

test_array = [
    {
        "cmd1": "echo -n \"Hello world\" | ./ft_ssl des-ecb -k 0123456789ABCDEF | hexdump",
        "cmd2": "echo -n \"Hello world\" | openssl des-ecb -K 0123456789ABCDEF -provider default -provider legacy | hexdump"
    },
    {
        "cmd1": "echo -n \"Hello world\" | ./ft_ssl des-ecb -p pass -s 0123456789ABCDEF -p pass | hexdump",
        "cmd2": "echo -n \"Hello world\" | openssl des-ecb -pbkdf2 -k pass -S 0123456789ABCDEF -provider default -provider legacy | hexdump"
    },
]

def exec_cmd(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True);
    if (result.returncode != 0):
        print(f"Command '{cmd}' failed with error: {result.stderr}");
    return result.stdout;

def tests():
    i = 0;
    for test in test_array:
        cmd1 = test.get("cmd1");
        cmd2 = test.get("cmd2");

        output1 = exec_cmd(cmd1);

        output2 = exec_cmd(cmd2);

        if output1.strip() == output2.strip():
            print(f"Test {i} passed");
        else:
            print(f"Test {i} failed: {cmd1} != {cmd2}");
            print(f"  {output1} != {output2}");
            exit(0);
        i += 1;

tests();