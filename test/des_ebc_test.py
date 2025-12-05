import subprocess

test_array = [
    {
        "cmd1": "echo -n \"Hello world\" | ./ft_ssl des-ecb -k 0123456789ABCDEF | hexdump",
        "cmd2": "echo -n \"Hello world\" | openssl enc -des-ecb -K 0123456789ABCDEF -nopad | hexdump"
    },
    {
        "cmd1": "echo -n \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | ./ft_ssl des-ecb -k 0123456789ABCDEF",
        "cmd2": "echo -n \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | openssl enc -des-ecb -K 0123456789ABCDEF -nopad"
    },
    {
        "cmd1": "echo -n \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | ./ft_ssl des-ecb -k 0123456789ABCDEF",
        "cmd2": "echo -n \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | openssl enc -des-ecb -K 0123456789ABCDEF -nopad"
    },
    {
        "cmd1": "echo \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | ./ft_ssl des-ecb -k 0123456789ABCDEF",
        "cmd2": "echo \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | openssl enc -des-ecb -K 0123456789ABCDEF -nopad"
    },
    {
        "cmd1": "echo \"\" | ./ft_ssl des-ecb -k 0123456789ABCDEF",
        "cmd2": "echo \"\" | openssl enc -des-ecb -K 0123456789ABCDEF -nopad"
    },
    {
        "cmd1": "echo \"Hello world\" | ./ft_ssl des-ecb -k 0123456789ABCDEF",
        "cmd2": "echo \"Hello world\" | openssl enc -des-ecb -K 0123456789ABCDEF -nopad"
    }
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