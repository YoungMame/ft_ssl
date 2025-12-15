import subprocess

test_array = [
    {
        "cmd1": "echo -n \"Hello world\" | ./ft_ssl sha256",
        "cmd2": "echo -n \"Hello world\" | openssl sha256"
    },
    {
        "cmd1": "echo -n \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | ./ft_ssl sha256",
        "cmd2": "echo -n \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | openssl sha256"
    },
    {
        "cmd1": "echo -n \"\" | ./ft_ssl sha256",
        "cmd2": "echo -n \"\" | openssl sha256"
    },
    {
        "cmd1": "echo -n \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | ./ft_ssl sha256",
        "cmd2": "echo -n \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | openssl sha256"
    },
    {
        "cmd1": "echo \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | ./ft_ssl sha256",
        "cmd2": "echo \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | openssl sha256"
    },
    {
        "cmd1": "echo \"\" | ./ft_ssl sha256",
        "cmd2": "echo \"\" | openssl sha256"
    },
    {
        "cmd1": "echo \"Hello world\" | ./ft_ssl sha256",
        "cmd2": "echo \"Hello world\" | openssl sha256"
    },
    {
        "cmd1": "echo \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | ./ft_ssl sha256",
        "cmd2": "echo \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | openssl sha256"
    },
    {
        "cmd1": "echo -n \"ggggggggggggggggggggggggggggsdsdsdshgshghsghsghsgbsbgbsbjbvbvgbvjbvgbbybiveboiobibwbiv\" | ./ft_ssl sha256",
        "cmd2": "echo -n \"ggggggggggggggggggggggggggggsdsdsdshgshghsghsghsgbsbgbsbjbvbvgbvjbvgbbybiveboiobibwbiv\" | openssl sha256"
    },
    {
        "cmd1": "echo -n \"1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111\" | ./ft_ssl sha256",
        "cmd2": "echo -n \"1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111\" | openssl sha256"
    },
    {
        "cmd1": "echo \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | ./ft_ssl sha256",
        "cmd2": "echo \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | openssl sha256"
    },
]

def exec_cmd(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True);
    if (result.returncode != 0):
        print(f"Command '{cmd}' failed with error: {result.stderr}");
    return result.stdout;

def parse_output(output):
    outputs = output.split('= ');
    if len(outputs) < 2:
        print(f"Unexpected output format: {output} for sha256");
        return "";
    return outputs[1];

def tests():
    print("Starting SHA256 tests...");
    i = 0;
    for test in test_array:
        cmd1 = test.get("cmd1");
        cmd2 = test.get("cmd2");

        output1 = exec_cmd(cmd1);
        hash1 = parse_output(output1);

        output2 = exec_cmd(cmd2);
        hash2 = parse_output(output2);

        if hash1 == hash2:
            print(f"Test sha256 {i} passed");
        else:
            # print(f"Test sha256 {i} failed: {cmd1} != {cmd2}");
            # print(f"  {hash1} != {hash2}");
            exit(0);
        i += 1;

tests();