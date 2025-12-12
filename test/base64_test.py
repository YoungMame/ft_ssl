import subprocess

test_array = [
    {
        "cmd1": "echo -n \"Hello world\" | ./ft_ssl base64",
        "cmd2": "echo -n \"Hello world\" | openssl base64"
    },
    {
        "cmd1": "echo -n \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | ./ft_ssl base64",
        "cmd2": "echo -n \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | openssl base64"
    },
    {
        "cmd1": "echo -n \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | ./ft_ssl base64",
        "cmd2": "echo -n \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | openssl base64"
    },
    {
        "cmd1": "echo \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | ./ft_ssl base64",
        "cmd2": "echo \"sh lk wog oog   sd  ds g   kdsl dsfg ls dds ksdfl glsdkf lsdf l slsd kl ggld l ds ssd \" | openssl base64"
    },
    {
        "cmd1": "echo \"\" | ./ft_ssl base64",
        "cmd2": "echo \"\" | openssl base64"
    },
    {
        "cmd1": "echo \"Hello world\" | ./ft_ssl base64",
        "cmd2": "echo \"Hello world\" | openssl base64"
    },
    {
        "cmd1": "echo \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | ./ft_ssl base64",
        "cmd2": "echo \"Lorem ipsssssssssssssssssssssssssssuuuuuuuuuuuuuum\" | openssl base64"
    },
    {
        "cmd1": "echo -n \"ggggggggggggggggggggggggggggsdsdsdshgshghsghsghsgbsbgbsbjbvbvgbvjbvgbbybiveboiobibwbiv\" | ./ft_ssl base64",
        "cmd2": "echo -n \"ggggggggggggggggggggggggggggsdsdsdshgshghsghsghsgbsbgbsbjbvbvgbvjbvgbbybiveboiobibwbiv\" | openssl base64"
    },
    {
        "cmd1": "echo -n \"1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111\" | ./ft_ssl base64",
        "cmd2": "echo -n \"1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111\" | openssl base64"
    },
    {
        "cmd1": "echo -n \"dmVyeXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5\neXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5\neXl5bG9vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29v\nb29ubm5ubm5ubm5uZwo=\" | ./ft_ssl base64 -d",
        "cmd2": "echo -n \"dmVyeXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5\neXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5\neXl5bG9vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb29v\nb29ubm5ubm5ubm5uZwo=\" | openssl base64 -d",
    }
]

def exec_cmd(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False, shell=True);
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
            print(f"Test base64 {i} passed");
        else:
            print(f"Test base64 {i} failed: {cmd1} != {cmd2}");
            print(f"  {output1} != {output2}");
            exit(0);
        i += 1;

tests();