import subprocess


def bare(value):
    # ruleid: ethos.python.bare-except
    try:
        return int(value)
    except:
        return None


def narrow(value):
    # ok: ethos.python.bare-except
    try:
        return int(value)
    except ValueError:
        return None


def run(name):
    # ruleid: ethos.python.shell-input
    subprocess.run("ls " + name, shell=True)
    # ok: ethos.python.shell-input
    subprocess.run(["ls", name])
