import os
import shlex
import subprocess

from flask import Flask, request

app = Flask(__name__)


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


def build_frontend():
    # ok: ethos.python.shell-input
    subprocess.run("npm ci && npm run build", shell=True, check=True)


def clear_console():
    # ok: ethos.python.shell-input
    subprocess.call("cls" if os.name == "nt" else "clear", shell=True)


def grep_logs(pattern):
    # ruleid: ethos.python.shell-input
    return subprocess.check_output(f"grep {pattern} /var/log/app.log", shell=True)


def tail_file(path):
    # ruleid: ethos.python.shell-input
    subprocess.Popen(args="tail -f " + path, shell=True)


def quoted(path):
    # ok: ethos.python.shell-input
    subprocess.run(f"wc -l {shlex.quote(path)}", shell=True)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # ok: ethos.python.shell-input
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)
