"""Host PTY regression: python3 tests/shell_transport.py /path/to/debug/ssal."""
import errno
import fcntl
import os
import pathlib
import pty
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time

with tempfile.TemporaryDirectory(prefix="ssal-terminal-") as temporary:
    directory = pathlib.Path(temporary)
    binary = directory / "ssal"
    shutil.copy2(sys.argv[1], binary)
    worker = directory / "ssald"
    worker.write_text("""#!/usr/bin/env python3
import fcntl, os, sys, termios
assert sys.argv[1] == '--shell-session' and sys.argv[3] == '--'
words = sys.argv[4:]
if words:
    os.execvp(words[0], words)
os.setsid()
fcntl.ioctl(0, termios.TIOCSCTTY, 0)
os.environ['PS1'] = 'SSAL_PROMPT> '
os.execv('/bin/sh', ['sh', '-i'])
""")
    worker.chmod(0o755)
    output = subprocess.run(
        [binary, "exec", "one", "--", "/bin/sh", "-c", 'printf "%s" "$1"; exit 37', "sh", "a b;$()"],
        capture_output=True, check=False,
    )
    assert (output.returncode, output.stdout, output.stderr) == (37, b"a b;$()", b""), output
    output = subprocess.run([binary, "exec", "--", "/bin/sh"], input=b"printf FIRST\nprintf SECOND\n", capture_output=True, check=False)
    assert (output.returncode, output.stdout, output.stderr) == (0, b"FIRSTSECOND", b""), output
    streaming = subprocess.Popen([binary, "exec", "--", "/bin/sh", "-c", 'printf PROMPT; read value; printf "%s" "$value"'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert select.select([streaming.stdout], [], [], 5)[0], "unflushed prompt"
        assert os.read(streaming.stdout.fileno(), 6) == b"PROMPT"
        assert streaming.communicate(b"reply\n", timeout=5) == (b"reply", b"")
        assert streaming.returncode == 0
    finally:
        if streaming.poll() is None:
            streaming.kill()
            streaming.wait()
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    child = subprocess.Popen([binary, "shell", "one"], stdin=slave, stdout=slave, stderr=slave)
    transcript = bytearray()

    def until(marker):
        deadline = time.monotonic() + 10
        while marker not in transcript:
            assert time.monotonic() < deadline, bytes(transcript)
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 8192)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    chunk = b""
                assert chunk, bytes(transcript)
                transcript.extend(chunk)

    try:
        until(b"SSAL_PROMPT> ")
        os.write(master, b"printf 'READY_RESULT\\n'; stty size\n")
        until(b"\r\n24 80\r\n")
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 31, 97, 0, 0))
        time.sleep(0.3)
        os.write(master, b"stty size\n")
        until(b"\r\n31 97\r\n")
        os.write(master, b"sleep 30\n")
        time.sleep(0.2)
        os.write(master, b"\x03")
        time.sleep(0.2)
        os.write(master, b"printf 'INTERRUPT_RESULT\\n'; exit 37\n")
        until(b"\r\nINTERRUPT_RESULT\r\n")
        assert child.wait(timeout=5) == 37
        assert termios.tcgetattr(slave) == original
        print("PASS: argv, stdout/stderr, status, PTY input/output, resize, Ctrl-C, terminal restore")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        os.close(master)
        os.close(slave)
