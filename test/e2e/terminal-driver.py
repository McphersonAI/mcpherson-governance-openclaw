"""Disposable PTY driver; secrets arrive through stdin, never argv or logs."""
import json, os, pty, select, signal, sys, time

data = json.load(sys.stdin)
pid, fd = pty.fork()
if pid == 0:
    os.execve(data['executable'], data['argv'], data['env'])
output = b''
step = 0
deadline = time.monotonic() + 90
try:
    while time.monotonic() < deadline:
        if select.select([fd], [], [], 0.2)[0]:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
        if step < len(data['inputs']) and data['inputs'][step][0].encode() in output:
            os.write(fd, (data['inputs'][step][1] + '\n').encode())
            step += 1
    else:
        os.kill(pid, signal.SIGTERM)
        raise RuntimeError('PTY qualification deadline')
    _, status = os.waitpid(pid, 0)
    print(json.dumps({'code': os.waitstatus_to_exitcode(status), 'steps': step, 'output': output.decode(errors='replace')}))
finally:
    os.close(fd)
