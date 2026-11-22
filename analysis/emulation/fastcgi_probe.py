"""Send one HNAP FastCGI request to an isolated firmware process.

Run inside the read-only, network-disabled Docker probe container. No port is
published. The response and selected syscall observations are emitted as JSON.
"""
import json
import os
import socket
import struct
import subprocess
import tempfile
import time
from html import escape
import re


def record(kind, payload, request_id=1):
    padding = (-len(payload)) % 8
    return struct.pack('!BBHHBB', 1, kind, request_id, len(payload), padding, 0) + payload + b'\0' * padding


def length(value):
    return bytes([value]) if value < 128 else struct.pack('!I', value | 0x80000000)


def parameter(name, value):
    name, value = name.encode(), value.encode()
    return length(len(name)) + length(len(value)) + name + value


body = b'''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
<SetPortForwardingSettings xmlns="http://purenetworks.com/HNAP1/">
<PortForwardingList><PortForwardingInfo><Enabled>false</Enabled>
<PortForwardingDescription>LOCAL_TEST</PortForwardingDescription>
<TCPPorts>8000</TCPPorts><UDPPorts></UDPPorts>
<LocalIPAddress>192.0.2.10</LocalIPAddress><ScheduleName>Always</ScheduleName>
</PortForwardingInfo></PortForwardingList></SetPortForwardingSettings>
</soap:Body></soap:Envelope>'''
local_ip = os.environ.get('TEST_LOCAL_IP', '192.0.2.10')
body = body.replace(b'192.0.2.10', escape(local_ip).encode())
udp_ports = os.environ.get('TEST_UDP_PORTS', '')
if udp_ports:
    body = body.replace(b'<UDPPorts></UDPPorts>',
                        b'<UDPPorts>' + escape(udp_ports).encode() + b'</UDPPorts>')
if os.environ.get('TEST_ENABLED') == '1':
    body = body.replace(b'<Enabled>false</Enabled>', b'<Enabled>true</Enabled>')
params = {
    'REQUEST_METHOD': 'POST', 'REQUEST_URI': '/HNAP1/', 'SCRIPT_NAME': '/HNAP1/',
    'SERVER_PROTOCOL': 'HTTP/1.1', 'SERVER_NAME': 'localhost', 'SERVER_PORT': '80',
    'REMOTE_ADDR': '127.0.0.1', 'CONTENT_TYPE': 'text/xml; charset=utf-8',
    'CONTENT_LENGTH': str(len(body)),
    'HTTP_CONTENT_LENGTH': str(len(body)),
    'HTTP_SOAPACTION': '"http://purenetworks.com/HNAP1/SetPortForwardingSettings"',
    'QUERY_STRING': '', 'PATH_INFO': '', 'DOCUMENT_ROOT': '/etc_ro/lighttpd/www/web',
    'SCRIPT_FILENAME': '/bin/prog.cgi', 'GATEWAY_INTERFACE': 'CGI/1.1',
    'SERVER_SOFTWARE': 'lighttpd', 'SERVER_ADDR': '127.0.0.1',
    'REMOTE_PORT': '12345', 'HTTP_HOST': 'localhost', 'HTTP_USER_AGENT': 'LocalFirmwareLab',
    'HTTP_ACCEPT': '*/*', 'HTTP_COOKIE': '', 'HTTP_HNAP_AUTH': '',
}
message = record(1, struct.pack('!HB5s', 1, 0, b'\0' * 5))
message += record(4, b''.join(parameter(k, v) for k, v in params.items()))
message += record(4, b'') + record(5, body) + record(5, b'')

path = '/tmp/dir882-fcgi.sock'
try:
    os.unlink(path)
except FileNotFoundError:
    pass
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(path)
listener.listen(2)
result = {'request_action': 'SetPortForwardingSettings', 'local_ip': local_ip,
          'udp_ports': udp_ports,
          'enabled': os.environ.get('TEST_ENABLED') == '1',
          'fastcgi_bytes_sent': len(message), 'response_bytes': 0}
label = os.environ.get('FIRMWARE_LABEL', 'original')
watch = {
    'original': {'hnap_dispatch': 0x4b337c, 'localip_check_start': 0x454ee8,
                 'localip_continue': 0x454f18, 'localip_reject': 0x455578},
    'hotfix_b03': {'hnap_dispatch': 0x4b525c, 'localip_check_start': 0x455b68,
                   'localip_continue': 0x455bac, 'localip_reject': 0x45620c},
}[label]
result['firmware'] = label
debug = os.environ.get('DEBUG_GDB') == '1'
trace_command_path = os.environ.get('TRACE_COMMAND_PATH') == '1'
gdb_proc = None
if debug:
    validator_commands = ''
    continue_bp, reject_bp = (4, 5) if label == 'hotfix_b03' else (2, 3)
    if label == 'hotfix_b03':
        validator_commands = '''break *0x455b80
commands
silent
printf "VALIDATOR_CALL target=%p a0=%p\\n", $t9, $a0
x/s $a0
x/i $t9
continue
end
break *0x455b88
commands
silent
printf "VALIDATOR_RETURN pc=%p v0=%d\\n", $pc, $v0
continue
end
'''
    if trace_command_path:
        rule_end, nvram_call, apply_call = (
            (0x455504, 0x455530, 0x45556c) if label == 'original'
            else (0x456198, 0x4561c4, 0x456200))
        continue_bp += 3
        reject_bp += 3
        validator_commands += f'''break *0x{rule_end:x}
commands
silent
printf "RULE_BUILT pc=%p status=", $pc
x/wx $sp+0x20
printf "RULE_VALUE "
x/s $sp+0x4c
continue
end
'''
        validator_commands += f'''break *0x{nvram_call:x}
commands
silent
printf "NVRAM_SAFE_SET pc=%p key=", $pc
x/s $a0
printf "NVRAM_VALUE "
x/s $a1
continue
end
break *0x{apply_call:x}
commands
silent
printf "SERVICE_APPLY pc=%p a0=%d a1=%d\\n", $pc, $a0, $a1
continue
end
'''
    script = f'''set pagination off
set sysroot /firmware
set confirm off
set debuginfod enabled off
file /firmware/bin/prog.cgi
target remote 127.0.0.1:1234
break *0x{watch['localip_check_start']:x}
commands
silent
printf "LOCALIP_START pc=%p v0=%p sp=%p\\n", $pc, $v0, $sp
x/s $v0
continue
end
{validator_commands}
break *0x{watch['localip_continue']:x}
commands
silent
printf "LOCALIP_CONTINUE pc=%p\\n", $pc
disable {continue_bp}
disable {reject_bp}
continue
end
break *0x{watch['localip_reject']:x}
commands
silent
printf "LOCALIP_REJECT pc=%p\\n", $pc
disable {continue_bp}
disable {reject_bp}
continue
end
continue
'''
    with open('/tmp/dir882.gdb', 'w') as commands:
        commands.write(script)
with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as trace:
    command = ['qemu-mipsel', '-strace', '-d', 'in_asm,exec',
                             '-D', '/tmp/dir882-exec.log', '-L', '/firmware',
                             '/firmware/bin/prog.cgi']
    if debug:
        command[1:1] = ['-g', '1234']
    proc = subprocess.Popen(command, stdin=listener.fileno(),
                            stdout=output, stderr=trace,
                            env={**os.environ, 'LD_BIND_NOW': '1'})
    try:
        if debug:
            time.sleep(0.5)
            gdb_proc = subprocess.Popen(['gdb-multiarch', '-q', '-batch', '-x',
                                         '/tmp/dir882.gdb'], stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(60 if debug else 3)
        client.connect(path)
        client.sendall(message)
        chunks = []
        deadline = time.monotonic() + (60 if debug else 4)
        while time.monotonic() < deadline:
            try:
                block = client.recv(65536)
            except socket.timeout:
                break
            if not block:
                break
            chunks.append(block)
            if b'\x01\x03\x00\x01' in block:
                break
        response = b''.join(chunks)
        result['response_bytes'] = len(response)
        result['response_preview'] = response[:1200].decode('utf-8', 'replace')
        match = re.search(rb'<SetPortForwardingSettingsResult>([^<]+)', response)
        result['soap_result'] = match.group(1).decode() if match else None
        client.close()
    except Exception as exc:
        result['client_error'] = f'{type(exc).__name__}: {exc}'
    finally:
        listener.close()
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        result['process_exit_code'] = proc.returncode
        result['marker_file_created'] = any(os.path.exists(path) for path in
                                            ('/tmp/dir882_command_marker', '/tmp/d882'))
        if gdb_proc is not None:
            try:
                gdb_output, _ = gdb_proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                gdb_proc.kill()
                gdb_output, _ = gdb_proc.communicate()
            result['gdb_exit_code'] = gdb_proc.returncode
            result['gdb_output'] = gdb_output[-8000:]
            decision = re.search(r'LOCALIP_(CONTINUE|REJECT) pc=', gdb_output)
            result['first_localip_decision'] = decision.group(1) if decision else None
            if trace_command_path:
                result['rule_built_seen'] = 'RULE_BUILT pc=' in gdb_output
                result['nvram_safe_set_seen'] = 'NVRAM_SAFE_SET pc=' in gdb_output
                result['service_apply_seen'] = 'SERVICE_APPLY pc=' in gdb_output
        trace.seek(0)
        lines = trace.read().decode('utf-8', 'replace').splitlines()
        result['relevant_syscalls'] = [line for line in lines if any(
            key in line for key in ('getpeername(', 'accept(', 'read(', 'open("/dev/apsoc_nvram"',
                                        'chdir("/etc_ro/', 'exit('))][-30:]
        result['trace_tail'] = lines[-30:]
        output.seek(0)
        result['stdout_preview'] = output.read(1000).decode('utf-8', 'replace')
        try:
            with open('/tmp/dir882-exec.log', errors='replace') as execution:
                execution_lines = execution.readlines()
                result['execution_tail'] = execution_lines[-35:]
                joined = ''.join(execution_lines)
                result['watch_address_translated'] = {
                    key: bool(re.search(rf'0x0*{address:x}:', joined))
                    for key, address in watch.items()
                }
                result['watch_tb_execution_count'] = {
                    key: len(re.findall(rf'^Trace 0: .*?/0*{address:x}/', joined,
                                        re.MULTILINE))
                    for key, address in watch.items()
                }
        except FileNotFoundError:
            result['execution_tail'] = []
print(json.dumps(result, ensure_ascii=False, indent=2))
