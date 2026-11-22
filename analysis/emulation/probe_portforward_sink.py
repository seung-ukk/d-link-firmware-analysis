"""Bounded Qiling probe of firmware PORTFORWARD_run with synthetic NVRAM.

Modes can record the command boundary or continue into the supplied MIPS
BusyBox shell inside an isolated copied rootfs. This does not run the full
HTTP/setting service.
"""
from pathlib import Path
import argparse
from collections import deque
import hashlib
import json

from compare_localip import load, got_slot
from elftools.elf.elffile import ELFFile

BASE = Path(__file__).resolve().parent
KEY = 'portforward_rule'
MARKER = '1$(>/tmp/d882)'
RULE_TEMPLATE = '1,LOCAL_TEST,{ip},8000,8000,Always'


def symbol_value(path, name):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        symbol = next(s for s in elf.get_section_by_name('.dynsym').iter_symbols()
                      if s.name == name)
        return symbol['st_value']


def function_bytes(path, virtual_address, size=64):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        segment = next(s for s in elf.iter_segments()
                       if s['p_type'] == 'PT_LOAD' and
                       s['p_vaddr'] <= virtual_address < s['p_vaddr'] + s['p_filesz'])
        stream.seek(segment['p_offset'] + virtual_address - segment['p_vaddr'])
        return stream.read(size)


def cstring(ql, address, max_bytes=4096):
    if address == 0:
        return None
    return ql.mem.string(address)[:max_bytes]


def run(label, ip, trace_shell=False, execute_shell=False, root_override=None,
        rule_override=None):
    if execute_shell and not root_override:
        raise ValueError('execute_shell requires a writable staged rootfs')
    ql, binary, digest = load(label, root_override=root_override)
    lib = binary.parent.parent / 'lib/librcm.so'
    tbs_addr = ql.mem.read_ptr(got_slot(binary, 'tbsCheckIp'), 4)
    bias = tbs_addr - symbol_value(lib, 'tbsCheckIp')
    function = bias + symbol_value(lib, 'PORTFORWARD_run')
    portforward_bytes = function_bytes(lib, symbol_value(lib, 'PORTFORWARD_run'))
    twsystem_bytes = function_bytes(lib, symbol_value(lib, 'twsystem'))
    rule = rule_override if rule_override is not None else RULE_TEMPLATE.format(ip=ip)
    if rule_override is not None and rule_override != RULE_TEMPLATE.format(ip=ip):
        raise ValueError('Captured rule differs from expected input and port settings')
    result = {'firmware': label, 'ip': ip, 'rule': rule,
              'mode': ('synthetic_nvram_firmware_shell_execution' if execute_shell
                       else 'synthetic_nvram_second_stage'),
              'function_args': {'operation': 1, 'schedule': 'Always'},
              'binary_sha256': digest, 'librcm_bias': hex(bias),
              'librcm_sha256': hashlib.sha256(lib.read_bytes()).hexdigest(),
              'portforward_run': hex(function), 'nvram_calls': [],
              'commands': [], 'outcome': 'unresolved'}
    result['portforward_code_bytes_match'] = (
        bytes(ql.mem.read(function, len(portforward_bytes))) == portforward_bytes)
    result['twsystem_code_bytes_match'] = (
        bytes(ql.mem.read(bias + symbol_value(lib, 'twsystem'),
                          len(twsystem_bytes))) == twsystem_bytes)
    if not result['portforward_code_bytes_match'] or not result['twsystem_code_bytes_match']:
        raise RuntimeError('Loaded MIPS library code differs from the supplied firmware')
    trace_enabled = {'value': False}
    recent = deque(maxlen=80)

    state = 0x70000000
    ql.mem.map(state, 0x30000, info='[synthetic sink probe state]')
    ql.mem.write(state + 0x20000, rule.encode() + b'\0')
    ql.mem.write(state + 0x21000, b'1\0')
    ql.mem.write(state + 0x22000, b'\0')
    ql.mem.write(state + 0x23000, b'eth0\0')
    ql.mem.write(state + 0x24000, b'dhcp\0')
    ql.mem.write(state + 0x25000, b'192.0.2.1\0')
    ql.mem.write(state + 0x26000, b'255.255.255.0\0')
    ql.mem.write(state + 0x27000, b'Always\0')
    ql.arch.regs.sp = state + 0x18000
    ql.arch.regs.ra = state + 0x1000
    ql.arch.regs.t9 = function
    ql.arch.regs.a0 = 1
    ql.arch.regs.a1 = state + 0x27000

    def returned(value):
        ql.arch.regs.v0 = value
        ql.arch.regs.arch_pc = ql.arch.regs.ra

    def hook_nvram(name):
        def handler(ql):
            key = cstring(ql, ql.arch.regs.a0)
            result['nvram_calls'].append({'api': name, 'key': key,
                                          'return_to': hex(ql.arch.regs.ra)})
            if key == KEY:
                trace_enabled['value'] = True
            if name == 'nvram_get_int':
                returned(1 if key == 'portforward_max_num' else 0)
            else:
                values = {
                    KEY: 0x20000,
                    'portforward_enable': 0x21000,
                    'wan_wan_count': 0x21000,
                    'wan_wan0_enable': 0x21000,
                    'wan_wan0_ifname': 0x23000,
                    'wan_wan0_proto': 0x24000,
                    'wan_wan0_ipaddr': 0x25000,
                    'wan_wan0_netmask': 0x26000,
                }
                returned(state + values.get(key, 0x22000))
        return handler

    for name in ('nvram_get', 'nvram_safe_get', 'nvram_get_int'):
        try:
            address = ql.mem.read_ptr(bias + got_slot(lib, name), 4)
        except Exception:
            continue
        ql.hook_address(hook_nvram(name), address)

    def hook_command(name):
        def handler(ql):
            command = cstring(ql, ql.arch.regs.a0, 8192)
            result['commands'].append({'api': name, 'argument': command,
                                       'second_arg': ql.arch.regs.a1})
            if (trace_shell or execute_shell) and name == 'twsystem':
                return
            returned(0)
        return handler

    for name in ('system', 'twsystem'):
        address = ql.mem.read_ptr(bias + got_slot(lib, name), 4)
        ql.hook_address(hook_command(name), address)

    if trace_shell or execute_shell:
        def fake_fork(ql):
            result['fork_intercepted'] = True
            returned(0)
        fork_addr = ql.mem.read_ptr(bias + got_slot(lib, 'fork'), 4)
        ql.hook_address(fake_fork, fork_addr)

        if execute_shell:
            from qiling.os.posix.syscall.unistd import ql_syscall_execve, ql_syscall_fork
            ql.os.set_syscall('execve', ql_syscall_execve)
            ql.os.set_syscall('fork', ql_syscall_fork)
            ql.os.set_syscall('vfork', ql_syscall_fork)

        def record_execv(ql):
            path = cstring(ql, ql.arch.regs.a0)
            argv_ptr = ql.arch.regs.a1
            argv = []
            for index in range(8):
                item = ql.mem.read_ptr(argv_ptr + 4 * index, 4)
                if not item:
                    break
                argv.append(cstring(ql, item))
            key = 'execv_observed' if execute_shell else 'execv_intercepted'
            result[key] = {'path': path, 'argv': argv}
            if not execute_shell:
                result['outcome'] = 'execv_intercepted'
                ql.emu_stop()
        execv_addr = ql.mem.read_ptr(bias + got_slot(lib, 'execv'), 4)
        ql.hook_address(record_execv, execv_addr)

    def finished(ql):
        result['outcome'] = 'returned'
        ql.emu_stop()
    ql.hook_address(finished, state + 0x1000)
    def parsed_fields(ql):
        sp = ql.arch.regs.sp
        result['parsed_fields'] = {
            'field0': cstring(ql, sp + 44),
            'field1': cstring(ql, sp + 100),
            'field2': cstring(ql, sp + 52),
            'field3': cstring(ql, sp + 708),
            'field4': cstring(ql, sp + 452),
            'field4_result': ql.arch.regs.v0,
        }
    ql.hook_address(parsed_fields, bias + 0x316f4)
    def invalid_memory(ql, access, address, size, value):
        result['invalid_memory'] = {'address': hex(address), 'size': size,
                                    'pc': hex(ql.arch.regs.arch_pc),
                                    'ra': hex(ql.arch.regs.ra),
                                    'a0': hex(ql.arch.regs.a0),
                                    'a1': hex(ql.arch.regs.a1)}
        return False
    ql.hook_mem_invalid(invalid_memory)
    def trace_code(ql, address, size):
        if trace_enabled['value'] and function <= address < function + 0x1780:
            recent.append(hex(address - bias))
    ql.hook_code(trace_code)
    try:
        ql.emu_start(function, 0, timeout=10_000_000, count=2_000_000)
        if result['outcome'] == 'unresolved':
            result['outcome'] = 'budget_or_stopped'
    except Exception as exc:
        result['outcome'] = 'execution_error'
        result['error'] = f'{type(exc).__name__}: {exc}'
    result['final_pc'] = hex(ql.arch.regs.arch_pc)
    if execute_shell:
        marker_path = Path(root_override) / 'tmp/d882'
        shell_path = Path(root_override) / 'bin/sh'
        source_shell = BASE.parent / label / 'rootfs/bin/busybox'
        shell_hash = hashlib.sha256(shell_path.read_bytes()).hexdigest()
        result['guest_shell_sha256'] = shell_hash
        result['guest_shell_matches_firmware_busybox'] = (
            shell_hash == hashlib.sha256(source_shell.read_bytes()).hexdigest())
        result['guest_marker_exists'] = marker_path.is_file()
        result['guest_marker_size'] = (marker_path.stat().st_size
                                       if marker_path.exists() else None)
        result['guest_exit_code'] = getattr(ql.os, 'exit_code', None)
        if result.get('execv_observed') and result['guest_exit_code'] is not None:
            result['outcome'] = 'guest_shell_exited'
    result['recent_portforward_addresses'] = list(recent)
    result['marker_in_command'] = any('$(>/tmp/d882)' in (x['argument'] or '')
                                      for x in result['commands'])
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--firmware', choices=('original', 'hotfix_b03'),
                        default='original')
    parser.add_argument('--marker', action='store_true')
    parser.add_argument('--trace-shell', action='store_true')
    parser.add_argument('--execute-shell', action='store_true')
    parser.add_argument('--root-override', type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.firmware, MARKER if args.marker else '192.0.2.10',
                         trace_shell=args.trace_shell,
                         execute_shell=args.execute_shell,
                         root_override=args.root_override),
                     ensure_ascii=False, indent=2))
