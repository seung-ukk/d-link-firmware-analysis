"""Execute real DIR-882 LocalIPAddress check blocks under Qiling.

The request-parser return value and caller stack are supplied by this harness.
Firmware validation functions are NOT replaced with Python validators.
This is a bounded code-path experiment, not an HTTP server or RCE test.
Reference design: qiling/examples/netgear_6220.py (see README).
"""
from pathlib import Path
import argparse, csv, hashlib, json, os, struct, sys

BASE=Path(__file__).resolve().parent
if sys.platform == 'win32':
    sys.path.insert(0,str(BASE/'deps'))
from qiling import Qiling
from qiling.const import QL_VERBOSE
from elftools.elf.elffile import ELFFile
from prepare_rootfs import prepare

PROFILES={
 'original':{
  'gp':0x4efea0,
  'port_forwarding':{'start':0x454ee8,'continue':0x454f18,'reject':0x455578},
  'virtual_server':{'start':0x456d7c,'continue':0x456dac,'reject':0x4573e4}},
 'hotfix_b03':{
  'gp':0x4f2150,
  'port_forwarding':{'start':0x455b68,'continue':0x455bac,'reject':0x45620c},
  'virtual_server':{'start':0x457a40,'continue':0x457a84,'reject':0x4580bc}}
}
CASES=[('normal','192.0.2.10'),('zero','0.0.0.0'),('out_of_range','999.1.2.3'),
       ('incomplete','192.0.2'),('empty',''),('separator_marker','192.0.2.10;MARKER'),
       ('missing',None)]

def got_slot(path,name):
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        syms=list(elf.get_section_by_name('.dynsym').iter_symbols())
        tags={t.entry.d_tag:t.entry.d_val for t in elf.get_section_by_name('.dynamic').iter_tags() if 'd_val' in t.entry}
        idx=next(i for i,s in enumerate(syms) if s.name==name)
        return elf.get_section_by_name('.got')['sh_addr']+4*(tags['DT_MIPS_LOCAL_GOTNO']+idx-tags['DT_MIPS_GOTSYM'])

def load(label,root_override=None):
    root=Path(root_override) if root_override is not None else prepare(label)
    binary=root/'bin/prog.cgi'
    actual=hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest=json.loads((BASE/'binary_manifest.json').read_text())
    if actual!=manifest[label]['sha256']:raise ValueError('Executable hash differs from address profile')
    old=os.getcwd()
    try:
        os.chdir(root)
        ql=Qiling(['bin/prog.cgi'],str(root),env={'LD_BIND_NOW':'1'},
                  profile=str(BASE/'dir882.ql'),verbose=QL_VERBOSE.OFF)
    finally:os.chdir(old)
    # Unlike the Netgear server demo, this experiment permits no child process
    # or network access and maps no host /proc or device directory.
    def make_blocker(syscall_name):
        def blocked(ql,*args):
            raise RuntimeError(f'{syscall_name} syscall reached outside experiment scope')
        return blocked
    for name in ('execve','execveat','fork','vfork','clone','socket','connect','bind'):
        ql.os.set_syscall(name,make_blocker(name))
    entry=ql.loader.elf_entry
    ql.emu_start(ql.loader.entry_point,entry,timeout=5_000_000,count=2_000_000)
    if ql.arch.regs.arch_pc!=entry:raise RuntimeError('Interpreter did not reach executable entry')
    return ql,binary,actual

def run_case(label,path,case,value):
    result={'firmware':label,'path':path,'case':case,'input':value,
            'scope':'post_request_lookup_to_localip_check_branch',
            'validator_mode':'firmware_machine_code','outcome':'unresolved',
            'validator_calls':0,'visited':[]}
    ql=None
    try:
        ql,binary,digest=load(label)
        result['binary_sha256']=digest
        profile=PROFILES[label];block=profile[path]
        # Caller state is synthetic. Input lookup, XML parsing and authentication
        # are deliberately outside the executed interval.
        stack=0x70000000;size=0x20000;sp=stack+0x10000;input_addr=stack+0x18000
        ql.mem.map(stack,size,info='[localip experiment state]')
        ql.mem.write(sp+0x18,struct.pack('<I',profile['gp']))
        ql.mem.write(sp+0x20,struct.pack('<I',1))
        if value is not None:ql.mem.write(input_addr,value.encode('ascii')+b'\0')
        ql.arch.regs.sp=sp;ql.arch.regs.gp=profile['gp']
        ql.arch.regs.v0=input_addr if value is not None else 0
        check=ql.mem.read_ptr(got_slot(binary,'tbsCheckIp'),4)
        result['validator_address']=hex(check)
        # Confirm that GOT resolution reached the unmodified firmware function,
        # rather than a synthetic validation stub or unresolved import thunk.
        with (binary.parent.parent/'lib/librcm.so').open('rb') as stream:
            elf=ELFFile(stream)
            symbol=next(s for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='tbsCheckIp')
            section=elf.get_section(symbol['st_shndx'])
            offset=symbol['st_value']-section['sh_addr']
            expected_code=section.data()[offset:offset+symbol['st_size']]
        if not expected_code or bytes(ql.mem.read(check,len(expected_code)))!=expected_code:
            raise RuntimeError('Loaded validator differs from firmware function bytes')
        result['validator_code_sha256']=hashlib.sha256(expected_code).hexdigest()
        result['validator_bytes_match']=True
        def validator_enter(ql):result['validator_calls']+=1
        ql.hook_address(validator_enter,check)
        def stop_at(outcome):
            def stop(ql):
                result['outcome']=outcome
                result['visited'].append(hex(ql.arch.regs.arch_pc))
                ql.emu_stop()
            return stop
        ql.hook_address(stop_at('continue_after_localip_check'),block['continue'])
        ql.hook_address(stop_at('reject_at_localip_check'),block['reject'])
        ql.emu_start(block['start'],0,timeout=5_000_000,count=500_000)
        if result['outcome']=='unresolved':result['error']='Instruction/time budget exhausted'
    except Exception as exc:
        result['outcome']='execution_error'
        result['error']=f'{type(exc).__name__}: {exc}'
    finally:
        if ql is not None:result['final_pc']=hex(ql.arch.regs.arch_pc)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware',choices=['all',*PROFILES],default='all')
    parser.add_argument('--path',choices=['all','port_forwarding','virtual_server'],default='all')
    parser.add_argument('--case',choices=['all',*[c[0] for c in CASES]],default='all')
    parser.add_argument('--output',type=Path,default=BASE/'results')
    args=parser.parse_args()
    results=[]
    for label in PROFILES if args.firmware=='all' else [args.firmware]:
        for path in ['port_forwarding','virtual_server'] if args.path=='all' else [args.path]:
            for case,value in CASES:
                if args.case!='all' and args.case!=case:continue
                r=run_case(label,path,case,value);results.append(r)
                print(label,path,case,r['outcome'],r.get('error',''),flush=True)
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/'comparison.json').write_text(json.dumps(results,indent=2,ensure_ascii=False),encoding='utf-8')
    with (args.output/'comparison.csv').open('w',encoding='utf-8-sig',newline='') as stream:
        fields=['firmware','path','case','input','outcome','validator_calls','final_pc','error']
        writer=csv.DictWriter(stream,fieldnames=fields,extrasaction='ignore');writer.writeheader();writer.writerows(results)
    return 1 if any(r['outcome'] in ('execution_error','unresolved') for r in results) else 0

if __name__=='__main__':sys.exit(main())
