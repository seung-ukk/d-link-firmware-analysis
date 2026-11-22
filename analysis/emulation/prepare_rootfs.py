"""Create an independent, ordinary-file-only loader root for each firmware."""
from pathlib import Path, PurePosixPath
import json, shutil

BASE=Path(__file__).resolve().parent
ANALYSIS=BASE.parent

def prepare(label):
    source=ANALYSIS/label/'rootfs'
    target=BASE/'runtime'/label
    target.mkdir(parents=True,exist_ok=True)
    records=json.loads((source.parent/'rootfs_inventory.json').read_text(encoding='utf-8'))
    indexed={r['path']:r for r in records}
    def resolve(path,seen=()):
        if path in seen:raise ValueError(f'Link cycle: {path}')
        item=indexed[path]
        if 'symlink_target' not in item:return source/path
        link=item['symlink_target'].rstrip('\0')
        parts=[] if link.startswith('/') else list(PurePosixPath(path).parent.parts)
        for part in PurePosixPath(link).parts:
            if part in ('/','.'):continue
            if part=='..':
                if not parts:raise ValueError('Link escapes root')
                parts.pop()
            else:parts.append(part)
        return resolve('/'.join(parts),seen+(path,))
    for item in records:
        rel=item['path']
        if not (rel.startswith('lib/') or rel=='bin/prog.cgi'):continue
        if int(item['mode'],8)&0o170000==0o040000:continue
        src=resolve(rel)
        if not src.is_file():continue
        dst=target/rel
        dst.parent.mkdir(parents=True,exist_ok=True)
        if not dst.exists() or dst.read_bytes()!=src.read_bytes():shutil.copyfile(src,dst)
    return target

if __name__=='__main__':
    for label in ('original','hotfix_b03'):print(prepare(label))
