"""Stage a fuller filesystem for a bounded FastCGI startup probe."""
from pathlib import Path
import shutil
from prepare_rootfs import prepare

BASE=Path(__file__).resolve().parent

def prepare_full(label):
    source=BASE.parent/label/'rootfs'
    target=BASE/'runtime_full'/label
    if not target.exists():shutil.copytree(source,target)
    mini=prepare(label)
    for file in (mini/'lib').rglob('*'):
        if file.is_file():
            dst=target/file.relative_to(mini)
            dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(file,dst)
    for path in ('var/run','var/log','tmp','dev','proc'):
        (target/path).mkdir(parents=True,exist_ok=True)
    return target

if __name__=='__main__':
    for label in ('original','hotfix_b03'):print(prepare_full(label))
