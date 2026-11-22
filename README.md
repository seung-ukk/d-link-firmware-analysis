# DIR-882 Rev A 팀 실습: 1차·2차 중간보고서 재현

대상은 일반 v1.30B06과 HOTFIX_B03의 `LocalIPAddress` 입력 경로다. 팀원은 WSL Ubuntu에서 ZIP 확인 → SHRS 복호화 → LZMA·CPIO·rootfs 추출 → 웹 구성 확인 → Docker 이미지 빌드 → FastCGI·GDB 비교 → 별도 MIPS 규칙 적용·BusyBox 셸 실험을 **한 단계씩** 수행한다. 실물 공유기는 필요하지 않다. `prog.cgi`는 추출된 **컴파일된 실행파일**이며 원본 소스코드가 아니다.

## 0. 준비

저장소에는 Dockerfile과 분석 코드만 넣는다. 펌웨어 ZIP·BIN, 추출된 파일시스템, Docker 이미지, 실행 결과는 Git에서 제외한다. 각 팀원은 [D-Link 공식 DIR-882 Rev A 다운로드 목록](https://support.dlink.com/resource/products/dir-882/REVA/)에서 두 ZIP을 직접 받는다. Docker 이미지는 clone한 뒤 각자 빌드한다.

WSL Ubuntu, Docker Desktop Linux 엔진, Python 3, `cryptography`, `curl`, `file`, `xxd`, `readelf`, `jq`가 필요하다. 모든 명령은 **clone한 저장소 루트의 WSL 터미널**에서 실행한다. 컨테이너 안 명령은 `root@...:/firmware#` 프롬프트에서만 입력한다. 예상과 다른 출력은 그대로 기록한다.

```bash
git clone https://github.com/seung-ukk/d-link-firmware-analysis.git
cd d-link-firmware-analysis
docker info --format '{{.OSType}} {{.ServerVersion}}'
python3 -c 'from cryptography.hazmat.primitives.ciphers import Cipher; print("ready")'
```

`linux ...`과 `ready`를 확인한다. Python 모듈이 없으면 Ubuntu에서 `sudo apt-get update` 후 `sudo apt-get install python3-cryptography`를 실행한다. 다른 도구가 없으면 `sudo apt-get install curl file xxd binutils jq`로 준비한다. **화면 1:** Docker 엔진과 도구 확인.

```bash
curl -fL 'https://support.dlink.com/resource/products/dir-882/REVA/DIR-882_REVA_FIRMWARE_v1.30B06.zip' -o firmware/original.zip
curl -fL 'https://support.dlink.com/resource/products/dir-882/REVA/DIR-882_REVA_FIRMWARE_v1.30B06%20HOTFIX_B03.zip' -o firmware/hotfix_b03.zip
python3 lab/firmware.py verify original
python3 lab/firmware.py verify hotfix_b03
```

브라우저에서 받아 위 이름으로 놓아도 된다. `verify`는 ZIP SHA-256, CRC, 내부 BIN·PDF 목록을 확인한다. 원본 ZIP의 SHA-256은 `fe85902d34cbeae8340fb6f9bf05117d445bcedf3fc6b8b017c3bedf2baff86a`, Hotfix는 `79e8712201b40ea128b8e776d7d0c02c0ae25e58b60d0b02d3d928eaa2cea5d1`이다. 다르면 파일명·버전·다운로드 완료 여부를 확인한다. **화면 2:** 두 ZIP 검사.

## 1. 1차 보고서: 단계별 언패킹

각 줄을 직접 실행하고 출력을 확인한다. 같은 단계의 출력 파일이 이미 있으면 도구가 덮어쓰지 않고 중단한다. Docker로 복호화용 Python을 준비하려면 `docker build -f lab/Dockerfile.unpack -t dir882-unpack:local .`을 실행하고 각 Python 호출을 `docker run --rm --network none -v "$PWD:/work" dir882-unpack:local python3 lab/firmware.py <단계> <버전>`으로 바꿀 수 있다.

```bash
python3 lab/firmware.py unzip original
python3 lab/firmware.py unzip hotfix_b03
python3 lab/firmware.py decrypt original
python3 lab/firmware.py decrypt hotfix_b03
python3 lab/firmware.py kernel original
python3 lab/firmware.py kernel hotfix_b03
python3 lab/firmware.py initramfs original
python3 lab/firmware.py initramfs hotfix_b03
python3 lab/firmware.py rootfs original
python3 lab/firmware.py rootfs hotfix_b03
```

순서는 ZIP에서 BIN·PDF 추출 → SHRS의 AES-CBC 복호화와 내부 SHA-512 검사 세 개 → uImage의 LZMA 커널 해제 → 커널 내부의 별도 LZMA initramfs 추출 → newc CPIO의 rootfs 추출이다. CPIO 링크·장치 파일은 생성하지 않고 목록으로 기록한다. 각 버전에서 CPIO는 1,693항목, 디렉터리 144, 일반 파일 1,392, 링크 목록 157이 예상된다. **화면 3:** SHRS·uImage·CPIO 단계 출력.

```bash
file analysis/original/initramfs.cpio analysis/hotfix_b03/initramfs.cpio
find analysis/original/rootfs -maxdepth 2 -type d | sort
find analysis/hotfix_b03/rootfs -maxdepth 2 -type d | sort
file analysis/original/rootfs/bin/lighttpd analysis/original/rootfs/bin/prog.cgi analysis/original/rootfs/lib/librcm.so
grep -nE 'mod_fastcgi|server.document-root|fastcgi.server|/HNAP1/|bin-path|cgi.assign' analysis/original/rootfs/etc_ro/lighttpd/lighttpd.conf
readelf -d analysis/original/rootfs/bin/prog.cgi | grep NEEDED
```

`etc_ro/lighttpd`, `bin`, `lib`, `www` 구조를 확인한다. `lighttpd` 설정에서 `/HNAP1/`의 FastCGI `bin-path`가 `/bin/prog.cgi`인지 본다. `readelf`는 `prog.cgi`가 요구하는 공유 라이브러리를 보여준다. Hotfix도 `original`을 `hotfix_b03`으로 바꾸어 확인한다. **화면 4:** rootfs 구조. **화면 5:** 웹 서버 설정·MIPS ELF·의존성.

## 2. 2차 보고서: Docker 준비

```bash
python3 analysis/emulation/prepare_full_rootfs.py
docker build -f analysis/emulation/Dockerfile.qemu-probe -t dir882-qemu-probe:local analysis/emulation
docker build -f analysis/emulation/Dockerfile.qemu-debug -t dir882-qemu-debug:local analysis/emulation
docker build -f analysis/emulation/Dockerfile.hands-on -t dir882-hands-on:local analysis/emulation
docker build -f analysis/emulation/Dockerfile.sink-probe -t dir882-sink-probe:local analysis/emulation
docker image ls --filter 'reference=dir882-*'
```

첫 명령은 추출한 rootfs로부터 실행용 복사본과 라이브러리 링크의 일반 파일 복사본을 만든다. 이미지 계층은 `qemu-user` → `gdb-multiarch` → MIPS binutils·`jq`이며, 별도의 `sink-probe` 이미지에는 Qiling·Unicorn 등이 있다. Dockerfile과 `requirements.txt`가 이미지 생성 방법의 근거다. 빌드 실패 시 Docker Linux 엔진과 패키지 다운로드를 확인한다. **화면 6:** Dockerfile 계층과 이미지 목록.

### 2.1 원본 FastCGI 요청과 GDB

WSL에서 원본 컨테이너를 연다. `/firmware`와 `/probe.py`는 읽기 전용이다. `/evidence`만 결과 기록용으로 연결한다.

```bash
mkdir -p output/hands_on
docker run --rm -it --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 32 --memory 512m \
  --tmpfs /tmp:rw,nosuid,size=64m --tmpfs /run:rw,nosuid,size=16m \
  --tmpfs /var:rw,nosuid,size=16m --tmpfs /firmware/var/run:rw,nosuid,size=4m \
  -e FIRMWARE_LABEL=original -e DEBUG_GDB=1 -e TRACE_COMMAND_PATH=1 \
  -v "$PWD/analysis/emulation/runtime_full/original:/firmware:ro" \
  -v "$PWD/analysis/emulation/runtime_full/original/etc_ro:/etc_ro:ro" \
  -v "$PWD/analysis/emulation/fastcgi_probe.py:/probe.py:ro" \
  -v "$PWD/output/hands_on:/evidence:rw" \
  dir882-hands-on:local bash
```

다음은 **컨테이너 내부**에서 한 줄씩 실행한다.

```bash
file /firmware/bin/prog.cgi /firmware/lib/librcm.so /firmware/bin/busybox
mkdir -p /var/run /var/log /var/tmp
TEST_LOCAL_IP=192.0.2.10 TEST_UDP_PORTS=8000 TEST_ENABLED=1 python3 /probe.py > /evidence/manual_original_normal.json
TEST_LOCAL_IP='1$(>/tmp/d882)' TEST_UDP_PORTS=8000 TEST_ENABLED=1 python3 /probe.py > /evidence/manual_original_marker.json
jq '{firmware,local_ip,soap_result,first_localip_decision,nvram_safe_set_seen,service_apply_seen,marker_file_created,process_exit_code,gdb_exit_code,client_error}' /evidence/manual_original_normal.json /evidence/manual_original_marker.json
jq -r .gdb_output /evidence/manual_original_marker.json | grep -E 'LOCALIP_START|LOCALIP_CONTINUE|NVRAM_VALUE|NVRAM_SAFE_SET|SERVICE_APPLY'
mipsel-linux-gnu-objdump -d --start-address=0x454ee8 --stop-address=0x454f28 /firmware/bin/prog.cgi
exit
```

`/probe.py`는 `lighttpd` 없이 FastCGI 클라이언트 역할을 해 SOAP 요청을 실제 MIPS `prog.cgi`에 보낸다. QEMU가 프로그램을 실행하고 GDB가 분기와 호출을 기록한다. 정상·시험 입력 모두 `OK`·`CONTINUE`가 예상된다. 시험 문자열이 `portforward_rule` 저장 호출 인자에 남는지 확인한다. 요청 단계의 `marker_file_created=false`는 예상 범위다. HTTP 인증·전체 웹 서버 동작은 실험 대상이 아니다. **화면 7:** 두 `jq` 결과·GDB 기록·원본 역어셈블.

### 2.2 Hotfix의 동일 요청

WSL로 나온 뒤 같은 옵션으로 Hotfix 컨테이너를 연다. **같은** `fastcgi_probe.py`를 사용하고 `FIRMWARE_LABEL`과 연결할 펌웨어 파일만 바꾼다.

```bash
docker run --rm -it --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 32 --memory 512m \
  --tmpfs /tmp:rw,nosuid,size=64m --tmpfs /run:rw,nosuid,size=16m \
  --tmpfs /var:rw,nosuid,size=16m --tmpfs /firmware/var/run:rw,nosuid,size=4m \
  -e FIRMWARE_LABEL=hotfix_b03 -e DEBUG_GDB=1 -e TRACE_COMMAND_PATH=1 \
  -v "$PWD/analysis/emulation/runtime_full/hotfix_b03:/firmware:ro" \
  -v "$PWD/analysis/emulation/runtime_full/hotfix_b03/etc_ro:/etc_ro:ro" \
  -v "$PWD/analysis/emulation/fastcgi_probe.py:/probe.py:ro" \
  -v "$PWD/output/hands_on:/evidence:rw" \
  dir882-hands-on:local bash
```

컨테이너 안에서 다음을 실행한다.

```bash
mkdir -p /var/run /var/log /var/tmp
TEST_LOCAL_IP=192.0.2.10 TEST_UDP_PORTS=8000 TEST_ENABLED=1 python3 /probe.py > /evidence/manual_hotfix_normal.json
TEST_LOCAL_IP='1$(>/tmp/d882)' TEST_UDP_PORTS=8000 TEST_ENABLED=1 python3 /probe.py > /evidence/manual_hotfix_marker.json
jq '{firmware,local_ip,soap_result,first_localip_decision,nvram_safe_set_seen,service_apply_seen,marker_file_created,process_exit_code,gdb_exit_code,client_error}' /evidence/manual_hotfix_normal.json /evidence/manual_hotfix_marker.json
jq -r .gdb_output /evidence/manual_hotfix_marker.json | grep -E 'LOCALIP_START|VALIDATOR_CALL|tbsCheckIp|VALIDATOR_RETURN|LOCALIP_REJECT'
mipsel-linux-gnu-objdump -d --start-address=0x455b68 --stop-address=0x455bc0 /firmware/bin/prog.cgi
exit
```

정상 IP는 `tbsCheckIp` 반환 `1`로 진행한다. 시험 문자열은 반환 `0`, `GET_JSON_NULL_ERROR`·`REJECT`, 저장·서비스 적용 호출 없음이 예상된다. 역어셈블의 근접 심볼 이름만으로 요청 처리 함수명을 단정하지 않는다. **화면 8:** Hotfix의 검사 호출·거부 분기·역어셈블.

WSL에서 네 결과를 한 표로 확인한다.

```bash
jq -r '[.firmware, .local_ip, .soap_result, .first_localip_decision, (.nvram_safe_set_seen|tostring), (.service_apply_seen|tostring), (.process_exit_code|tostring), (.gdb_exit_code|tostring), (.client_error|tostring)] | @tsv' output/hands_on/manual_original_normal.json output/hands_on/manual_original_marker.json output/hands_on/manual_hotfix_normal.json output/hands_on/manual_hotfix_marker.json
```

**화면 9:** 원본·Hotfix 네 경우의 비교표. 모든 경우 `process_exit_code=0`, `gdb_exit_code=0`, `client_error=null`인지 확인한다.

### 2.3 별도의 MIPS 규칙 적용·BusyBox 셸 실험

**앞의 FastCGI 프로세스와 분리된 실행이다.** 원본 GDB에서 관찰한 규칙 문자열을 시험용 NVRAM 값으로 공급한다. Qiling이 실제 MIPS `PORTFORWARD_run`·`twsystem` 코드와 복사한 펌웨어 BusyBox 셸을 실행한다. NVRAM·WAN 상태와 최초 `fork` 자식 분기는 모의한다. 실제 공유기의 영구 NVRAM·방화벽 서비스를 실행하는 것은 아니다.

```bash
mkdir -p output/qiling_guest_runtime/original
cp -a analysis/emulation/runtime/original/. output/qiling_guest_runtime/original/
cp analysis/original/rootfs/bin/busybox output/qiling_guest_runtime/original/bin/sh
mkdir -p output/qiling_guest_runtime/original/tmp
cmp -s analysis/original/rootfs/bin/busybox output/qiling_guest_runtime/original/bin/sh && echo 'guest shell matches firmware BusyBox'
test ! -e output/qiling_guest_runtime/original/tmp/d882 && echo 'marker absent'
```

정상 규칙을 추출해 실행한다. `NORMAL_RULE`은 현재 WSL 셸에 유지된다.

```bash
NORMAL_RULE=$(python3 -c 'import json,re; x=json.load(open("output/hands_on/manual_original_normal.json")); print(re.search(r"NVRAM_VALUE [^\n]*\"([^\"]+)\"", x["gdb_output"]).group(1))')
printf '%s\n' "$NORMAL_RULE"
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 32 --memory 512m \
  --tmpfs /tmp:rw,nosuid,size=32m \
  -e "TEST_RULE=$NORMAL_RULE" -e PYTHONPATH=/workspace/analysis/emulation \
  -v "$PWD:/workspace:ro" -v "$PWD/output/qiling_guest_runtime/original:/guest:rw" \
  dir882-sink-probe:local python3 -c 'import json,os; from pathlib import Path; from probe_portforward_sink import run; r=run("original","192.0.2.10",execute_shell=True,root_override=Path("/guest"),rule_override=os.environ["TEST_RULE"]); print(json.dumps({k:r.get(k) for k in ("outcome","portforward_code_bytes_match","twsystem_code_bytes_match","guest_marker_exists","guest_exit_code","guest_shell_matches_firmware_busybox","execv_observed","commands")},ensure_ascii=False,indent=2))'
test ! -e output/qiling_guest_runtime/original/tmp/d882 && echo 'normal-no-marker'
```

정상 규칙에서는 `--to-destination 192.0.2.10` 명령을 관찰하고 마커가 없어야 한다. 이어 원본의 시험 규칙을 공급한다.

```bash
MARKER_RULE=$(python3 -c 'import json,re; x=json.load(open("output/hands_on/manual_original_marker.json")); print(re.search(r"NVRAM_VALUE [^\n]*\"([^\"]+)\"", x["gdb_output"]).group(1))')
printf '%s\n' "$MARKER_RULE"
test ! -e output/qiling_guest_runtime/original/tmp/d882 && echo 'marker absent before marker run'
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 32 --memory 512m \
  --tmpfs /tmp:rw,nosuid,size=32m \
  -e "TEST_RULE=$MARKER_RULE" -e PYTHONPATH=/workspace/analysis/emulation \
  -v "$PWD:/workspace:ro" -v "$PWD/output/qiling_guest_runtime/original:/guest:rw" \
  dir882-sink-probe:local python3 -c 'import json,os; from pathlib import Path; from probe_portforward_sink import run; r=run("original","1$(>/tmp/d882)",execute_shell=True,root_override=Path("/guest"),rule_override=os.environ["TEST_RULE"]); print(json.dumps({k:r.get(k) for k in ("outcome","portforward_code_bytes_match","twsystem_code_bytes_match","guest_marker_exists","guest_marker_size","guest_exit_code","guest_shell_matches_firmware_busybox","execv_observed","commands")},ensure_ascii=False,indent=2))'
ls -l output/qiling_guest_runtime/original/tmp/d882
```

시험 규칙에서만 `guest_marker_exists=true`, `guest_marker_size=0`을 확인한다. 시험용 파일시스템에는 `iptables`가 없어 셸 종료 코드 `127`과 `/dev/null` 접근 오류가 나올 수 있다. **방화벽 적용 성공과 셸 명령 치환 효과를 구분한다.** Hotfix는 앞선 요청 단계에서 시험 입력을 거부했으므로, 임의로 주입한 Hotfix 규칙의 셸 실행을 패치 증거로 사용하지 않는다. 재실습할 때는 시험용 마커 하나만 `rm -f -- output/qiling_guest_runtime/original/tmp/d882`로 지우고 실행 전 부재를 확인한다. **화면 10:** 정상 규칙 마커 미생성. **화면 11:** 시험 규칙의 셸 인자와 0바이트 마커.

## 보고서에 쓸 수 있는 결론과 한계

| 단계 | 일반 정상 IP | 일반 시험 문자열 | Hotfix 시험 문자열 |
|---|---|---|---|
| FastCGI `prog.cgi` | `OK`, 진행·저장 호출 | `OK`, 진행·저장 호출 | `GET_JSON_NULL_ERROR`, `tbsCheckIp`에서 거부 |
| 별도 규칙 적용·셸 실험 | 마커 없음 | 0바이트 마커 생성 | 앞단에서 거부돼 별도 셸 실험을 패치 근거로 사용하지 않음 |

일반 버전은 시험 입력을 규칙 저장 호출까지 전달했고, **관찰한 저장값을 공급한 별도의** MIPS 규칙 적용·셸 실험에서 명령 치환 효과가 나타났다. Hotfix는 같은 요청을 IP 검사에서 거부했다. 전체 공유기의 HTTP 인증·설정 서비스·NVRAM·방화벽을 단일 요청으로 실행했다고 쓰지 않는다. 각 화면에는 실제 명령과 출력을 함께 캡처한다.

## 파일 안내

- `lab/firmware.py`: 1차 언패킹의 단계별 코드. 출력 파일을 덮어쓰지 않는다.
- `analysis/emulation/fastcgi_probe.py`: FastCGI 요청·QEMU·GDB 측정 도구.
- `analysis/emulation/probe_portforward_sink.py`: 별도 MIPS 규칙 적용·셸 실험 코드.
- `analysis/emulation/prepare_rootfs.py`, `prepare_full_rootfs.py`: 실행용 파일시스템 복사본 준비.
- `analysis/emulation/Dockerfile.*`, `requirements.txt`: Docker 이미지 구성 정의.
- `analysis/emulation/binary_manifest.json`: 실험 주소 설정과 연결되는 `prog.cgi` 식별값.
- `firmware/`, `analysis/original/`, `analysis/hotfix_b03/`, `output/`: 각자 생성하며 Git에 올리지 않는 파일.
