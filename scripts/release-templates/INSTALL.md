# pcap-analyzer 설치 가이드

이 문서는 압축 해제 후 함께 들어있는 사용자용 설치 가이드입니다.

## 1. 시스템 요구사항

| 항목 | 최소 사양 |
|---|---|
| OS | Linux (Ubuntu/Debian 권장), macOS, Windows 10/11 |
| Python | 3.10 이상 |
| tshark | Wireshark CLI (필수) |
| 디스크 | 약 500MB (venv + wheels + vendor 포함) |
| 메모리 | 2GB 이상 권장 (대용량 pcap 분석 시 4GB+) |

### tshark 설치

- **Linux (Ubuntu/Debian)**: `sudo apt install tshark`
- **macOS**: `brew install wireshark`
- **Windows**: https://www.wireshark.org/ 에서 설치 (설치 옵션에서 "Install TShark" + "Add path" 체크)

### Python 3.10+ 확인

```bash
python3 --version        # Linux/macOS
python --version         # Windows
```

3.10 미만이면 OS별 안내에 따라 업그레이드 후 진행하세요.

#### Linux에서 venv 모듈 없음 오류

Ubuntu/Debian 일부 minimal 이미지에는 `python3-venv` 패키지가 빠져 있어 `install.sh`의 [2/5] 단계에서 `ensurepip not available` 오류가 납니다. 해결:

```bash
sudo apt install python3-venv
```

## 2. 다운로드 & 압축 해제

### Linux/macOS
```bash
tar -xzf pcap-analyzer-<VERSION>.tar.gz
cd pcap-analyzer-<VERSION>
```

### Windows
1. `pcap-analyzer-<VERSION>.zip` 우클릭 → "압축 풀기"
2. 풀린 폴더 안으로 이동

**주의(Windows)**: 한글이 포함된 경로(`바탕 화면` 등)에서 가끔 venv 생성이 실패합니다. 영문 경로(`C:\pcap` 등) 권장.

## 3. 설치

### Linux/macOS
```bash
./install.sh
```

상세 로그는 `install.log`에 자동 저장됩니다.

### Windows
```cmd
install.bat
```

Windows에서는 `install.log` 자동 저장이 없습니다. 로그가 필요하면:
```cmd
install.bat > install.log 2>&1
```

> **참고**: 위 명령은 콘솔 출력을 모두 파일로만 보냅니다. 진행 상황을 화면에서도 보려면 PowerShell의 `Tee-Object`를 사용하세요:
> ```powershell
> .\install.bat 2>&1 | Tee-Object install.log
> ```

### 공통: 5단계가 모두 ERROR 없이 끝나야 완료

```
[1/5] 시스템 의존성 확인
[2/5] Python 가상환경 생성
[3/5] 의존성 설치
[4/5] 설치 확인
[5/5] 완료
```

### 오프라인 우선 동작 (wheels/ + PyPI fallback)

설치 스크립트는 `wheels/` 안의 사전 빌드된 wheel을 **우선** 사용하고, ABI 불일치나 누락이 있으면 자동으로 PyPI에서 보완합니다.

- **완전 폐쇄망**: 빌드 호스트와 동일한 Python 마이너 버전(예: 3.10)이면 wheels/만으로 설치 완료. PyPI 호출 없음.
- **인터넷 가용 + ABI 다름**: 호환 wheel은 wheels/에서, 나머지는 PyPI에서 받아 설치 (예: 빌드 호스트 Python 3.10 → 설치 대상 Python 3.12).
- **완전 폐쇄망 + ABI 불일치**: 설치 실패. 빌드 호스트와 동일한 Python 마이너 버전 설치 후 재시도.

빌드 호스트 정보는 `wheels/` 안의 native wheel 파일명(예: `markupsafe-3.0.3-cp310-...whl`)의 `cp310` 부분으로 확인 가능합니다.

## 4. 실행 & 접속

### Linux/macOS
```bash
./run.sh
```

### Windows
```cmd
run.bat
```

시작 후 출력되는 배너의 URL로 브라우저 접속:
```
 접속 URL:
   http://localhost:8000
   http://192.168.x.x:8000  (LAN)
```

종료: `Ctrl+C`

> **macOS 참고**: `run.sh`는 LAN IP 자동 감지에 `hostname -I`를 사용합니다. macOS는 이 옵션을 지원하지 않아 LAN URL 줄이 표시되지 않을 수 있습니다. 동작에는 영향 없으며, `ipconfig getifaddr en0`로 IP를 확인할 수 있습니다.

### 옵션: 포트/호스트 변경

```bash
PCAP_PORT=9000 ./run.sh        # Linux/macOS
```
```cmd
set PCAP_PORT=9000 && run.bat  # Windows
```

### .env 파일 사용 (선택)

런타임 환경변수를 파일로 관리하려면 압축 풀린 디렉토리에 `.env` 파일을 만드세요:

```
PCAP_PORT=9000
PCAP_AI_PROVIDER=claude
PCAP_AI_API_KEY=sk-ant-...
```

**.env 포맷 제약**:
- 한 줄에 `KEY=VALUE` 하나
- Windows에서 안전하게 동작하려면: 값에 따옴표 사용 금지, 주석(`#`) 행 금지, bash의 `export` 접두사 금지 (모두 문자 그대로 파싱되어 실패)
- Linux/macOS는 bash `source`로 로드되어 위 제약이 완화되지만, 양 OS에서 호환을 위해 동일 규칙 권장

## 5. 트러블슈팅

| 증상 | 해결 |
|---|---|
| `install.sh: tshark가 필요합니다` | tshark 미설치. 위 1. 시스템 요구사항 참조 |
| `ensurepip not available` (Linux) | `sudo apt install python3-venv` |
| `Python 3.10 이상 필요` | Python 업그레이드 필요 |
| `address already in use` | 8000 포트 점유 중. `PCAP_PORT=9000`으로 재실행 |
| LAN URL 접속 불가 | 호스트 방화벽(`sudo ufw allow 8000` / Windows Defender 인바운드 허용) 확인 |
| `install.bat`: `tshark가 필요합니다` (Windows) | Wireshark는 설치되어 있지만 PATH 미등록. Wireshark 재설치 후 "Add Wireshark to system PATH" 옵션 체크 또는 시스템 환경변수에 `C:\Program Files\Wireshark` 수동 추가 후 install.bat 재실행 |
| `tshark 감지: 미감지` (런타임) | install 후 런타임에 못 찾는 드문 경우. 설정 페이지(`/settings`)에서 `tshark.exe` 절대 경로 지정 |
| 분석 진행률 멈춤 | 수백만 프레임 pcap은 분 단위 소요. `/api/progress`로 진행 상태 확인 |
| Windows 콘솔에서 한글 깨짐 | install.bat/run.bat는 UTF-8 BOM + CRLF로 저장되어 chcp 65001 전에도 한글 정상 파싱됨. 그래도 깨지면 Windows Terminal 또는 PowerShell 사용 권장 |
| `'XXX'은(는) 내부 또는 외부 명령...` 류 에러 다발 (Windows) | .bat의 BOM이 압축 해제 중 손실됐을 가능성. zip을 다시 받아 압축 해제 도구를 바꿔서 시도 (탐색기 기본 vs 7-Zip) |
| 한글 경로(Windows)에서 venv 실패 | 영문 경로(`C:\pcap` 등)로 이동 후 재시도 |
| `Could not find a version that satisfies` (offline 모드) | 빌드 호스트와 설치 대상의 Python 마이너 버전 다름. 인터넷 가용하면 자동 fallback됨. 폐쇄망이면 동일 Python 버전 설치 필요 |

## 6. AI 리뷰 사용 (선택)

분석 결과를 Claude/OpenAI로 자동 해석하려면 환경변수 또는 `config.local.json`에 다음 지정:

```bash
export PCAP_AI_PROVIDER=claude
export PCAP_AI_API_KEY=sk-ant-...
export PCAP_AI_MODEL=claude-sonnet-4-6
./run.sh
```

자세한 설정 키는 압축에 포함된 `README.md` 참조.

## 7. 재설치 / 업데이트

새 버전을 받으면:

1. 기존 디렉토리에서 `Ctrl+C`로 종료
2. 새 압축을 별도 디렉토리에 풀기
3. (선택) 기존 `data/` 디렉토리를 새 디렉토리로 복사하면 이전 분석 결과 유지
4. 새 디렉토리에서 `./install.sh` (또는 `install.bat`) → `./run.sh` (또는 `run.bat`)

기존 `.venv/`는 버리고 새로 만드는 게 안전합니다 (의존성 버전 차이 가능).

## 8. PDF 리포트 (선택)

분석 결과 페이지의 **🖨️ 인쇄용 리포트** 버튼은 추가 설치 없이 모든 환경에서
동작합니다 — 열린 화면에서 브라우저 인쇄(`Ctrl+P`) → "PDF로 저장"을 선택하세요.

서버에서 바로 PDF 파일을 받는 **📑 PDF 다운로드** 버튼은 선택 기능이며,
인터넷 가능 환경에서만 설치할 수 있습니다:

```bash
# venv 활성화 후
pip install -r requirements-pdf.txt
playwright install chromium        # ~150MB 다운로드
```

- 미설치 상태에서는 버튼이 표시되지 않으며 앱은 정상 동작합니다.
- Linux 서버에서 PDF 한글이 □(tofu)로 나오면: `sudo apt install fonts-noto-cjk`
- PDF 생성이 끝나지 않고 멈춘 것처럼 보이면(드묾 — chromium 이상) 서버를
  재시작하세요 (`Ctrl+C` 후 run 스크립트 재실행). 인쇄용 리포트는 영향 없이 동작합니다.
- 폐쇄망 고급 절차: 온라인 PC에서 `PLAYWRIGHT_BROWSERS_PATH=<경로> playwright install chromium`
  으로 받은 브라우저 캐시를 대상 PC의 같은 경로로 복사하고, 실행 전 동일한
  환경변수를 지정하면 동작합니다 (OS·Python 마이너 버전 일치 필요).
