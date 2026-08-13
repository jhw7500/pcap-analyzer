/* pcap 파일 업로드 + 드래그앤드롭 + 진행률 polling */
(function () {
    const form = document.getElementById('upload-form');
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('pcap-file');
    const fileName = document.getElementById('file-name');
    const progressArea = document.getElementById('progress-area');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const progressMsg = document.getElementById('progress-msg');
    const uploadBtn = document.getElementById('upload-btn');
    const cancelBtn = document.getElementById('cancel-btn');

    let pollTimer = null;
    let currentJobId = null;

    // 옵션 폼 localStorage 캐시 (파일은 제외, 텍스트 옵션만)
    const OPT_KEY = 'pcap.upload.options';
    const OPT_FIELDS = ['ssid', 'passphrase', 'mac_filter', 'ip_filter', 'time_start', 'time_end', 'ping_timeout_sec', 'independent_validation'];
    function restoreOptions() {
        try {
            const saved = JSON.parse(localStorage.getItem(OPT_KEY) || '{}');
            for (const name of OPT_FIELDS) {
                const el = form.querySelector(`[name="${name}"]`);
                if (el && saved[name] !== undefined) {
                    if (el.type === 'checkbox') el.checked = Boolean(saved[name]);
                    else el.value = saved[name];
                }
            }
        } catch (e) { /* ignore */ }
    }
    function saveOptions() {
        try {
            const data = {};
            for (const name of OPT_FIELDS) {
                const el = form.querySelector(`[name="${name}"]`);
                if (el) data[name] = el.type === 'checkbox' ? el.checked : el.value;
            }
            localStorage.setItem(OPT_KEY, JSON.stringify(data));
        } catch (e) { /* ignore */ }
    }
    restoreOptions();
    // 입력값이 바뀔 때마다 즉시 저장 (분석 시작 안 해도 새로고침/재방문 시 유지)
    for (const name of OPT_FIELDS) {
        const el = form.querySelector(`[name="${name}"]`);
        if (el) el.addEventListener(el.type === 'checkbox' ? 'change' : 'input', saveOptions);
    }

    // 클라이언트 측 파일 크기 즉시 검사
    const MAX_MB = parseInt(fileInput.getAttribute('data-max-mb') || '200', 10);
    const MAX_BYTES = MAX_MB * 1024 * 1024;
    // 상한은 **조각 하나씩** 적용된다 — 서버도 파일 단위로 검사한다
    // (routes/upload.py `_save_pcap_upload`). 여러 조각을 고르면 전부 검사한다.
    const MAX_SPLIT_PARTS = 32;
    function validateFiles(files) {
        if (!files || !files.length) return false;
        if (files.length > MAX_SPLIT_PARTS) {
            alert(`한 캡처의 분할 조각은 최대 ${MAX_SPLIT_PARTS}개입니다 (선택 ${files.length}개).`);
            fileInput.value = '';
            fileName.classList.add('hidden');
            return false;
        }
        for (const file of files) {
            if (file.size > MAX_BYTES) {
                const sizeMb = (file.size / 1024 / 1024).toFixed(1);
                alert(`파일이 너무 큽니다: ${file.name} — ${sizeMb}MB (조각당 상한 ${MAX_MB}MB)\n\n` +
                      `환경변수 PCAP_MAX_UPLOAD_MB 또는 config.local.json의 max_upload_mb 키로 조정 가능.`);
                fileInput.value = '';
                fileName.classList.add('hidden');
                return false;
            }
        }
        return true;
    }

    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('border-blue-500', 'bg-gray-700/30');
    });
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('border-blue-500', 'bg-gray-700/30');
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('border-blue-500', 'bg-gray-700/30');
        if (e.dataTransfer.files.length) {
            if (!validateFiles(e.dataTransfer.files)) return;
            fileInput.files = e.dataTransfer.files;
            showFileName(e.dataTransfer.files);
        }
    });

    /* STA 로그 선택 — 브라우저의 webkitdirectory는 **한 번에 폴더 하나**만 고를 수
       있고, 매 선택마다 input.files가 통째로 교체된다. 호기가 여러 대면 한 번으로는
       다 못 담으므로 선택할 때마다 여기에 **누적**한다(상대경로를 키로 중복 제거).
       호기들을 담은 상위 폴더를 한 번에 골라도 동작한다 — 서버는 경로 깊이와 무관하게
       파일 바로 위 디렉터리를 호기 이름으로 쓴다. */
    const WANTED_STATION_LOGS = ['wpa.log', 'kern.log', 'logger.log'];
    const stationInputEl = document.getElementById('station-logs');
    const stationSummary = document.getElementById('station-logs-summary');
    const stationClearBtn = document.getElementById('station-logs-clear');
    const stationDrop = document.getElementById('station-drop');
    const stationPicked = new Map();   // 상대경로 → File

    function renderStationSummary(lastPickHadNone) {
        if (!stationSummary) return;
        const byStation = {};
        for (const rel of stationPicked.keys()) {
            const parts = rel.split('/');
            const base = parts.pop();
            const st = parts.pop() || 'station';
            (byStation[st] = byStation[st] || []).push(base);
        }
        const names = Object.keys(byStation).sort();
        if (stationClearBtn) stationClearBtn.classList.toggle('hidden', !names.length);
        if (!names.length) {
            stationSummary.textContent = lastPickHadNone
                ? '선택한 폴더에서 wpa.log / kern.log / logger.log를 찾지 못했습니다.'
                : '';
            stationSummary.classList.toggle('hidden', !lastPickHadNone);
            stationSummary.classList.remove('text-blue-400');
            stationSummary.classList.add('text-yellow-400');
            return;
        }
        // 3종이 다 없는 호기는 눈에 띄게 — 없는 로그만큼 분석이 비게 된다.
        const parts = names.map(n => {
            const got = byStation[n].sort();
            const miss = WANTED_STATION_LOGS.filter(w => !got.includes(w));
            return miss.length ? `${n}(${got.join(', ')} — ${miss.join(', ')} 없음)`
                               : `${n}(${got.join(', ')})`;
        });
        const anyMissing = names.some(n => byStation[n].length < WANTED_STATION_LOGS.length);
        stationSummary.textContent = `${names.length}대: ` + parts.join(' · ');
        stationSummary.classList.remove('hidden');
        stationSummary.classList.toggle('text-yellow-400', anyMissing);
        stationSummary.classList.toggle('text-blue-400', !anyMissing);
    }

    /* 드래그앤드롭 — 브라우저 파일 선택창은 폴더를 하나씩만 주지만, 드롭은
       **여러 폴더를 한 번에** 받는다. DataTransferItem.webkitGetAsEntry()로
       디렉터리 트리를 재귀 순회해 상대경로를 만든다(호기 구분에 필요). */
    function readAllEntries(reader) {
        // readEntries()는 한 번에 최대 100개만 준다 — 빈 배열이 올 때까지 반복해야
        // 파일이 많은 폴더에서 조용히 누락된다.
        return new Promise((resolve, reject) => {
            const acc = [];
            const step = () => reader.readEntries(batch => {
                if (!batch.length) { resolve(acc); return; }
                acc.push(...batch);
                step();
            }, reject);
            step();
        });
    }

    async function walkEntry(entry, prefix, sink) {
        if (!entry) return;
        const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
        if (entry.isFile) {
            if (!WANTED_STATION_LOGS.includes(entry.name)) return;
            await new Promise(res => entry.file(f => { sink.set(rel, f); res(); }, () => res()));
            return;
        }
        if (entry.isDirectory) {
            const kids = await readAllEntries(entry.createReader());
            for (const k of kids) await walkEntry(k, rel, sink);
        }
    }

    if (stationDrop) {
        stationDrop.addEventListener('click', () => stationInputEl && stationInputEl.click());
        stationDrop.addEventListener('dragover', (e) => {
            e.preventDefault();
            stationDrop.classList.add('border-blue-500', 'bg-gray-700/30');
        });
        stationDrop.addEventListener('dragleave', () => {
            stationDrop.classList.remove('border-blue-500', 'bg-gray-700/30');
        });
        stationDrop.addEventListener('drop', async (e) => {
            e.preventDefault();
            stationDrop.classList.remove('border-blue-500', 'bg-gray-700/30');
            const items = Array.from(e.dataTransfer.items || []);
            // getAsEntry는 이벤트 핸들러가 끝나면 무효화되므로 **먼저 전부 꺼낸다**.
            const entries = items
                .map(it => (it.webkitGetAsEntry ? it.webkitGetAsEntry() : null))
                .filter(Boolean);
            if (entries.length) {
                const before = stationPicked.size;
                for (const en of entries) await walkEntry(en, '', stationPicked);
                renderStationSummary(stationPicked.size === before);
                return;
            }
            // webkitGetAsEntry 미지원 브라우저 — 파일만이라도 받는다(폴더 구분 없음).
            let added = 0;
            for (const f of Array.from(e.dataTransfer.files || [])) {
                if (!WANTED_STATION_LOGS.includes(f.name)) continue;
                stationPicked.set(f.webkitRelativePath || f.name, f);
                added++;
            }
            renderStationSummary(added === 0);
        });
    }

    if (stationInputEl) {
        stationInputEl.addEventListener('change', () => {
            let added = 0;
            for (const f of stationInputEl.files) {
                const rel = f.webkitRelativePath || f.name;
                if (!WANTED_STATION_LOGS.includes(rel.split('/').pop())) continue;
                stationPicked.set(rel, f);
                added++;
            }
            // 같은 폴더를 다시 고를 수 있도록 input을 비운다(값이 같으면 change가 안 뜬다).
            stationInputEl.value = '';
            renderStationSummary(added === 0);
        });
    }
    if (stationClearBtn) {
        stationClearBtn.addEventListener('click', () => {
            stationPicked.clear();
            if (stationInputEl) stationInputEl.value = '';
            renderStationSummary(false);
        });
    }

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) {
            if (!validateFiles(fileInput.files)) return;
            showFileName(fileInput.files);
        }
    });

    function showFileName(files) {
        // 조각이 여러 개면 이어붙여 하나로 분석된다는 걸 이름에서 바로 드러낸다.
        const names = Array.from(files).map(f => f.name);
        fileName.textContent = names.length === 1
            ? names[0]
            : `${names.length}개 조각을 시간순으로 이어붙여 분석: ${names.join(', ')}`;
        fileName.classList.remove('hidden');
    }

    function startPolling(jobId) {
        pollTimer = setInterval(async () => {
            try {
                const resp = await fetch(
                    jobId ? `/api/progress/${encodeURIComponent(jobId)}` : '/api/progress'
                );
                const data = await resp.json();
                if (data.pct !== undefined) {
                    progressBar.style.width = data.pct + '%';
                    progressText.textContent = data.pct + '%';
                }
                if (data.msg) {
                    progressMsg.textContent = data.msg;
                }
            } catch (e) { /* ignore */ }
        }, 500);
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!fileInput.files.length) {
            alert('pcap 파일을 선택하세요.');
            return;
        }

        const wiredInput = document.getElementById('wired-file');
        if (wiredInput && wiredInput.files.length) {
            const maxMb = parseInt(wiredInput.dataset.maxMb || fileInput.dataset.maxMb || '200', 10);
            if (wiredInput.files.length > MAX_SPLIT_PARTS) {
                alert(`유선 캡처의 분할 조각은 최대 ${MAX_SPLIT_PARTS}개입니다.`);
                return;
            }
            for (const wf of wiredInput.files) {
                if (wf.size > maxMb * 1024 * 1024) {
                    alert(`유선 pcap이 업로드 상한(${maxMb}MB)을 초과합니다: ${wf.name}`);
                    return;
                }
            }
        }

        const wirelessInput = document.getElementById('wireless-files');
        if (wirelessInput && wirelessInput.files.length) {
            if (wirelessInput.files.length > 3) {
                alert('추가 무선 pcap은 최대 3개입니다.');
                return;
            }
            const maxMb = parseInt(wirelessInput.dataset.maxMb || fileInput.dataset.maxMb || '200', 10);
            for (const wf of wirelessInput.files) {
                if (wf.size > maxMb * 1024 * 1024) {
                    alert(`추가 무선 pcap이 업로드 상한(${maxMb}MB)을 초과합니다: ${wf.name}`);
                    return;
                }
            }
        }

        const formData = new FormData(form);
        /* STA 로그: 브라우저 디렉터리 업로드는 basename만 보내 호기 구분이 사라진다.
           FormData의 3번째 인자(filename)에 webkitRelativePath를 넣어 서버가
           `<호기>/<파일>`로 그룹핑할 수 있게 한다. 관심 있는 3종만 올려 불필요한
           전송(cpu/stat 등 폴더 전체)을 막는다. */
        formData.delete('station_log_files');
        for (const [rel, f] of stationPicked) {
            formData.append('station_log_files', f, rel);
        }
        // 드롭존으로 넣은 경우까지 확실히 반영되도록 file 파트를 다시 만든다.
        // 조각을 **전부** 보내야 서버가 mergecap으로 이어붙인다(첫 파일만
        // 보내던 기존 동작은 나머지 조각을 조용히 버렸다).
        formData.delete('file');
        for (const f of fileInput.files) formData.append('file', f);
        // 진행률/취소를 본인 분석에만 한정하기 위해 클라이언트가 job_id를 먼저 생성해 전송.
        const jobId = (window.crypto && crypto.randomUUID)
            ? crypto.randomUUID()
            : `job-${Date.now()}-${Math.random().toString(36).slice(2)}`;
        currentJobId = jobId;
        formData.set('client_job_id', jobId);

        uploadBtn.disabled = true;
        uploadBtn.textContent = '분석 중...';
        progressArea.classList.remove('hidden');
        cancelBtn.classList.remove('hidden');

        startPolling(jobId);

        try {
            const resp = await fetch('/api/upload', { method: 'POST', body: formData });
            const data = await resp.json();

            stopPolling();

            if (!resp.ok) {
                alert(data.error || '분석 실패');
                resetForm();
                return;
            }

            progressBar.style.width = '100%';
            progressText.textContent = '100%';
            progressMsg.textContent = '완료! 결과 페이지로 이동합니다...';

            setTimeout(() => {
                window.location.href = data.redirect;
            }, 500);
        } catch (err) {
            stopPolling();
            alert('업로드 실패: ' + err.message);
            resetForm();
        }
    });

    function resetForm() {
        uploadBtn.disabled = false;
        uploadBtn.textContent = '분석 시작';
        progressArea.classList.add('hidden');
        progressBar.style.width = '0%';
        progressText.textContent = '0%';
        progressMsg.textContent = '';
        cancelBtn.classList.add('hidden');
        currentJobId = null;
    }

    // 본인 job만 취소한다(과거 전역 /api/cancel은 동시 사용자의 분석까지 죽였음).
    // onclick="cancelAnalysis()"가 호출하도록 window에 노출하되 job_id는 클로저로 참조.
    async function cancelAnalysis() {
        const btn = document.getElementById('cancel-btn');
        btn.disabled = true;
        btn.textContent = '중지 중...';
        try {
            await fetch(
                currentJobId
                    ? `/api/cancel/${encodeURIComponent(currentJobId)}`
                    : '/api/cancel',
                { method: 'POST' }
            );
        } catch (e) {
            /* ignore */
        }
    }
    window.cancelAnalysis = cancelAnalysis;
})();
