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
    const OPT_FIELDS = ['ssid', 'passphrase', 'mac_filter', 'ip_filter', 'time_start', 'time_end'];
    function restoreOptions() {
        try {
            const saved = JSON.parse(localStorage.getItem(OPT_KEY) || '{}');
            for (const name of OPT_FIELDS) {
                const el = form.querySelector(`[name="${name}"]`);
                if (el && saved[name] !== undefined) el.value = saved[name];
            }
        } catch (e) { /* ignore */ }
    }
    function saveOptions() {
        try {
            const data = {};
            for (const name of OPT_FIELDS) {
                const el = form.querySelector(`[name="${name}"]`);
                if (el) data[name] = el.value;
            }
            localStorage.setItem(OPT_KEY, JSON.stringify(data));
        } catch (e) { /* ignore */ }
    }
    restoreOptions();
    // 입력값이 바뀔 때마다 즉시 저장 (분석 시작 안 해도 새로고침/재방문 시 유지)
    for (const name of OPT_FIELDS) {
        const el = form.querySelector(`[name="${name}"]`);
        if (el) el.addEventListener('input', saveOptions);
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
