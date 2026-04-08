/* pcap 파일 업로드 + 드래그앤드롭 */
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
            fileInput.files = e.dataTransfer.files;
            showFileName(e.dataTransfer.files[0].name);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) {
            showFileName(fileInput.files[0].name);
        }
    });

    function showFileName(name) {
        fileName.textContent = name;
        fileName.classList.remove('hidden');
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!fileInput.files.length) {
            alert('pcap 파일을 선택하세요.');
            return;
        }

        const formData = new FormData(form);
        formData.set('file', fileInput.files[0]);

        uploadBtn.disabled = true;
        uploadBtn.textContent = '분석 중...';
        progressArea.classList.remove('hidden');
        document.getElementById('cancel-btn').classList.remove('hidden');

        try {
            const resp = await fetch('/api/upload', { method: 'POST', body: formData });
            const data = await resp.json();

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
        document.getElementById('cancel-btn').classList.add('hidden');
    }
})();

async function cancelAnalysis() {
    const btn = document.getElementById('cancel-btn');
    btn.disabled = true;
    btn.textContent = '중지 중...';
    try {
        await fetch('/api/cancel', { method: 'POST' });
    } catch (e) {
        /* ignore */
    }
}
