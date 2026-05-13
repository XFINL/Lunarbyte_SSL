
let currentRequestId = null;

document.getElementById('ssl-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const domain = document.getElementById('domain').value;
    const ca = document.getElementById('ca').value;
    const email = document.getElementById('email').value;
    
    try {
        const response = await fetch('/api/request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, ca, email })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentRequestId = data.id;
            showVerificationStep(data.verification);
        } else {
            alert('錯誤: ' + data.error);
        }
    } catch (err) {
        alert('網路錯誤: ' + err);
    }
});

function showVerificationStep(verification) {
    document.getElementById('step-form').classList.add('hidden');
    document.getElementById('step-verify').classList.remove('hidden');
    
    const content = document.getElementById('verification-content');
    
    if (verification.type === 'http-01') {
        content.innerHTML = `
            <div class="mb-6 p-4 bg-yellow-50 border border-yellow-200 rounded-xl">
                <h3 class="font-bold text-yellow-800 mb-2">HTTP-01 驗證方法</h3>
                <p class="text-yellow-700 text-sm mb-4">請在您的網站根目錄建立以下檔案</p>
            </div>
            <div class="mb-4">
                <label class="block text-sm font-medium text-gray-700 mb-2">檔案路徑</label>
                <div class="flex gap-2">
                    <div class="code-block flex-grow">${verification.file.path}</div>
                    <button class="copy-btn" onclick="copyText('${verification.file.path}')">複製</button>
                </div>
            </div>
            <div class="mb-4">
                <label class="block text-sm font-medium text-gray-700 mb-2">檔案內容</label>
                <div class="flex gap-2">
                    <div class="code-block flex-grow">${verification.file.content}</div>
                    <button class="copy-btn" onclick="copyText('${verification.file.content}')">複製</button>
                </div>
            </div>
            <p class="text-gray-600 text-sm">建立完檔案後，點擊「檢查驗證狀態」按鈕</p>
        `;
    } else if (verification.type === 'dns-01') {
        content.innerHTML = `
            <div class="mb-6 p-4 bg-yellow-50 border border-yellow-200 rounded-xl">
                <h3 class="font-bold text-yellow-800 mb-2">DNS-01 驗證方法</h3>
                <p class="text-yellow-700 text-sm mb-4">請在您的DNS管理員新增以下TXT記錄</p>
            </div>
            <div class="mb-4">
                <label class="block text-sm font-medium text-gray-700 mb-2">記錄類型</label>
                <div class="code-block">${verification.record.type}</div>
            </div>
            <div class="mb-4">
                <label class="block text-sm font-medium text-gray-700 mb-2">主機名稱</label>
                <div class="flex gap-2">
                    <div class="code-block flex-grow">${verification.record.name}</div>
                    <button class="copy-btn" onclick="copyText('${verification.record.name}')">複製</button>
                </div>
            </div>
            <div class="mb-4">
                <label class="block text-sm font-medium text-gray-700 mb-2">記錄值</label>
                <div class="flex gap-2">
                    <div class="code-block flex-grow">${verification.record.value}</div>
                    <button class="copy-btn" onclick="copyText('${verification.record.value}')">複製</button>
                </div>
            </div>
            <p class="text-gray-600 text-sm">DNS記錄生效可能需要幾分鐘，請稍後再點擊「檢查驗證狀態」</p>
        `;
    }
}

document.getElementById('check-btn').addEventListener('click', async () => {
    document.getElementById('checking-status').classList.remove('hidden');
    document.getElementById('check-btn').disabled = true;
    
    try {
        const response = await fetch(`/api/check/${currentRequestId}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            if (data.status === 'valid') {
                showDownloadStep();
            } else if (data.status === 'invalid') {
                alert('驗證失敗: ' + (data.message || '請檢查您的驗證設置'));
            } else {
                alert('還在等待驗證，請稍後再試...');
            }
        } else {
            alert('錯誤: ' + data.error);
        }
    } catch (err) {
        alert('網路錯誤: ' + err);
    } finally {
        document.getElementById('checking-status').classList.add('hidden');
        document.getElementById('check-btn').disabled = false;
    }
});

document.getElementById('back-btn').addEventListener('click', () => {
    document.getElementById('step-verify').classList.add('hidden');
    document.getElementById('step-form').classList.remove('hidden');
    currentRequestId = null;
});

function showDownloadStep() {
    document.getElementById('step-verify').classList.add('hidden');
    document.getElementById('step-download').classList.remove('hidden');
}

function downloadFile(type) {
    window.location.href = `/api/cert/${currentRequestId}?type=${type}`;
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('已複製到剪貼簿!');
    }).catch(() => {
        alert('複製失敗，請手動複製');
    });
}
