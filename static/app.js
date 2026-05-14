let currentRequestId = null;
let selectedCA = null;

document.getElementById('ssl-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    if (!selectedCA) {
        alert('請先選擇SSL服務商');
        return;
    }
    
    const domain = document.getElementById('domain').value;
    const email = document.getElementById('email').value;
    
    try {
        const response = await fetch('/api/request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, ca: selectedCA, email })
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

// CA Selector Functions
function toggleCAOptions() {
    const modal = document.getElementById('ca-modal');
    const arrow = document.getElementById('ca-arrow');
    
    if (modal.classList.contains('hidden')) {
        modal.classList.remove('hidden');
        modal.classList.add('modal-enter');
        arrow.style.transform = 'rotate(180deg)';
    } else {
        modal.classList.add('hidden');
        modal.classList.remove('modal-enter');
        arrow.style.transform = 'rotate(0deg)';
    }
}

function selectCA(value, displayText) {
    selectedCA = value;
    document.getElementById('ca-selected-text').textContent = displayText;
    document.getElementById('ca-selected-text').classList.remove('opacity-50');
    document.getElementById('ca-selected-text').classList.add('font-medium');
    
    // Mark selected option
    document.querySelectorAll('.ca-option').forEach(el => el.classList.remove('selected'));
    event.currentTarget.classList.add('selected');
    
    toggleCAOptions();
}

function showVerificationStep(verification) {
    document.getElementById('step-form').classList.add('hidden');
    document.getElementById('step-verify').classList.remove('hidden');
    
    const content = document.getElementById('verification-content');
    
    if (verification.type === 'http-01') {
        content.innerHTML = `
            <div class="mb-7 glass-card p-7">
                <h3 class="font-bold text-blue-800 text-xl mb-4 flex items-center">
                    <span class="text-2xl mr-3">📁</span>
                    HTTP-01 驗證方法
                </h3>
                <p class="text-blue-700 opacity-80 mb-6">請在您的網站根目錄建立以下檔案</p>
            </div>
            <div class="mb-5">
                <label class="block text-sm font-semibold text-blue-800 opacity-80 mb-3">檔案路徑</label>
                <div class="flex gap-3">
                    <div class="code-block flex-grow">${verification.file.path}</div>
                    <button class="copy-btn" onclick="copyText('${verification.file.path}')">複製</button>
                </div>
            </div>
            <div class="mb-5">
                <label class="block text-sm font-semibold text-blue-800 opacity-80 mb-3">檔案內容</label>
                <div class="flex gap-3">
                    <div class="code-block flex-grow">${verification.file.content}</div>
                    <button class="copy-btn" onclick="copyText('${verification.file.content}')">複製</button>
                </div>
            </div>
            <p class="text-blue-700 opacity-70 text-sm">建立完檔案後，點擊「檢查驗證狀態」按鈕</p>
        `;
    } else if (verification.type === 'dns-01') {
        content.innerHTML = `
            <div class="mb-7 glass-card p-7">
                <h3 class="font-bold text-blue-800 text-xl mb-4 flex items-center">
                    <span class="text-2xl mr-3">🌐</span>
                    DNS-01 驗證方法
                </h3>
                <p class="text-blue-700 opacity-80 mb-6">請在您的DNS管理員新增以下TXT記錄</p>
            </div>
            <div class="mb-5">
                <label class="block text-sm font-semibold text-blue-800 opacity-80 mb-3">記錄類型</label>
                <div class="code-block">${verification.record.type}</div>
            </div>
            <div class="mb-5">
                <label class="block text-sm font-semibold text-blue-800 opacity-80 mb-3">主機名稱</label>
                <div class="flex gap-3">
                    <div class="code-block flex-grow">${verification.record.name}</div>
                    <button class="copy-btn" onclick="copyText('${verification.record.name}')">複製</button>
                </div>
            </div>
            <div class="mb-5">
                <label class="block text-sm font-semibold text-blue-800 opacity-80 mb-3">記錄值</label>
                <div class="flex gap-3">
                    <div class="code-block flex-grow">${verification.record.value}</div>
                    <button class="copy-btn" onclick="copyText('${verification.record.value}')">複製</button>
                </div>
            </div>
            <p class="text-blue-700 opacity-70 text-sm">DNS記錄生效可能需要幾分鐘，請稍後再點擊「檢查驗證狀態」</p>
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
