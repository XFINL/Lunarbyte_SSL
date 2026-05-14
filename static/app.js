let currentRequestId = null;
let selectedCA = null;

document.getElementById('ssl-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    if (!selectedCA) {
        alert('请先选择SSL服务商');
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
            alert('错误: ' + data.error);
        }
    } catch (err) {
        alert('网络错误: ' + err);
    }
});

// CA Selector Functions
function toggleCAOptions() {
    const modal = document.getElementById('ca-modal');
    const arrow = document.getElementById('ca-arrow');
    const selector = document.getElementById('ca-selector');
    
    if (modal.classList.contains('hidden')) {
        modal.classList.remove('hidden');
        modal.classList.add('modal-enter');
        arrow.style.transform = 'rotate(180deg)';
        selector.setAttribute('aria-expanded', 'true');
    } else {
        modal.classList.add('hidden');
        modal.classList.remove('modal-enter');
        arrow.style.transform = 'rotate(0deg)';
        selector.setAttribute('aria-expanded', 'false');
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
                <h3 class="font-bold text-gray-800 text-xl mb-4 flex items-center">
                    <svg class="w-7 h-7 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                    </svg>
                    HTTP-01 验证方法
                </h3>
                <p class="text-gray-700 opacity-80 mb-6">请在您的网站根目录建立以下文件</p>
            </div>
            <div class="mb-5">
                <label class="block text-sm font-semibold text-gray-700 opacity-80 mb-3">文件路径</label>
                <div class="flex gap-3">
                    <div class="code-block flex-grow">${verification.file.path}</div>
                    <button class="copy-btn" onclick="copyText('${verification.file.path}')">复制</button>
                </div>
            </div>
            <div class="mb-5">
                <label class="block text-sm font-semibold text-gray-700 opacity-80 mb-3">文件内容</label>
                <div class="flex gap-3">
                    <div class="code-block flex-grow">${verification.file.content}</div>
                    <button class="copy-btn" onclick="copyText('${verification.file.content}')">复制</button>
                </div>
            </div>
            <p class="text-gray-700 opacity-70 text-sm">建立完文件后，点击「检查验证状态」按钮</p>
        `;
    } else if (verification.type === 'dns-01') {
        content.innerHTML = `
            <div class="mb-7 glass-card p-7">
                <h3 class="font-bold text-gray-800 text-xl mb-4 flex items-center">
                    <svg class="w-7 h-7 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path>
                    </svg>
                    DNS-01 验证方法
                </h3>
                <p class="text-gray-700 opacity-80 mb-6">请在您的DNS管理员新增以下TXT记录</p>
            </div>
            <div class="mb-5">
                <label class="block text-sm font-semibold text-gray-700 opacity-80 mb-3">记录类型</label>
                <div class="code-block">${verification.record.type}</div>
            </div>
            <div class="mb-5">
                <label class="block text-sm font-semibold text-gray-700 opacity-80 mb-3">主机名称</label>
                <div class="flex gap-3">
                    <div class="code-block flex-grow">${verification.record.name}</div>
                    <button class="copy-btn" onclick="copyText('${verification.record.name}')">复制</button>
                </div>
            </div>
            <div class="mb-5">
                <label class="block text-sm font-semibold text-gray-700 opacity-80 mb-3">记录值</label>
                <div class="flex gap-3">
                    <div class="code-block flex-grow">${verification.record.value}</div>
                    <button class="copy-btn" onclick="copyText('${verification.record.value}')">复制</button>
                </div>
            </div>
            <p class="text-gray-700 opacity-70 text-sm">DNS记录生效可能需要几分钟，请稍后再点击「检查验证状态」</p>
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
                alert('验证失败: ' + (data.message || '请检查您的验证设置'));
            } else {
                alert('还在等待验证，请稍后再试...');
            }
        } else {
            alert('错误: ' + data.error);
        }
    } catch (err) {
        alert('网络错误: ' + err);
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
        alert('已复制到剪贴簿!');
    }).catch(() => {
        alert('复制失败，请手动复制');
    });
}

// Keyboard accessibility
document.getElementById('ca-selector').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleCAOptions();
    }
});
