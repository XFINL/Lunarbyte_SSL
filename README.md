
# 一鍵免費SSL申請工具

一個簡單易用的Web應用，幫助您快速申請免費的SSL證書（支持Let's Encrypt和ZeroSSL）。

## 功能特點

- 🚀 一鍵申請，操作簡單
- 🔐 支持Let's Encrypt和ZeroSSL
- 📋 HTTP-01和DNS-01驗證
- 💾 證書自動下載
- 🎨 現代化的介面設計

## 安裝與執行

### 1. 安裝依賴

```bash
pip install -r requirements.txt
```

### 2. 啟動應用

```bash
python app.py
```

### 3. 打開瀏覽器

訪問 `http://localhost:5000`

## 使用說明

1. 輸入您的域名（例如: example.com）
2. 選擇SSL服務商（建議先使用Let's Encrypt Staging進行測試）
3. 按照頁面提示完成域名驗證
4. 下載您的SSL證書

## 注意事項

- 本應用僅用於學習和開發測試
- 正式環境請使用成熟的ACME客戶端（如certbot）
- 證書和私鑰臨時儲存於記憶體中，重啟應用後會丟失
