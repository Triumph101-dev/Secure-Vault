/* ===================================
   FILEHANDLER.JS - File Operations Manager
   Handles file upload, encryption, and download
   AES-256-GCM + RSA-OAEP Hybrid Cryptography
   =================================== */

var FileHandler = {
    currentFile: null,
    currentDecryptFile: null,

    init() {
        console.log('FileHandler initialized');
        this.setupFileInput();
        this.setupDragAndDrop();
        this.setupDecryptInput();
    },

    setupFileInput() {
        const fileInput = document.getElementById('file-input');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) this.handleFileSelect(file);
            });
        }
    },

    setupDragAndDrop() {
        const uploadArea = document.getElementById('upload-area');
        if (!uploadArea) return;

        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('drag-over');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('drag-over');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            const file = e.dataTransfer.files[0];
            if (file) this.handleFileSelect(file);
        });
    },

    setupDecryptInput() {
        const decryptInput = document.getElementById('decrypt-file-input');
        if (decryptInput) {
            decryptInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) this.handleDecryptFileSelect(file);
            });
        }
    },

    handleFileSelect(file) {
        const maxSize = 1024 * 1024 * 1024; // 1GB
        if (file.size > maxSize) {
            AuthManager.showAlert('File too large. Maximum size is 1GB', 'error');
            return;
        }

        this.currentFile = file;

        const uploadArea = document.getElementById('upload-area');
        const fileInfo = document.getElementById('file-info');
        const fileName = document.getElementById('file-name');
        const fileSize = document.getElementById('file-size');
        const fileType = document.getElementById('file-type');

        if (uploadArea) uploadArea.style.display = 'none';
        if (fileInfo) fileInfo.style.display = 'block';
        if (fileName) fileName.textContent = file.name;
        if (fileSize) fileSize.textContent = this.formatFileSize(file.size);
        if (fileType) fileType.textContent = file.type || 'Unknown type';

        document.getElementById('encrypt-password').value = '';
        document.getElementById('encrypt-password-confirm').value = '';
    },

    cancelFileSelection() {
        this.currentFile = null;
        const uploadArea = document.getElementById('upload-area');
        const fileInfo = document.getElementById('file-info');
        if (uploadArea) uploadArea.style.display = 'flex';
        if (fileInfo) fileInfo.style.display = 'none';
        const fileInput = document.getElementById('file-input');
        if (fileInput) fileInput.value = '';
    },

    async encryptFile() {
        if (!this.currentFile) {
            AuthManager.showAlert('No file selected', 'error');
            return;
        }

        const password = document.getElementById('encrypt-password').value;
        const confirmPassword = document.getElementById('encrypt-password-confirm').value;

        if (!password || !confirmPassword) {
            AuthManager.showAlert('Please enter and confirm encryption password', 'error');
            return;
        }

        if (password !== confirmPassword) {
            AuthManager.showAlert('Passwords do not match', 'error');
            return;
        }

        const strengthCheck = EncryptionManager.validatePasswordStrength(password);
        if (strengthCheck.strength === 'weak') {
            AuthManager.showAlert('Password is too weak. Use at least 12 characters.', 'error');
            return;
        }

        const fileInfo = document.getElementById('file-info');
        const progress = document.getElementById('encrypt-progress');
        const progressFill = document.getElementById('encrypt-progress-fill');
        const status = document.getElementById('encrypt-status');

        if (fileInfo) fileInfo.style.display = 'none';
        if (progress) progress.style.display = 'block';

        try {
            status.textContent = 'Reading file...';
            progressFill.style.width = '10%';
            const fileData = await this.readFileAsArrayBuffer(this.currentFile);

            // Encrypt with AES-256-GCM session key wrapped by RSA-OAEP
            status.textContent = 'Encrypting with AES-256-GCM + RSA-OAEP...';
            const encrypted = await EncryptionManager.encryptFile(
                fileData,
                password,
                (percent) => {
                    progressFill.style.width = (10 + percent * 0.8) + '%';
                }
            );

            if (!encrypted.success) {
                throw new Error(encrypted.error);
            }

            status.textContent = 'Preparing download...';
            progressFill.style.width = '95%';

            // File package now includes RSA-OAEP fields
            const filePackage = {
                version: '2.0',
                fileName: this.currentFile.name,
                fileSize: this.currentFile.size,
                mimeType: this.currentFile.type,
                encryptedData: encrypted.encryptedData,
                salt: encrypted.salt,
                iv: encrypted.iv,
                wrappedSessionKey: encrypted.wrappedSessionKey,
                encryptedPrivateKey: encrypted.encryptedPrivateKey,
                privateKeyIv: encrypted.privateKeyIv,
                encryptedAt: new Date().toISOString()
            };

            this.downloadEncryptedFile(filePackage);

            progressFill.style.width = '100%';
            status.textContent = 'Complete!';

            AuthManager.showAlert('File encrypted successfully!', 'success');

            setTimeout(() => {
                this.resetEncryptTab();
            }, 2000);

        } catch (error) {
            console.error('Encryption error:', error);
            AuthManager.showAlert('Encryption failed: ' + error.message, 'error');
            this.resetEncryptTab();
        }
    },

    handleDecryptFileSelect(file) {
        if (!file.name.endsWith('.encrypted')) {
            AuthManager.showAlert('Please select a valid encrypted file (.encrypted)', 'warning');
            return;
        }

        this.currentDecryptFile = file;

        const uploadArea = document.getElementById('decrypt-upload-area');
        const decryptInfo = document.getElementById('decrypt-info');
        const fileName = document.getElementById('decrypt-file-name');

        if (uploadArea) uploadArea.style.display = 'none';
        if (decryptInfo) decryptInfo.style.display = 'block';
        if (fileName) fileName.textContent = file.name;

        document.getElementById('decrypt-password').value = '';
    },

    cancelDecryptSelection() {
        this.currentDecryptFile = null;
        const uploadArea = document.getElementById('decrypt-upload-area');
        const decryptInfo = document.getElementById('decrypt-info');
        if (uploadArea) uploadArea.style.display = 'flex';
        if (decryptInfo) decryptInfo.style.display = 'none';
        const fileInput = document.getElementById('decrypt-file-input');
        if (fileInput) fileInput.value = '';
    },

    async decryptFile() {
        if (!this.currentDecryptFile) {
            AuthManager.showAlert('No file selected', 'error');
            return;
        }

        const password = document.getElementById('decrypt-password').value;

        if (!password) {
            AuthManager.showAlert('Please enter decryption password', 'error');
            return;
        }

        const decryptInfo = document.getElementById('decrypt-info');
        const progress = document.getElementById('decrypt-progress');
        const progressFill = document.getElementById('decrypt-progress-fill');
        const status = document.getElementById('decrypt-status');

        if (decryptInfo) decryptInfo.style.display = 'none';
        if (progress) progress.style.display = 'block';

        try {
            status.textContent = 'Reading encrypted file...';
            progressFill.style.width = '10%';
            const fileContent = await this.readFileAsText(this.currentDecryptFile);

            status.textContent = 'Parsing...';
            progressFill.style.width = '20%';
            const filePackage = JSON.parse(fileContent);

            // Decrypt using AES-256-GCM session key unwrapped via RSA-OAEP
            status.textContent = 'Decrypting with AES-256-GCM + RSA-OAEP...';
            const decrypted = await EncryptionManager.decryptFile(
                filePackage.encryptedData,
                password,
                filePackage.salt,
                filePackage.iv,
                filePackage.wrappedSessionKey,
                filePackage.encryptedPrivateKey,
                filePackage.privateKeyIv,
                (percent) => {
                    progressFill.style.width = (20 + percent * 0.7) + '%';
                }
            );

            if (!decrypted.success) {
                throw new Error(decrypted.error);
            }

            status.textContent = 'Preparing download...';
            progressFill.style.width = '95%';

            this.downloadDecryptedFile(
                decrypted.fileData,
                filePackage.fileName,
                filePackage.mimeType
            );

            progressFill.style.width = '100%';
            status.textContent = 'Complete!';

            AuthManager.showAlert('File decrypted successfully!', 'success');

            setTimeout(() => {
                this.resetDecryptTab();
            }, 2000);

        } catch (error) {
            console.error('Decryption error:', error);
            AuthManager.showAlert('Decryption failed. Check your password.', 'error');
            this.resetDecryptTab();
        }
    },

    readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsArrayBuffer(file);
        });
    },

    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsText(file);
        });
    },

    downloadEncryptedFile(filePackage) {
        const blob = new Blob([JSON.stringify(filePackage)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filePackage.fileName + '.encrypted';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },

    downloadDecryptedFile(arrayBuffer, fileName, mimeType) {
        const blob = new Blob([arrayBuffer], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },

    resetEncryptTab() {
        this.currentFile = null;
        const uploadArea = document.getElementById('upload-area');
        const fileInfo = document.getElementById('file-info');
        const progress = document.getElementById('encrypt-progress');
        const progressFill = document.getElementById('encrypt-progress-fill');
        if (uploadArea) uploadArea.style.display = 'flex';
        if (fileInfo) fileInfo.style.display = 'none';
        if (progress) progress.style.display = 'none';
        if (progressFill) progressFill.style.width = '0%';
        const fileInput = document.getElementById('file-input');
        if (fileInput) fileInput.value = '';
        document.getElementById('encrypt-password').value = '';
        document.getElementById('encrypt-password-confirm').value = '';
    },

    resetDecryptTab() {
        this.currentDecryptFile = null;
        const uploadArea = document.getElementById('decrypt-upload-area');
        const decryptInfo = document.getElementById('decrypt-info');
        const progress = document.getElementById('decrypt-progress');
        const progressFill = document.getElementById('decrypt-progress-fill');
        if (uploadArea) uploadArea.style.display = 'flex';
        if (decryptInfo) decryptInfo.style.display = 'none';
        if (progress) progress.style.display = 'none';
        if (progressFill) progressFill.style.width = '0%';
        const fileInput = document.getElementById('decrypt-file-input');
        if (fileInput) fileInput.value = '';
        document.getElementById('decrypt-password').value = '';
    },

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    }
};

// Global functions
function encryptFile() { FileHandler.encryptFile(); }
function decryptFile() { FileHandler.decryptFile(); }
function cancelFileSelection() { FileHandler.cancelFileSelection(); }
function cancelDecryptSelection() { FileHandler.cancelDecryptSelection(); }

if (typeof window !== 'undefined') {
    console.log('FileHandler module loaded');
}
