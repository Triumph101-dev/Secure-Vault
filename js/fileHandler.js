/* ===================================
   FILEHANDLER.JS - File Operations Manager
   Handles file upload, encryption, and download
   =================================== */

var FileHandler = {
    // Current file being processed
    currentFile: null,
    currentDecryptFile: null,

    /**
     * Initialize file handler
     */
    init() {
        console.log('FileHandler initialized');
        this.setupFileInput();
        this.setupDragAndDrop();
        this.setupDecryptInput();
    },

    /**
     * Setup file input for encryption
     */
    setupFileInput() {
        const fileInput = document.getElementById('file-input');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) {
                    this.handleFileSelect(file);
                }
            });
        }
    },

    /**
     * Setup drag and drop for encryption
     */
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
            if (file) {
                this.handleFileSelect(file);
            }
        });
    },

    /**
     * Setup decrypt file input
     */
    setupDecryptInput() {
        const decryptInput = document.getElementById('decrypt-file-input');
        if (decryptInput) {
            decryptInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) {
                    this.handleDecryptFileSelect(file);
                }
            });
        }
    },

    /**
     * Handle file selection for encryption
     */
    handleFileSelect(file) {
        // Check file size (1GB limit)
        const maxSize = 1024 * 1024 * 1024; // 1GB in bytes
        if (file.size > maxSize) {
            AuthManager.showAlert('File too large. Maximum size is 1GB', 'error');
            return;
        }

        this.currentFile = file;

        // Show file info
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

        // Clear password fields
        document.getElementById('encrypt-password').value = '';
        document.getElementById('encrypt-password-confirm').value = '';
    },

    /**
     * Cancel file selection
     */
    cancelFileSelection() {
        this.currentFile = null;

        const uploadArea = document.getElementById('upload-area');
        const fileInfo = document.getElementById('file-info');

        if (uploadArea) uploadArea.style.display = 'flex';
        if (fileInfo) fileInfo.style.display = 'none';

        // Reset file input
        const fileInput = document.getElementById('file-input');
        if (fileInput) fileInput.value = '';
    },

    /**
     * Encrypt selected file
     */
    async encryptFile() {
        if (!this.currentFile) {
            AuthManager.showAlert('No file selected', 'error');
            return;
        }

        const password = document.getElementById('encrypt-password').value;
        const confirmPassword = document.getElementById('encrypt-password-confirm').value;

        // Validation
        if (!password || !confirmPassword) {
            AuthManager.showAlert('Please enter and confirm encryption password', 'error');
            return;
        }

        if (password !== confirmPassword) {
            AuthManager.showAlert('Passwords do not match', 'error');
            return;
        }

        // Check password strength
        const strengthCheck = EncryptionManager.validatePasswordStrength(password);
        if (strengthCheck.strength === 'weak') {
            AuthManager.showAlert('Password is too weak. Use at least 12 characters.', 'error');
            return;
        }

        // Show progress
        const fileInfo = document.getElementById('file-info');
        const progress = document.getElementById('encrypt-progress');
        const progressFill = document.getElementById('encrypt-progress-fill');
        const status = document.getElementById('encrypt-status');

        if (fileInfo) fileInfo.style.display = 'none';
        if (progress) progress.style.display = 'block';

        try {
            // Read file
            status.textContent = 'Reading file...';
            progressFill.style.width = '10%';
            const fileData = await this.readFileAsArrayBuffer(this.currentFile);

            // Encrypt
            status.textContent = 'Encrypting...';
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

            // Create encrypted file package
            status.textContent = 'Preparing download...';
            progressFill.style.width = '95%';

            const filePackage = {
                version: '1.0',
                fileName: this.currentFile.name,
                fileSize: this.currentFile.size,
                mimeType: this.currentFile.type,
                encryptedData: encrypted.encryptedData,
                salt: encrypted.salt,
                iv: encrypted.iv,
                encryptedAt: new Date().toISOString()
            };

            // Download encrypted file
            this.downloadEncryptedFile(filePackage);

            progressFill.style.width = '100%';
            status.textContent = 'Complete!';

            AuthManager.showAlert('File encrypted successfully!', 'success');

            // Reset after 2 seconds
            setTimeout(() => {
                this.resetEncryptTab();
            }, 2000);

        } catch (error) {
            console.error('Encryption error:', error);
            AuthManager.showAlert('Encryption failed: ' + error.message, 'error');
            this.resetEncryptTab();
        }
    },

    /**
     * Handle decrypt file selection
     */
    handleDecryptFileSelect(file) {
        // Check if it's our encrypted file format
        if (!file.name.endsWith('.encrypted')) {
            AuthManager.showAlert('Please select a valid encrypted file (.encrypted)', 'warning');
            return;
        }

        this.currentDecryptFile = file;

        // Show decrypt info
        const uploadArea = document.getElementById('decrypt-upload-area');
        const decryptInfo = document.getElementById('decrypt-info');
        const fileName = document.getElementById('decrypt-file-name');

        if (uploadArea) uploadArea.style.display = 'none';
        if (decryptInfo) decryptInfo.style.display = 'block';
        if (fileName) fileName.textContent = file.name;

        // Clear password field
        document.getElementById('decrypt-password').value = '';
    },

    /**
     * Cancel decrypt file selection
     */
    cancelDecryptSelection() {
        this.currentDecryptFile = null;

        const uploadArea = document.getElementById('decrypt-upload-area');
        const decryptInfo = document.getElementById('decrypt-info');

        if (uploadArea) uploadArea.style.display = 'flex';
        if (decryptInfo) decryptInfo.style.display = 'none';

        // Reset file input
        const fileInput = document.getElementById('decrypt-file-input');
        if (fileInput) fileInput.value = '';
    },

    /**
     * Decrypt selected file
     */
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

        // Show progress
        const decryptInfo = document.getElementById('decrypt-info');
        const progress = document.getElementById('decrypt-progress');
        const progressFill = document.getElementById('decrypt-progress-fill');
        const status = document.getElementById('decrypt-status');

        if (decryptInfo) decryptInfo.style.display = 'none';
        if (progress) progress.style.display = 'block';

        try {
            // Read encrypted file
            status.textContent = 'Reading encrypted file...';
            progressFill.style.width = '10%';
            const fileContent = await this.readFileAsText(this.currentDecryptFile);

            // Parse file package
            status.textContent = 'Parsing...';
            progressFill.style.width = '20%';
            const filePackage = JSON.parse(fileContent);

            // Decrypt
            status.textContent = 'Decrypting...';
            const decrypted = await EncryptionManager.decryptFile(
                filePackage.encryptedData,
                password,
                filePackage.salt,
                filePackage.iv,
                (percent) => {
                    progressFill.style.width = (20 + percent * 0.7) + '%';
                }
            );

            if (!decrypted.success) {
                throw new Error(decrypted.error);
            }

            // Download decrypted file
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

            // Reset after 2 seconds
            setTimeout(() => {
                this.resetDecryptTab();
            }, 2000);

        } catch (error) {
            console.error('Decryption error:', error);
            AuthManager.showAlert('Decryption failed. Check your password.', 'error');
            this.resetDecryptTab();
        }
    },

    /**
     * Read file as ArrayBuffer
     */
    readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsArrayBuffer(file);
        });
    },

    /**
     * Read file as text
     */
    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsText(file);
        });
    },

    /**
     * Download encrypted file
     */
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

    /**
     * Download decrypted file
     */
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

    /**
     * Reset encrypt tab
     */
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

        // Reset file input
        const fileInput = document.getElementById('file-input');
        if (fileInput) fileInput.value = '';

        // Clear password fields
        document.getElementById('encrypt-password').value = '';
        document.getElementById('encrypt-password-confirm').value = '';
    },

    /**
     * Reset decrypt tab
     */
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

        // Reset file input
        const fileInput = document.getElementById('decrypt-file-input');
        if (fileInput) fileInput.value = '';

        // Clear password field
        document.getElementById('decrypt-password').value = '';
    },

    /**
     * Format file size for display
     */
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    }
};

// Global functions for HTML onclick events
function encryptFile() {
    FileHandler.encryptFile();
}

function decryptFile() {
    FileHandler.decryptFile();
}

function cancelFileSelection() {
    FileHandler.cancelFileSelection();
}

function cancelDecryptSelection() {
    FileHandler.cancelDecryptSelection();
}

// Initialize on load
if (typeof window !== 'undefined') {
    console.log('FileHandler module loaded');
}