/* ===================================
   APP.JS - Main Application Controller
   Orchestrates all modules and handles navigation
   =================================== */

   // Global functions
function showSection(section) { AppController.showSection(section); }
function switchTab(tab) { AppController.switchTab(tab); }
function exportData() { AppController.exportData(); }
function importData() { AppController.importData(); }
function deleteAllData() { AppController.deleteAllData(); }
function generateAndShowPassword() { AppController.generateAndShowPassword(); }
function refreshStorageInfo() { AppController.refreshStorageInfo(); }

function copyGeneratedPassword() {
    const text = document.getElementById('generated-password-text')?.textContent;
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        AuthManager.showAlert('Password copied to clipboard!', 'success');
    }).catch(() => {
        AuthManager.showAlert('Could not copy. Please copy manually.', 'warning');
    });
}

var AppController = {
    currentSection: 'files',

    init() {
        console.log('AppController initialized');
        FileHandler.init();
        NoteManager.init();
        this.setupNavigation();
        this.showSection('files');
        this.setupSettings();
        console.log('✓ SecureVault is ready!');
    },

    setupNavigation() {
        console.log('Navigation setup complete');
    },

   async showSection(sectionName) {
        document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));

        const selectedSection = document.getElementById(sectionName + '-section');
        if (selectedSection) selectedSection.classList.add('active');

        const selectedNav = document.getElementById('nav-' + sectionName);
        if (selectedNav) selectedNav.classList.add('active');

        this.currentSection = sectionName;

if (sectionName === 'notes') {
    await NoteManager.loadNotes();
    NoteManager.displayNotes();
}

        if (sectionName === 'settings') {
            this.refreshStorageInfo();
        }
    },

    switchTab(tabName) {
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));

        const selectedTab = document.getElementById(tabName + '-tab');
        if (selectedTab) selectedTab.classList.add('active');

        const selectedBtn = document.getElementById('tab-' + tabName);
        if (selectedBtn) selectedBtn.classList.add('active');
    },

    setupSettings() {
        console.log('Settings handlers ready');
    },

    exportData() {
        try {
            const data = SVStorage.exportData();
            if (!data) {
                AuthManager.showAlert('Export failed', 'error');
                return;
            }

            const blob = new Blob([data], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `securevault_backup_${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            AuthManager.showAlert('Data exported successfully!', 'success');
        } catch (error) {
            console.error('Export error:', error);
            AuthManager.showAlert('Export failed: ' + error.message, 'error');
        }
    },

    importData() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';

        input.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            try {
                const text = await this.readFileAsText(file);

                if (!confirm('⚠️ WARNING: Importing will replace ALL your current data. Make sure you have a backup! Continue?')) return;

                if (SVStorage.importData(text)) {
                    AuthManager.showAlert('Data imported successfully! Please login again.', 'success');
                    setTimeout(() => {
                        AuthManager.logout();
                        location.reload();
                    }, 2000);
                } else {
                    AuthManager.showAlert('Import failed. Invalid file format.', 'error');
                }
            } catch (error) {
                console.error('Import error:', error);
                AuthManager.showAlert('Import failed: ' + error.message, 'error');
            }
        };

        input.click();
    },

    deleteAllData() {
        const confirmation = prompt('⚠️ FINAL WARNING: This will delete ALL your data permanently!\n\nType "DELETE ALL" to confirm:');

        if (confirmation === 'DELETE ALL') {
            if (SVStorage.clearAllData()) {
                AuthManager.showAlert('All data deleted. Reloading...', 'success');
                setTimeout(() => { location.reload(); }, 2000);
            } else {
                AuthManager.showAlert('Error deleting data', 'error');
            }
        } else {
            AuthManager.showAlert('Deletion cancelled', 'warning');
        }
    },

    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsText(file);
        });
    },

    /**
     * Generate a strong password and display it in Settings
     */
    generateAndShowPassword() {
        const password = EncryptionManager.generateSecurePassword(18);
        const display = document.getElementById('generated-password-display');
        const text = document.getElementById('generated-password-text');

        if (display && text) {
            text.textContent = password;
            display.style.display = 'block';
        }
    },

    /**
     * Refresh and display storage info
     */
    refreshStorageInfo() {
        const info = SVStorage.getStorageInfo();
        const container = document.getElementById('storage-info-display');
        if (!container || !info) return;

        const percentage = parseFloat(info.percentage);
        const barColor = percentage > 80 ? 'var(--accent-danger)' : percentage > 50 ? 'var(--accent-warning)' : 'var(--accent-success)';

        container.innerHTML = `
            <div class="storage-stats">
                <div class="storage-stat">
                    <span class="stat-label">Used Storage</span>
                    <span class="stat-value">${info.used} KB</span>
                </div>
                <div class="storage-stat">
                    <span class="stat-label">Notes Saved</span>
                    <span class="stat-value">${info.notes}</span>
                </div>
                <div class="storage-stat">
                    <span class="stat-label">Usage</span>
                    <span class="stat-value">${info.percentage}%</span>
                </div>
            </div>
            <div class="storage-bar-wrapper">
                <div class="storage-bar-track">
                    <div class="storage-bar-fill" style="width: ${Math.min(percentage, 100)}%; background: ${barColor};"></div>
                </div>
                <span class="storage-bar-label">of estimated ${info.estimated}</span>
            </div>
            <button onclick="refreshStorageInfo()" class="btn btn-secondary btn-sm" style="margin-top: 0.75rem;">↻ Refresh</button>
        `;
    }
};


document.addEventListener('DOMContentLoaded', () => {
    console.log('=== SecureVault Starting ===');
    AuthManager.init();
    console.log('=== SecureVault Ready ===');
});
```

---

## **🎉 YOUR PROJECT IS COMPLETE! 🎉**

---

## **WHAT WE'VE BUILT:**

### **✅ Complete File Structure:**
```
// secure-vault/
// ├── index.html              ✅ Complete
// ├── css/
// │   └── style.css          ✅ Professional & Modern
// ├── js/
// │   ├── storage.js         ✅ Browser Storage Manager
// │   ├── encryption.js      ✅ AES-256 Encryption
// │   ├── auth.js            ✅ Authentication System
// │   ├── fileHandler.js     ✅ File Encryption/Decryption
// │   ├── noteManager.js     ✅ Secure Notes CRUD
// │   └── app.js             ✅ Main Controller
// └── lib/
//     └── crypto-js.min.js   ✅ (Download from CDN)
