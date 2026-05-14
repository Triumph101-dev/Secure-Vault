/* ===================================
   STORAGE.JS - Browser Storage Management
   Handles all localStorage and data persistence
   =================================== */

var SVStorage = {
    KEYS: {
        MASTER_HASH: 'sv_master_hash',
        MASTER_SALT: 'sv_master_salt',
        ENCRYPTED_NOTES: 'sv_notes',
        SETTINGS: 'sv_settings',
        SESSION: 'sv_session',
        USER_EMAIL: 'sv_user_email'
    },

    init() {
        console.log('SVStorage initialized');
        return this.hasUser();
    },

    hasUser() {
        return localStorage.getItem(this.KEYS.MASTER_HASH) !== null;
    },

saveMasterPassword(passwordHash, salt) {
    try {
        const saltBase64 = EncryptionManager.arrayBufferToBase64(
            salt instanceof Uint8Array ? salt.buffer : salt
        );
        localStorage.setItem(this.KEYS.MASTER_HASH, passwordHash);
        localStorage.setItem(this.KEYS.MASTER_SALT, saltBase64);
        return true;
    } catch (error) {
        console.error('Error saving master password:', error);
        return false;
    }
},

getSalt() {
    const saltBase64 = localStorage.getItem(this.KEYS.MASTER_SALT);
    if (!saltBase64) return null;
    return EncryptionManager.base64ToUint8Array(saltBase64);
},

getMasterHash() {
    return localStorage.getItem(this.KEYS.MASTER_HASH);
},


    /**
     * Save user email for recovery
     */
    saveUserEmail(email) {
        try {
            // Store email as-is (it's not sensitive like the password)
            localStorage.setItem(this.KEYS.USER_EMAIL, email);
            return true;
        } catch (error) {
            console.error('Error saving email:', error);
            return false;
        }
    },

    /**
     * Get registered user email
     */
    getUserEmail() {
        return localStorage.getItem(this.KEYS.USER_EMAIL);
    },

    saveNotes(encryptedNotes) {
        try {
            localStorage.setItem(this.KEYS.ENCRYPTED_NOTES, JSON.stringify(encryptedNotes));
            return true;
        } catch (error) {
            console.error('Error saving notes:', error);
            alert('Storage quota exceeded. Please delete some notes or export your data.');
            return false;
        }
    },

    getNotes() {
        try {
            const notes = localStorage.getItem(this.KEYS.ENCRYPTED_NOTES);
            return notes ? JSON.parse(notes) : [];
        } catch (error) {
            console.error('Error retrieving notes:', error);
            return [];
        }
    },

    saveSettings(settings) {
        try {
            localStorage.setItem(this.KEYS.SETTINGS, JSON.stringify(settings));
            return true;
        } catch (error) {
            console.error('Error saving settings:', error);
            return false;
        }
    },

    getSettings() {
        try {
            const settings = localStorage.getItem(this.KEYS.SETTINGS);
            return settings ? JSON.parse(settings) : this.getDefaultSettings();
        } catch (error) {
            return this.getDefaultSettings();
        }
    },

getDefaultSettings() {
    return {
        autoLockTimeout: 15,
        theme: 'dark',
        encryptionIterations: 310000
    };
},

    createSession() {
        const session = { timestamp: Date.now(), isActive: true };
        sessionStorage.setItem(this.KEYS.SESSION, JSON.stringify(session));
    },

    isSessionActive() {
        try {
            const session = sessionStorage.getItem(this.KEYS.SESSION);
            if (!session) return false;

            const sessionData = JSON.parse(session);
            const settings = this.getSettings();
            const timeout = settings.autoLockTimeout * 60 * 1000;

            if (Date.now() - sessionData.timestamp > timeout) {
                this.clearSession();
                return false;
            }
            return sessionData.isActive;
        } catch (error) {
            return false;
        }
    },

    refreshSession() {
        try {
            const session = sessionStorage.getItem(this.KEYS.SESSION);
            if (session) {
                const sessionData = JSON.parse(session);
                sessionData.timestamp = Date.now();
                sessionStorage.setItem(this.KEYS.SESSION, JSON.stringify(sessionData));
            }
        } catch (error) {
            console.error('Error refreshing session:', error);
        }
    },

    clearSession() {
        sessionStorage.removeItem(this.KEYS.SESSION);
    },

exportData() {
    try {
        const data = {
            version: '1.1',
            exportDate: new Date().toISOString(),
            masterHash: this.getMasterHash(),
            masterSalt: localStorage.getItem(this.KEYS.MASTER_SALT), // raw Base64 string
            userEmail: this.getUserEmail(),
            notes: this.getNotes(),
            settings: this.getSettings()
        };
        return JSON.stringify(data);
    } catch (error) {
        console.error('Error exporting data:', error);
        return null;
    }
},

    importData(jsonData) {
        try {
            const data = JSON.parse(jsonData);

            if (!data.version || !data.masterHash || !data.masterSalt) {
                throw new Error('Invalid backup file format');
            }

            localStorage.setItem(this.KEYS.MASTER_HASH, data.masterHash);
            localStorage.setItem(this.KEYS.MASTER_SALT, data.masterSalt);

            if (data.userEmail) {
                localStorage.setItem(this.KEYS.USER_EMAIL, data.userEmail);
            }
            if (data.notes) {
                localStorage.setItem(this.KEYS.ENCRYPTED_NOTES, JSON.stringify(data.notes));
            }
            if (data.settings) {
                localStorage.setItem(this.KEYS.SETTINGS, JSON.stringify(data.settings));
            }

            return true;
        } catch (error) {
            console.error('Error importing data:', error);
            return false;
        }
    },

    clearAllData() {
        try {
            Object.values(this.KEYS).forEach(key => {
                localStorage.removeItem(key);
            });
            this.clearSession();
            return true;
        } catch (error) {
            console.error('Error clearing data:', error);
            return false;
        }
    },

    getStorageInfo() {
        try {
            let totalSize = 0;
            for (let key in localStorage) {
                if (localStorage.hasOwnProperty(key)) {
                    totalSize += localStorage[key].length + key.length;
                }
            }
            const sizeInKB = (totalSize / 1024).toFixed(2);
            return {
                used: sizeInKB,
                estimated: '5-10 MB',
                percentage: (totalSize / (5 * 1024 * 1024) * 100).toFixed(2),
                notes: this.getNotes().length
            };
        } catch (error) {
            return null;
        }
    }
};

if (typeof window !== 'undefined') {
    console.log('Storage module loaded');
}