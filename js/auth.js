/* ===================================
   AUTH.JS - Authentication Manager
   Handles user authentication, login, password management,
   email-based password recovery via EmailJS
   =================================== */

// EmailJS Configuration
const EMAILJS_CONFIG = {
    SERVICE_ID: 'service_7nfnwjj',
    TEMPLATE_ID: 'template_ztpdugi',
    PUBLIC_KEY: 'safbQLpWAhWMOuQKI'
};

// Recovery state (in-memory only, never stored)
let recoveryState = {
    code: null,
    email: null,
    expiresAt: null
};

var AuthManager = {
    currentSession: {
        isAuthenticated: false,
        masterPassword: null,
        loginTime: null
    },

    /**
     * Initialize authentication on page load
     */
    init() {
        console.log('AuthManager initialized');

        // Initialize EmailJS safely
        try {
            if (typeof emailjs !== 'undefined') {
                emailjs.init(EMAILJS_CONFIG.PUBLIC_KEY);
            }
        } catch(e) {
            console.warn('EmailJS not available:', e);
        }

        if (SVStorage.hasUser()) {
            this.showReturningUserForm();
        } else {
            this.showNewUserForm();
        }

        this.setupAutoLock();

        // If page was refreshed while logged in, show lock overlay instead of full login
        if (sessionStorage.getItem('sv_was_locked') === 'true') {
            sessionStorage.removeItem('sv_was_locked');
            if (SVStorage.hasUser()) {
                document.getElementById('landing-page').classList.remove('active');
                document.getElementById('app-page').classList.add('active');
                setTimeout(() => {
                    this.showLockOverlay();
                }, 100);
            }
        }
    },

    showNewUserForm() {
        document.getElementById('new-user-section').style.display = 'block';
        document.getElementById('returning-user-section').style.display = 'none';

        const newPasswordInput = document.getElementById('new-password');
        if (newPasswordInput) {
            newPasswordInput.addEventListener('input', () => {
                this.checkPasswordStrength(newPasswordInput.value);
            });
        }
    },

    showReturningUserForm() {
        document.getElementById('new-user-section').style.display = 'none';
        document.getElementById('returning-user-section').style.display = 'block';
    },

    checkPasswordStrength(password) {
        const strengthIndicator = document.getElementById('password-strength');
        const strengthFill = document.getElementById('strength-fill');
        const strengthText = document.getElementById('strength-text');

        if (!password) {
            strengthIndicator.style.display = 'none';
            return;
        }

        strengthIndicator.style.display = 'block';
        const result = EncryptionManager.validatePasswordStrength(password);
        strengthFill.className = 'strength-fill ' + result.strength;

        if (result.strength === 'strong') {
            strengthText.textContent = '✓ Strong password';
            strengthText.style.color = 'var(--accent-success)';
        } else if (result.strength === 'medium') {
            strengthText.textContent = '⚠ Medium strength - ' + result.feedback[0];
            strengthText.style.color = 'var(--accent-warning)';
        } else {
            strengthText.textContent = '✗ Weak - ' + result.feedback[0];
            strengthText.style.color = 'var(--accent-danger)';
        }
    },

    /**
     * Create master password (first time setup)
     */
    async createMasterPassword() {
        const email = document.getElementById('user-email').value.trim();
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;

        if (!email) {
            this.showAlert('Please enter your email address for password recovery', 'error');
            return;
        }

        if (!this.isValidEmail(email)) {
            this.showAlert('Please enter a valid email address', 'error');
            return;
        }

        if (!newPassword || !confirmPassword) {
            this.showAlert('Please enter and confirm your password', 'error');
            return;
        }

        if (newPassword !== confirmPassword) {
            this.showAlert('Passwords do not match', 'error');
            return;
        }

        const strengthCheck = EncryptionManager.validatePasswordStrength(newPassword);
        if (strengthCheck.strength === 'weak') {
            this.showAlert('Password is too weak. Please use at least 12 characters with mixed case, numbers, and symbols.', 'error');
            return;
        }

        const salt = EncryptionManager.generateSalt();
        const passwordHash = await EncryptionManager.hashPassword(newPassword, salt);

        if (SVStorage.saveMasterPassword(passwordHash, salt)) {
            // Save email for recovery (encrypted with a fixed app key)
            SVStorage.saveUserEmail(email);
            this.showAlert('Master password created successfully! Logging you in...', 'success');

            setTimeout(() => {
                this.loginUser(newPassword);
            }, 1000);
        } else {
            this.showAlert('Error saving password. Please try again.', 'error');
        }
    },

    /**
     * Login with master password
     */
    async login() {
        const password = document.getElementById('master-password').value;

        if (!password) {
            this.showAlert('Please enter your password', 'error');
            return;
        }

        const storedHash = SVStorage.getMasterHash();
        const salt = SVStorage.getSalt();
        const enteredHash = await EncryptionManager.hashPassword(password, salt);

        if (enteredHash === storedHash) {
            this.loginUser(password);
        } else {
            this.showAlert('Incorrect password', 'error');
            document.getElementById('master-password').value = '';
        }
    },

    loginUser(password) {
        this.currentSession.isAuthenticated = true;
        this.currentSession.masterPassword = password;
        this.currentSession.loginTime = Date.now();
        SVStorage.createSession();
        this.showAlert('Login successful! Welcome to SecureVault', 'success');

        setTimeout(() => {
            this.showApp();
        }, 800);
    },

    showApp() {
        document.getElementById('landing-page').classList.remove('active');
        document.getElementById('app-page').classList.add('active');

        if (typeof AppController !== 'undefined') {
            AppController.init();
        }
    },

    logout() {
        if (confirm('Are you sure you want to logout?')) {
            this.currentSession.isAuthenticated = false;
            this.currentSession.masterPassword = null;
            this.currentSession.loginTime = null;
            SVStorage.clearSession();

            document.getElementById('app-page').classList.remove('active');
            document.getElementById('landing-page').classList.add('active');

            this.resetForms();
            this.showAlert('Logged out successfully', 'success');
        }
    },

    resetForms() {
        const forms = ['new-password', 'confirm-password', 'master-password', 'user-email'];
        forms.forEach(id => {
            const input = document.getElementById(id);
            if (input) input.value = '';
        });
        const strengthIndicator = document.getElementById('password-strength');
        if (strengthIndicator) strengthIndicator.style.display = 'none';
    },

    // ===================================
    // PASSWORD RECOVERY FUNCTIONS
    // ===================================

    /**
     * Show the recovery modal
     */
    showRecoveryModal() {
        document.getElementById('recovery-modal').style.display = 'flex';
        document.getElementById('recovery-step-1').style.display = 'block';
        document.getElementById('recovery-step-2').style.display = 'none';
        document.getElementById('recovery-step-3').style.display = 'none';

        // Pre-fill email if we have it
        const savedEmail = SVStorage.getUserEmail();
        if (savedEmail) {
            document.getElementById('recovery-email').value = savedEmail;
        }
    },

    closeRecoveryModal() {
        document.getElementById('recovery-modal').style.display = 'none';
        // Clear recovery state
        recoveryState = { code: null, email: null, expiresAt: null };
        document.getElementById('recovery-email').value = '';
        document.getElementById('recovery-code-input').value = '';
        document.getElementById('recovery-new-password').value = '';
        document.getElementById('recovery-confirm-password').value = '';
    },

    /**
     * Send recovery code via EmailJS
     */
    async sendRecoveryCode() {
        const enteredEmail = document.getElementById('recovery-email').value.trim();

        if (!enteredEmail || !this.isValidEmail(enteredEmail)) {
            this.showAlert('Please enter a valid email address', 'error');
            return;
        }

        // Check if email matches registered email
        const savedEmail = SVStorage.getUserEmail();
        if (!savedEmail) {
            this.showAlert('No email found. If you registered without an email, recovery is not available.', 'error');
            return;
        }

        if (enteredEmail.toLowerCase() !== savedEmail.toLowerCase()) {
            this.showAlert('This email does not match the registered email for this vault.', 'error');
            return;
        }

        // Generate 6-digit code
        const arr = new Uint32Array(1);
window.crypto.getRandomValues(arr);
const code = (100000 + (arr[0] % 900000)).toString();
        recoveryState.code = code;
        recoveryState.email = enteredEmail;
        recoveryState.expiresAt = Date.now() + (15 * 60 * 1000); // 15 minutes

        // Show sending state
        const sendBtn = document.querySelector('#recovery-step-1 .btn-primary');
        sendBtn.textContent = 'Sending...';
        sendBtn.disabled = true;

        try {
            await emailjs.send(
                EMAILJS_CONFIG.SERVICE_ID,
                EMAILJS_CONFIG.TEMPLATE_ID,
                {
                    to_email: enteredEmail,
                    recovery_code: code
                }
            );

            this.showAlert('Recovery code sent! Check your inbox.', 'success');

            // Move to step 2
            document.getElementById('recovery-step-1').style.display = 'none';
            document.getElementById('recovery-step-2').style.display = 'block';

            // Start resend countdown
            this.startResendCountdown();

        } catch (error) {
            console.error('EmailJS error:', error);
            this.showAlert('Failed to send email. Check your internet connection and try again.', 'error');
            recoveryState = { code: null, email: null, expiresAt: null };
        } finally {
            sendBtn.textContent = 'Send Recovery Code';
            sendBtn.disabled = false;
        }
    },

    /**
     * Resend the recovery code
     */
    async resendCode() {
        if (!recoveryState.email) return;

        const arr = new Uint32Array(1);
window.crypto.getRandomValues(arr);
const code = (100000 + (arr[0] % 900000)).toString();
        recoveryState.code = code;
        recoveryState.expiresAt = Date.now() + (15 * 60 * 1000);

        try {
            await emailjs.send(
                EMAILJS_CONFIG.SERVICE_ID,
                EMAILJS_CONFIG.TEMPLATE_ID,
                {
                    to_email: recoveryState.email,
                    recovery_code: code
                }
            );
            this.showAlert('A new code has been sent!', 'success');
            this.startResendCountdown();
        } catch (error) {
            this.showAlert('Failed to resend. Try again.', 'error');
        }
    },

    /**
     * Start resend button countdown
     */
    startResendCountdown() {
        const resendBtn = document.getElementById('resend-btn');
        resendBtn.disabled = true;
        let seconds = 60;

        resendBtn.textContent = `Resend in ${seconds}s`;

        const interval = setInterval(() => {
            seconds--;
            resendBtn.textContent = `Resend in ${seconds}s`;

            if (seconds <= 0) {
                clearInterval(interval);
                resendBtn.disabled = false;
                resendBtn.textContent = 'Resend Code';
            }
        }, 1000);
    },

    /**
     * Verify the recovery code entered by user
     */
    verifyRecoveryCode() {
        const enteredCode = document.getElementById('recovery-code-input').value.trim();

        if (!enteredCode || enteredCode.length !== 6) {
            this.showAlert('Please enter the 6-digit code', 'error');
            return;
        }

        if (!recoveryState.code) {
            this.showAlert('No active recovery session. Please start again.', 'error');
            return;
        }

        if (Date.now() > recoveryState.expiresAt) {
            this.showAlert('Recovery code has expired. Please request a new one.', 'error');
            recoveryState = { code: null, email: null, expiresAt: null };
            document.getElementById('recovery-step-2').style.display = 'none';
            document.getElementById('recovery-step-1').style.display = 'block';
            return;
        }

        if (enteredCode !== recoveryState.code) {
            this.showAlert('Incorrect code. Please try again.', 'error');
            return;
        }

        // Code is correct — move to step 3
        this.showAlert('Code verified! Now set your new password.', 'success');
        document.getElementById('recovery-step-2').style.display = 'none';
        document.getElementById('recovery-step-3').style.display = 'block';
    },

    /**
     * Reset password after successful code verification
     */
    async resetPasswordWithCode() {
        const newPassword = document.getElementById('recovery-new-password').value;
        const confirmPassword = document.getElementById('recovery-confirm-password').value;

        if (!newPassword || !confirmPassword) {
            this.showAlert('Please fill in both password fields', 'error');
            return;
        }

        if (newPassword !== confirmPassword) {
            this.showAlert('Passwords do not match', 'error');
            return;
        }

        const strengthCheck = EncryptionManager.validatePasswordStrength(newPassword);
        if (strengthCheck.strength === 'weak') {
            this.showAlert('Password is too weak. Use at least 12 characters with mixed case, numbers, and symbols.', 'error');
            return;
        }

        // ⚠️ Important note for project report:
        // Because this is zero-knowledge architecture, notes encrypted with the OLD master
        // password CANNOT be decrypted with the new one. They are wiped on reset.
        // This is by design - true zero-knowledge means we cannot recover encrypted data.
        // Files are unaffected since they are stored locally on the user's device.

        // Clear all notes (they were encrypted with old password)
        SVStorage.saveNotes([]);

        // Save new password
        const newSalt = EncryptionManager.generateSalt();
        const newHash = await EncryptionManager.hashPassword(newPassword, newSalt);
        SVStorage.saveMasterPassword(newHash, newSalt);

        // Clear recovery state
        recoveryState = { code: null, email: null, expiresAt: null };

        this.showAlert('Password reset successfully! Your notes have been cleared (zero-knowledge limitation). Please login with your new password.', 'success');

        setTimeout(() => {
            this.closeRecoveryModal();
            // Reload to fresh login state
            location.reload();
        }, 3000);
    },

    /**
     * Change master password (from settings)
     */
    async changeMasterPassword() {
        if (!this.currentSession.isAuthenticated) {
            this.showAlert('Please login first', 'error');
            return;
        }

        const currentPassword = prompt('Enter your current master password:');
        if (!currentPassword) return;

        const storedHash = SVStorage.getMasterHash();
        const salt = SVStorage.getSalt();
        const enteredHash = await EncryptionManager.hashPassword(currentPassword, salt);

        if (enteredHash !== storedHash) {
            this.showAlert('Current password is incorrect', 'error');
            return;
        }

        const newPassword = prompt('Enter new master password:');
        if (!newPassword) return;

        const confirmNew = prompt('Confirm new master password:');
        if (!confirmNew) return;

        if (newPassword !== confirmNew) {
            this.showAlert('New passwords do not match', 'error');
            return;
        }

        const strengthCheck = EncryptionManager.validatePasswordStrength(newPassword);
        if (strengthCheck.strength === 'weak') {
            this.showAlert('New password is too weak', 'error');
            return;
        }

        // Re-encrypt all notes with new password
        const notes = SVStorage.getNotes();
        const reencryptedNotes = [];

        for (let note of notes) {
            const decrypted = await EncryptionManager.decryptText(
                note.encryptedContent,
                currentPassword,
                note.salt,
                note.iv
            );

            if (!decrypted.success) {
                this.showAlert('Error re-encrypting notes. Password not changed.', 'error');
                return;
            }

            const encrypted = await EncryptionManager.encryptText(decrypted.plaintext, newPassword);
            reencryptedNotes.push({
                id: note.id,
                title: note.title,
                encryptedContent: encrypted.ciphertext,
                salt: encrypted.salt,
                iv: encrypted.iv,
                isDoubleEncrypted: note.isDoubleEncrypted || false,
                createdAt: note.createdAt,
                updatedAt: Date.now()
            });
        }

        SVStorage.saveNotes(reencryptedNotes);

        const newSalt = EncryptionManager.generateSalt();
        const newHash = await EncryptionManager.hashPassword(newPassword, newSalt);
        SVStorage.saveMasterPassword(newHash, newSalt);

        this.currentSession.masterPassword = newPassword;
        this.showAlert('Master password changed successfully!', 'success');
    },

    /**
     * Reset vault
     */
    resetVault() {
        const confirmation = prompt('⚠️ WARNING: This will delete ALL your data permanently!\n\nType "DELETE" to confirm:');

        if (confirmation === 'DELETE') {
            if (SVStorage.clearAllData()) {
                this.showAlert('All data has been deleted', 'success');
                this.currentSession.isAuthenticated = false;
                this.currentSession.masterPassword = null;
                setTimeout(() => { location.reload(); }, 1500);
            } else {
                this.showAlert('Error deleting data', 'error');
            }
        } else {
            this.showAlert('Vault reset cancelled', 'warning');
        }
    },

    setupAutoLock() {
        setInterval(() => {
            if (this.currentSession.isAuthenticated) {
                if (!SVStorage.isSessionActive()) {
                    this.showLockOverlay();
                }
            }
        }, 30000);

        // Lock IMMEDIATELY when tab becomes visible again (no session check needed)
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) return; // tab is being hidden, ignore
            if (this.currentSession.isAuthenticated) {
                this.showLockOverlay(); // always lock on return
            }
        });

        // Lock on page refresh/reload (beforeunload sets a flag, on load we check it)
        window.addEventListener('beforeunload', () => {
            if (this.currentSession.isAuthenticated) {
                sessionStorage.setItem('sv_was_locked', 'true');
            }
        });

        ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
            document.addEventListener(event, () => {
                if (this.currentSession.isAuthenticated) {
                    SVStorage.refreshSession();
                }
            });
        });
    },

    showLockOverlay() {
        const overlay = document.getElementById('lock-overlay');
        if (overlay) {
            overlay.style.display = 'flex';
            setTimeout(() => {
                const input = document.getElementById('lock-password');
                if (input) { input.value = ''; input.focus(); }
            }, 100);
        }
    },

async unlockFromOverlay() {
    const password = document.getElementById('lock-password').value;

    if (!password) {
        this.showAlert('Please enter your password', 'error');
        return;
    }

    const storedHash = SVStorage.getMasterHash();
    const salt = SVStorage.getSalt();

    const enteredHash = await EncryptionManager.hashPassword(password, salt);

    if (enteredHash === storedHash) {
        this.currentSession.isAuthenticated = true;
        this.currentSession.masterPassword = password;
        this.currentSession.loginTime = Date.now();

        SVStorage.createSession();

        document.getElementById('lock-overlay').style.display = 'none';
        document.getElementById('lock-password').value = '';

        if (typeof AppController !== 'undefined') {
            AppController.init();
        }

        this.showAlert('Welcome back!', 'success');
    } else {
        this.showAlert('Incorrect password', 'error');
        document.getElementById('lock-password').value = '';
    }
},

    logoutFromOverlay() {
        document.getElementById('lock-overlay').style.display = 'none';
        this.currentSession.isAuthenticated = false;
        this.currentSession.masterPassword = null;
        this.currentSession.loginTime = null;
        SVStorage.clearSession();
        document.getElementById('app-page').classList.remove('active');
        document.getElementById('landing-page').classList.add('active');
        this.resetForms();
    },

    showAlert(message, type = 'info') {
        // Remove any existing alerts first
        document.querySelectorAll('.alert').forEach(a => a.remove());

        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.style.cssText = 'margin-bottom:1rem; position:relative; z-index:9999;';
        alert.innerHTML = `<span>${this.getAlertIcon(type)}</span><span>${message}</span>`;

        // Pick the most visible container based on what is currently shown
        let container = null;

        const lockOverlay = document.getElementById('lock-overlay');
        const returningSection = document.getElementById('returning-user-section');
        const newUserSection = document.getElementById('new-user-section');
        const appContent = document.querySelector('.app-content');

        if (lockOverlay && lockOverlay.style.display !== 'none') {
            container = lockOverlay.querySelector('.lock-box');
        } else if (returningSection && returningSection.style.display !== 'none') {
            container = returningSection;
        } else if (newUserSection && newUserSection.style.display !== 'none') {
            container = newUserSection;
        } else if (appContent) {
            container = appContent;
        } else {
            container = document.body;
        }

        // Insert at the top of the container
        container.insertBefore(alert, container.firstChild);

        // Scroll alert into view
        alert.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        setTimeout(() => {
            alert.style.animation = 'fadeOut 0.3s ease-out';
            setTimeout(() => { alert.remove(); }, 300);
        }, 5000);
    },

    getAlertIcon(type) {
        return { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' }[type] || 'ℹ';
    },

    getMasterPassword() {
        return this.currentSession.masterPassword;
    },

    isAuthenticated() {
        return this.currentSession.isAuthenticated;
    },

    isValidEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }
};

// ===================================
// GLOBAL FUNCTIONS
// ===================================

async function createMasterPassword() { 
    await AuthManager.createMasterPassword(); 
}
async function login() { 
    await AuthManager.login(); 
}
function logout() { AuthManager.logout(); }
function unlockFromOverlay() { AuthManager.unlockFromOverlay(); }
function logoutFromOverlay() { AuthManager.logoutFromOverlay(); }
function resetVault() { AuthManager.resetVault(); }
function changeMasterPassword() { AuthManager.changeMasterPassword(); }
function showRecoveryModal() { AuthManager.showRecoveryModal(); }
function closeRecoveryModal() { AuthManager.closeRecoveryModal(); }
function sendRecoveryCode() { AuthManager.sendRecoveryCode(); }
function verifyRecoveryCode() { AuthManager.verifyRecoveryCode(); }
function resetPasswordWithCode() { AuthManager.resetPasswordWithCode(); }
function resendCode() { AuthManager.resendCode(); }

/**
 * Toggle password field visibility (eye icon)
 */
function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;

    if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = '<i class="fas fa-eye-slash"></i>';
        btn.title = 'Hide password';
    } else {
        input.type = 'password';
        btn.innerHTML = '<i class="fas fa-eye"></i>';
        btn.title = 'Show password';
    }
}

// Add fadeOut animation
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeOut {
        from { opacity: 1; transform: translateY(0); }
        to { opacity: 0; transform: translateY(-20px); }
    }
`;
document.head.appendChild(style);

if (typeof window !== 'undefined') {
    console.log('Auth module loaded');
}
