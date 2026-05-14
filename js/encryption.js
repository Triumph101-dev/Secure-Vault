/* ===================================
   ENCRYPTION.JS - Web Crypto API
   AES-256-GCM + PBKDF2 Implementation
   Native Browser Cryptography
   =================================== */

var EncryptionManager = {

    CONFIG: {
        ALGORITHM: 'AES-GCM',
        KEY_LENGTH: 256,
        ITERATIONS: 310000,
        SALT_SIZE: 16, // 128-bit salt
        IV_SIZE: 12,   // 96-bit IV for GCM
        HASH: 'SHA-256'
    },

    /* ===================================
       RANDOM GENERATION
       =================================== */

    generateSalt() {
        return window.crypto.getRandomValues(
            new Uint8Array(this.CONFIG.SALT_SIZE)
        );
    },

    generateIV() {
        return window.crypto.getRandomValues(
            new Uint8Array(this.CONFIG.IV_SIZE)
        );
    },

    /* ===================================
       KEY DERIVATION (PBKDF2)
       =================================== */

    async deriveKey(password, salt) {

        const encoder = new TextEncoder();

        const passwordKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.CONFIG.ITERATIONS,
                hash: this.CONFIG.HASH
            },
            passwordKey,
            {
                name: 'AES-GCM',
                length: this.CONFIG.KEY_LENGTH
            },
            false,
            ['encrypt', 'decrypt']
        );
    },

    /* ===================================
       PASSWORD HASHING
       =================================== */

    async hashPassword(password, salt) {

        const encoder = new TextEncoder();

        const data = encoder.encode(password);

        const combined = new Uint8Array(salt.length + data.length);

        combined.set(salt);
        combined.set(data, salt.length);

        const hashBuffer = await crypto.subtle.digest(
            'SHA-256',
            combined
        );

        return this.arrayBufferToBase64(hashBuffer);
    },

    /* ===================================
       TEXT ENCRYPTION
       =================================== */

    async encryptText(plaintext, password) {

        try {

            const encoder = new TextEncoder();

            const salt = this.generateSalt();

            const iv = this.generateIV();

            const key = await this.deriveKey(password, salt);

            const encryptedBuffer = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                encoder.encode(plaintext)
            );

            return {
                ciphertext: this.arrayBufferToBase64(encryptedBuffer),
                salt: this.arrayBufferToBase64(salt),
                iv: this.arrayBufferToBase64(iv),
                success: true
            };

        } catch (error) {

            console.error('Encryption error:', error);

            return {
                success: false,
                error: error.message
            };
        }
    },

    /* ===================================
       TEXT DECRYPTION
       =================================== */

    async decryptText(ciphertext, password, salt, iv) {

        try {

            const decoder = new TextDecoder();

            const saltBytes = this.base64ToUint8Array(salt);

            const ivBytes = this.base64ToUint8Array(iv);

            const encryptedBytes = this.base64ToArrayBuffer(ciphertext);

            const key = await this.deriveKey(password, saltBytes);

            const decryptedBuffer = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: ivBytes
                },
                key,
                encryptedBytes
            );

            return {
                plaintext: decoder.decode(decryptedBuffer),
                success: true
            };

        } catch (error) {

            console.error('Decryption error:', error);

            return {
                success: false,
                error: 'Decryption failed. Invalid password or corrupted data.'
            };
        }
    },

    /* ===================================
       FILE ENCRYPTION
       =================================== */

    async encryptFile(fileData, password, progressCallback = null) {

        try {

            const salt = this.generateSalt();

            const iv = this.generateIV();

            const key = await this.deriveKey(password, salt);

            if (progressCallback) progressCallback(30);

            const encryptedBuffer = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                fileData
            );

            if (progressCallback) progressCallback(80);

            const result = {
                encryptedData: this.arrayBufferToBase64(encryptedBuffer),
                salt: this.arrayBufferToBase64(salt),
                iv: this.arrayBufferToBase64(iv),
                success: true
            };

            if (progressCallback) progressCallback(100);

            return result;

        } catch (error) {

            console.error('File encryption error:', error);

            return {
                success: false,
                error: error.message
            };
        }
    },

    /* ===================================
       FILE DECRYPTION
       =================================== */

    async decryptFile(encryptedData, password, salt, iv, progressCallback = null) {

        try {

            const saltBytes = this.base64ToUint8Array(salt);

            const ivBytes = this.base64ToUint8Array(iv);

            const encryptedBytes = this.base64ToArrayBuffer(encryptedData);

            const key = await this.deriveKey(password, saltBytes);

            if (progressCallback) progressCallback(30);

            const decryptedBuffer = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: ivBytes
                },
                key,
                encryptedBytes
            );

            if (progressCallback) progressCallback(100);

            return {
                fileData: decryptedBuffer,
                success: true
            };

        } catch (error) {

            console.error('File decryption error:', error);

            return {
                success: false,
                error: 'Decryption failed. Invalid password or corrupted file.'
            };
        }
    },

    /* ===================================
       BASE64 HELPERS
       =================================== */

    arrayBufferToBase64(buffer) {

        const bytes = new Uint8Array(buffer);

        let binary = '';

        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }

        return btoa(binary);
    },

    base64ToArrayBuffer(base64) {

        const binary = atob(base64);

        const bytes = new Uint8Array(binary.length);

        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return bytes.buffer;
    },

    base64ToUint8Array(base64) {
        return new Uint8Array(
            this.base64ToArrayBuffer(base64)
        );
    },

    /* ===================================
       PASSWORD STRENGTH
       =================================== */

    validatePasswordStrength(password) {

        let score = 0;

        const feedback = [];

        if (password.length >= 8) score += 1;
        if (password.length >= 12) score += 1;
        if (password.length >= 16) score += 1;
        else feedback.push('Use at least 12 characters');

        if (/[a-z]/.test(password)) score += 1;
        else feedback.push('Add lowercase letters');

        if (/[A-Z]/.test(password)) score += 1;
        else feedback.push('Add uppercase letters');

        if (/[0-9]/.test(password)) score += 1;
        else feedback.push('Add numbers');

        if (/[^a-zA-Z0-9]/.test(password)) score += 1;
        else feedback.push('Add special characters');

        let strength = 'weak';

        if (score >= 7) strength = 'strong';
        else if (score >= 5) strength = 'medium';

        return {
            strength,
            score,
            maxScore: 7,
            feedback
        };
    },

    /* ===================================
       PASSWORD GENERATOR
       =================================== */

    generateSecurePassword(length = 16) {

        const charset =
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';

        let password = '';

        const randomValues = new Uint32Array(length);

        window.crypto.getRandomValues(randomValues);

        for (let i = 0; i < length; i++) {
            password += charset[randomValues[i] % charset.length];
        }

        return password;
    }
};

/* ===================================
   INIT
   =================================== */

if (typeof window !== 'undefined') {
    console.log('Web Crypto encryption module loaded');
}