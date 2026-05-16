/* ===================================
   ENCRYPTION.JS - Web Crypto API
   AES-256-GCM + PBKDF2 + RSA-OAEP
   Hybrid Cryptography Implementation
   Native Browser Cryptography
   =================================== */

var EncryptionManager = {

    CONFIG: {
        ALGORITHM: 'AES-GCM',
        KEY_LENGTH: 256,
        ITERATIONS: 310000,
        SALT_SIZE: 16,   // 128-bit salt
        IV_SIZE: 12,     // 96-bit IV for GCM
        HASH: 'SHA-256',
        RSA_KEY_SIZE: 2048
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
       RSA-OAEP KEY PAIR GENERATION
       =================================== */

    async generateRSAKeyPair() {
        return crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: this.CONFIG.RSA_KEY_SIZE,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            ['wrapKey', 'unwrapKey']
        );
    },

    /* ===================================
       EXPORT / IMPORT RSA KEYS
       =================================== */

    async exportPublicKey(publicKey) {
        const exported = await crypto.subtle.exportKey('spki', publicKey);
        return this.arrayBufferToBase64(exported);
    },

    async exportPrivateKey(privateKey) {
        const exported = await crypto.subtle.exportKey('pkcs8', privateKey);
        return this.arrayBufferToBase64(exported);
    },

    async importPublicKey(base64Key) {
        const keyBuffer = this.base64ToArrayBuffer(base64Key);
        return crypto.subtle.importKey(
            'spki',
            keyBuffer,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            true,
            ['wrapKey']
        );
    },

    async importPrivateKey(base64Key) {
        const keyBuffer = this.base64ToArrayBuffer(base64Key);
        return crypto.subtle.importKey(
            'pkcs8',
            keyBuffer,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            true,
            ['unwrapKey']
        );
    },

    /* ===================================
       RSA-OAEP WRAP / UNWRAP AES SESSION KEY
       =================================== */

    async wrapAESKey(aesKey, rsaPublicKey) {
        const wrapped = await crypto.subtle.wrapKey(
            'raw',
            aesKey,
            rsaPublicKey,
            { name: 'RSA-OAEP' }
        );
        return this.arrayBufferToBase64(wrapped);
    },

    async unwrapAESKey(wrappedKeyBase64, rsaPrivateKey) {
        const wrappedKeyBuffer = this.base64ToArrayBuffer(wrappedKeyBase64);
        return crypto.subtle.unwrapKey(
            'raw',
            wrappedKeyBuffer,
            rsaPrivateKey,
            { name: 'RSA-OAEP' },
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    },

    /* ===================================
       PROTECT RSA PRIVATE KEY WITH AES MASTER KEY
       =================================== */

    async encryptPrivateKey(privateKeyBase64, masterPassword, salt) {
        return this.encryptText(privateKeyBase64, masterPassword, salt);
    },

    async decryptPrivateKey(encryptedPrivateKey, masterPassword, salt, iv) {
        return this.decryptText(encryptedPrivateKey, masterPassword, salt, iv);
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
        const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
        return this.arrayBufferToBase64(hashBuffer);
    },

    /* ===================================
       TEXT ENCRYPTION (AES-256-GCM)
       PBKDF2 derives key, RSA-OAEP wraps it
       =================================== */

    async encryptText(plaintext, password) {
        try {
            const encoder = new TextEncoder();
            const salt = this.generateSalt();
            const iv = this.generateIV();

            // Step 1: Derive AES master key from password via PBKDF2
            const aesKey = await this.deriveKey(password, salt);

            // Step 2: Generate RSA key pair for session key encapsulation
            const rsaKeyPair = await this.generateRSAKeyPair();

            // Step 3: Generate a fresh AES session key for this encryption
            const sessionKey = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );

            // Step 4: Wrap session key with RSA public key (RSA-OAEP)
            const wrappedSessionKey = await this.wrapAESKey(
                sessionKey,
                rsaKeyPair.publicKey
            );

            // Step 5: Encrypt plaintext with AES session key
            const encryptedBuffer = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                sessionKey,
                encoder.encode(plaintext)
            );

            // Step 6: Export and protect RSA private key with PBKDF2-derived AES master key
            const privateKeyBase64 = await this.exportPrivateKey(
                rsaKeyPair.privateKey
            );
            const privateKeyIv = this.generateIV();
            const encryptedPrivateKey = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: privateKeyIv },
                aesKey,
                new TextEncoder().encode(privateKeyBase64)
            );

            return {
                ciphertext: this.arrayBufferToBase64(encryptedBuffer),
                salt: this.arrayBufferToBase64(salt),
                iv: this.arrayBufferToBase64(iv),
                wrappedSessionKey: wrappedSessionKey,
                encryptedPrivateKey: this.arrayBufferToBase64(encryptedPrivateKey),
                privateKeyIv: this.arrayBufferToBase64(privateKeyIv),
                success: true
            };

        } catch (error) {
            console.error('Encryption error:', error);
            return { success: false, error: error.message };
        }
    },

    /* ===================================
       TEXT DECRYPTION
       =================================== */

    async decryptText(ciphertext, password, salt, iv,
                      wrappedSessionKey, encryptedPrivateKey, privateKeyIv) {
        try {
            const saltBytes = this.base64ToUint8Array(salt);
            const ivBytes = this.base64ToUint8Array(iv);
            const encryptedBytes = this.base64ToArrayBuffer(ciphertext);

            // Step 1: Re-derive AES master key from password via PBKDF2
            const aesKey = await this.deriveKey(password, saltBytes);

            // Step 2: Decrypt RSA private key using AES master key
            const privateKeyIvBytes = this.base64ToUint8Array(privateKeyIv);
            const encryptedPrivKeyBytes = this.base64ToArrayBuffer(encryptedPrivateKey);
            const privateKeyBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: privateKeyIvBytes },
                aesKey,
                encryptedPrivKeyBytes
            );
            const privateKeyBase64 = new TextDecoder().decode(privateKeyBuffer);

            // Step 3: Import RSA private key
            const rsaPrivateKey = await this.importPrivateKey(privateKeyBase64);

            // Step 4: Unwrap AES session key using RSA private key
            const sessionKey = await this.unwrapAESKey(
                wrappedSessionKey,
                rsaPrivateKey
            );

            // Step 5: Decrypt ciphertext with AES session key
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: ivBytes },
                sessionKey,
                encryptedBytes
            );

            return {
                plaintext: new TextDecoder().decode(decryptedBuffer),
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
       FILE ENCRYPTION (AES-256-GCM + RSA-OAEP)
       =================================== */

    async encryptFile(fileData, password, progressCallback = null) {
        try {
            const salt = this.generateSalt();
            const iv = this.generateIV();

            // Step 1: Derive AES master key from password via PBKDF2
            const aesKey = await this.deriveKey(password, salt);
            if (progressCallback) progressCallback(20);

            // Step 2: Generate RSA key pair
            const rsaKeyPair = await this.generateRSAKeyPair();
            if (progressCallback) progressCallback(35);

            // Step 3: Generate AES session key
            const sessionKey = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );

            // Step 4: Wrap session key with RSA public key
            const wrappedSessionKey = await this.wrapAESKey(
                sessionKey,
                rsaKeyPair.publicKey
            );

            // Step 5: Encrypt file data with AES session key
            const encryptedBuffer = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                sessionKey,
                fileData
            );
            if (progressCallback) progressCallback(70);

            // Step 6: Protect RSA private key with AES master key
            const privateKeyBase64 = await this.exportPrivateKey(
                rsaKeyPair.privateKey
            );
            const privateKeyIv = this.generateIV();
            const encryptedPrivateKey = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: privateKeyIv },
                aesKey,
                new TextEncoder().encode(privateKeyBase64)
            );
            if (progressCallback) progressCallback(90);

            const result = {
                encryptedData: this.arrayBufferToBase64(encryptedBuffer),
                salt: this.arrayBufferToBase64(salt),
                iv: this.arrayBufferToBase64(iv),
                wrappedSessionKey: wrappedSessionKey,
                encryptedPrivateKey: this.arrayBufferToBase64(encryptedPrivateKey),
                privateKeyIv: this.arrayBufferToBase64(privateKeyIv),
                success: true
            };

            if (progressCallback) progressCallback(100);
            return result;

        } catch (error) {
            console.error('File encryption error:', error);
            return { success: false, error: error.message };
        }
    },

    /* ===================================
       FILE DECRYPTION
       =================================== */

    async decryptFile(encryptedData, password, salt, iv,
                      wrappedSessionKey, encryptedPrivateKey, privateKeyIv,
                      progressCallback = null) {
        try {
            const saltBytes = this.base64ToUint8Array(salt);
            const ivBytes = this.base64ToUint8Array(iv);
            const encryptedBytes = this.base64ToArrayBuffer(encryptedData);

            // Step 1: Re-derive AES master key from password via PBKDF2
            const aesKey = await this.deriveKey(password, saltBytes);
            if (progressCallback) progressCallback(20);

            // Step 2: Decrypt RSA private key using AES master key
            const privateKeyIvBytes = this.base64ToUint8Array(privateKeyIv);
            const encryptedPrivKeyBytes = this.base64ToArrayBuffer(encryptedPrivateKey);
            const privateKeyBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: privateKeyIvBytes },
                aesKey,
                encryptedPrivKeyBytes
            );
            const privateKeyBase64 = new TextDecoder().decode(privateKeyBuffer);
            if (progressCallback) progressCallback(50);

            // Step 3: Import RSA private key
            const rsaPrivateKey = await this.importPrivateKey(privateKeyBase64);

            // Step 4: Unwrap AES session key using RSA private key
            const sessionKey = await this.unwrapAESKey(
                wrappedSessionKey,
                rsaPrivateKey
            );

            // Step 5: Decrypt file with AES session key
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: ivBytes },
                sessionKey,
                encryptedBytes
            );
            if (progressCallback) progressCallback(100);

            return { fileData: decryptedBuffer, success: true };

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
        return new Uint8Array(this.base64ToArrayBuffer(base64));
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
        return { strength, score, maxScore: 7, feedback };
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
    console.log('Web Crypto hybrid encryption module loaded (AES-256-GCM + RSA-OAEP)');
}
