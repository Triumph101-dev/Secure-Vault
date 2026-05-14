/* ===================================
   NOTEMANAGER.JS - Secure Notes Manager
   Handles CRUD operations for encrypted notes
   Supports double-encryption (master password + extra note password)
   =================================== */

var NoteManager = {
    currentNotes: [],
    currentNote: null,
    editingNoteId: null,
    noteExtraEncryptionEnabled: false,
    autoSaveTimer: null,
    autoSaveDelay: 30000, // 30 seconds
async init() {
    console.log('NoteManager initialized');
    await this.loadNotes();
    this.displayNotes();
    this.setupAutoSave();
},

    /**
     * Setup auto-save — triggers 30s after user stops typing
     */
    setupAutoSave() {
        const titleInput = document.getElementById('note-title');
        const contentInput = document.getElementById('note-content');

        const triggerAutoSave = () => {
            // Only auto-save if editor is open and has a title
            if (document.getElementById('note-editor').style.display === 'none') return;
            const title = document.getElementById('note-title').value.trim();
            if (!title) return;

            // Clear existing timer and start fresh
            clearTimeout(this.autoSaveTimer);
            this.autoSaveTimer = setTimeout(() => {
                this.autoSave();
            }, this.autoSaveDelay);

            // Show "unsaved changes" indicator
            this.setAutoSaveStatus('unsaved');
        };

        if (titleInput) titleInput.addEventListener('input', triggerAutoSave);
        if (contentInput) contentInput.addEventListener('input', triggerAutoSave);
    },

    /**
     * Perform auto-save silently
     */
async autoSave() {
    const title = document.getElementById('note-title').value.trim();
    const content = document.getElementById('note-content').value.trim();

    if (!title || !content) return;
    if (content === '[🔒 Content locked — use the Unlock button below]') return;

    const masterPassword = AuthManager.getMasterPassword();
    if (!masterPassword) return;

    if (this.editingNoteId) {
        const note = this.currentNotes.find(n => n.id === this.editingNoteId);
        if (note && note.isDoubleEncrypted && document.getElementById('note-content').readOnly) return;
    }

    const now = Date.now();
    const outerEncrypted = await EncryptionManager.encryptText(content, masterPassword);
    if (!outerEncrypted.success) return;


        let encryptedNotes = SVStorage.getNotes();

        if (this.editingNoteId) {
            // Update existing note
            const idx = encryptedNotes.findIndex(n => n.id === this.editingNoteId);
            if (idx !== -1) {
                encryptedNotes[idx] = {
                    ...encryptedNotes[idx],
                    title,
                    encryptedContent: outerEncrypted.ciphertext,
                    salt: outerEncrypted.salt,
                    iv: outerEncrypted.iv,
                    updatedAt: now
                };
            }

            const noteIdx = this.currentNotes.findIndex(n => n.id === this.editingNoteId);
            if (noteIdx !== -1) {
                this.currentNotes[noteIdx].title = title;
                this.currentNotes[noteIdx].content = content;
                this.currentNotes[noteIdx].updatedAt = now;
            }
        } else {
            // Create new note via auto-save
            const newId = this.generateNoteId();
            this.editingNoteId = newId;

            const newEncNote = {
                id: newId,
                title,
                encryptedContent: outerEncrypted.ciphertext,
                salt: outerEncrypted.salt,
                iv: outerEncrypted.iv,
                isDoubleEncrypted: false,
                createdAt: now,
                updatedAt: now
            };

            encryptedNotes.unshift(newEncNote);
            this.currentNotes.unshift({
                id: newId,
                title,
                content,
                isDoubleEncrypted: false,
                createdAt: now,
                updatedAt: now
            });
        }

        SVStorage.saveNotes(encryptedNotes);
        this.displayNotes();
        this.setAutoSaveStatus('saved');
    },

    /**
     * Update the auto-save status indicator
     */
    setAutoSaveStatus(status) {
        const indicator = document.getElementById('autosave-indicator');
        if (!indicator) return;

        if (status === 'saved') {
            indicator.textContent = '✓ Auto-saved';
            indicator.className = 'autosave-indicator saved';
            // Fade out after 3 seconds
            setTimeout(() => {
                indicator.textContent = '';
                indicator.className = 'autosave-indicator';
            }, 3000);
        } else if (status === 'unsaved') {
            indicator.textContent = '● Unsaved changes';
            indicator.className = 'autosave-indicator unsaved';
        }
    },

    /**
     * Load and decrypt notes from storage
     */
    async loadNotes() {
    const masterPassword = AuthManager.getMasterPassword();
    if (!masterPassword) return;

    const encryptedNotes = SVStorage.getNotes();
    this.currentNotes = [];

    for (let encNote of encryptedNotes) {
        try {
            const decrypted = await EncryptionManager.decryptText(
                encNote.encryptedContent,
                masterPassword,
                encNote.salt,
                encNote.iv
            );

            if (decrypted.success) {
                this.currentNotes.push({
                    id: encNote.id,
                    title: encNote.title,
                    content: decrypted.plaintext,
                    isDoubleEncrypted: encNote.isDoubleEncrypted || false,
                    createdAt: encNote.createdAt,
                    updatedAt: encNote.updatedAt
                });
            }
        } catch (error) {
            console.error('Error decrypting note:', error);
        }
    }

    this.currentNotes.sort((a, b) => b.updatedAt - a.updatedAt);
},
    /**
     * Display notes list
     */
    displayNotes() {
        const notesList = document.getElementById('notes-list');
        if (!notesList) return;

        notesList.innerHTML = '';

        if (this.currentNotes.length === 0) {
            notesList.innerHTML = '<p class="empty-state">No notes yet. Create your first secure note!</p>';
            return;
        }

        this.currentNotes.forEach(note => {
            const noteItem = document.createElement('div');
            noteItem.className = 'note-item';
            noteItem.dataset.noteId = note.id;

            const preview = note.isDoubleEncrypted
                ? '🔒 Double-encrypted — enter extra password to view'
                : note.content.substring(0, 100) + (note.content.length > 100 ? '...' : '');

            noteItem.innerHTML = `
                <h4>${this.escapeHtml(note.title)} ${note.isDoubleEncrypted ? '<span class="double-lock-badge">🔒🔒</span>' : ''}</h4>
                <div class="note-preview">${this.escapeHtml(preview)}</div>
                <div class="note-date">${this.formatDate(note.updatedAt)}</div>
            `;

            noteItem.addEventListener('click', () => this.openNote(note.id));
            notesList.appendChild(noteItem);
        });
    },

    /**
     * Create new note
     */
    createNewNote() {
        this.editingNoteId = null;
        this.currentNote = null;
        this.noteExtraEncryptionEnabled = false;

        document.getElementById('note-title').value = '';
        document.getElementById('note-content').value = '';
        document.getElementById('note-content').readOnly = false;
        document.getElementById('note-editor').style.display = 'block';
        document.getElementById('delete-note-btn').style.display = 'none';
        document.getElementById('note-encrypt-panel').style.display = 'none';
        document.getElementById('note-decrypt-panel').style.display = 'none';
        document.getElementById('note-extra-password').value = '';

        const toggleBtn = document.getElementById('toggle-encrypt-btn');
        toggleBtn.textContent = '🔒 Add Extra Lock';
        toggleBtn.className = 'btn btn-primary';

        this.updateWordCount();
        this.deselectAllNotes();
        document.getElementById('note-title').focus();
    },

    /**
     * Open existing note
     */
    openNote(noteId) {
        const note = this.currentNotes.find(n => n.id === noteId);
        if (!note) return;

        this.editingNoteId = noteId;
        this.currentNote = note;

        document.getElementById('note-title').value = note.title;
        document.getElementById('note-editor').style.display = 'block';
        document.getElementById('delete-note-btn').style.display = 'inline-flex';
        document.getElementById('note-encrypt-panel').style.display = 'none';
        document.getElementById('note-extra-password').value = '';

        const toggleBtn = document.getElementById('toggle-encrypt-btn');

        if (note.isDoubleEncrypted) {
            // Show locked content placeholder and decryption panel
            document.getElementById('note-content').value = '[🔒 Content locked — use the Unlock button below]';
            document.getElementById('note-content').readOnly = true;
            document.getElementById('note-decrypt-panel').style.display = 'block';
            document.getElementById('note-decrypt-extra-password').value = '';
            toggleBtn.textContent = '🔓 Remove Extra Lock';
            toggleBtn.className = 'btn btn-secondary';
            this.noteExtraEncryptionEnabled = true;
        } else {
            document.getElementById('note-content').value = note.content;
            document.getElementById('note-content').readOnly = false;
            document.getElementById('note-decrypt-panel').style.display = 'none';
            toggleBtn.textContent = '🔒 Add Extra Lock';
            toggleBtn.className = 'btn btn-primary';
            this.noteExtraEncryptionEnabled = false;
        }

        this.updateWordCount();
        this.deselectAllNotes();
        const noteItem = document.querySelector(`[data-note-id="${noteId}"]`);
        if (noteItem) noteItem.classList.add('active');
    },

    /**
     * Toggle the extra encryption panel on/off
     */
    toggleNoteEncryption() {
        const panel = document.getElementById('note-encrypt-panel');
        const toggleBtn = document.getElementById('toggle-encrypt-btn');

        if (!this.noteExtraEncryptionEnabled) {
            // Show warning modal before enabling extra lock
            this.showExtraLockWarning(() => {
                this.noteExtraEncryptionEnabled = true;
                panel.style.display = 'block';
                toggleBtn.textContent = '🔓 Remove Extra Lock';
                toggleBtn.className = 'btn btn-secondary';
                document.getElementById('note-extra-password').focus();
            });
        } else {
            this.noteExtraEncryptionEnabled = false;
            panel.style.display = 'none';
            document.getElementById('note-extra-password').value = '';
            toggleBtn.textContent = '🔒 Add Extra Lock';
            toggleBtn.className = 'btn btn-primary';
        }
    },

    /**
     * Show warning modal before setting extra lock
     */
    showExtraLockWarning(onConfirm) {
        const modal = document.getElementById('extra-lock-warning-modal');
        if (modal) {
            modal.style.display = 'flex';
            // Store callback
            modal._onConfirm = onConfirm;
        }
    },

    confirmExtraLock() {
        const modal = document.getElementById('extra-lock-warning-modal');
        if (modal) {
            modal.style.display = 'none';
            if (typeof modal._onConfirm === 'function') {
                modal._onConfirm();
            }
        }
    },

    cancelExtraLock() {
        const modal = document.getElementById('extra-lock-warning-modal');
        if (modal) modal.style.display = 'none';
    },

    /**
     * Decrypt a double-encrypted note's content for viewing
     */
    async decryptNoteContent() {
        const extraPassword = document.getElementById('note-decrypt-extra-password').value;
        if (!extraPassword) {
            AuthManager.showAlert('Please enter the extra password', 'error');
            return;
        }

        if (!this.editingNoteId) return;

        // Get the raw double-encrypted note from storage
        const encryptedNotes = SVStorage.getNotes();
        const encNote = encryptedNotes.find(n => n.id === this.editingNoteId);
        if (!encNote || !encNote.doubleEncryptedContent) {
            AuthManager.showAlert('Could not find double-encrypted content', 'error');
            return;
        }

        // Decrypt inner layer with extra password
    const innerDecrypted = await EncryptionManager.decryptText(
        encNote.doubleEncryptedContent,
        extraPassword,
        encNote.doubleSalt,
        encNote.doubleIv
    );

        if (!innerDecrypted.success) {
            AuthManager.showAlert('Incorrect extra password', 'error');
            return;
        }

        // Show decrypted content
        document.getElementById('note-content').value = innerDecrypted.plaintext;
        document.getElementById('note-content').readOnly = false;
        document.getElementById('note-decrypt-panel').style.display = 'none';

        // Store decrypted content in currentNotes for saving
        const noteIndex = this.currentNotes.findIndex(n => n.id === this.editingNoteId);
        if (noteIndex !== -1) {
            this.currentNotes[noteIndex].content = innerDecrypted.plaintext;
            this.currentNotes[noteIndex]._unlockedExtraPassword = extraPassword;
        }

        this.updateWordCount();
        AuthManager.showAlert('Note unlocked!', 'success');
    },

    /**
     * Save note (create or update)
     */
    async saveNote() {
        const title = document.getElementById('note-title').value.trim();
        const content = document.getElementById('note-content').value.trim();

        if (!title) {
            AuthManager.showAlert('Please enter a note title', 'error');
            return;
        }

        if (!content || content === '[🔒 Content locked — use the Unlock button below]') {
            AuthManager.showAlert('Please enter note content', 'error');
            return;
        }

        const masterPassword = AuthManager.getMasterPassword();
        if (!masterPassword) {
            AuthManager.showAlert('Authentication error. Please login again.', 'error');
            return;
        }

        // Check if extra encryption is enabled
        const extraPassword = this.noteExtraEncryptionEnabled
            ? document.getElementById('note-extra-password').value
            : null;

        if (this.noteExtraEncryptionEnabled && !extraPassword) {
            AuthManager.showAlert('Please enter an extra password for the extra lock, or remove it.', 'error');
            return;
        }

        // Check if editing a previously unlocked double-encrypted note
        const currentNoteObj = this.currentNotes.find(n => n.id === this.editingNoteId);
        const unlockedExtraPassword = currentNoteObj?._unlockedExtraPassword || null;
        const effectiveExtraPassword = extraPassword || unlockedExtraPassword;
        const willBeDoubleEncrypted = this.noteExtraEncryptionEnabled || (unlockedExtraPassword != null);

        const now = Date.now();

        // Encrypt the content with master password (outer layer)
    const outerEncrypted = await EncryptionManager.encryptText(content, masterPassword);
    if (!outerEncrypted.success) {
        AuthManager.showAlert('Encryption failed', 'error');
        return;
    }

        // Build the note storage object
        let noteStorageObj = {
            id: this.editingNoteId || this.generateNoteId(),
            title: title,
            encryptedContent: outerEncrypted.ciphertext,
            salt: outerEncrypted.salt,
            iv: outerEncrypted.iv,
            isDoubleEncrypted: willBeDoubleEncrypted,
            createdAt: now,
            updatedAt: now
        };

        // If double-encrypted, also encrypt with extra password (inner layer)
    if (willBeDoubleEncrypted && effectiveExtraPassword) {
        const innerEncrypted = await EncryptionManager.encryptText(content, effectiveExtraPassword);
        if (!innerEncrypted.success) {
            AuthManager.showAlert('Extra encryption failed', 'error');
            return;
        }
        noteStorageObj.doubleEncryptedContent = innerEncrypted.ciphertext;
        noteStorageObj.doubleSalt = innerEncrypted.salt;
        noteStorageObj.doubleIv = innerEncrypted.iv;
    }

        // Save to storage
        let encryptedNotes = SVStorage.getNotes();

        if (this.editingNoteId) {
            // Update existing
            const idx = encryptedNotes.findIndex(n => n.id === this.editingNoteId);
            if (idx !== -1) {
                noteStorageObj.createdAt = encryptedNotes[idx].createdAt;
                encryptedNotes[idx] = noteStorageObj;
            }

            const noteIdx = this.currentNotes.findIndex(n => n.id === this.editingNoteId);
            if (noteIdx !== -1) {
                this.currentNotes[noteIdx] = {
                    id: noteStorageObj.id,
                    title,
                    content,
                    isDoubleEncrypted: willBeDoubleEncrypted,
                    createdAt: this.currentNotes[noteIdx].createdAt,
                    updatedAt: now
                };
            }
        } else {
            // Create new
            encryptedNotes.unshift(noteStorageObj);
            this.currentNotes.unshift({
                id: noteStorageObj.id,
                title,
                content,
                isDoubleEncrypted: willBeDoubleEncrypted,
                createdAt: now,
                updatedAt: now
            });
        }

        SVStorage.saveNotes(encryptedNotes);
        this.displayNotes();
        this.closeNoteEditor();
        AuthManager.showAlert('Note saved successfully!', 'success');
    },

    /**
     * Delete current note
     */
    deleteCurrentNote() {
        if (!this.editingNoteId) return;

        if (!confirm('Are you sure you want to delete this note? This cannot be undone.')) return;

        this.currentNotes = this.currentNotes.filter(n => n.id !== this.editingNoteId);
        let encryptedNotes = SVStorage.getNotes();
        encryptedNotes = encryptedNotes.filter(n => n.id !== this.editingNoteId);
        SVStorage.saveNotes(encryptedNotes);

        this.displayNotes();
        this.closeNoteEditor();
        AuthManager.showAlert('Note deleted', 'success');
    },

    closeNoteEditor() {
        // Clear auto-save timer
        clearTimeout(this.autoSaveTimer);
        this.autoSaveTimer = null;

        document.getElementById('note-editor').style.display = 'none';
        document.getElementById('note-title').value = '';
        document.getElementById('note-content').value = '';
        document.getElementById('note-content').readOnly = false;
        document.getElementById('note-encrypt-panel').style.display = 'none';
        document.getElementById('note-decrypt-panel').style.display = 'none';
        document.getElementById('note-extra-password').value = '';
        document.getElementById('note-decrypt-extra-password').value = '';
        document.getElementById('word-count').textContent = '0 words · 0 characters';
        document.getElementById('autosave-indicator').textContent = '';
        document.getElementById('autosave-indicator').className = 'autosave-indicator';

        const toggleBtn = document.getElementById('toggle-encrypt-btn');
        if (toggleBtn) {
            toggleBtn.textContent = '🔒 Add Extra Lock';
            toggleBtn.className = 'btn btn-primary';
        }

        this.editingNoteId = null;
        this.currentNote = null;
        this.noteExtraEncryptionEnabled = false;
        this.deselectAllNotes();
    },

    /**
     * Search notes
     */
    searchNotes(searchTerm) {
        if (!searchTerm) {
            this.displayNotes();
            return;
        }

        const filtered = this.currentNotes.filter(note =>
            note.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
            (!note.isDoubleEncrypted && note.content.toLowerCase().includes(searchTerm.toLowerCase()))
        );

        const notesList = document.getElementById('notes-list');
        if (!notesList) return;

        notesList.innerHTML = '';

        if (filtered.length === 0) {
            notesList.innerHTML = '<p class="empty-state">No notes found matching your search.</p>';
            return;
        }

        filtered.forEach(note => {
            const noteItem = document.createElement('div');
            noteItem.className = 'note-item';
            noteItem.dataset.noteId = note.id;

            const preview = note.isDoubleEncrypted
                ? '🔒 Double-encrypted'
                : note.content.substring(0, 100) + (note.content.length > 100 ? '...' : '');

            noteItem.innerHTML = `
                <h4>${this.escapeHtml(note.title)} ${note.isDoubleEncrypted ? '<span class="double-lock-badge">🔒🔒</span>' : ''}</h4>
                <div class="note-preview">${this.escapeHtml(preview)}</div>
                <div class="note-date">${this.formatDate(note.updatedAt)}</div>
            `;

            noteItem.addEventListener('click', () => this.openNote(note.id));
            notesList.appendChild(noteItem);
        });
    },

    deselectAllNotes() {
        document.querySelectorAll('.note-item').forEach(note => note.classList.remove('active'));
    },

    generateNoteId() {
        return 'note_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    },

    formatDate(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;

        if (diff < 60000) return 'Just now';
        if (diff < 3600000) {
            const m = Math.floor(diff / 60000);
            return `${m} minute${m > 1 ? 's' : ''} ago`;
        }
        if (diff < 86400000) {
            const h = Math.floor(diff / 3600000);
            return `${h} hour${h > 1 ? 's' : ''} ago`;
        }
        if (diff < 604800000) {
            const d = Math.floor(diff / 86400000);
            return `${d} day${d > 1 ? 's' : ''} ago`;
        }
        return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

// Global functions
function createNewNote() { NoteManager.createNewNote(); }
async function saveNote() { await NoteManager.saveNote(); }
function closeNoteEditor() { NoteManager.closeNoteEditor(); }
function deleteCurrentNote() { NoteManager.deleteCurrentNote(); }
function toggleNoteEncryption() { NoteManager.toggleNoteEncryption(); }
function confirmExtraLock() { NoteManager.confirmExtraLock(); }
function cancelExtraLock() { NoteManager.cancelExtraLock(); }
async function decryptNoteContent() { await NoteManager.decryptNoteContent(); }

function updateWordCount() {
    const content = document.getElementById('note-content')?.value || '';
    const words = content.trim() === '' ? 0 : content.trim().split(/\s+/).length;
    const chars = content.length;
    const el = document.getElementById('word-count');
    if (el) el.textContent = `${words} word${words !== 1 ? 's' : ''} · ${chars} character${chars !== 1 ? 's' : ''}`;
}

if (typeof window !== 'undefined') {
    console.log('NoteManager module loaded');
}