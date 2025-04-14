const STORAGE_PREFIX = 'chat_';
let CURRENT_USER = null;

function setUser() {
    const username = document.getElementById('username').value.trim();
    if (!username) return alert('Please enter a username');

    CURRENT_USER = username;
    document.getElementById('user-title').textContent = `${CURRENT_USER}'s Chat`;
    document.querySelectorAll('.hidden').forEach(el => el.classList.remove('hidden'));
    document.getElementById('message-input').disabled = false;
    
    const storedPublicKey = localStorage.getItem(`${STORAGE_PREFIX}${CURRENT_USER}_public_key`);
    if (storedPublicKey) {
        document.getElementById('public-key').value = storedPublicKey;
        document.getElementById('key-display').classList.remove('hidden');
    }
    refreshMessages(); 
}
async function generateKeys() {
    if (!CURRENT_USER) return alert('Please login first');

    const keyPair = await crypto.subtle.generateKey(
        { 
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1,0,1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    
    localStorage.setItem(`${STORAGE_PREFIX}${CURRENT_USER}_public_key`, arrayToBase64(publicKey));
    localStorage.setItem(`${STORAGE_PREFIX}${CURRENT_USER}_private_key`, arrayToBase64(privateKey));
    
    document.getElementById('public-key').value = arrayToBase64(publicKey);
    document.getElementById('key-display').classList.remove('hidden');
}

function arrayToBase64(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}

function base64ToArray(base64) {
    const binaryString = atob(base64);
    return new Uint8Array([...binaryString].map(c => c.charCodeAt(0))).buffer;
}
async function sendMessage() {
    if (!CURRENT_USER) return alert('Please login first');

    const recipientKey = document.getElementById('recipient-key').value;
    const message = document.getElementById('message-input').value;

    if (!recipientKey || !message) {
        alert('Please enter both recipient key and message');
        return;
    }

    try {
        if (recipientKey === localStorage.getItem(`${STORAGE_PREFIX}${CURRENT_USER}_public_key`)) {
            alert("You can't send messages to yourself!");
            return;
        }

        let recipient = null;
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.endsWith('_public_key') && localStorage.getItem(key) === recipientKey) {
                recipient = key.replace('_public_key', '').replace(STORAGE_PREFIX, '');
                break;
            }
        }

        if (!recipient) {
            alert('Recipient public key not found in system');
            return;
        }

        const recipientPublicKey = await crypto.subtle.importKey(
            'spki',
            base64ToArray(recipientKey),
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['encrypt']
        );

        const encryptedForRecipient = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            recipientPublicKey,
            new TextEncoder().encode(message)
        );

        const existingRecipient = JSON.parse(localStorage.getItem(`${STORAGE_PREFIX}${recipient}_messages`) || '[]');
        existingRecipient.push({
            type: 'received',
            data: arrayToBase64(encryptedForRecipient)
        });
        localStorage.setItem(`${STORAGE_PREFIX}${recipient}_messages`, JSON.stringify(existingRecipient));

        const senderPublicKey = await crypto.subtle.importKey(
            'spki',
            base64ToArray(localStorage.getItem(`${STORAGE_PREFIX}${CURRENT_USER}_public_key`)),
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['encrypt']
        );

        const encryptedForSender = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            senderPublicKey,
            new TextEncoder().encode(message)
        );

        
        const existingSender = JSON.parse(localStorage.getItem(`${STORAGE_PREFIX}${CURRENT_USER}_messages`) || '[]');
        existingSender.push({
            type: 'sent',
            data: arrayToBase64(encryptedForSender)
        });
        localStorage.setItem(`${STORAGE_PREFIX}${CURRENT_USER}_messages`, JSON.stringify(existingSender));

        document.getElementById('message-input').value = '';
        
        
        refreshMessages();

    } catch (e) {
        alert('Encryption failed. Check the recipient key.');
    }
}
function toggleView(view) {
    document.getElementById('messages-view').classList.toggle('hidden', view !== 'messages');
    document.getElementById('encrypted-view').classList.toggle('hidden', view !== 'encrypted');
    refreshMessages();
}

async function refreshMessages() {
    if (!CURRENT_USER) return;
    
    const messages = JSON.parse(localStorage.getItem(`${STORAGE_PREFIX}${CURRENT_USER}_messages`) || '[]');
    const messagesDiv = document.getElementById('messages');
    const encryptedDiv = document.getElementById('encrypted-messages');
    
    messagesDiv.innerHTML = '';
    encryptedDiv.innerHTML = '';

    try {
        const privateKey = await crypto.subtle.importKey(
            'pkcs8',
            base64ToArray(localStorage.getItem(`${STORAGE_PREFIX}${CURRENT_USER}_private_key`)),
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['decrypt']
        );

        for (const msg of messages) {
            // Decrypt for messages view
            try {
                const decrypted = await crypto.subtle.decrypt(
                    { name: 'RSA-OAEP' },
                    privateKey,
                    base64ToArray(msg.data)
                );
                messagesDiv.innerHTML += `
                    <div class="message ${msg.type}">
                        ${msg.type === 'sent' ? '→' : '←'}
                        ${new TextDecoder().decode(decrypted)}
                    </div>
                `;
            } catch (e) {
                messagesDiv.innerHTML += `
                    <div class="message encrypted ${msg.type}">
                        ${msg.type === 'sent' ? '→' : '←'}
                        Failed to decrypt
                    </div>
                `;
            }
            encryptedDiv.innerHTML += `
                <div class="encrypted-msg">
                    ${msg.type === 'sent' ? '→' : '←'} 
                    ${msg.data}
                </div>
            `;
        }
    } catch (e) {
        messagesDiv.innerHTML = '<div class="message encrypted">Private key not found</div>';
    }
}
window.addEventListener('storage', async (event) => {
    if (event.key === `${STORAGE_PREFIX}${CURRENT_USER}_messages`) {
        refreshMessages();
    }
});