console.log("CONTENT SCRIPT GELADEN!");
function findLoginFields() {
    const usernameFields = document.querySelectorAll('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[id*="user"]');
    const passwordFields = document.querySelectorAll('input[type="password"]');
    
    return {
        username: usernameFields[0] || null,
        password: passwordFields[0] || null
    };
}

function fillLogin(benutzername, passwort) {
    const fields = findLoginFields();
    
    if (fields.username) {
        fields.username.value = benutzername;
        fields.username.dispatchEvent(new Event('input', { bubbles: true }));
    }
    
    if (fields.password) {
        fields.password.value = passwort;
        fields.password.dispatchEvent(new Event('input', { bubbles: true }));
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

function init() {
    console.log("INIT WIRD AUFGERUFEN");
    const url = window.location.href;
    
    const fields = findLoginFields();
    console.log("GEFUNDENE FELDER:", fields);
    
    if (!fields.password) {
        console.log("KEIN PASSWORTFELD GEFUNDEN");
        return;
    }
    
    console.log("SENDE NACHRICHT AN BACKGROUND...");
    chrome.runtime.sendMessage({
        action: 'getPasswords',
        url: url
    }, (response) => {
        console.log("ANTWORT ERHALTEN:", response);
        if (response && response.status === 'success' && response.passwoerter.length > 0) {
            showPasswordSelector(response.passwoerter);
        } else {
            console.log("KEINE PASSWÖRTER GEFUNDEN ODER FEHLER");
        }
    });
}

function showPasswordSelector(passwoerter) {
    const div = document.createElement('div');
    div.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #2d2d2d;
        color: white;
        padding: 15px;
        border-radius: 8px;
        z-index: 999999;
        font-family: sans-serif;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    `;
    
    div.innerHTML = `
        <h3 style="margin:0 0 10px 0;">🔐 Passwort-Manager</h3>
        <p style="margin:0 0 10px 0; font-size: 12px;">Gefundene Einträge:</p>
    `;
    
    passwoerter.forEach(pw => {
        const btn = document.createElement('button');
        btn.textContent = `${pw.name} (${pw.benutzername})`;
        btn.style.cssText = `
            display: block;
            width: 100%;
            margin: 5px 0;
            padding: 8px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        `;
        btn.onclick = () => {
            fillLogin(pw.benutzername, pw.passwort);
            div.remove();
        };
        div.appendChild(btn);
    });
    
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕';
    closeBtn.style.cssText = `
        position: absolute;
        top: 5px;
        right: 5px;
        background: none;
        border: none;
        color: white;
        cursor: pointer;
    `;
    closeBtn.onclick = () => div.remove();
    div.appendChild(closeBtn);
    
    document.body.appendChild(div);
}