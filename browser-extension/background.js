let nativePort = null;
let isUnlocked = false;

function connectNative() {
    nativePort = chrome.runtime.connectNative('com.phylo04.passwortmanager');
    
    nativePort.onMessage.addListener((response) => {
        console.log('Vom Native Host:', response);
    });
    
    nativePort.onDisconnect.addListener(() => {
        console.log('Native Host getrennt');
        nativePort = null;
        isUnlocked = false;
    });
}

function sendToNative(message) {
    return new Promise((resolve, reject) => {
        if (!nativePort) {
            connectNative();
        }
        
        // Warte kurz bis Verbindung steht
        setTimeout(() => {
            if (!nativePort) {
                resolve({status: 'error', message: 'Native Host nicht erreichbar'});
                return;
            }
            
            const listener = (response) => {
                nativePort.onMessage.removeListener(listener);
                resolve(response);
            };
            
            nativePort.onMessage.addListener(listener);
            nativePort.postMessage(message);
        }, 100);
    });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getPasswords') {
        if (!isUnlocked) {
            sendResponse({status: 'error', message: 'Nicht entsperrt'});
            return true;
        }
        
        sendToNative({
            action: 'get_passwords',
            url: request.url
        }).then(response => {
            sendResponse(response);
        });
        return true;
    }
    
    if (request.action === 'unlock') {
        sendToNative({
            action: 'unlock',
            password: request.password
        }).then(response => {
            if (response.status === 'success') {
                isUnlocked = true;
            }
            sendResponse(response);
        });
        return true;
    }
});