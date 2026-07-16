document.getElementById('unlock').onclick = () => {
    const pw = document.getElementById('masterPw').value;
    chrome.runtime.sendMessage({
        action: 'unlock',
        password: pw
    }, (response) => {
        const status = document.getElementById('status');
        if (response && response.status === 'success') {
            status.textContent = '✅ Entsperrt!';
            status.style.color = 'green';
        } else {
            status.textContent = '❌ ' + (response ? response.message : 'Keine Antwort');
            status.style.color = 'red';
        }
    });
};