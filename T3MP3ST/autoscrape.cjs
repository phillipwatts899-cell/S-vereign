const http = require('http');
const fs = require('fs');
const { exec } = require('child_process');

const PORT = 3000;
const TRIGGER_FILE = 'search_trigger.txt';
const LOG_FILE = 'google_searches_archive.log';

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

    if (req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            try {
                const payload = JSON.parse(body);
                const incomingUrl = payload.url || body;

                if (incomingUrl.includes('://google.com')) {
                    // Update the local file instantly
                    fs.writeFileSync(TRIGGER_FILE, incomingUrl);
                    
                    const urlObj = new URL(incomingUrl);
                    const cleanQuery = decodeURIComponent(urlObj.searchParams.get('q').replace(/\+/g, ' '));
                    console.log(`\n[Network Intercept] Search Caught: "${cleanQuery}"`);

                    exec(`ollama run qwen2.5:0.5b "Categorize this query: \\"${cleanQuery}\\""`, (err, stdout) => {
                        if (err) return;
                        console.log(`[Intel Log Summary] ${stdout.trim()}`);
                        fs.appendFileSync(LOG_FILE, `[SEARCH] ${cleanQuery} -> ${stdout.trim()}\n`);
                    });
                }
                res.writeHead(200); res.end('{"status":"ok"}');
            } catch (e) { res.writeHead(200); res.end(); }
        });
    }
});

server.listen(PORT, '127.0.0.1', () => {
    console.log(`\n[Daemon Online] URL to copy into your browser extension:`);
    console.log(`http://127.0.0\n`);
});
