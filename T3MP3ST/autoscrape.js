import { exec } from 'child_process';
import https from 'https';

// Settings
const TARGET_URL = '127.0.0.1
'; 
const INTERVAL_MS = 30000; // Scrape every 30 seconds (30000ms)

let lastScrapedContent = '';

function runAutosaveScraper() {
    console.log(`\n[Autosave] Checking target page: ${TARGET_URL}...`);
    
    https.get(TARGET_URL, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
            // Strip HTML and grab the first 1000 characters
            let cleanText = data.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().substring(0, 1000);
            
            // Check if the webpage content has actually changed since last time
            if (cleanText === lastScrapedContent) {
                console.log("[Autosave] No new changes detected on page. Skipping model analysis.");
                return;
            }
            
            console.log("[Autosave] New data found! Sending update to Qwen...");
            lastScrapedContent = cleanText;
            
            const systemPrompt = "You are an automated background scraping daemon. Summarize this freshly updated text in two direct bullet points for a chat window:";
            const fullPrompt = `${systemPrompt}\n\n${cleanText}`;
            
            exec(`ollama run qwen2.5:0.5b "${fullPrompt.replace(/"/g, '\\"')}"`, (error, stdout, stderr) => {
                if (error) {
                    console.error(`[Error] Model issue: ${error.message}`);
                    return;
                }
                console.log("\n=== AUTOSAVED CHAT UPDATE ===");
                console.log(stdout.trim());
            });
        });
    }).on('error', (err) => {
        console.error(`[Error] Connection failed: ${err.message}`);
    });
}

// Run immediately on start, then repeat every 30 seconds
runAutosaveScraper();
setInterval(runAutosaveScraper, INTERVAL_MS);
