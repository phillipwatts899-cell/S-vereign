import time
import subprocess
import requests
from bs4 import BeautifulSoup

def scrape_page_text(url):
    """Fetches a web page and extracts clean text content."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return f"Error: Unable to fetch page (Status {response.status_code})"
            
        # Parse HTML and remove script/style tags
        soup = BeautifulSoup(response.text, 'html.parser')
        for script in soup(["script", "style"]):
            script.extract()
            
        # Extract readable text layout
        text = soup.get_text(separator=' ')
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        clean_text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return clean_text[:2000] # Limit to first 2000 characters for the 0.5B model
    except Exception as e:
        return f"Scraping Error: {e}"

def process_with_qwen(text_content):
    """Passes scraped web text to the local Qwen 0.5B model."""
    system_overlay = (
        "You are an AI parsing daemon. Analyze the following scraped web page text. "
        "Provide a clean, 3-bullet-point summary suitable to paste into a chat."
    )
    prompt = f"{system_overlay}\n\nScraped Content:\n{text_content}"
    
    try:
        result = subprocess.run(
            ["ollama", "run", "qwen2.5:0.5b", prompt], 
            capture_output=True, 
            text=True, 
            check=True
        )
        return result.stdout.strip()
    except Exception as e:
        return f"Model Error: {e}"

def main():
    print("Scraper daemon active. Paste a URL to start...")
    # Example target URL (Can be replaced with clipboard monitoring or file inputs)
    target_url = "https://example.com" 
    
    print(f"Scraping target: {target_url}")
    raw_text = scrape_page_text(target_url)
    
    print("Processing scraped text with Qwen...")
    summary = process_with_qwen(raw_text)
    
    print("\n=== FINAL CHAT OUTPUT ===")
    print(summary)

if __name__ == "__main__":
    main()

