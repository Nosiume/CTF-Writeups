const puppeteer = require('puppeteer');

const API_URL = process.env.API_URL || 'http://127.0.0.1:5080';
const CHECK_INTERVAL = 30000;



let browser;

async function initBrowser() {
    if (!browser) {
        browser = await puppeteer.launch({
            headless: true,
            executablePath: '/usr/bin/chromium',
            args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors', '--ignore-ssl-errors']
        });
    }
    return browser;
}

async function checkAndDeleteMessages() {
    try {
        const b = await initBrowser();
        const page = await b.newPage();
        
        await page.setRequestInterception(true);
        page.on('request', (req) => {
            let url = req.url();
            req.continue({ url });
        });
        
        await page.goto(`${API_URL}/admin/messages`, {
            waitUntil: 'networkidle2',
            timeout: 10000,
            ignoreHTTPSErrors: true
        });
        
        await new Promise(r => setTimeout(r, 10000));
        
        await page.setRequestInterception(false);
        await page.close();
    } catch (error) {
        console.error(`[!] Error: ${error.message}`);
    }
}

async function main() {
    await new Promise(r => setTimeout(r, 2000));
    await checkAndDeleteMessages();
    setInterval(checkAndDeleteMessages, CHECK_INTERVAL);
}

process.on('SIGTERM', async () => {
    if (browser) await browser.close();
    process.exit(0);
});

main().catch(console.error);
