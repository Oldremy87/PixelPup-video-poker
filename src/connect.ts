import { Buffer } from 'buffer';
import process from 'process';
import * as nodeCrypto from 'crypto-browserify';

(globalThis as any).Buffer = Buffer;
(globalThis as any).process = process;
(globalThis as any).__nodeCrypto = nodeCrypto;

const KEY = 'kk_wallet_v1';
const IV = 'kk_wallet_iv_v1';

// --- NODE CONFIGURATIONS (Unified with walletBet.ts) ---
const PRIVATE_NODE = { scheme: 'wss' as const, host: 'node.remy-dev.com', port: 443 };
const PUBLIC_NODE  = { scheme: 'wss' as const, host: 'electrum.nexa.org', port: 20004 };

async function sdk() {
  return await import('nexa-wallet-sdk');
}

async function ensureCsrf() {
  if ((window as any).csrfToken) return (window as any).csrfToken;
  const r = await fetch('/api/csrf', { credentials: 'include' });
  if (!r.ok) throw new Error(`CSRF fetch failed: ${r.status}`);
  const { csrfToken } = await r.json();
  (window as any).csrfToken = csrfToken;
  return csrfToken;
}

async function postJSON(url: string, body: any) {
  const csrf = await ensureCsrf();
  const r = await fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrf },
    body: JSON.stringify(body),
  });
  let j: any = null;
  try { j = await r.json(); } catch { }
  if (!r.ok || (j && j.ok === false)) {
    throw new Error(j?.error || `HTTP ${r.status}`);
  }
  return j;
}

function normalizeSeed(raw: string) {
  return (raw || '').toLowerCase().replace(/[^a-z\s]/g, ' ').split(/\s+/).filter(Boolean).join(' ');
}

function require12Words(seed: string) {
  const words = seed.split(' ');
  if (words.length !== 12) throw new Error(`Seed must be 12 words (got ${words.length}).`);
  return seed;
}

async function aesKey(pass: string) {
  const raw = new TextEncoder().encode(pass);
  const h = await crypto.subtle.digest('SHA-256', raw);
  return crypto.subtle.importKey('raw', h, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function enc(pass: string, data: string) {
  if (!pass || pass.length < 8) throw new Error('Password must be 8+ chars.');
  const key = await aesKey(pass);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(data));
  localStorage.setItem(IV, btoa(String.fromCharCode(...iv)));
  localStorage.setItem(KEY, btoa(String.fromCharCode(...new Uint8Array(ct))));
  localStorage.setItem('kk_has_pass', '1');
}

async function init() {
  const passEl = document.getElementById('pass') as HTMLInputElement;
  const pass2El = document.getElementById('pass2') as HTMLInputElement;
  const btnCreate = document.getElementById('btnCreate') as HTMLButtonElement;
  const btnImport = document.getElementById('btnImport') as HTMLButtonElement;
  const importArea = document.getElementById('importArea') as HTMLElement;
  const seedIn = document.getElementById('seedIn') as HTMLTextAreaElement;
  const btnDoImport = document.getElementById('btnDoImport') as HTMLButtonElement;
  const linked = document.getElementById('linked') as HTMLElement;
  const addrText = document.getElementById('addr') as HTMLElement;
  const btnLink = document.getElementById('btnLink') as HTMLButtonElement;
  const passHint = document.getElementById('passHint') as HTMLElement;
  const kiblBalanceEl = document.getElementById('kiblBalance') as HTMLElement;

  let address: string | null = null;

  function passOk() {
    const p1 = passEl.value;
    const p2 = pass2El.value;
    const ok = p1.length >= 8 && p1 === p2;
    btnCreate.disabled = !ok;
    btnImport.disabled = !ok;
    passHint.hidden = ok;
  }

  passEl.addEventListener('input', passOk);
  pass2El.addEventListener('input', passOk);

  // --- ROBUST BOOT FUNCTION ---
  async function bootFromSeed(seed: string, net: 'mainnet') {
    const { Wallet, rostrumProvider } = await sdk();

    // 1. Health Check Helper (The Ping Test)
    const checkConnection = async () => {
        try {
            // Race against 2s timeout
            const timeout = new Promise((_, r) => setTimeout(() => r(new Error('timeout')), 2000));
            await Promise.race([rostrumProvider.getBlockTip(), timeout]);
            return true;
        } catch { return false; }
    };

    console.log('[Connect] Connecting to network...');
    let connected = false;

    // 2. Try Private Node (Priority)
    try {
        await rostrumProvider.connect(PRIVATE_NODE);
        if (await checkConnection()) {
            console.log('✅ Connected: Private Node');
            connected = true;
        }
    } catch (e) {
        console.warn('⚠️ Private node unreachable, trying public...');
    }

    // 3. Failover to Public Node
    if (!connected) {
        try {
            await rostrumProvider.connect(PUBLIC_NODE);
            if (await checkConnection()) {
                console.log('⚠️ Connected: Public Node');
                connected = true;
            }
        } catch (e) {
            console.error('❌ Public node failed');
        }
    }

    if (!connected) {
        throw new Error("Network Error: Could not reach Nexa nodes. Please check your internet connection.");
    }

    // 4. Initialize Wallet
    console.log('[Connect] Scanning wallet...');
    const wallet = new Wallet(seed, net);
    await wallet.initialize();
    
    const account = wallet.accountStore.getAccount('2.0');
    const k = account.getPrimaryAddressKey();
    
    // Get KIBL Balance
    const tokenId = process.env.KIBL_TOKEN_ID_HEX || '656bfefce8a0885acba5c809c5afcfbfa62589417d84d54108e6bb42a6f30000';
    const kiblBal = account.tokenBalances[tokenId]?.confirmed || 0;
    
    if (kiblBalanceEl) kiblBalanceEl.textContent = `Balance: ${(Number(kiblBal)/100).toFixed(2)} KIBL`;

    return { address: k.address };
  }

  btnCreate.addEventListener('click', async () => {
    try {
      btnCreate.disabled = true;
      btnCreate.textContent = "Generating...";
      
      const pass = passEl.value;
      const net = 'mainnet';
      const { Wallet } = await sdk();
      const w = Wallet.create();
      const seed = w.export().phrase;
      
      await enc(pass, JSON.stringify({ seed, net }));
      
      btnCreate.textContent = "Connecting...";
      const r = await bootFromSeed(seed, net);
      address = r.address;
      addrText.textContent = `Address: ${address}`;
      linked.hidden = false;
      
      importArea.hidden = false;
      seedIn.value = seed;
      alert('Wallet Created! \n\nIMPORTANT: Write down the seed phrase shown below immediately.');
      
    } catch (e: any) {
      alert(e.message || 'Create failed');
    } finally {
      btnCreate.disabled = false;
      btnCreate.textContent = "Create New Wallet";
    }
  });

  btnImport.addEventListener('click', () => {
    importArea.hidden = !importArea.hidden;
  });

  btnDoImport.addEventListener('click', async () => {
    try {
      btnDoImport.disabled = true;
      btnDoImport.textContent = "Importing...";

      const pass = passEl.value;
      const net = 'mainnet';
      const seed = require12Words(normalizeSeed(seedIn.value));
      
      await enc(pass, JSON.stringify({ seed, net }));
      
      const r = await bootFromSeed(seed, net);
      address = r.address;
      addrText.textContent = `Address: ${address}`;
      linked.hidden = false;
      alert('Wallet Imported Successfully!');
    } catch (e: any) {
      alert(e.message || 'Import failed');
    } finally {
      btnDoImport.disabled = false;
      btnDoImport.textContent = "Load Wallet";
    }
  });

  btnLink.addEventListener('click', async () => {
    try {
      if (!address) return alert('No address loaded.');
      await postJSON('/api/wallet/link', { address, network: 'mainnet' });
      alert('Wallet Linked Successfully!');
      window.location.href = '/play.html';
    } catch (e: any) {
      alert('Link failed: ' + e.message);
    }
  });

  if (localStorage.getItem(KEY)) {
      passEl.placeholder = "Enter password to unlock existing wallet";
  }
  
  ensureCsrf();
}

addEventListener('DOMContentLoaded', init);