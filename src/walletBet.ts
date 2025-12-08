// src/walletBet.ts
import { Buffer } from 'buffer';
import process from 'process';
import * as nodeCrypto from 'crypto-browserify';
import { rostrumProvider } from 'nexa-wallet-sdk';

// Polyfills
(globalThis as any).Buffer  ||= Buffer;
(globalThis as any).process ||= process;
(globalThis as any).__nodeCrypto = nodeCrypto;

const KEY='kk_wallet_v1', IV='kk_wallet_iv_v1';
const KIBL_GROUP_ADDR = 'nexa:tpjkhlhuazsgskkt5hyqn3d0e7l6vfvfg97cf42pprntks4x7vqqqcavzypmt';
const KIBL_TOKEN_HEX  = '656bfefce8a0885acba5c809c5afcfbfa62589417d84d54108e6bb42a6f30000';
const HOUSE_ADDRESS   = 'nexa:nqtsq5g5pvucuzm2kh92kqtxy5s3zfutq3xgnhh5src65fc3';
const KIBL_TOKEN_ID   = 'nexa:tpjkhlhuazsgskkt5hyqn3d0e7l6vfvfg97cf42pprntks4x7vqqqcavzypmt';

// --- NODES ---
const PRIVATE_NODE = { scheme: 'wss' as const, host: 'node.remy-dev.com', port: 443 };
const PUBLIC_NODE  = { scheme: 'wss' as const, host: 'electrum.nexa.org', port: 20004 };

// --- CACHE STATE ---
let cachedSession: {
  wallet: any;
  account: any;
  address: any;
  network: any;
  balances: any;
  sdk: any;
  seed: any; 
  net: any;
} | null = null;

// Lock to prevent parallel reconnects (The Singleton Guard)
let reconnectLock: Promise<void> | null = null;

async function getSdk() { return await import('nexa-wallet-sdk'); }
function getWalletCtor(mod: any) { return mod?.Wallet ?? mod?.default?.Wallet; }

/**
 * HEALTH CHECK
 * Replaces the "made up" .isConnected check.
 * We try to fetch the block tip. If it works, the pipe is open.
 */
async function isConnectionHealthy(rostrumProvider: any) {
  if (!rostrumProvider) return false;
  try {
    // "Ping" the server
    await rostrumProvider.getBlockTip();
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * CONNECT / RECONNECT ROUTINE
 * Tries Private Node -> Fails over to Public Node
 */
async function establishConnection(rostrumProvider: any) {
  console.log('[Client] Connecting to network...');

  // 1. Try Private Node
  try {
    // Per your RostrumProvider.ts, this replaces the internal client
    await rostrumProvider.connect(PRIVATE_NODE);
    
    // Verify it actually works (Handshake isn't enough, we need data flow)
    if (await isConnectionHealthy(rostrumProvider)) {
        console.log('✅ Connected: Private Node');
        return true;
    }
  } catch (e) {
    console.warn('⚠️ Private node unreachable, trying public...');
  }

  // 2. Try Public Node (Failover)
  try {
    await rostrumProvider.connect(PUBLIC_NODE);
    if (await isConnectionHealthy(rostrumProvider)) {
        console.log('⚠️ Connected: Public Node');
        return true;
    }
  } catch (e) {
    console.error('❌ Connection failed:', e);
  }
  return false;
}

export async function loadWallet(pass: string) {
  // 1. Existing Session? Check health using PING.
  if (cachedSession) {
    // If a reconnect is already happening, wait for it
    if (reconnectLock) { await reconnectLock; return cachedSession; }

    const { wallet } = cachedSession;

    // Fast Check: "Are we still there?"
    // We use getBlockTip() instead of .isConnected
    const healthy = await isConnectionHealthy(rostrumProvider);

    if (healthy) {
        return cachedSession; // FAST PATH (Instant)
    }

    // SLOW PATH (Repairing dropped connection)
    console.log('[Client] Connection stale. Reconnecting...');
    
    reconnectLock = (async () => {
        try {
            const success = await establishConnection(rostrumProvider);
            if (!success) throw new Error("Unable to reach network.");
            
            // If we reconnected, we MUST resync the wallet 
            // because the old internal subscriptions were lost.
            console.log('[Client] Resyncing wallet...');
            await wallet.initialize();
        } finally {
            reconnectLock = null;
        }
    })();

    await reconnectLock;
    return cachedSession;
  }

  // 2. Initial Load (Decrypt from Storage)
  const rawB64 = localStorage.getItem(KEY);
  const ivB64  = localStorage.getItem(IV);
  if (!rawB64 || !ivB64) throw new Error('No local wallet. Visit Connect.');

  const raw = atob(rawB64);
  const ivb = atob(ivB64);
  const iv  = new Uint8Array([...ivb].map(c=>c.charCodeAt(0)));
  const ct  = new Uint8Array([...raw].map(c=>c.charCodeAt(0)));

  const h   = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pass));
  const key = await crypto.subtle.importKey('raw', h, 'AES-GCM', false, ['decrypt']);
  const pt  = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
  
  const { seed, net } = JSON.parse(new TextDecoder().decode(pt)); 

  const sdk = await getSdk();
  const WalletCtor = getWalletCtor(sdk);
  
  const wallet = new WalletCtor(seed, net);
  const provider = wallet.rostrumProvider || wallet.provider;
  
  // Initial Connect
  const connected = await establishConnection(rostrumProvider);
  if (!connected) throw new Error('Could not connect to network.');

  console.log('[Client] Initializing Wallet (Scanning UTXOs)...');
  await wallet.initialize(); 

  const account = wallet.accountStore.getAccount('2.0');
  if (!account) throw new Error('Account 2.0 missing');
  const address = account.getPrimaryAddressKey().address; 

  const nexaMinor = Number(account.balance?.confirmed || 0);
  const kiblMinor = Number(account.tokenBalances?.[KIBL_GROUP_ADDR]?.confirmed || 0);
  const DEC = 2;

  // Save to Cache
  cachedSession = { 
    wallet, account, address, network: net, sdk, seed, net,
    balances: {
        kiblMinor, kibl: (kiblMinor / 10 ** DEC),
        nexaMinor, nexa: (nexaMinor / 10 ** DEC),
        tokenHex: KIBL_TOKEN_HEX, tokenGroup: KIBL_GROUP_ADDR,
    }
  };
  return cachedSession;
}

export async function placeBet({ passphrase, kiblAmount, tokenIdHex, feeNexa }: any) {
  if (!cachedSession && (!passphrase || passphrase.length < 8)) throw new Error('Password required.');
  
  // Auto-reconnects if needed
  const { wallet, account } = await loadWallet(passphrase);
  
  console.log('[Client] Building...');

  const signedTx = await wallet.newTransaction(account)
    .onNetwork('mainnet')
    .sendToToken(HOUSE_ADDRESS, kiblAmount.toString(), KIBL_TOKEN_ID)
    .populate()
    .sign()
    .build();
  
  const txId = await wallet.sendTransaction(signedTx);
  console.log('[Client] Sent:', txId);

  return { txId, house: HOUSE_ADDRESS };
}
export async function recoverSeed(pass: string) {
  const rawB64 = localStorage.getItem(KEY);
  const ivB64  = localStorage.getItem(IV);
  
  if (!rawB64 || !ivB64) throw new Error('No wallet found to back up.');

  const raw = atob(rawB64);
  const ivb = atob(ivB64);
  const iv  = new Uint8Array([...ivb].map(c=>c.charCodeAt(0)));
  const ct  = new Uint8Array([...raw].map(c=>c.charCodeAt(0)));

  const h   = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pass));
  const key = await crypto.subtle.importKey('raw', h, 'AES-GCM', false, ['decrypt']);
  
  try {
    const pt  = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
    const { seed } = JSON.parse(new TextDecoder().decode(pt));
    return seed; // Returns the 12-word string
  } catch (e) {
    throw new Error('Incorrect password.');
  }
}
export async function sendFunds({ passphrase, toAddress, amountNexa, amountKibl }: any) {
  const { wallet, account } = await loadWallet(passphrase);
  
  let tx = wallet.newTransaction(account)
  .onNetwork('mainnet')
  .sendTo(toAddress, amountNexa.toString())
  .sendToToken(toAddress, amountKibl.toString(), KIBL_TOKEN_ID);
  const signed = await tx.populate().sign().build();
  
  const txId = await wallet.sendTransaction(signed);
  return txId;
}