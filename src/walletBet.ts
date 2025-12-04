// src/walletBet.ts
import { Buffer } from 'buffer';
import process from 'process';
import * as nodeCrypto from 'crypto-browserify';

// Polyfills
(globalThis as any).Buffer  ||= Buffer;
(globalThis as any).process ||= process;
(globalThis as any).__nodeCrypto = nodeCrypto;

const KEY='kk_wallet_v1', IV='kk_wallet_iv_v1';

// Constants
const KIBL_GROUP_ADDR = 'nexa:tpjkhlhuazsgskkt5hyqn3d0e7l6vfvfg97cf42pprntks4x7vqqqcavzypmt';
const KIBL_TOKEN_HEX  = '656bfefce8a0885acba5c809c5afcfbfa62589417d84d54108e6bb42a6f30000';
const HOUSE_ADDRESS   = 'nexa:nqtsq5g5pvucuzm2kh92kqtxy5s3zfutq3xgnhh5src65fc3';
const KIBL_TOKEN_ID   = 'nexa:tpjkhlhuazsgskkt5hyqn3d0e7l6vfvfg97cf42pprntks4x7vqqqcavzypmt';

async function getSdk() {
  return await import('nexa-wallet-sdk');
}

// --- NODE CONFIGURATIONS ---
const PRIVATE_NODE = {
  scheme: 'wss' as const,
  host: 'node.remy-dev.com', // Your Bare Metal NVMe Node
  port: 443,                 // Cloudflare Tunnel
};

const PUBLIC_NODE = {
  scheme: 'wss' as const,
  host: 'electrum.nexa.org', // Backup
  port: 20004,
};

async function connectMainnet(rostrumProvider: any) {
  // 1. Check if already connected
  if (rostrumProvider.isConnected) return;

  console.log('[Client] connecting to network...');

  // 2. Attempt Private Node (Fast Lane)
  try {
    await rostrumProvider.connect(PRIVATE_NODE);
    console.log('✅ Connected to Private Node');
    return;
  } catch (e) {
    console.warn('⚠️ Private node unreachable, switching to public backup...');
  }

  // 3. Fallback to Public Node (Slow Lane)
  try {
    await rostrumProvider.connect(PUBLIC_NODE);
    console.log('⚠️ Connected to Public Backup Node');
  } catch (e) {
    console.error('❌ All network nodes failed.');
    throw new Error('Network connection failed. Please refresh.');
  }
}

function getWalletCtor(mod: any) {
  return mod?.Wallet ?? mod?.default?.Wallet;
}

export async function loadWallet(pass: string) {
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

  // --- SDK + provider
  const sdk = await getSdk();
  const { rostrumProvider } = sdk;

  await connectMainnet(rostrumProvider);

  // --- wallet + account
  const WalletCtor = getWalletCtor(sdk);
  if (!WalletCtor) throw new Error('Wallet export missing');

  const wallet  = new WalletCtor(seed, net);
  await wallet.initialize();

  const account = wallet.accountStore.getAccount('2.0');
  if (!account) throw new Error('DApp account (2.0) not found.');
  const address = account.getPrimaryAddressKey().address; 

  // ✅ Use account aggregates
  const nexaMinor = Number(account.balance?.confirmed || 0);
  const kiblMinor = Number(account.tokenBalances?.[KIBL_GROUP_ADDR]?.confirmed || 0);

  const DEC = 2;
  const balances = {
    kiblMinor,
    kibl: (kiblMinor / 10 ** DEC),
    nexaMinor,
    nexa: (nexaMinor / 10 ** DEC),
    tokenHex: KIBL_TOKEN_HEX,
    tokenGroup: KIBL_GROUP_ADDR,
  };

  return { wallet, account, address, network: net, balances };
}

export async function placeBet({
  passphrase,
  kiblAmount,   
  tokenIdHex,   
  feeNexa       
}: {
  passphrase: string; kiblAmount: number; tokenIdHex: string; feeNexa: number;
}) {
  if (!passphrase || passphrase.length < 8) throw new Error('Password required (8+ chars).');
  
  console.log('[Client] Loading wallet...');
  
  // 1. Load Wallet (Auto-connects to private node)
  const { wallet, account, address, network } = await loadWallet(passphrase);
  
  console.log('[Client] Building Transaction locally...');

  // 2. BUILD LOCALLY
  // Create the builder but DO NOT call .build() yet!
  const signedTx = await wallet.newTransaction(account)
    .onNetwork('mainnet')
    .sendTo(HOUSE_ADDRESS, feeNexa.toString())
    .sendToToken(HOUSE_ADDRESS, kiblAmount.toString(), KIBL_TOKEN_ID)
    .populate()
    .sign()
    .build();
  console.log('[Client] Broadcasting via Tunnel...');
  
  // 4. BROADCAST
  const txId = await wallet.sendTransaction(signedTx);

  console.log('[Client] Bet Sent! TxId:', txId);

  return { txId, network, address, house: HOUSE_ADDRESS };
}