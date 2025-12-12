import { B as Buffer$1, p as process$1, n as nodeCrypto } from "./chunks/index-C_zbkbH-.js";
import { rostrumProvider as $884ce55f1db7e177$export$eaa49f0478d81b9d } from "./chunks/index.web-Does7zZT.js";
globalThis.Buffer ||= Buffer$1;
globalThis.process ||= process$1;
globalThis.__nodeCrypto = nodeCrypto;
const KEY = "kk_wallet_v1", IV = "kk_wallet_iv_v1";
const KIBL_GROUP_ADDR = "nexa:tpjkhlhuazsgskkt5hyqn3d0e7l6vfvfg97cf42pprntks4x7vqqqcavzypmt";
const KIBL_TOKEN_HEX = "656bfefce8a0885acba5c809c5afcfbfa62589417d84d54108e6bb42a6f30000";
const HOUSE_ADDRESS = "nexa:nqtsq5g5pvucuzm2kh92kqtxy5s3zfutq3xgnhh5src65fc3";
const KIBL_TOKEN_ID = "nexa:tpjkhlhuazsgskkt5hyqn3d0e7l6vfvfg97cf42pprntks4x7vqqqcavzypmt";
const PUBLIC_NODE = { scheme: "wss", host: "electrum.nexa.org", port: 20004 };
const GLOBALS = globalThis;
GLOBALS.__WALLET_SESSION = GLOBALS.__WALLET_SESSION || null;
GLOBALS.__WALLET_LOADING = GLOBALS.__WALLET_LOADING || null;
GLOBALS.__WALLET_RECONNECT = GLOBALS.__WALLET_RECONNECT || null;
async function getSdk() {
  return await import("./chunks/index.web-Does7zZT.js");
}
function getWalletCtor(mod) {
  return mod?.Wallet ?? mod?.default?.Wallet;
}
async function isConnectionHealthy(rostrumProvider2) {
  if (!rostrumProvider2) return false;
  try {
    await rostrumProvider2.getBlockTip();
    return true;
  } catch (e) {
    return false;
  }
}
async function establishConnection(rostrumProvider2) {
  console.log("[Client] Connecting to network...");
  try {
    await rostrumProvider2.connect(PUBLIC_NODE);
    if (await isConnectionHealthy(rostrumProvider2)) {
      console.log("⚠️ Connected: Public Node");
      return true;
    }
  } catch (e) {
    console.error("❌ Connection failed:", e);
  }
  return false;
}
async function loadWallet(pass) {
  if (GLOBALS.__WALLET_LOADING) {
    return await GLOBALS.__WALLET_LOADING;
  }
  if (GLOBALS.__WALLET_SESSION) {
    if (GLOBALS.__WALLET_RECONNECT) {
      await GLOBALS.__WALLET_RECONNECT;
      return GLOBALS.__WALLET_SESSION;
    }
    const { wallet } = GLOBALS.__WALLET_SESSION;
    const healthy = await isConnectionHealthy($884ce55f1db7e177$export$eaa49f0478d81b9d);
    if (healthy) {
      return GLOBALS.__WALLET_SESSION;
    }
    console.log("[Client] Connection stale. Reconnecting...");
    GLOBALS.__WALLET_RECONNECT = (async () => {
      try {
        const success = await establishConnection($884ce55f1db7e177$export$eaa49f0478d81b9d);
        if (!success) throw new Error("Unable to reach network.");
        console.log("[Client] Resyncing wallet...");
        await wallet.initialize();
      } finally {
        GLOBALS.__WALLET_RECONNECT = null;
      }
    })();
    await GLOBALS.__WALLET_RECONNECT;
    return GLOBALS.__WALLET_SESSION;
  }
  GLOBALS.__WALLET_LOADING = (async () => {
    try {
      const rawB64 = localStorage.getItem(KEY);
      const ivB64 = localStorage.getItem(IV);
      if (!rawB64 || !ivB64) throw new Error("No local wallet. Visit Connect.");
      const raw = atob(rawB64);
      const ivb = atob(ivB64);
      const iv = new Uint8Array([...ivb].map((c) => c.charCodeAt(0)));
      const ct = new Uint8Array([...raw].map((c) => c.charCodeAt(0)));
      const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pass));
      const key = await crypto.subtle.importKey("raw", h, "AES-GCM", false, ["decrypt"]);
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
      const { seed, net } = JSON.parse(new TextDecoder().decode(pt));
      const sdk = await getSdk();
      const WalletCtor = getWalletCtor(sdk);
      const wallet = new WalletCtor(seed, net);
      const connected = await establishConnection($884ce55f1db7e177$export$eaa49f0478d81b9d);
      if (!connected) throw new Error("Could not connect to network.");
      console.log("[Client] Initializing Wallet (Scanning UTXOs)...");
      await wallet.initialize();
      const account = wallet.accountStore.getAccount("2.0");
      if (!account) throw new Error("Account 2.0 missing");
      const address = account.getPrimaryAddressKey().address;
      const nexaMinor = Number(account.balance?.confirmed || 0);
      const kiblMinor = Number(account.tokenBalances?.[KIBL_GROUP_ADDR]?.confirmed || 0);
      GLOBALS.__WALLET_SESSION = {
        wallet,
        account,
        address,
        network: net,
        sdk,
        seed,
        net,
        balances: {
          kiblMinor,
          kibl: kiblMinor / 100,
          nexaMinor,
          nexa: nexaMinor / 100,
          tokenHex: KIBL_TOKEN_HEX,
          tokenGroup: KIBL_GROUP_ADDR
        }
      };
      return GLOBALS.__WALLET_SESSION;
    } finally {
      GLOBALS.__WALLET_LOADING = null;
    }
  })();
  return await GLOBALS.__WALLET_LOADING;
}
async function _buildAndSend({ passphrase, kiblAmount, tokenIdHex, feeNexa }) {
  if (!GLOBALS.__WALLET_SESSION && (!passphrase || passphrase.length < 8)) throw new Error("Password required.");
  const { wallet, account } = await loadWallet(passphrase);
  console.log("[Client] Building...");
  const signedTx = await wallet.newTransaction(account).onNetwork("mainnet").sendToToken(HOUSE_ADDRESS, kiblAmount.toString(), KIBL_TOKEN_ID).populate().sign().build();
  console.log("---------------------------------------------------");
  console.log("[Client] 🔍 DEBUG: Signed Transaction Hex:");
  console.log(signedTx);
  console.log("---------------------------------------------------");
  const txId = await wallet.sendTransaction(signedTx);
  console.log("[Client] Sent:", txId);
  return { txId, house: HOUSE_ADDRESS };
}
async function placeBet(params) {
  try {
    return await _buildAndSend(params);
  } catch (e) {
    const msg = e.message || String(e);
    if (msg.includes("Missing inputs") || msg.includes("-32602") || msg.includes("-32000")) {
      console.warn("⚠️ [Client] State Drift detected (Missing inputs). Force-resyncing...");
      GLOBALS.__WALLET_SESSION = null;
      await loadWallet(params.passphrase);
      console.log("🔄 [Client] Resync complete. Retrying bet...");
      return await _buildAndSend(params);
    }
    throw e;
  }
}
async function recoverSeed(pass) {
  const rawB64 = localStorage.getItem(KEY);
  const ivB64 = localStorage.getItem(IV);
  if (!rawB64 || !ivB64) throw new Error("No wallet found to back up.");
  const raw = atob(rawB64);
  const ivb = atob(ivB64);
  const iv = new Uint8Array([...ivb].map((c) => c.charCodeAt(0)));
  const ct = new Uint8Array([...raw].map((c) => c.charCodeAt(0)));
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pass));
  const key = await crypto.subtle.importKey("raw", h, "AES-GCM", false, ["decrypt"]);
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    const { seed } = JSON.parse(new TextDecoder().decode(pt));
    return seed;
  } catch (e) {
    throw new Error("Incorrect password.");
  }
}
async function sendFunds({ passphrase, toAddress, amountNexa, amountKibl }) {
  const { wallet, account } = await loadWallet(passphrase);
  let tx = wallet.newTransaction(account).onNetwork("mainnet").sendTo(toAddress, amountNexa.toString()).sendToToken(toAddress, amountKibl.toString(), KIBL_TOKEN_ID);
  const signed = await tx.populate().sign().build();
  const txId = await wallet.sendTransaction(signed);
  return txId;
}
export {
  loadWallet,
  placeBet,
  recoverSeed,
  sendFunds
};
//# sourceMappingURL=walletBet.bundle.js.map
