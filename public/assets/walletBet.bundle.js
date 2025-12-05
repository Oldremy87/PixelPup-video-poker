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
const PRIVATE_NODE = { scheme: "wss", host: "node.remy-dev.com", port: 443 };
const PUBLIC_NODE = { scheme: "wss", host: "electrum.nexa.org", port: 20004 };
let cachedSession = null;
let reconnectLock = null;
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
    await rostrumProvider2.connect(PRIVATE_NODE);
    if (await isConnectionHealthy(rostrumProvider2)) {
      console.log("✅ Connected: Private Node");
      return true;
    }
  } catch (e) {
    console.warn("⚠️ Private node unreachable, trying public...");
  }
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
  if (cachedSession) {
    if (reconnectLock) {
      await reconnectLock;
      return cachedSession;
    }
    const { wallet: wallet2 } = cachedSession;
    const healthy = await isConnectionHealthy($884ce55f1db7e177$export$eaa49f0478d81b9d);
    if (healthy) {
      return cachedSession;
    }
    console.log("[Client] Connection stale. Reconnecting...");
    reconnectLock = (async () => {
      try {
        const success = await establishConnection($884ce55f1db7e177$export$eaa49f0478d81b9d);
        if (!success) throw new Error("Unable to reach network.");
        console.log("[Client] Resyncing wallet...");
        await wallet2.initialize();
      } finally {
        reconnectLock = null;
      }
    })();
    await reconnectLock;
    return cachedSession;
  }
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
  wallet.rostrumProvider || wallet.provider;
  const connected = await establishConnection($884ce55f1db7e177$export$eaa49f0478d81b9d);
  if (!connected) throw new Error("Could not connect to network.");
  console.log("[Client] Initializing Wallet (Scanning UTXOs)...");
  await wallet.initialize();
  const account = wallet.accountStore.getAccount("2.0");
  if (!account) throw new Error("Account 2.0 missing");
  const address = account.getPrimaryAddressKey().address;
  const nexaMinor = Number(account.balance?.confirmed || 0);
  const kiblMinor = Number(account.tokenBalances?.[KIBL_GROUP_ADDR]?.confirmed || 0);
  const DEC = 2;
  cachedSession = {
    wallet,
    account,
    address,
    network: net,
    sdk,
    seed,
    net,
    balances: {
      kiblMinor,
      kibl: kiblMinor / 10 ** DEC,
      nexaMinor,
      nexa: nexaMinor / 10 ** DEC,
      tokenHex: KIBL_TOKEN_HEX,
      tokenGroup: KIBL_GROUP_ADDR
    }
  };
  return cachedSession;
}
async function placeBet({ passphrase, kiblAmount, tokenIdHex, feeNexa }) {
  if (!cachedSession && (!passphrase || passphrase.length < 8)) throw new Error("Password required.");
  const { wallet, account } = await loadWallet(passphrase);
  console.log("[Client] Building...");
  const signedTx = await wallet.newTransaction(account).onNetwork("mainnet").sendTo(HOUSE_ADDRESS, feeNexa.toString()).sendToToken(HOUSE_ADDRESS, kiblAmount.toString(), KIBL_TOKEN_ID).populate().sign().build();
  const txId = await wallet.sendTransaction(signedTx);
  console.log("[Client] Sent:", txId);
  return { txId, house: HOUSE_ADDRESS };
}
export {
  loadWallet,
  placeBet
};
//# sourceMappingURL=walletBet.bundle.js.map
