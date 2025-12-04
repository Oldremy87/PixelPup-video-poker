import { B as Buffer$1, p as process$1, n as nodeCrypto } from "./chunks/index-C_zbkbH-.js";
globalThis.Buffer ||= Buffer$1;
globalThis.process ||= process$1;
globalThis.__nodeCrypto = nodeCrypto;
const KEY = "kk_wallet_v1", IV = "kk_wallet_iv_v1";
const KIBL_GROUP_ADDR = "nexa:tpjkhlhuazsgskkt5hyqn3d0e7l6vfvfg97cf42pprntks4x7vqqqcavzypmt";
const KIBL_TOKEN_HEX = "656bfefce8a0885acba5c809c5afcfbfa62589417d84d54108e6bb42a6f30000";
const HOUSE_ADDRESS = "nexa:nqtsq5g5pvucuzm2kh92kqtxy5s3zfutq3xgnhh5src65fc3";
const KIBL_TOKEN_ID = "nexa:tpjkhlhuazsgskkt5hyqn3d0e7l6vfvfg97cf42pprntks4x7vqqqcavzypmt";
async function getSdk() {
  return await import("./chunks/index.web-Does7zZT.js");
}
const PRIVATE_NODE = {
  scheme: "wss",
  host: "node.remy-dev.com",
  // Your Bare Metal NVMe Node
  port: 443
  // Cloudflare Tunnel
};
const PUBLIC_NODE = {
  scheme: "wss",
  host: "electrum.nexa.org",
  // Backup
  port: 20004
};
async function connectMainnet(rostrumProvider) {
  if (rostrumProvider.isConnected) return;
  console.log("[Client] connecting to network...");
  try {
    await rostrumProvider.connect(PRIVATE_NODE);
    console.log("✅ Connected to Private Node");
    return;
  } catch (e) {
    console.warn("⚠️ Private node unreachable, switching to public backup...");
  }
  try {
    await rostrumProvider.connect(PUBLIC_NODE);
    console.log("⚠️ Connected to Public Backup Node");
  } catch (e) {
    console.error("❌ All network nodes failed.");
    throw new Error("Network connection failed. Please refresh.");
  }
}
function getWalletCtor(mod) {
  return mod?.Wallet ?? mod?.default?.Wallet;
}
async function loadWallet(pass) {
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
  const { rostrumProvider } = sdk;
  await connectMainnet(rostrumProvider);
  const WalletCtor = getWalletCtor(sdk);
  if (!WalletCtor) throw new Error("Wallet export missing");
  const wallet = new WalletCtor(seed, net);
  await wallet.initialize();
  const account = wallet.accountStore.getAccount("2.0");
  if (!account) throw new Error("DApp account (2.0) not found.");
  const address = account.getPrimaryAddressKey().address;
  const nexaMinor = Number(account.balance?.confirmed || 0);
  const kiblMinor = Number(account.tokenBalances?.[KIBL_GROUP_ADDR]?.confirmed || 0);
  const DEC = 2;
  const balances = {
    kiblMinor,
    kibl: kiblMinor / 10 ** DEC,
    nexaMinor,
    nexa: nexaMinor / 10 ** DEC,
    tokenHex: KIBL_TOKEN_HEX,
    tokenGroup: KIBL_GROUP_ADDR
  };
  return { wallet, account, address, network: net, balances };
}
async function placeBet({
  passphrase,
  kiblAmount,
  tokenIdHex,
  feeNexa
}) {
  if (!passphrase || passphrase.length < 8) throw new Error("Password required (8+ chars).");
  console.log("[Client] Loading wallet...");
  const { wallet, account, address, network } = await loadWallet(passphrase);
  console.log("[Client] Building Transaction locally...");
  const signedTx = await wallet.newTransaction(account).onNetwork("mainnet").sendTo(HOUSE_ADDRESS, feeNexa.toString()).sendToToken(HOUSE_ADDRESS, kiblAmount.toString(), KIBL_TOKEN_ID).populate().sign().build();
  console.log("[Client] Broadcasting via Tunnel...");
  const txId = await wallet.sendTransaction(signedTx);
  console.log("[Client] Bet Sent! TxId:", txId);
  return { txId, network, address, house: HOUSE_ADDRESS };
}
export {
  loadWallet,
  placeBet
};
//# sourceMappingURL=walletBet.bundle.js.map
