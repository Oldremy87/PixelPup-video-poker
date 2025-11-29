import { B as Buffer$1, p as process$1, n as nodeCrypto } from "./chunks/index-C_zbkbH-.js";
globalThis.Buffer = Buffer$1;
globalThis.process = process$1;
globalThis.__nodeCrypto = nodeCrypto;
const KEY = "kk_wallet_v1";
const IV = "kk_wallet_iv_v1";
async function sdk() {
  return await import("./chunks/index.web-Does7zZT.js");
}
const MAINNET = {
  scheme: "wss",
  host: "electrum.nexa.org",
  port: 20004
};
async function connectMainnet(rostrumProvider) {
  if (globalThis.__kk_rostrum_mainnet_ok) return;
  await rostrumProvider.connect(MAINNET);
  globalThis.__kk_rostrum_mainnet_ok = true;
}
async function ensureCsrf() {
  if (window.csrfToken) return window.csrfToken;
  const r = await fetch("/api/csrf", { credentials: "include" });
  if (!r.ok) throw new Error(`CSRF fetch failed: ${r.status}`);
  const { csrfToken } = await r.json();
  window.csrfToken = csrfToken;
  return csrfToken;
}
async function postJSON(url, body) {
  const csrf = await ensureCsrf();
  const r = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json", "CSRF-Token": csrf },
    body: JSON.stringify(body)
  });
  let j = null;
  try {
    j = await r.json();
  } catch {
  }
  if (!r.ok || j && j.ok === false) {
    throw new Error(j?.error || `HTTP ${r.status}`);
  }
  return j;
}
function normalizeSeed(raw) {
  return (raw || "").toLowerCase().replace(/[^a-z\s]/g, " ").split(/\s+/).filter(Boolean).join(" ");
}
function require12Words(seed) {
  const words = seed.split(" ");
  if (words.length !== 12) throw new Error(`Seed must be 12 words (got ${words.length}).`);
  return seed;
}
async function aesKey(pass) {
  const raw = new TextEncoder().encode(pass);
  const h = await crypto.subtle.digest("SHA-256", raw);
  return crypto.subtle.importKey("raw", h, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function enc(pass, data) {
  if (!pass || pass.length < 8) throw new Error("Password must be 8+ chars.");
  const key = await aesKey(pass);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(data));
  localStorage.setItem(IV, btoa(String.fromCharCode(...iv)));
  localStorage.setItem(KEY, btoa(String.fromCharCode(...new Uint8Array(ct))));
  localStorage.setItem("kk_has_pass", "1");
}
async function init() {
  document.getElementById("net");
  const passEl = document.getElementById("pass");
  const pass2El = document.getElementById("pass2");
  const btnCreate = document.getElementById("btnCreate");
  const btnImport = document.getElementById("btnImport");
  const importArea = document.getElementById("importArea");
  const seedIn = document.getElementById("seedIn");
  const btnDoImport = document.getElementById("btnDoImport");
  const linked = document.getElementById("linked");
  const addrText = document.getElementById("addr");
  const btnLink = document.getElementById("btnLink");
  const passHint = document.getElementById("passHint");
  const kiblBalanceEl = document.getElementById("kiblBalance");
  let address = null;
  function passOk() {
    const p1 = passEl.value;
    const p2 = pass2El.value;
    const ok = p1.length >= 8 && p1 === p2;
    btnCreate.disabled = !ok;
    btnImport.disabled = !ok;
    passHint.hidden = ok;
  }
  passEl.addEventListener("input", passOk);
  pass2El.addEventListener("input", passOk);
  async function bootFromSeed(seed, net) {
    const { Wallet, rostrumProvider } = await sdk();
    await connectMainnet(rostrumProvider);
    const wallet = new Wallet(seed, net);
    await wallet.initialize();
    const account = wallet.accountStore.getAccount("2.0");
    const k = account.getPrimaryAddressKey();
    const tokenId = process$1.env.KIBL_TOKEN_ID_HEX || "656bfefce8a0885acba5c809c5afcfbfa62589417d84d54108e6bb42a6f30000";
    const kiblBal = account.tokenBalances[tokenId]?.confirmed || 0;
    if (kiblBalanceEl) kiblBalanceEl.textContent = `Balance: ${(Number(kiblBal) / 100).toFixed(2)} KIBL`;
    return { address: k.address };
  }
  btnCreate.addEventListener("click", async () => {
    try {
      const pass = passEl.value;
      const net = "mainnet";
      const { Wallet } = await sdk();
      const w = Wallet.create();
      const seed = w.export().phrase;
      await enc(pass, JSON.stringify({ seed, net }));
      const r = await bootFromSeed(seed, net);
      address = r.address;
      addrText.textContent = `Address: ${address}`;
      linked.hidden = false;
      importArea.hidden = false;
      seedIn.value = seed;
      alert("Wallet Created! \n\nIMPORTANT: Your seed phrase is shown in the box below. Write it down now. It will disappear when you leave this page.");
    } catch (e) {
      alert(e.message || "Create failed");
    }
  });
  btnImport.addEventListener("click", () => {
    importArea.hidden = !importArea.hidden;
  });
  btnDoImport.addEventListener("click", async () => {
    try {
      const pass = passEl.value;
      const net = "mainnet";
      const seed = require12Words(normalizeSeed(seedIn.value));
      await enc(pass, JSON.stringify({ seed, net }));
      const r = await bootFromSeed(seed, net);
      address = r.address;
      addrText.textContent = `Address: ${address}`;
      linked.hidden = false;
      alert("Wallet Imported & Encrypted!");
    } catch (e) {
      alert(e.message || "Import failed");
    }
  });
  btnLink.addEventListener("click", async () => {
    try {
      if (!address) return alert("No address loaded.");
      await postJSON("/api/wallet/link", { address, network: "mainnet" });
      alert("Wallet Linked Successfully!");
      window.location.href = "/play.html";
    } catch (e) {
      alert("Link failed: " + e.message);
    }
  });
  if (localStorage.getItem(KEY)) {
    passEl.placeholder = "Enter password to unlock existing wallet";
  }
  ensureCsrf();
}
addEventListener("DOMContentLoaded", init);
//# sourceMappingURL=connect.bundle.js.map
