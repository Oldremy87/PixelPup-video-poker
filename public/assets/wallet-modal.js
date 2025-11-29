import { loadWallet } from '/assets/walletBet.bundle.js';

let _cachedPass = null;
let _unlockTime = 0;
const SESSION_DURATION = 15 * 60 * 1000; // 15 minutes

export async function getSigner() {
  // 1. Return cached password if session is valid
  if (_cachedPass && (Date.now() - _unlockTime < SESSION_DURATION)) {
    return _cachedPass;
  }

  // 2. Otherwise, open the modal
  _cachedPass = null;
  return new Promise((resolve, reject) => {
    showModal(async (pass) => {
      if (!pass) return reject(new Error('Cancelled'));
      try {
        // Verify password by attempting a load
        // This checks if the password decrypts the local storage key
        await loadWallet(pass);
        _cachedPass = pass;
        _unlockTime = Date.now();
        resolve(pass);
      } catch (e) {
        alert('Incorrect password or wallet not found. Please create/import a wallet first.');
        // If wallet is missing, redirect to connect
        if (e.message.includes('No local wallet')) {
            window.location.href = '/connect.html';
        }
        reject(new Error('Auth failed'));
      }
    });
  });
}

function showModal(callback) {
  // Remove existing if any
  const old = document.getElementById('kk-wallet-modal');
  if (old) old.remove();

  const div = document.createElement('div');
  div.id = 'kk-wallet-modal';
  div.innerHTML = `
    <style>
      #kk-wallet-modal { 
        position: fixed; inset: 0; 
        background: rgba(11, 15, 25, 0.9); 
        backdrop-filter: blur(5px);
        z-index: 10000; 
        display: flex; align-items: center; justify-content: center; 
      }
      .kk-modal-box { 
        background: #111827; 
        border: 1px solid #3af5d9; 
        padding: 24px; 
        border-radius: 16px; 
        width: 100%; max-width: 320px; 
        text-align: center; 
        box-shadow: 0 0 30px rgba(58,245,217,0.15); 
        animation: fadeIn 0.2s ease-out;
      }
      .kk-modal-box h3 { margin: 0 0 12px; color: #00ffc6; font-family: system-ui, sans-serif; font-size: 1.2rem; }
      .kk-modal-box input { 
        width: 100%; padding: 12px; margin-bottom: 16px; 
        background: #05070d; border: 1px solid rgba(58,245,217,0.3); 
        color: #fff; border-radius: 8px; font-size: 16px; outline: none;
      }
      .kk-modal-box input:focus { border-color: #ffcc00; }
      .kk-modal-btn { 
        width: 100%; padding: 12px; 
        background: #ffcc00; color: #000; 
        border: none; border-radius: 8px; 
        font-weight: 700; cursor: pointer; font-size: 14px; 
        transition: transform 0.1s;
      }
      .kk-modal-btn:hover { transform: scale(1.02); }
      .kk-modal-close { 
        margin-top: 16px; background: none; border: none; 
        color: #7fffe6; cursor: pointer; font-size: 13px; text-decoration: underline; 
      }
      @keyframes fadeIn { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
    </style>
    <div class="kk-modal-box">
      <h3>Unlock Session</h3>
      <p style="font-size:13px; color:#7fffe6; margin-bottom:16px; line-height:1.4;">
        Enter your wallet password to enable betting for 15 minutes.
      </p>
      <input type="password" id="kk-wallet-pass" placeholder="Password" autofocus>
      <button id="kk-wallet-confirm" class="kk-modal-btn">Unlock</button>
      <button id="kk-wallet-cancel" class="kk-modal-close">Cancel</button>
    </div>
  `;
  document.body.appendChild(div);

  const inp = document.getElementById('kk-wallet-pass');
  const btn = document.getElementById('kk-wallet-confirm');
  const close = document.getElementById('kk-wallet-cancel');

  const finish = (val) => {
    div.remove();
    callback(val);
  };

  const onEnter = (e) => { if(e.key === 'Enter') finish(inp.value); };
  const onBtn = () => finish(inp.value);
  const onCancel = () => finish(null);

  btn.addEventListener('click', onBtn);
  close.addEventListener('click', onCancel);
  inp.addEventListener('keydown', onEnter);
  inp.focus();
}
