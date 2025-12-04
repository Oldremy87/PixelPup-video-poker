export async function initOnboarding(gameType = null) {
  // 1. Get Wallet Status
  let wallet = null;
  try {
    const r = await fetch('/api/wallet/status');
    const j = await r.json();
    if (j.ok && j.linked) wallet = j;
  } catch {}

  // 2. Check Balances if linked
  let hasFunds = false;
  if (wallet) {
    try {
      const r = await fetch(`/api/wallet/balance?address=${wallet.address}`);
      const b = await r.json();
      // Assume "Funded" if > 100 KIBL (min bet)
      if (b.ok && Number(b.kibl) >= 100) hasFunds = true;
    } catch {}
  }

  // 3. Determine Context
  const isIndex = !gameType; // If no gameType passed, we are on Home
  const LS_KEY = `kk_seen_${gameType || 'beta_intro'}_v2`; 
  const hasSeen = localStorage.getItem(LS_KEY) === '1';

  // --- LOGIC TREE ---

  // SCENARIO A: Index Page (Welcome)
  if (isIndex) {
    if (!hasSeen) {
      showModal({
        title: '🎄 Welcome to Christmas Beta',
        body: `
          <p>We've upgraded the Arcade! Here is what is new:</p>
          <ul>
            <li><strong>Wallet Connect:</strong> Link your wallet once. Play for 15 minutes without signing every hand, </li>
            <li>unlock wallet with password to play for another 15 minutes.</li>
            <li><strong>Auto-Payouts:</strong> Winnings go directly to your wallet via Claim, no need to enter your address.</li>
            <li><strong>Achievements:</strong> Earn badges and bonus KIBL for winning streaks.</li>
          </ul>
          <p>Ready to start? Link your wallet to get a session key.</p>
        `,
        btnText: 'Connect Wallet',
        btnAction: () => window.location.href = '/connect.html',
        secondaryText: 'Just looking',
        onClose: () => localStorage.setItem(LS_KEY, '1')
      });
    }
    return;
  }

  // SCENARIO B: Game Page (Poker/BJ) - NOT LINKED
  if (!wallet) {
    showModal({
      title: '⚠️ Wallet Not Connected',
      body: `
        <p>To play the Christmas Beta, you must link a Nexa wallet.</p>
        <p>This creates a secure <strong>Session Key</strong> so you can bet fast without popups on every hand.</p>
        <p>You can import an Otoplo or Wally wallet seed phrase, or create a wallet and save your seed to import to Otoplo or Wally"
      `,
      btnText: 'Connect Now',
      btnAction: () => window.location.href = '/connect.html'
    });
    return; // Stop here, don't show game rules yet
  }

  // SCENARIO C: Game Page - LINKED BUT EMPTY (Needs Funding)
  if (!hasFunds) {
    showModal({
      title: '⬇️ Deposit to Play',
      body: `
        <p>Your wallet is linked, but you need <strong>KIBL</strong> to bet.</p>
        <p>Send KIBL (plus a tiny bit of NEXA for fees) to your session address:</p>
        <div class="address-box" onclick="navigator.clipboard.writeText(this.innerText); alert('Copied!');">
          ${wallet.address}
        </div>
        <p style="font-size:0.85em">Refresh this page after sending. Your funds stay in your wallet (we just have permission to sign bets).</p>
      `,
      btnText: 'I Sent It (Refresh)',
      btnAction: () => window.location.reload()
    });
    return;
  }

  // SCENARIO D: Game Page - READY (Show Rules if not seen)
  if (!hasSeen) {
    const rules = gameType === 'poker' 
      ? `
        <p><strong>Video Poker Rules:</strong></p>
        <ul>
          <li><strong>Jacks or Better:</strong> Pair of Jacks is the minimum win.</li>
          <li><strong>One Draw:</strong> Tap cards to HOLD, then draw replacement cards.</li>
          <li><strong>Royal Flush:</strong> Pays 250x!</li>
        </ul>
        <p>Winnings are paid <strong></strong> to your wallet via Claim.</p>
      `
      : `
        <p><strong>Blackjack Rules:</strong></p>
        <ul>
          <li><strong>Goal:</strong> Beat the dealer without going over 21.</li>
          <li><strong>Payouts:</strong> 3:2 for Blackjack. Dealer stands on Soft 17.</li>
          <li><strong>Controls:</strong> Hit, Stand, Double, and Split are supported.</li>
        </ul>
        <p>Winnings are paid <strong></strong> to your wallet via FeedMe.</p>
      `;

    showModal({
      title: `How to Play ${gameType === 'poker' ? 'Poker' : 'Blackjack'}`,
      body: rules,
      btnText: 'Let\'s Play!',
      onClose: () => localStorage.setItem(LS_KEY, '1')
    });
  }
}

// Internal Helper to Render Modal
function showModal({ title, body, btnText, btnAction, secondaryText, onClose }) {
  // Remove existing
  const old = document.getElementById('smartModal');
  if (old) old.remove();

  const html = `
    <div id="smartModal" class="smart-modal active">
      <div class="smart-modal-card">
        <div class="smart-modal-header">
          <h2>${title}</h2>
          <button class="smart-modal-close" onclick="closeSmartModal()">×</button>
        </div>
        <div class="smart-modal-body">${body}</div>
        <div class="smart-modal-footer">
          ${secondaryText ? `<button class="btn btn-ghost" onclick="closeSmartModal()">${secondaryText}</button>` : ''}
          <button id="smartBtn" class="btn btn-primary">${btnText || 'Okay'}</button>
        </div>
      </div>
    </div>
  `;
  document.body.insertAdjacentHTML('beforeend', html);

  // Bind events
  window.closeSmartModal = () => {
    document.getElementById('smartModal').classList.remove('active');
    if (onClose) onClose();
  };

  document.getElementById('smartBtn').onclick = () => {
    if (btnAction) btnAction();
    else window.closeSmartModal();
  };
}