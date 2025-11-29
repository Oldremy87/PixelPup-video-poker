#!/usr/bin/env node

/**
 * Simple CLI Wallet for testing WalletComms integration
 *
 * Usage:
 *   node wallet-cli.js <pairing-uri>
 *
 * Example:
 *   node wallet-cli.js "wl:1@wss://relay.otoplo.com?session=abc&secret=123"
 */

const { WalletCommsIntegration, Wallet, rostrumProvider } = require('../dist/index.cjs');
const {UnitUtils, GroupToken, Address, AddressType} = require("libnexa-ts");

/**
 * Get token permissions from token amount
 */
function getTokenPermissions(amount) {
  if (amount > 0) {
    return []
  }

  const flags = BigInt.asUintN(64, BigInt(amount))
  const permissions = []

  if (GroupToken.isAuthority(flags)) {
    permissions.push('AUTHORITY')
  }

  if (GroupToken.allowsRenew(flags)) {
    permissions.push('BATON')
  }
  if (GroupToken.allowsMint(flags)) {
    permissions.push('MINT')
  }
  if (GroupToken.allowsMelt(flags)) {
    permissions.push('MELT')
  }
  if (GroupToken.allowsRescript(flags)) {
    permissions.push('RESCRIPT')
  }
  if (GroupToken.allowsSubgroup(flags)) {
    permissions.push('SUBGROUP')
  }

  return permissions
}


/**
 * Format address for display (show first 10 and last 6 characters)
 */
function formatAddress(address) {
    if (address.length <= 20) return address;
    return address.substring(0, 10) + '...' + address.substring(address.length - 6);
}

/**
 * Display wallet balance and token balances
 */
async function displayBalances(wallet) {
    try {
        const defaultAccount = wallet.accountStore.getAccount('2.0');
        if (!defaultAccount) return;

        // Load fresh balances from the network
        await defaultAccount.loadBalances();

        console.log('\n💰 WALLET BALANCES');
        console.log('==================');

        // Get NEXA balance from account
        const nexaBalance = defaultAccount.balance;
        console.log(`NEXA Balance: ${UnitUtils.formatNEXA(nexaBalance.confirmed)} NEXA`);

        if (nexaBalance.unconfirmed > 0) {
            console.log(`Unconfirmed: ${UnitUtils.formatNEXA(nexaBalance.unconfirmed)} NEXA`);
        }

        // Get token balances from account
        const tokenBalances = defaultAccount.tokenBalances;

        if (tokenBalances && Object.keys(tokenBalances).length > 0) {
            console.log('\n🪙 Token Balances:');
            for (const [tokenIdHex, amount] of Object.entries(tokenBalances)) {
                try {
                    // Convert token ID hex to address
                    const tokenAddress = Address.fromObject({
                        data: tokenIdHex,
                        network: wallet.network,
                        type: AddressType.GroupIdAddress
                    });

                    const permissions = getTokenPermissions(amount.confirmed);
                    if (permissions.length > 0) {
                        console.log(`  → ${tokenAddress.toString()}: Authority [${permissions.join(', ')}]`);
                    } else {
                        console.log(`  → ${tokenAddress.toString()}: ${amount.confirmed}`);
                    }
                } catch (error) {
                    console.log(error);
                    // Fallback to hex if address conversion fails
                    console.log(`  → ${tokenIdHex}: ${amount.confirmed} (address conversion failed)`);
                }
            }
        } else {
            console.log('\n🪙 No token balances found');
        }

        console.log('');

    } catch (error) {
        console.error('Failed to fetch balances:', error.message);
    }
}

/**
 * Raw input using process.stdin
 */
function askQuestion(question) {
    return new Promise((resolve) => {
        process.stdout.write(question);
        process.stdin.setRawMode(false);
        process.stdin.setEncoding('utf8');

        const onData = (input) => {
            process.stdin.removeListener('data', onData);
            resolve(input.toString().trim());
        };

        process.stdin.once('data', onData);
        process.stdin.resume();
    });
}

/**
 * Prompt user for yes/no input
 */
async function promptYesNo(question) {
    const answer = await askQuestion(question + ' (y/N): ');
    return answer && answer.toLowerCase().startsWith('y');
}

/**
 * Create CLI approval callbacks with wallet reference for balance display
 */
function createCliApprovalCallbacks(wallet) {
    return {
    /**
     * Request approval for dApp connection
     */
    async approveConnection(dAppInfo) {
        console.log('\n🔗 CONNECTION REQUEST');
        console.log('=====================');
        console.log(`dApp Name: ${dAppInfo.name}`);
        console.log(`URL: ${dAppInfo.url}`);
        if (dAppInfo.description) {
            console.log(`Description: ${dAppInfo.description}`);
        }
        console.log('');

        return await promptYesNo('Do you want to connect to this dApp?');
    },

    /**
     * Request approval for message signing
     */
    async approveMessage(details) {
        console.log('\n✍️  MESSAGE SIGNING REQUEST');
        console.log('===========================');
        console.log(`dApp: ${details.dApp.name}`);
        console.log(`Account: ${formatAddress(details.account)}`);
        console.log(`Message: "${details.messagePreview}"`);
        console.log('');

        return await promptYesNo('Do you want to sign this message?');
    },

    /**
     * Request approval for transaction signing
     */
    async approveTransaction(details) {
        console.log('\n📝 TRANSACTION SIGNING REQUEST');
        console.log('==============================');
        console.log(`dApp: ${details.dApp.name}`);
        console.log(`Account: ${formatAddress(details.account)}`);
        console.log(`Transaction Hex: ${details.transactionHex.substring(0, 60)}...`);

        if (details.totalAmount !== 'Unknown') {
            console.log(`Amount: ${UnitUtils.formatNEXA(details.totalAmount)}`);
        }
        if (details.fees !== 'Unknown') {
            console.log(`Fees: ${UnitUtils.formatNEXA(details.fees)}`);
        }
        if (details.opReturn) {
            console.log(`OP_RETURN: "${details.opReturn}"`);
        }

        // Display token outputs if present
        if (details.tokenOutputs && details.tokenOutputs.length > 0) {
            console.log('\n🪙 Token Outputs:');
            const uniqueTokens = new Map();

            // Group outputs by token ID and sum amounts
            for (const tokenOutput of details.tokenOutputs) {
                const current = uniqueTokens.get(tokenOutput.tokenId) || BigInt(0);
                uniqueTokens.set(tokenOutput.tokenId, current + BigInt(tokenOutput.amount));
            }

            // Display summary
            for (const [tokenId, totalAmount] of uniqueTokens) {
                const permissions = getTokenPermissions(totalAmount);
                if (permissions.length > 0) {
                    console.log(`  → ${tokenId}: Authority [${permissions.join(', ')}]`);
                } else {
                    console.log(`  → ${tokenId}: ${totalAmount.toString()}`);
                }
            }

            // Show individual outputs if there are multiple for the same token
            if (details.tokenOutputs.length > uniqueTokens.size) {
                console.log('\n  Detailed outputs:');
                details.tokenOutputs.forEach((output, index) => {
                    const permissions = getTokenPermissions(output.amount);
                    if (permissions.length > 0) {
                        console.log(`    Output ${index + 1}: Authority [${permissions.join(', ')}] of ${output.tokenId}`);
                    } else {
                        console.log(`    Output ${index + 1}: ${output.amount} of ${output.tokenId}`);
                    }
                });
            }
        }

        // Display sighash specification if present
        if (details.sighashSpec) {
            console.log(`Sighash Spec: Custom signing requested`);
            // You could add more detailed display of the spec here if needed
        }

        console.log(`Will broadcast: ${details.broadcast ? 'Yes' : 'No'}`);
        console.log('');

        const approved = await promptYesNo('Do you want to sign this transaction?');

        // Show updated balances after transaction if approved and broadcast
        if (approved) {
            console.log('\n⏳ Transaction signed and broadcast, updating balances...');
            // Wait a bit for the transaction to propagate
            await new Promise(resolve => setTimeout(resolve, 2000));
            await displayBalances(wallet);
        }

        return approved;
    },

    /**
     * Request approval for sending transaction
     */
    async approveSendTransaction(details) {
        console.log('\n💸 SEND TRANSACTION REQUEST');
        console.log('===========================');
        console.log(`dApp: ${details.dApp.name}`);
        console.log(`From: ${formatAddress(details.fromAccount)}`);
        console.log('Recipients:');

        for (const recipient of details.recipients) {
            console.log(`  → ${formatAddress(recipient.address)}: ${UnitUtils.formatNEXA(recipient.amount)}`);
            if (recipient.token) {
                console.log(`    Token: ${recipient.token}`);
            }
        }

        console.log(`Total Amount: ${UnitUtils.formatNEXA(details.totalAmount)}`);

        if (details.estimatedFees) {
            console.log(`Estimated Fees: ${UnitUtils.formatNEXA(details.estimatedFees)}`);
        }
        if (details.opReturn) {
            console.log(`OP_RETURN: "${details.opReturn}"`);
        }
        console.log('');

        const approved = await promptYesNo('Do you want to send this transaction?');

        // Show updated balances after transaction if approved
        if (approved) {
            console.log('\n⏳ Transaction sent, updating balances...');
            // Wait a bit for the transaction to propagate
            await new Promise(resolve => setTimeout(resolve, 2000));
            await displayBalances(wallet);
        }

        return approved;
    },

    /**
     * Request approval for network switching
     */
    async approveNetworkSwitch(details) {
        console.log('\n🌐 NETWORK SWITCH REQUEST');
        console.log('=========================');
        console.log(`dApp: ${details.dApp.name}`);
        console.log(`Current Network: ${details.currentNetwork}`);
        console.log(`Requested Network: ${details.requestedNetwork}`);
        console.log('');

        return await promptYesNo(`Do you want to switch to ${details.requestedNetwork}?`);
    },

    /**
     * Request approval for adding token
     */
    async approveAddToken(details) {
        console.log('\n🪙 ADD TOKEN REQUEST');
        console.log('===================');
        console.log(`dApp: ${details.dApp.name}`);
        console.log(`Account: ${formatAddress(details.account)}`);
        console.log(`Token ID: ${details.tokenId}`);

        if (details.tokenInfo) {
            if (details.tokenInfo.name) console.log(`Token Name: ${details.tokenInfo.name}`);
            if (details.tokenInfo.symbol) console.log(`Token Symbol: ${details.tokenInfo.symbol}`);
            if (details.tokenInfo.decimals !== undefined) console.log(`Decimals: ${details.tokenInfo.decimals}`);
        }
        console.log('');

        return await promptYesNo('Do you want to add this token to your wallet?');
    }
    };
}

async function connectToDApp(walletComms, pairingURI) {
    try {
        console.log('\n🔗 Connecting to dApp...');
        const dAppInfo = await walletComms.connect(pairingURI);

        console.log('✅ Connected to dApp!');
        console.log(`   Name: ${dAppInfo.name}`);
        console.log(`   URL: ${dAppInfo.url}`);
        console.log(`   Description: ${dAppInfo.description || 'No description'}`);
        console.log('\n📊 Wallet is now ready to receive requests from the dApp');
        console.log('   Commands: type "disconnect" to disconnect, "reconnect" for new pairing URI, Ctrl+C to exit\n');

        return true;
    } catch (error) {
        console.error('\n❌ Connection failed:', error.message);
        console.error('Make sure:');
        console.error('1. The pairing URI is valid and not expired');
        console.error('2. The dApp is still waiting for connection');
        console.error('3. You have network connectivity\n');
        return false;
    }
}

async function promptForPairingURI() {
    return await askQuestion('📱 Enter the pairing URI from the dApp (or "exit" to quit):\n> ');
}

async function promptForCommand() {
    return await askQuestion('> ');
}

/**
 * Prompt for seedphrase or generate a new one
 */
async function promptForSeedphrase() {
    console.log('🔐 Enter your 12-word seedphrase (or press Enter to generate a new wallet):');
    console.log('   Note: Input is visible for security reasons in this CLI demo');
    const seedphrase = await askQuestion('> ');
    
    // If empty, generate a new wallet using the SDK's create method
    if (!seedphrase.trim()) {
        console.log('\n🎲 Generating new wallet...');
        const newWallet = Wallet.create();
        const walletData = newWallet.export();
        const newSeedphrase = walletData.phrase;
        
        console.log('\n✨ New wallet generated!');
        console.log('📝 IMPORTANT: Save this seedphrase to recover your wallet:');
        console.log(`\n   ${newSeedphrase}\n`);
        console.log('⚠️  WARNING: This seedphrase will not be shown again!\n');
        
        const confirmed = await promptYesNo('Have you saved your seedphrase?');
        if (!confirmed) {
            console.log('❌ Please save your seedphrase before continuing.');
            process.exit(1);
        }
        
        return newSeedphrase;
    }
    
    // Validate seedphrase has 12 words
    const words = seedphrase.trim().split(/\s+/);
    if (words.length !== 12) {
        console.log(`❌ Invalid seedphrase: expected 12 words, got ${words.length}`);
        process.exit(1);
    }
    
    return seedphrase.trim();
}

async function main() {
    console.log('🚀 Nexa Wallet CLI - WalletComms Integration');
    console.log('=============================================\n');

    let wallet, walletComms;

    try {
        // Step 1: Connect to testnet
        console.log('📡 Connecting to testnet...');
        await rostrumProvider.connect('testnet');
        console.log('✅ Connected to testnet\n');

        // Step 2: Prompt for seedphrase
        const seedphrase = await promptForSeedphrase();

        // Step 3: Initialize wallet (this is the slow part we want to avoid repeating)
        console.log('\n🔑 Initializing wallet...');
        wallet = new Wallet(seedphrase, 'testnet');
        await wallet.initialize();

        console.log('✅ Wallet initialized');
        const defaultAccount = wallet.accountStore.getAccount('2.0');
        if (defaultAccount) {
            const primaryAddress = defaultAccount.getPrimaryAddressKey();
            console.log(`   Address: ${primaryAddress.address}`);
        }

        // Display initial balances
        await displayBalances(wallet);

        // Step 3: Create WalletComms integration with CLI approval callbacks
        const cliApprovalCallbacks = createCliApprovalCallbacks(wallet);
        walletComms = new WalletCommsIntegration(wallet, cliApprovalCallbacks);

        console.log('🔒 Approval system enabled - you will be prompted before any wallet operations\n');

    } catch (error) {
        console.error('\n❌ Wallet initialization failed:', error.message);
        process.exit(1);
    }

    // Main connection loop
    let isConnected = false;

    // Handle initial pairing URI from command line
    let pairingURI = process.argv[2];

    if (pairingURI) {
        isConnected = await connectToDApp(walletComms, pairingURI);
    }

    // Main interactive loop
    while (true) {
        try {
            let input;

            if (!isConnected) {
                // Not connected - ask for pairing URI
                input = await promptForPairingURI();

                if (input.toLowerCase() === 'exit') {
                    break;
                }

                if (input.startsWith('wl:')) {
                    isConnected = await connectToDApp(walletComms, input);
                } else {
                    console.log('❌ Invalid pairing URI. Must start with "wl:"\n');
                }
            } else {
                // Connected - wait for commands
                input = await promptForCommand();

                if (input.toLowerCase() === 'disconnect') {
                    console.log('\n🔌 Disconnecting from dApp...');
                    walletComms.disconnect();
                    isConnected = false;
                    console.log('✅ Disconnected\n');
                } else if (input.toLowerCase() === 'reconnect') {
                    console.log('\n🔌 Disconnecting from current dApp...');
                    walletComms.disconnect();
                    isConnected = false;
                    console.log('✅ Disconnected\n');
                } else if (input.toLowerCase() === 'status') {
                    console.log(`\n📊 Status: ${isConnected ? 'Connected' : 'Disconnected'}`);
                    if (isConnected) {
                        const sessionInfo = walletComms.getSessionInfo();
                        if (sessionInfo) {
                            console.log(`   Session: ${sessionInfo.sessionId}`);
                        }
                    }
                    console.log();
                } else if (input.toLowerCase() === 'balance') {
                    await displayBalances(wallet);
                } else if (input.toLowerCase() === 'help') {
                    console.log('\n📚 Available commands:');
                    console.log('  disconnect  - Disconnect from current dApp');
                    console.log('  reconnect   - Disconnect and connect to new dApp');
                    console.log('  status      - Show connection status');
                    console.log('  balance     - Show wallet balances');
                    console.log('  help        - Show this help message');
                    console.log('  Ctrl+C      - Exit the CLI\n');
                } else if (input.trim()) {
                    console.log('❌ Unknown command. Type "help" for available commands\n');
                }
            }
        } catch (error) {
            console.error('\n❌ Error:', error.message);
            if (isConnected) {
                console.log('Connection may have been lost. Type "reconnect" to try again\n');
                isConnected = false;
            }
        }
    }

    // Cleanup and exit
    console.log('\n🔌 Disconnecting...');
    if (walletComms) {
        walletComms.disconnect();
    }
    if (rostrumProvider) {
        await rostrumProvider.disconnect();
    }
    process.exit(0);
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n\n🔌 Shutting down...');
    process.exit(0);
});

// Run the CLI
main().catch(console.error);
