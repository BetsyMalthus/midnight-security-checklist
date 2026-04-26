# Security Checklist for Midnight dApps Before Deployment

*A comprehensive guide to auditing, testing, and hardening your Midnight decentralized application before mainnet deployment.*

---

## Table of Contents

1. [Introduction](#introduction)
2. [The Midnight Security Mindset](#the-midnight-security-mindset)
3. [Pre-Deployment Checklist](#pre-deployment-checklist)
4. [Step 1: `disclose()` Audit — No Secret Leaks](#step-1-disclose-audit--no-secret-leaks)
5. [Step 2: `ownPublicKey()` Usage Review — The Known Vulnerability](#step-2-ownpublickey-usage-review--the-known-vulnerability)
6. [Step 3: Replay Protection Verification — Nonces & Nullifiers](#step-3-replay-protection-verification--nonces--nullifiers)
7. [Step 4: Exported Ledger Field Review](#step-4-exported-ledger-field-review)
8. [Step 5: Witness Implementation Correctness](#step-5-witness-implementation-correctness)
9. [Step 6: Version Compatibility Confirmation](#step-6-version-compatibility-confirmation)
10. [Step 7: Proof Generation Testing on Testnet](#step-7-proof-generation-testing-on-testnet)
11. [Putting It All Together: A CI Pipeline Approach](#putting-it-all-together-a-ci-pipeline-approach)
12. [Common Attack Vectors and Mitigations](#common-attack-vectors-and-mitigations)
13. [Conclusion](#conclusion)

---

## Introduction

Deploying a Midnight dApp is not like deploying a standard smart contract. Midnight's **dual-ledger architecture** — combining a public ledger with shielded state managed through zero-knowledge proofs — introduces a fundamentally different security model. A bug that would be a minor inconvenience on Ethereum can become a catastrophic privacy leak on Midnight.

This guide provides a **durable, repeatable checklist** that any developer can run through before deploying their Midnight dApp to mainnet. Each step includes concrete code examples, common pitfalls, and verification techniques.

By the end of this tutorial, you will be able to systematically audit your Compact contracts, verify witness implementations, test proof generation, and confirm that your dApp is secure and production-ready.

---

## The Midnight Security Mindset

Before diving into the specific checklist items, it's important to understand the security paradigm shift that Midnight introduces:

| Traditional Smart Contract | Midnight Compact Contract |
|---|---|
| All state is publicly visible | State can be shielded (private) |
| Access control via `require()` | Access control via ZK circuit verification |
| No privacy leaks possible (everything is public) | Privacy leaks via `disclose()` are the #1 risk |
| Replay protection via nonces | Nullifier-based replay protection |
| Single ledger state | Dual ledger (public + shielded) |
| Upgrade via proxy patterns | Version-sensitive serialization |

The single most important rule: **In Midnight, privacy is not the default — it must be consciously preserved.** Every `disclose()` call, every exported ledger field, and every witness implementation is a potential privacy leak.

---

## Pre-Deployment Checklist

Here is the **7-point checklist** every Midnight developer should run before deployment:

- [ ] **Step 1**: `disclose()` Audit — No Secret Leaks
- [ ] **Step 2**: `ownPublicKey()` Usage Review — The Known Vulnerability
- [ ] **Step 3**: Replay Protection — Nonces or Nullifiers Present?
- [ ] **Step 4**: Exported Ledger Fields — No Accidental Exposure
- [ ] **Step 5**: Witness Implementations — Correct and Complete
- [ ] **Step 6**: Version Compatibility — SDK, Compact, and Network Match
- [ ] **Step 7**: Proof Generation — Tested on Testnet

We'll walk through each step in detail.

---

## Step 1: `disclose()` Audit — No Secret Leaks

### Why It Matters

`disclose()` is the mechanism by which shielded state is selectively revealed. Used correctly, it enables compliance, auditability, and user-controlled transparency. Used incorrectly, it can expose **all** shielded state to the public ledger.

### What to Check

**1.1 — Audit every `disclose()` call in your contract**

Go through each `disclose()` invocation and verify that only the intended fields are revealed. A common mistake is calling `disclose()` with a broad set of fields during development and forgetting to narrow it down for production.

```compact
// ❌ DANGEROUS: Discloses ALL shielded state
function dangerousDisclose() {
    disclose(allShieldedFields);
}

// ✅ SAFE: Only discloses the minimum required
function safeDisclose(address owner) {
    disclose(owner.balance, owner.auditNonce);
}
```

**1.2 — Check for conditional disclosure paths**

Ensure that disclosure only happens under the correct conditions:

```compact
// ❌ DANGEROUS: Disclosure without access control
function auditDisclose(address target) {
    disclose(target.balance, target.transactionHistory);
}

// ✅ SAFE: Only the owner or an authorized auditor can trigger disclosure
function auditDisclose(address target) {
    verify(self.role == Role.Auditor || self == target);
    disclose(target.balance, target.transactionHistory);
}
```

**1.3 — Verify that `disclose()` is never called in view/pure functions**

`disclose()` should only appear in state-modifying functions. A `disclose()` in a view function suggests logic that should be restructured.

### Verification Script

```typescript
import { DiscloseAuditor } from '@midnight/disclose-auditor';

const auditor = new DiscloseAuditor('./contracts');
const result = await auditor.audit();

result.forEach(violation => {
    console.warn(`⚠️  Potential disclosure in ${violation.file}:${violation.line}`);
    console.warn(`   Fields disclosed: ${violation.fields.join(', ')}`);
    console.warn(`   Suggestion: ${violation.suggestion}`);
});

console.log(`✅ Audit complete: ${result.length} disclosure(s) found.`);
```

---

## Step 2: `ownPublicKey()` Usage Review — The Known Vulnerability

### Why It Matters

`ownPublicKey()` is a known vulnerability surface in Midnight. It returns the calling contract's own public key, which can be used to derive the contract's identity on the public ledger. If this value is accidentally disclosed or used in an unshielded context, it can deanonymize the contract.

### What to Check

**2.1 — Review every `ownPublicKey()` call**

```compact
// ❌ DANGEROUS: Using ownPublicKey() in a disclosed context
function registerPublic() {
    disclose(ownPublicKey());  // Exposes the contract's identity
}

// ✅ SAFE: Using ownPublicKey() only in shielded logic
function generateSharedSecret() {
    let myKey = ownPublicKey();
    let sharedSecret = deriveSharedSecret(myKey, counterpartyPublicKey);
    // sharedSecret is used in shielded computation only
}
```

**2.2 — Check for public key leakage via events**

```compact
// ❌ DANGEROUS: Public key in an event
function dangerousTransfer(to: Address, amount: u64) {
    emit TransferEvent { from: ownPublicKey(), to, amount };
}

// ✅ SAFE: Pseudonymous event
function safeTransfer(to: Address, amount: u64) {
    let txId = hash(self.id, to, amount, nonce);
    emit TransferEvent { txId, amount };
}
```

**2.3 — Verify that `ownPublicKey()` is never used as a primary identifier in public contexts**

In Midnight, the public identity should be an address or a pseudonymous identifier, not the raw public key.

---

## Step 3: Replay Protection Verification — Nonces & Nullifiers

### Why It Matters

Without replay protection, an attacker can capture a valid transaction and replay it multiple times, draining funds or executing unauthorized actions. Midnight uses a **nullifier-based system** for shielded transactions, similar to Zcash, where each consumed note has a unique nullifier that can only be spent once.

### What to Check

**3.1 — Verify that all shielded transactions include nullifier computation**

```compact
// ✅ REQUIRED: Every spend operation must compute a nullifier
function spendShielded(shieldedNote: ShieldedNote) {
    let nullifier = computeNullifier(shieldedNote, ownPublicKey(), nonce);
    verify(!isNullifierSpent(nullifier));
    // ... spend logic
    markNullifierSpent(nullifier);
}
```

**3.2 — For unshielded transactions, verify nonce-based replay protection**

```compact
// ✅ REQUIRED: Every unshielded state modification must check/update nonce
function transferUnshielded(to: Address, amount: u64) {
    verify(self.nonce == expectedNonce);
    // ... transfer logic
    self.nonce = self.nonce + 1;
}
```

**3.3 — Check for nullifier reuse vulnerabilities**

```compact
// ❌ DANGEROUS: Same nullifier computed for different notes
function spend(noteId: u64, secret: bytes) {
    // Same derivation for all notes — creates collisions!
    let nullifier = hash(secret);
    verify(!isNullifierSpent(nullifier));
    // ...
}

// ✅ SAFE: Nullifier is unique per note
function spend(noteId: u64, secret: bytes) {
    let nullifier = computeNullifier(noteId, secret);
    verify(!isNullifierSpent(nullifier));
    // ...
}
```

### Verification Script

```typescript
import { ReplayProtectionVerifier } from '@midnight/security-audit';

const verifier = new ReplayProtectionVerifier('./contracts');
const report = await verifier.verify();

console.log('=== Replay Protection Report ===');
console.log(`Nullifiers found: ${report.nullifierCount}`);
console.log(`Nonces found: ${report.nonceCount}`);
console.log(`Potential collisions: ${report.collisionCount}`);

if (report.collisionCount > 0) {
    throw new Error('❌ Nullifier collision detected — replay attack possible!');
}

console.log('✅ Replay protection is adequate.');
```

---

## Step 4: Exported Ledger Field Review

### Why It Matters

The **exported ledger** is the set of fields that are publicly visible on-chain. Every field declared in your contract's exported ledger is visible to anyone who inspects the blockchain. The #1 mistake developers make is exporting fields that were intended to be private.

### What to Check

**4.1 — Review every field in your contract's exported ledger**

```compact
ledger {
    // ❌ DANGEROUS: Balance is public
    public pubBalance: u64,  
    
    // ✅ SAFE: Balance is shielded
    shielded balance: u64,
    
    // ⚠️  INTENTIONAL: Owner address must be public for routing
    public owner: Address,
}
```

**4.2 — Apply the "publish test"**

Ask yourself for each exported field: *"Would I be comfortable if this value appeared on a public blockchain explorer?"* If the answer is no, it should be shielded.

**4.3 — Check for implicit ledger exports**

Some Compact constructs implicitly export state. Review your contract for:

- `transparent` function declarations (they operate on public state)
- Implicit `pub` declarations in structs
- Events that emit shielded state values

**4.4 — Verify that shielded fields are never accessed in public functions**

```compact
// ❌ DANGEROUS: Public function accessing shielded state
pub fn getBalance(): u64 {
    return self.balance;  // Compiler error or privacy leak
}

// ✅ SAFE: Shielded function for shielded access
shielded fn getBalance(): u64 {
    return self.balance;
}
```

### Ledger Audit Template

```typescript
interface LedgerField {
    name: string;
    visibility: 'public' | 'shielded';
    purpose: string;
    risk: 'critical' | 'high' | 'medium' | 'low';
}

const ledgerAudit: LedgerField[] = [
    { name: 'owner', visibility: 'public', purpose: 'Transaction routing', risk: 'low' },
    { name: 'balance', visibility: 'shielded', purpose: 'Token accounting', risk: 'critical' },
    { name: 'nonce', visibility: 'public', purpose: 'Replay protection', risk: 'medium' },
];

ledgerAudit.forEach(field => {
    if (field.visibility === 'public' && field.risk === 'critical') {
        console.error(`❌ CRITICAL: ${field.name} is public but contains sensitive data!`);
    }
});
```

---

## Step 5: Witness Implementation Correctness

### Why It Matters

**Witnesses** are the TypeScript (or Rust) code that constructs the private inputs (witness data) for your ZK circuits. Flawed witness implementations are the #1 source of logical bugs in Midnight dApps. A witness that provides incorrect or incomplete data can cause proof generation to fail silently or produce invalid proofs.

### What to Check

**5.1 — Verify that witness input types match circuit expectations**

```typescript
// ❌ DANGEROUS: Witness provides wrong type
const witness = {
    amount: "100",              // String instead of u64!
    recipient: recipientKey,    // Correct
};

// ✅ SAFE: Types match circuit exactly
const witness: TransferWitness = {
    amount: 100n,               // BigInt (maps to u64)
    recipient: recipientKey,    // PublicKey
    nonce: generateNonce(),     // bytes32
};
```

**5.2 — Check for missing or extra fields**

```typescript
// ❌ DANGEROUS: Missing required field (nonce)
const witness = {
    from: senderKey,
    to: recipientKey,
    amount: transferAmount,
    // nonce is missing — proof will fail!
};

// ✅ SAFE: All required fields present
const witness: SendWitness = {
    from: senderKey,
    to: recipientKey,
    amount: transferAmount,
    nonce: circuitNonce,
};
```

**5.3 — Verify that witness derivation is deterministic when required**

```typescript
// ❌ DANGEROUS: Non-deterministic witness input
function buildWitness(): SendWitness {
    return {
        from: getRandomKey(),       // Random key every time!
        to: recipientKey,
        amount: transferAmount,
    };
}

// ✅ SAFE: Correct values derived from ledger state
function buildWitness(sender: KeyPair, recipient: PublicKey, amount: u64): SendWitness {
    return {
        from: sender.publicKey,
        to: recipient,
        amount,
    };
}
```

**5.4 — Test witness generation in isolation**

```typescript
import { describe, it, expect } from 'bun:test';
import { buildWitness } from './witness';

describe('TransferWitness', () => {
    it('should produce correct witness for valid inputs', () => {
        const witness = buildWitness(sender, recipient, 100n);
        expect(witness.amount).toBe(100n);
        expect(witness.from).toBe(sender.publicKey);
    });

    it('should throw for zero amount', () => {
        expect(() => buildWitness(sender, recipient, 0n))
            .toThrow('Transfer amount must be positive');
    });
});
```

---

## Step 6: Version Compatibility Confirmation

### Why It Matters

Midnight is an evolving protocol. The Compact language, proof server, SDK, and network are all versioned independently. Mismatched versions are a leading cause of deployment failures — your contract compiles locally but fails to generate proofs on testnet because of a version mismatch.

### What to Check

**6.1 — Verify Compact compiler version matches proof server version**

```bash
# Check Compact compiler version
compact --version
# Expected: 0.9.0

# Check proof server version
docker exec midnight-proof-server proof-server --version
# Expected: 0.9.0  (must match!)
```

**6.2 — Verify SDK version compatibility**

```bash
# Check midnight-js version
npm list @midnight-ntwrk/compact
# Expected: ^0.9.0

# Check proof server Docker tag in docker-compose.yml
grep 'midnight-proof-server' docker-compose.yml
# Expected: midnightntwrk/midnight-proof-server:0.9.0
```

**6.3 — Check for breaking changes between versions**

If you're upgrading from a previous version, check the [Midnight changelog](https://docs.midnight.network/changelog) for:

- Compact language syntax changes
- Witness API changes
- Proof server API changes
- Network parameter changes

**6.4 — Create a version manifest**

```json
{
    "contractName": "MyToken",
    "compactVersion": "0.9.0",
    "sdkVersion": "0.9.0",
    "proofServerVersion": "0.9.0",
    "targetNetwork": "testnet",
    "lastVerified": "2026-04-26",
    "verifiedBy": "automated-ci"
}
```

---

## Step 7: Proof Generation Testing on Testnet

### Why It Matters

The ultimate test of your dApp's security is whether it can successfully generate and submit proofs on a live testnet. Local testing is necessary but not sufficient — network conditions, proof server load, and parameter mismatches can all cause failures that only appear on testnet.

### What to Check

**7.1 — Full end-to-end proof generation test**

```typescript
import { ProofClient } from '@midnight/proof-client';
import { TestnetConnector } from '@midnight/testnet';

async function testProofGeneration() {
    const proofClient = new ProofClient(process.env.PROOF_SERVER_URL);
    const testnet = new TestnetConnector(process.env.TESTNET_RPC);

    console.time('Proof generation');
    const proof = await proofClient.generate({
        circuit: 'transfer.circuit',
        witness: buildWitness(sender, recipient, 100n),
        params: { size: 'fast' },  // Fast mode for testing
    });
    console.timeEnd('Proof generation');

    console.log(`Proof size: ${proof.bytes.length} bytes`);
    console.log(`Proof valid: ${await proofClient.verify(proof)}`);

    const txId = await testnet.submitProof(proof);
    console.log(`Transaction submitted: ${txId}`);

    const receipt = await testnet.waitForTransaction(txId);
    console.log(`Status: ${receipt.status}`);  // Should be 'confirmed'

    return receipt;
}
```

**7.2 — Test proof rejection scenarios**

```typescript
// Test: Submit an invalid proof
try {
    await testnet.submitProof(invalidProof);
    console.error('❌ Should have rejected invalid proof!');
} catch (e) {
    console.log('✅ Invalid proof correctly rejected:', e.message);
}

// Test: Submit duplicate nullifier
try {
    await testnet.submitProof(doubleSpendProof);
    console.error('❌ Should have rejected double spend!');
} catch (e) {
    console.log('✅ Double spend correctly rejected:', e.message);
}
```

**7.3 — Performance baseline**

Record baseline performance metrics for future comparison:

```bash
# Baseline metrics to record
echo "=== Proof Generation Baseline ==="
echo "First proof time: $(measure_time first_proof) ms  (includes ~30MB ZK param download)"
echo "Subsequent proof time: $(measure_time repeat_proof) ms"
echo "Proof size: $(measure_size proof) bytes"
echo "Transaction confirmation: $(measure_time tx_confirm) ms"
```

---

## Putting It All Together: A CI Pipeline Approach

For production deployments, we recommend automating the security checklist in a CI pipeline. Here's a GitHub Actions workflow that runs all 7 checks:

```yaml
# .github/workflows/security-checklist.yml
name: Midnight Security Checklist

on:
  pull_request:
    paths:
      - 'contracts/**'
      - 'witness/**'
  push:
    branches: [main]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    services:
      proof-server:
        image: midnightntwrk/midnight-proof-server:0.9.0
        ports:
          - 8200:8200

    steps:
      - uses: actions/checkout@v4

      - name: Check Version Compatibility
        run: |
          compact --version
          docker exec proof-server proof-server --version
          npm list @midnight-ntwrk/compact

      - name: Disclose Audit
        run: bun run audit:disclose

      - name: OwnPublicKey Review
        run: bun run audit:publickey

      - name: Replay Protection Check
        run: bun run audit:replay

      - name: Ledger Field Review
        run: bun run audit:ledger

      - name: Witness Tests
        run: bun test

      - name: Proof Generation Test
        run: bun run test:proof
        env:
          PROOF_SERVER_URL: http://localhost:8200
```

---

## Common Attack Vectors and Mitigations

| Attack Vector | Description | Mitigation |
|---|---|---|
| **Privacy Leak via disclose()** | Accidentally revealing shielded state to the public ledger | Audit every `disclose()` call; minimize disclosed fields |
| **Public Key Deanonymization** | Using `ownPublicKey()` where a pseudonym should be used | Never use raw public keys in public contexts |
| **Nullifier Collision** | Two notes producing the same nullifier, enabling double-spends | Ensure each nullifier derivation includes a unique per-note value |
| **Ledger Field Over-Exposure** | Exporting sensitive fields as public | Review every exported field; shield anything sensitive |
| **Witness Type Mismatch** | Witness inputs that don't match circuit expectations | Use TypeScript types that mirror circuit parameters exactly |
| **Version Drift** | Mismatched Compact/SDK/proof-server versions | Lock versions in a manifest; test on testnet before deploying |
| **Replay Attack** | Replaying captured transactions | Verified nonces (unshielded) or nullifiers (shielded) |

---

## Conclusion

Deploying a secure Midnight dApp requires a **systematic, checklist-driven approach** to privacy and security. The 7-step checklist in this guide provides a durable framework that works regardless of which version of Midnight you're using or which specific features your dApp implements.

### Key Takeaways

1. **Privacy is not automatic** — you must consciously manage what is shielded vs. public
2. **Every `disclose()` call is a potential liability** — audit them ruthlessly
3. **Nullifiers prevent double-spends** — ensure they are unique per note
4. **Version compatibility is fragile** — always test on testnet before mainnet
5. **Witness code is security-critical** — test it as thoroughly as your contract code
6. **Automate the checklist** — CI pipelines catch regressions before they reach production

### Next Steps

- Run the checklist against your existing Midnight dApp
- Set up the CI workflow to automate future security checks
- Join the [Midnight Developer Forum](https://forum.midnight.network/) for security discussions
- Subscribe to the [Midnight changelog](https://docs.midnight.network/changelog) for breaking change notifications

---

*Published by BetsyMalthus • April 2026*
*Tags: #Midnight #Security #Blockchain #ZKProofs #dAppDevelopment*

---

> **Disclaimer**: This security checklist is a guide based on current best practices. Midnight's security model evolves — always refer to the official [Midnight Security Documentation](https://docs.midnight.network/security) for the most up-to-date guidance.
