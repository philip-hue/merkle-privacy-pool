# Privacy Layer for Bitcoin Transactions

## Overview

This smart contract implements a privacy-enhancing layer for Bitcoin transactions using a Merkle tree structure and fungible token (SIP-010) trait. The contract provides a secure and private mechanism for depositing and withdrawing tokens while maintaining anonymity and preventing double-spending.

## Features

- **Privacy-Preserving Transactions**: Utilize Merkle tree structure to obfuscate transaction details
- **Fungible Token Support**: Compatible with SIP-010 fungible token standard
- **Configurable Deposit Limits**: Maximum deposit amount configurable
- **Administrative Controls**:
  - Contract pause/unpause functionality
  - Emergency token recovery
- **Robust Error Handling**: Comprehensive error constants for various scenarios
- **Merkle Proof Verification**: Secure withdrawal mechanism with proof validation

## Contract Components

### Key Constants

- **Merkle Tree Height**: 20 levels
- **Maximum Deposit Amount**: 1,000,000 tokens
- **Contract Owner**: Transaction sender at deployment

### State Variables

- `merkle-root`: Current Merkle tree root
- `next-leaf-index`: Index for next deposit
- `contract-paused`: Contract operational status
- `total-deposited`: Cumulative deposited amount

### Main Functions

1. **`make-deposit`**

   - Deposit tokens into the privacy pool
   - Validates token, commitment, and amount
   - Updates Merkle tree
   - Records deposit details

2. **`process-withdrawal`**

   - Withdraw tokens from the privacy pool
   - Verifies Merkle proof
   - Prevents double-spending via nullifier tracking
   - Transfers tokens to specified recipient

3. **`admin-recovery`**
   - Emergency token recovery function
   - Accessible only by contract owner

### Security Mechanisms

- Input validation for tokens, commitments, and nullifiers
- Merkle proof verification
- Nullifier tracking to prevent double-spending
- Contract pause functionality
- Administrative recovery option

## Error Handling

The contract defines multiple error constants to handle various scenarios:

- Authorization errors
- Invalid input errors
- Insufficient balance
- Merkle tree and proof validation errors
- Transfer failures

## Usage Example

```clarity
;; Deposit tokens
(contract-call? privacy-pool make-deposit
    commitment-hash
    deposit-amount
    token-contract)

;; Withdraw tokens
(contract-call? privacy-pool process-withdrawal
    nullifier-hash
    merkle-root
    proof-list
    recipient
    token-contract
    withdrawal-amount)
```

## Security Considerations

- Only deposit up to the maximum allowed amount
- Verify token contract compatibility
- Keep Merkle proof and nullifier information secure
- Contract owner has emergency recovery capabilities

## Deployment Requirements

- Stacks blockchain environment
- SIP-010 compatible fungible token
- Merkle tree computational resources

## Limitations

- Fixed Merkle tree height (20 levels)
- Maximum deposit amount restriction
- Requires careful management of proofs and nullifiers

## Contributing

Contributions, security audits, and improvements are welcome. Please submit pull requests or open issues with detailed descriptions.
