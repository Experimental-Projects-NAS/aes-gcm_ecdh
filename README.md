# aes-gcm_ecdh
AES-256-GCM encryption using ECDH shared key.

This repository provides cryptographic utilities for secure communication and data protection. It includes functionality for key exchange, encryption, and decryption using various elliptic curves and symmetric encryption algorithms.

## Modules

### `Curve`
Defines various elliptic curves used in cryptographic operations. You can use these curves for key exchange and other cryptographic tasks.

### `Utilities`
Provides utility functions for cryptographic operations, including:
- `encryptECDH`: Encrypts a message using Elliptic Curve Diffie-Hellman (ECDH) for key exchange and AES-GCM for encryption.
- `decryptECDH`: Decrypts a message encrypted with the `encryptECDH` function.
- `deriveSharedSecret`: Derives a shared secret using Elliptic Curve Diffie-Hellman (ECDH) key exchange.

## Installation

To use these utilities, install the package via npm or yarn:

```bash
npm install <package-name>
# or
yarn add <package-name>
```

## Usage

### Importing

To use the utilities and curve definitions, import them into your project:

```typescript
import { Curve, encryptECDH, decryptECDH } from '<package-name>';
```

### Encrypting a Message

To encrypt a message, use the `encryptECDH` function:

```typescript
const encryptedMessage = encryptECDH(
  senderPrivKey,       // Sender's private key in hexadecimal string format
  recipientPubKey,    // Recipient's public key in hexadecimal string format
  message,            // Message to encrypt
  Curve.SECP256K1,    // Elliptic curve to use (default: SECP256K1)
  false               // Whether the message is already in hexadecimal format (default: false)
);
```

### Decrypting a Message

To decrypt a message, use the `decryptECDH` function:

```typescript
const decryptedMessage = decryptECDH(
  recipientPrivKey,   // Recipient's private key in hexadecimal string format
  senderPubKey,      // Sender's public key in hexadecimal string format
  encryptedMessage, // Encrypted message in hexadecimal format
  Curve.SECP256K1    // Elliptic curve to use (default: SECP256K1)
);
```

## API Reference

### `Curve`
- An enumeration of various elliptic curves.

### `encryptECDH`
- **Parameters**:
  - `senderPrivKey`: Sender's private key in hexadecimal string format.
  - `recipientPubKey`: Recipient's public key in hexadecimal string format.
  - `msg`: The message to be encrypted.
  - `curve`: The elliptic curve to be used for ECDH key exchange.
  - `isHex`: Whether the message is already in hexadecimal format (default: false).
- **Returns**: Encrypted message in hexadecimal format, prefixed with the IV.
- **Throws**: Error if any required argument is missing.

### `decryptECDH`
- **Parameters**:
  - `recipientPrivKey`: Recipient's private key in hexadecimal string format.
  - `senderPubKey`: Sender's public key in hexadecimal string format.
  - `encryptedMsg`: The encrypted message to be decrypted in hexadecimal format.
  - `curve`: The elliptic curve to be used for ECDH key exchange.
- **Returns**: Decrypted message as a string.
- **Throws**: Error if any of the parameters are missing.

### `deriveSharedSecret`
- **Parameters**:
  - `privKey`: Private key in hexadecimal string format.
  - `pubKey`: Public key in hexadecimal string format.
  - `curve`: The elliptic curve to be used for ECDH key exchange (default: SECP256K1).
- **Returns**: Derived shared secret as a Buffer.
- **Throws**: Error if any required argument is missing or if the curve is not specified.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss potential improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.