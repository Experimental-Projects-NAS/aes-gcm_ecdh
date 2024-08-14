/**
 * Cryptographic Module for Secure Communication
 * 
 * This module provides functionality for encrypting and decrypting messages using
 * Elliptic Curve Diffie-Hellman (ECDH) for key exchange and AES-GCM for encryption and decryption.
 * 
 * The module includes the following functions:
 * 
 * 1. `encryptECDH`:
 *    - Encrypts a message by performing an ECDH key exchange to derive a shared secret.
 *    - Uses the derived shared secret to create an AES-256-GCM key for encryption.
 *    - Returns the encrypted message in hexadecimal format, prefixed with the initialization vector (IV).
 * 
 * 2. `decryptECDH`:
 *    - Decrypts an encrypted message by performing an ECDH key exchange to derive a shared secret.
 *    - Uses the derived shared secret to create an AES-256-GCM key for decryption.
 *    - Extracts and verifies the IV and authentication tag from the encrypted message.
 *    - Returns the decrypted message as a string.
 * 
 * 3. `deriveSharedSecret`:
 *    - Derives a shared secret using ECDH key exchange with a specified elliptic curve.
 *    - Takes the private key of the local party and the public key of the remote party.
 *    - Returns the derived shared secret as a Buffer.
 * 
 * **Dependencies:**
 * - `crypto`: Node.js built-in module providing cryptographic functionality for key generation, encryption, and decryption.
 * - `Curve`: A type representing elliptic curves used in ECDH key exchange, imported from the `./models/Curve` module.
 * 
 * **Usage:**
 * - To encrypt a message, call `encryptECDH` with the sender's private key, recipient's public key, the message to encrypt, and the elliptic curve to use.
 * - To decrypt a message, call `decryptECDH` with the recipient's private key, the sender's public key, the encrypted message, and the elliptic curve to use.
 * - To derive a shared secret, call `deriveSharedSecret` with the private key, the public key, and the elliptic curve to use.
 * 
 * **Notes:**
 * - Encryption is performed using AES-256-GCM, which requires a 256-bit key and a 12-byte IV.
 * - ECDH key exchange uses elliptic curves for deriving a shared secret. The default curve used in `deriveSharedSecret` is SECP256K1 if not specified.
 * 
 * @module CryptographicModule
 */
import * as crypto from "crypto";
import { Curve } from "./models/Curve";

/**
 * Encrypts a message using Elliptic Curve Diffie-Hellman (ECDH) for key exchange
 * and AES-GCM for encryption.
 *
 * @param {string} senderPrivKey - The private key of the sender in hexadecimal string format.
 * @param {string} recipientPubKey - The public key of the recipient in hexadecimal string format.
 * @param {string} msg - The message to be encrypted.
 * @param {Curve} curve - The elliptic curve to be used for ECDH key exchange.
 * @param {boolean} [isHex=false] - Whether the message is already in hexadecimal format.
 * @returns {string} - The encrypted message in hexadecimal format, prefixed with the IV.
 * @throws {Error} - Throws an error if any required argument is missing.
 */
const encryptECDH = (
  senderPrivKey: string,
  recipientPubKey: string,
  msg: string,
  curve: Curve,
  isHex: boolean = false
): string => {
  // Validate input parameters
  if (!senderPrivKey || !recipientPubKey || !msg || !curve) {
    throw new Error("Missing argument!");
  }

  // Generate a random initialization vector (IV) for AES-GCM encryption
  const iv = crypto.randomBytes(12);

  // Derive the shared secret using ECDH key exchange
  const sharedSecret = deriveSharedSecret(senderPrivKey, recipientPubKey, curve);

  // Derive the AES key from the shared secret using SHA-256 hash function
  const key = crypto.createHash('sha256').update(sharedSecret).digest().subarray(0, 32);

  // Create a cipher object for AES-GCM encryption
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  // Encrypt the message and concatenate the encrypted data with the authentication tag
  const encrypted = Buffer.concat([
    cipher.update(isHex ? msg : Buffer.from(msg).toString("hex")), // Encrypt the message
    cipher.final(), // Finalize encryption
    cipher.getAuthTag() // Get the authentication tag for integrity check
  ]);

  // Return the IV and encrypted message as a hexadecimal string
  return iv.toString("hex") + encrypted.toString("hex");
}

/**
 * Decrypts an encrypted message using Elliptic Curve Diffie-Hellman (ECDH) key exchange and AES-GCM symmetric encryption.
 *
 * @param {string} recipientPrivKey - The private key of the recipient in hexadecimal format.
 * @param {string} senderPubKey - The public key of the sender in hexadecimal format.
 * @param {string} encryptedMsg - The encrypted message to be decrypted in hexadecimal format.
 * @param {Curve} curve - The elliptic curve to be used for ECDH key exchange.
 *
 * @throws {Error} Will throw an error if any of the parameters are missing.
 *
 * @returns {string} The decrypted message as a string.
 */
const decryptECDH = (
  recipientPrivKey: string,
  senderPubKey: string,
  encryptedMsg: string,
  curve: Curve
): string => {
  if (!recipientPrivKey || !senderPubKey || !encryptedMsg || !curve) {
    throw new Error("Missing argument!");
  }

  // Extract IV and encrypted data
  const iv = Buffer.from(encryptedMsg.slice(0, 24), 'hex'); // 12 bytes IV
  const authTag = Buffer.from(encryptedMsg.slice(-32), 'hex'); // 16 bytes authentication tag
  const encryptedData = Buffer.from(encryptedMsg.slice(24, -32), 'hex'); // Encrypted message without IV and authTag

  // Derive the shared secret
  const sharedSecret = deriveSharedSecret(recipientPrivKey, senderPubKey, curve);

  // Hash or truncate the shared secret to fit AES key length
  const key = crypto.createHash('sha256')
    .update(sharedSecret)
    .digest()
    .subarray(0, 32); // AES-256

  // Create decipher instance with AES-GCM
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  // Decrypt the message
  const decrypted = Buffer.concat([
    decipher.update(encryptedData),
    decipher.final()
  ]);

  return decrypted.toString();
}

/**
 * Derives a shared secret using Elliptic Curve Diffie-Hellman (ECDH) key exchange.
 *
 * @param {string} privKey - The private key of the local party in hexadecimal string format.
 * @param {string} pubKey - The public key of the remote party in hexadecimal string format.
 * @param {Curve} [curve=Curve.SECP256K1] - The elliptic curve to be used for ECDH key exchange. Defaults to SECP256K1.
 * @returns {Buffer} - The derived shared secret as a Buffer.
 * @throws {Error} - Throws an error if any required argument is missing or if the curve is not specified.
 */
const deriveSharedSecret = (
  privKey: string,
  pubKey: string,
  curve: Curve
): Buffer => {
  // Validate input parameters
  if (!privKey || !pubKey || !curve) {
    throw new Error("Missing argument!");
  }

  // Create an ECDH object for the specified elliptic curve
  const ecdh = crypto.createECDH(curve);

  // Set the private key for the ECDH object
  ecdh.setPrivateKey(Buffer.from(privKey, "hex"));

  // Compute and return the shared secret using the provided public key
  return ecdh.computeSecret(Buffer.from(pubKey, "hex"));
}

export { encryptECDH, decryptECDH, deriveSharedSecret };