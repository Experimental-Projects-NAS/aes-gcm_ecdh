/**
 * This module re-exports functionality from other modules to simplify imports.
 *
 * - Exports the `Curve` enum from the `models/Curve` module, which includes various elliptic curves used in cryptographic operations.
 * - Exports utility functions (`encryptECDH`, `decryptECDH`, `deriveSharedSecret`) from the `Utilities` module for performing cryptographic operations such as message encryption, decryption, and shared secret derivation.
 *
 * By re-exporting these modules, users of this module can access the necessary cryptographic tools and data types with a single import statement.
 *
 * Example usage:
 * ```typescript
 * import { Curve, encryptECDH, decryptECDH } from 'aes-256-gcm_edch';
 * ```
 */
export * from "./models/Curve";
export * from "./Utilities";