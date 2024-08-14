/**
 * Enum for representing various elliptic curves used in cryptographic operations.
 * 
 * This enumeration defines a comprehensive list of elliptic curves, including:
 * - Standards curves from various organizations (e.g., SECP, Brainpool, NIST).
 * - Curves used in specific protocols or applications (e.g., WAP WSG ECID).
 * 
 * **Usage:**
 * - The `Curve` enum is used to specify the elliptic curve for cryptographic operations, such as key exchange or digital signatures.
 * - It is utilized by functions and methods that require a specific elliptic curve as an argument.
 * 
 * **Example:**
 * ```typescript
 * import { Curve } from './models/Curve';
 * 
 * const myCurve: Curve = Curve.SECP256K1;
 * ```
 * 
 * **Curves Included:**
 * - `SECP` curves (e.g., `SECP256K1`, `SECP384R1`)
 * - `Brainpool` curves (e.g., `BRAINPOOLP256R1`)
 * - `SM2` curve
 * - Various `C2PNB` and `C2TNB` curves
 * - `WAP` curves (e.g., `WAP_WSG_IDM_ECID_WTLS1`)
 * - And more.
 * 
 * @enum {string}
 * @readonly
 */
export enum Curve {
  OAKLEY_EC2N_3 = "Oakley-EC2N-3",
  OAKLEY_EC2N_4 = "Oakley-EC2N-4",
  SM2 = "SM2",
  BRAINPOOLP160R1 = "brainpoolP160r1",
  BRAINPOOLP160T1 = "brainpoolP160t1",
  BRAINPOOLP192R1 = "brainpoolP192r1",
  BRAINPOOLP192T1 = "brainpoolP192t1",
  BRAINPOOLP224R1 = "brainpoolP224r1",
  BRAINPOOLP224T1 = "brainpoolP224t1",
  BRAINPOOLP256R1 = "brainpoolP256r1",
  BRAINPOOLP256T1 = "brainpoolP256t1",
  BRAINPOOLP320R1 = "brainpoolP320r1",
  BRAINPOOLP320T1 = "brainpoolP320t1",
  BRAINPOOLP384R1 = "brainpoolP384r1",
  BRAINPOOLP384T1 = "brainpoolP384t1",
  BRAINPOOLP512R1 = "brainpoolP512r1",
  BRAINPOOLP512T1 = "brainpoolP512t1",
  C2PNB163V1 = "c2pnb163v1",
  C2PNB163V2 = "c2pnb163v2",
  C2PNB163V3 = "c2pnb163v3",
  C2PNB176V1 = "c2pnb176v1",
  C2PNB208W1 = "c2pnb208w1",
  C2PNB272W1 = "c2pnb272w1",
  C2PNB304W1 = "c2pnb304w1",
  C2PNB368W1 = "c2pnb368w1",
  C2TNB191V1 = "c2tnb191v1",
  C2TNB191V2 = "c2tnb191v2",
  C2TNB191V3 = "c2tnb191v3",
  C2TNB239V1 = "c2tnb239v1",
  C2TNB239V2 = "c2tnb239v2",
  C2TNB239V3 = "c2tnb239v3",
  C2TNB359V1 = "c2tnb359v1",
  C2TNB431R1 = "c2tnb431r1",
  PRIME192V1 = "prime192v1",
  PRIME192V2 = "prime192v2",
  PRIME192V3 = "prime192v3",
  PRIME239V1 = "prime239v1",
  PRIME239V2 = "prime239v2",
  PRIME239V3 = "prime239v3",
  PRIME256V1 = "prime256v1",
  SECP112R1 = "secp112r1",
  SECP112R2 = "secp112r2",
  SECP128R1 = "secp128r1",
  SECP128R2 = "secp128r2",
  SECP160K1 = "secp160k1",
  SECP160R1 = "secp160r1",
  SECP160R2 = "secp160r2",
  SECP192K1 = "secp192k1",
  SECP224K1 = "secp224k1",
  SECP224R1 = "secp224r1",
  SECP256K1 = "secp256k1",
  SECP384R1 = "secp384r1",
  SECP521R1 = "secp521r1",
  SECT113R1 = "sect113r1",
  SECT113R2 = "sect113r2",
  SECT131R1 = "sect131r1",
  SECT131R2 = "sect131r2",
  SECT163K1 = "sect163k1",
  SECT163R1 = "sect163r1",
  SECT163R2 = "sect163r2",
  SECT193R1 = "sect193r1",
  SECT193R2 = "sect193r2",
  SECT233K1 = "sect233k1",
  SECT233R1 = "sect233r1",
  SECT239K1 = "sect239k1",
  SECT283K1 = "sect283k1",
  SECT283R1 = "sect283r1",
  SECT409K1 = "sect409k1",
  SECT409R1 = "sect409r1",
  SECT571K1 = "sect571k1",
  SECT571R1 = "sect571r1",
  WAP_WSG_IDM_ECID_WTLS1 = "wap-wsg-idm-ecid-wtls1",
  WAP_WSG_IDM_ECID_WTLS10 = "wap-wsg-idm-ecid-wtls10",
  WAP_WSG_IDM_ECID_WTLS11 = "wap-wsg-idm-ecid-wtls11",
  WAP_WSG_IDM_ECID_WTLS12 = "wap-wsg-idm-ecid-wtls12",
  WAP_WSG_IDM_ECID_WTLS3 = "wap-wsg-idm-ecid-wtls3",
  WAP_WSG_IDM_ECID_WTLS4 = "wap-wsg-idm-ecid-wtls4",
  WAP_WSG_IDM_ECID_WTLS5 = "wap-wsg-idm-ecid-wtls5",
  WAP_WSG_IDM_ECID_WTLS6 = "wap-wsg-idm-ecid-wtls6",
  WAP_WSG_IDM_ECID_WTLS7 = "wap-wsg-idm-ecid-wtls7",
  WAP_WSG_IDM_ECID_WTLS8 = "wap-wsg-idm-ecid-wtls8",
  WAP_WSG_IDM_ECID_WTLS9 = "wap-wsg-idm-ecid-wtls9"
}