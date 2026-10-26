#pragma once

// ---------------------------------------------------------------------------
// TPM2 persistent handle and NV index constants for BMC mTLS certificates.
// These must match the handles used when provisioning keys/certs into the TPM.
//
// NV indices (spec layout):
//   01C1 0190h  BMC mTLS Root CA Certificate      (truststore / peer CA)
//   01C1 0191h  BMC mTLS Server Certificate
//   01C1 0192h  BMC mTLS Client Certificate
//   01C1 0193h  BMC mTLS Peer Root CA Certificate  (local CA cert / chain)
//
// Persistent key handles (spec layout):
//   8100 0191h  BMC mTLS Server Key
//   8100 0192h  BMC mTLS Client Key
//
// Local CA signing key (issues server/client entity certs) — no spec-defined
// index, kept at the original well-known handle:
//   8100 0001h  Attestation CA Key
// ---------------------------------------------------------------------------

// NV indices
inline constexpr const char* TPM_TRUSTSTORE_CA_CERT_NV = "0x01C10190";
inline constexpr const char* TPM_SERVER_CERT_NV = "0x01C10191";
inline constexpr const char* TPM_CLIENT_CERT_NV = "0x01C10192";
// Peer Root CA — also used as the local CA cert stored in TPM NV for chain
inline constexpr const char* TPM_PEER_ROOT_CA_CERT_NV = "0x01C10193";

// Persistent key handles
inline constexpr const char* TPM_SERVER_KEY_HANDLE = "0x81000191";
inline constexpr const char* TPM_CLIENT_KEY_HANDLE = "0x81000192";

// Local attestation CA signing key (not spec-assigned)
inline constexpr const char* TPM_CA_KEY_HANDLE = "0x81000001";

// Aliases used by ssl_functions.hpp: CA cert for the server chain is the
// same as the Peer Root CA NV index.
inline constexpr const char* TPM_SERVER_CA_CERT_NV = TPM_PEER_ROOT_CA_CERT_NV;
inline constexpr const char* TPM_CLIENT_CA_CERT_NV = TPM_PEER_ROOT_CA_CERT_NV;
