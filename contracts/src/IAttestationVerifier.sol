// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

/// @title IAttestationVerifier
/// @notice Pluggable verifier for deployment attestation evidence. DeploymentRegistry keeps one verifier per
///         method id and asks it whether `evidence` attests to `recordDigest`.
/// @dev `recordDigest` is always an EIP-712 digest produced by DeploymentRegistry (`recordDigest` or
///      `heartbeatDigest`). Implementations must not re-hash it. Implementations should return false rather
///      than revert on malformed evidence.
interface IAttestationVerifier {
    /// @notice Checks attestation evidence for an EIP-712 digest.
    /// @param recordDigest The EIP-712 digest of a Record or Heartbeat, computed by DeploymentRegistry.
    /// @param evidence Method-specific evidence bytes.
    /// @return True when the evidence is valid for `recordDigest`.
    function verify(bytes32 recordDigest, bytes calldata evidence) external view returns (bool);
}

/// @title AttestationMethods
/// @notice Method ids understood by DeploymentRegistry.setVerifier.
library AttestationMethods {
    /// @notice Oracle signature over the EIP-712 digest (OracleSignatureVerifier). Built now.
    uint8 internal constant ORACLE_SIG_V1 = 1;
    /// @notice ZK proof of an Intel DCAP quote verification. Reserved; left unset at deploy.
    uint8 internal constant ZK_DCAP_V1 = 2;
}
