// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IAttestationVerifier, AttestationMethods} from "./IAttestationVerifier.sol";
import {OwnableNoRenounce} from "./utils/OwnableNoRenounce.sol";

/// @title OracleSignatureVerifier
/// @notice Attestation method 1 (ORACLE_SIG_V1). The platform oracle verifies the TDX quote offchain and signs the
///         EIP-712 digest that DeploymentRegistry computes. This contract checks that signature against an
///         owner-managed set of oracle signers.
/// @dev Evidence layout: `abi.encode(bytes signature)` where `signature` is a 65-byte (r, s, v) ECDSA signature
///      over the digest itself (no EIP-191 prefix, no re-hashing). Only the canonical ABI encoding is accepted
///      (160 bytes: offset 0x20, length 65, 65 signature bytes, 31 zero padding bytes). verify() never reverts.
contract OracleSignatureVerifier is IAttestationVerifier, OwnableNoRenounce {
    /// @notice Contract version.
    string public constant VERSION = "1.0.0";

    /// @notice The DeploymentRegistry method id this verifier implements.
    uint8 public constant METHOD_ID = AttestationMethods.ORACLE_SIG_V1;

    /// @dev Length of abi.encode(bytes) for a 65-byte payload: offset word + length word + 3 data words.
    uint256 private constant CANONICAL_EVIDENCE_LENGTH = 160;

    /// @notice Whether an address is an allowed oracle signer.
    mapping(address signer => bool allowed) public isSigner;

    /// @notice Number of allowed oracle signers.
    uint256 public signerCount;

    /// @notice Emitted when an oracle signer is allowed.
    /// @param signer The signer address.
    event SignerAdded(address indexed signer);

    /// @notice Emitted when an oracle signer is removed.
    /// @param signer The signer address.
    event SignerRemoved(address indexed signer);

    /// @notice The zero address was given as a signer.
    error ZeroSigner();
    /// @notice The signer is already allowed.
    error SignerAlreadyAdded(address signer);
    /// @notice The signer is not allowed.
    error SignerNotFound(address signer);

    /// @param initialOwner The owner (OWNER), who manages the signer set.
    constructor(address initialOwner) OwnableNoRenounce(initialOwner) {}

    /// @notice Allows an oracle signer. Owner only.
    /// @param signer The signer address (non-zero, not already allowed).
    function addSigner(address signer) external onlyOwner {
        if (signer == address(0)) revert ZeroSigner();
        if (isSigner[signer]) revert SignerAlreadyAdded(signer);
        isSigner[signer] = true;
        unchecked {
            ++signerCount;
        }
        emit SignerAdded(signer);
    }

    /// @notice Removes an oracle signer. Owner only. Records already registered stay registered.
    /// @param signer The signer address (must be allowed).
    function removeSigner(address signer) external onlyOwner {
        if (!isSigner[signer]) revert SignerNotFound(signer);
        isSigner[signer] = false;
        unchecked {
            --signerCount;
        }
        emit SignerRemoved(signer);
    }

    /// @inheritdoc IAttestationVerifier
    /// @dev Returns false (never reverts) for non-canonical encodings, signatures that are not 65 bytes, invalid or
    ///      high-s signatures, and signatures by addresses that are not allowed signers.
    function verify(bytes32 recordDigest, bytes calldata evidence) external view returns (bool) {
        (bool ok, address signer) = recoverSigner(recordDigest, evidence);
        return ok && isSigner[signer];
    }

    /// @notice Decodes the evidence and recovers the signer, without checking the signer set.
    /// @param recordDigest The EIP-712 digest that was signed.
    /// @param evidence abi.encode(bytes signature).
    /// @return ok False when the evidence is malformed or the signature is invalid.
    /// @return signer The recovered signer (zero when ok is false).
    function recoverSigner(bytes32 recordDigest, bytes calldata evidence)
        public
        pure
        returns (bool ok, address signer)
    {
        if (evidence.length != CANONICAL_EVIDENCE_LENGTH) return (false, address(0));
        if (uint256(bytes32(evidence[0:32])) != 0x20) return (false, address(0));
        if (uint256(bytes32(evidence[32:64])) != 65) return (false, address(0));
        // The 31 bytes after the signature are ABI padding and must be zero for a canonical encoding.
        if (bytes31(evidence[129:160]) != bytes31(0)) return (false, address(0));

        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecoverCalldata(recordDigest, evidence[64:129]);
        if (err != ECDSA.RecoverError.NoError || recovered == address(0)) return (false, address(0));
        return (true, recovered);
    }
}
