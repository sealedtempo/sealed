// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {IAttestationVerifier} from "../../src/IAttestationVerifier.sol";

/// @notice Verifier whose answer is set by the test.
contract MockVerifier is IAttestationVerifier {
    bool public result = true;

    function setResult(bool result_) external {
        result = result_;
    }

    function verify(bytes32, bytes calldata) external view returns (bool) {
        return result;
    }
}

/// @notice Stand-in for a future ZK_DCAP_V1 verifier (method 2). Accepts evidence = abi.encode(digest, proofTag)
///         when proofTag matches the configured tag. It only exercises the plumbing (setVerifier, method ids,
///         mixing methods): a real TDX quote cannot commit to recordDigest, which itself contains sha256(quote).
///         A real method-2 verifier recomputes the digest from the record and checks a report_data v2 binding
///         (contract-review.md, crypto-SEAL-03).
contract MockZkDcapVerifier is IAttestationVerifier {
    bytes32 public immutable PROOF_TAG;

    constructor(bytes32 proofTag) {
        PROOF_TAG = proofTag;
    }

    function verify(bytes32 recordDigest, bytes calldata evidence) external view returns (bool) {
        if (evidence.length != 64) return false;
        (bytes32 committedDigest, bytes32 tag) = abi.decode(evidence, (bytes32, bytes32));
        return committedDigest == recordDigest && tag == PROOF_TAG;
    }
}

/// @notice Verifier that always reverts.
contract RevertingVerifier is IAttestationVerifier {
    error Boom();

    function verify(bytes32, bytes calldata) external pure returns (bool) {
        revert Boom();
    }
}
