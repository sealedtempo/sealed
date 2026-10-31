// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {OracleSignatureVerifier} from "../../src/OracleSignatureVerifier.sol";
import {OracleVerifierHandler} from "./OracleVerifierHandler.sol";

/// @notice OracleSignatureVerifier: a signature verifies exactly when its signer is in the current signer set
///         (so removal takes effect at once and old evidence of a removed signer stops verifying), malleable
///         (high s) and wrong-v signatures never verify, non-canonical encodings never verify, verify never
///         reverts, and only the current owner changes the signer set or the owner.
contract OracleVerifierInvariantTest is Test {
    OracleSignatureVerifier internal verifier;
    OracleVerifierHandler internal handler;
    address internal owner = makeAddr("verifier-owner");

    /// @dev A fixed digest no handler call signs with intent, used to re-sign with every pool key.
    bytes32 internal constant PROBE = keccak256("oracle-verifier-invariant-probe");

    function setUp() public {
        verifier = new OracleSignatureVerifier(owner);
        address[] memory others = new address[](2);
        others[0] = makeAddr("verifier-owner-2");
        others[1] = makeAddr("verifier-stranger");
        handler = new OracleVerifierHandler(verifier, owner, others, 5);
        // Start with two of the five keys allowed, as on mainnet plus one rotation key.
        vm.startPrank(owner);
        verifier.addSigner(handler.keyAddrs(0));
        verifier.addSigner(handler.keyAddrs(1));
        vm.stopPrank();
        handler.seedGhost();

        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](10);
        selectors[0] = OracleVerifierHandler.addSigner.selector;
        selectors[1] = OracleVerifierHandler.removeSigner.selector;
        selectors[2] = OracleVerifierHandler.transferOwnership.selector;
        selectors[3] = OracleVerifierHandler.acceptOwnership.selector;
        selectors[4] = OracleVerifierHandler.renounceOwnership.selector;
        selectors[5] = OracleVerifierHandler.verifyCanonical.selector;
        selectors[6] = OracleVerifierHandler.verifyMutated.selector;
        selectors[7] = OracleVerifierHandler.verifyMutated.selector; // weight the attack paths
        selectors[8] = OracleVerifierHandler.verifyCanonical.selector;
        selectors[9] = OracleVerifierHandler.addSigner.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_signerSetMatchesModel() public view {
        uint256 n = handler.keyCount();
        for (uint256 i; i < n; ++i) {
            address a = handler.keyAddrs(i);
            assertEq(verifier.isSigner(a), handler.ghostSigner(a), "isSigner == model");
        }
        assertEq(verifier.signerCount(), handler.ghostSignerCount(), "signerCount == model");
        assertFalse(verifier.isSigner(address(0)), "zero is never a signer");
    }

    function invariant_ownerMatchesModel() public view {
        assertEq(verifier.owner(), handler.ghostOwner(), "owner == model");
        assertEq(verifier.pendingOwner(), handler.ghostPending(), "pendingOwner == model");
    }

    /// @dev Signer removal takes effect: every canonical signature the campaign produced verifies exactly when
    ///      its signer is allowed now, including signatures made while the signer was allowed.
    function invariant_oldEvidenceFollowsCurrentSignerSet() public view {
        uint256 n = handler.seenCount();
        for (uint256 i; i < n; ++i) {
            OracleVerifierHandler.Seen memory e = handler.seen(i);
            assertEq(verifier.verify(e.digest, e.evidence), handler.ghostSigner(e.signer), "old evidence");
            assertFalse(verifier.verify(e.digest, handler.malleate(e.evidence)), "high-s twin of old evidence");
        }
    }

    /// @dev A fresh signature over a fixed digest by each pool key verifies iff the key is a signer; its high-s
    ///      twin and its wrong-v variants never verify.
    function invariant_freshSignaturesFollowSignerSet() public view {
        uint256 n = handler.keyCount();
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(handler.keyOf(i), PROBE);
            bytes memory good = abi.encode(abi.encodePacked(r, s, v));
            assertEq(verifier.verify(PROBE, good), handler.ghostSigner(handler.keyAddrs(i)), "fresh signature");
            assertFalse(verifier.verify(PROBE, handler.malleate(good)), "high-s twin");
            assertFalse(verifier.verify(PROBE, abi.encode(abi.encodePacked(r, s, v - 27))), "v of 0 or 1");
            (bool ok, address recovered) =
                verifier.recoverSigner(PROBE, abi.encode(abi.encodePacked(r, s, v == 27 ? uint8(28) : uint8(27))));
            assertTrue(!ok || recovered != handler.keyAddrs(i), "flipped v recovers another key");
        }
    }

    function invariant_handlerPredictionsHeld() public view {
        assertFalse(handler.unexpectedOutcome(), handler.lastMismatch());
        assertFalse(handler.verifyReverted(), "verify reverted");
        assertFalse(handler.malleableAccepted(), "high-s signature accepted");
        assertFalse(handler.wrongVAccepted(), "wrong v accepted");
        assertFalse(handler.nonCanonicalAccepted(), "non-canonical evidence accepted");
        assertFalse(handler.nonSignerAccepted(), "non-signer accepted");
    }

    /// @dev Sanity check that the handler reaches every path: one fixed sequence, counting outcomes.
    function test_handlerReachesEveryPath() public {
        for (uint256 i; i < 400; ++i) {
            uint256 seed = uint256(keccak256(abi.encode("verifier-path", i)));
            uint256 action = seed % 7;
            if (action == 0) handler.addSigner(seed >> 8, seed >> 16, (seed >> 24) % 9 == 0);
            else if (action == 1) handler.removeSigner(seed >> 8, seed >> 16);
            else if (action == 2) handler.transferOwnership(seed >> 8, seed >> 16);
            else if (action == 3) handler.acceptOwnership(seed >> 8);
            else if (action == 4) handler.verifyCanonical(seed >> 8, keccak256(abi.encode(seed)));
            else handler.verifyMutated(seed >> 8, keccak256(abi.encode(seed)), seed >> 16, seed >> 32);
        }
        invariant_signerSetMatchesModel();
        invariant_ownerMatchesModel();
        invariant_oldEvidenceFollowsCurrentSignerSet();
        invariant_freshSignaturesFollowSignerSet();
        invariant_handlerPredictionsHeld();
        assertGt(handler.calls("addSigner"), 0, "signers added");
        assertGt(handler.calls("removeSigner"), 0, "signers removed");
        assertGt(handler.calls("addSignerRejected"), 0, "unauthorized or duplicate adds rejected");
        assertGt(handler.calls("verifyCanonical"), 20, "canonical verifications");
        for (uint256 k; k < 12; ++k) {
            assertGt(handler.calls(string.concat("verifyMutated-", vm.toString(k))), 0, "every mutation kind");
        }
    }
}
