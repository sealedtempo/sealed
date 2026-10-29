// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {OracleSignatureVerifier} from "../../src/OracleSignatureVerifier.sol";

/// @notice Drives OracleSignatureVerifier with signer changes (by the owner and by others), two-step ownership
///         moves, and verify calls on canonical, malleated (high s), wrong-v, wrong-digest and non-canonical
///         evidence from a fixed pool of keys. Keeps a ghost signer set and every canonical signature it produced,
///         so the invariants can re-check old evidence after a signer was removed or re-added.
contract OracleVerifierHandler is Test {
    /// @dev secp256k1 group order.
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant MAX_SEEN = 64;

    OracleSignatureVerifier public immutable verifier;

    uint256[] internal _keys;
    address[] public keyAddrs;
    address[] public actors;

    address public ghostOwner;
    address public ghostPending;
    mapping(address signer => bool) public ghostSigner;
    uint256 public ghostSignerCount;

    struct Seen {
        bytes32 digest;
        bytes evidence;
        address signer;
    }

    Seen[] internal _seen;

    bool public unexpectedOutcome;
    bool public verifyReverted;
    bool public malleableAccepted;
    bool public wrongVAccepted;
    bool public nonCanonicalAccepted;
    bool public nonSignerAccepted;
    string public lastMismatch;
    mapping(string name => uint256) public calls;

    constructor(OracleSignatureVerifier verifier_, address owner_, address[] memory otherActors, uint256 keys_) {
        verifier = verifier_;
        ghostOwner = owner_;
        actors.push(owner_);
        for (uint256 i; i < otherActors.length; ++i) {
            actors.push(otherActors[i]);
        }
        for (uint256 i; i < keys_; ++i) {
            (address a, uint256 k) = makeAddrAndKey(string.concat("verifier-key-", vm.toString(i)));
            _keys.push(k);
            keyAddrs.push(a);
            // Signer keys can also act, so a signer is never mistaken for an admin.
            actors.push(a);
        }
    }

    /// @notice Copies the signer set the test's setUp configured into the model.
    function seedGhost() external {
        for (uint256 i; i < keyAddrs.length; ++i) {
            if (verifier.isSigner(keyAddrs[i]) && !ghostSigner[keyAddrs[i]]) {
                ghostSigner[keyAddrs[i]] = true;
                ++ghostSignerCount;
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------------------------------------------

    function keyCount() external view returns (uint256) {
        return _keys.length;
    }

    function keyOf(uint256 i) external view returns (uint256) {
        return _keys[i];
    }

    function seenCount() external view returns (uint256) {
        return _seen.length;
    }

    function seen(uint256 i) external view returns (Seen memory) {
        return _seen[i];
    }

    /// @notice The high-s twin of a canonical 65-byte signature (s' = n - s, v flipped), ABI-wrapped.
    function malleate(bytes memory evidence) public pure returns (bytes memory) {
        bytes memory sig = abi.decode(evidence, (bytes));
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        return abi.encode(abi.encodePacked(r, bytes32(N - uint256(s)), v == 27 ? uint8(28) : uint8(27)));
    }

    // ------------------------------------------------------------------------------------------------------
    // Signer set and ownership
    // ------------------------------------------------------------------------------------------------------

    function addSigner(uint256 actorSeed, uint256 keySeed, bool zero) external {
        address actor = actors[actorSeed % actors.length];
        address signer = zero ? address(0) : keyAddrs[keySeed % keyAddrs.length];
        bool expected = actor == ghostOwner && signer != address(0) && !ghostSigner[signer];
        vm.prank(actor);
        try verifier.addSigner(signer) {
            if (!expected) _mismatch("addSigner succeeded");
            ghostSigner[signer] = true;
            ++ghostSignerCount;
            calls["addSigner"]++;
        } catch {
            if (expected) _mismatch("addSigner reverted");
            calls["addSignerRejected"]++;
        }
    }

    function removeSigner(uint256 actorSeed, uint256 keySeed) external {
        address actor = actors[actorSeed % actors.length];
        address signer = keyAddrs[keySeed % keyAddrs.length];
        bool expected = actor == ghostOwner && ghostSigner[signer];
        vm.prank(actor);
        try verifier.removeSigner(signer) {
            if (!expected) _mismatch("removeSigner succeeded");
            ghostSigner[signer] = false;
            --ghostSignerCount;
            calls["removeSigner"]++;
        } catch {
            if (expected) _mismatch("removeSigner reverted");
            calls["removeSignerRejected"]++;
        }
    }

    function transferOwnership(uint256 actorSeed, uint256 newOwnerSeed) external {
        address actor = actors[actorSeed % actors.length];
        address next = actors[newOwnerSeed % actors.length];
        bool expected = actor == ghostOwner;
        vm.prank(actor);
        try verifier.transferOwnership(next) {
            if (!expected) _mismatch("transferOwnership succeeded");
            ghostPending = next;
            calls["transferOwnership"]++;
        } catch {
            if (expected) _mismatch("transferOwnership reverted");
        }
    }

    function acceptOwnership(uint256 actorSeed) external {
        address actor = actors[actorSeed % actors.length];
        bool expected = ghostPending != address(0) && actor == ghostPending;
        vm.prank(actor);
        try verifier.acceptOwnership() {
            if (!expected) _mismatch("acceptOwnership succeeded");
            ghostOwner = actor;
            ghostPending = address(0);
            calls["acceptOwnership"]++;
        } catch {
            if (expected) _mismatch("acceptOwnership reverted");
        }
    }

    function renounceOwnership(uint256 actorSeed) external {
        address actor = actors[actorSeed % actors.length];
        vm.prank(actor);
        try verifier.renounceOwnership() {
            _mismatch("renounceOwnership succeeded");
        } catch {}
    }

    // ------------------------------------------------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------------------------------------------------

    /// @dev A canonical signature by a pool key verifies exactly when the key is a signer now.
    function verifyCanonical(uint256 keySeed, bytes32 digest) external {
        uint256 i = keySeed % _keys.length;
        bytes memory evidence = _evidence(_keys[i], digest);
        bool got = _verify(digest, evidence);
        if (got != ghostSigner[keyAddrs[i]]) _mismatch("canonical verify != signer set");
        if (got && !ghostSigner[keyAddrs[i]]) nonSignerAccepted = true;
        (bool ok, address recovered) = verifier.recoverSigner(digest, evidence);
        if (!ok || recovered != keyAddrs[i]) _mismatch("recoverSigner of a canonical signature");
        if (_seen.length < MAX_SEEN) _seen.push(Seen(digest, evidence, keyAddrs[i]));
        calls["verifyCanonical"]++;
    }

    /// @dev Every malleated, wrong-v, wrong-digest and non-canonical variant of a pool key's signature is
    ///      rejected, whether or not the key is a signer.
    function verifyMutated(uint256 keySeed, bytes32 digest, uint256 kind, uint256 noise) external {
        uint256 i = keySeed % _keys.length;
        address key = keyAddrs[i];
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_keys[i], digest);
        kind = kind % 12;
        bytes memory evidence;
        bytes32 checkDigest = digest;
        if (kind == 0) {
            // The other valid ECDSA signature for the same key and digest: high s, flipped v.
            evidence = abi.encode(abi.encodePacked(r, bytes32(N - uint256(s)), v == 27 ? uint8(28) : uint8(27)));
        } else if (kind == 1) {
            evidence = abi.encode(abi.encodePacked(r, bytes32(N - uint256(s)), v));
        } else if (kind == 2) {
            // Flipped v recovers another public key (or none).
            evidence = abi.encode(abi.encodePacked(r, s, v == 27 ? uint8(28) : uint8(27)));
        } else if (kind == 3) {
            evidence = abi.encode(abi.encodePacked(r, s, v - 27)); // 0 or 1
        } else if (kind == 4) {
            uint8 badV = uint8(noise);
            if (badV == 27 || badV == 28) badV = 29;
            evidence = abi.encode(abi.encodePacked(r, s, badV));
        } else if (kind == 5) {
            evidence = abi.encode(abi.encodePacked(bytes32(0), s, v));
        } else if (kind == 6) {
            evidence = abi.encode(abi.encodePacked(r, bytes32(0), v));
        } else if (kind == 7) {
            // A signature over another digest.
            checkDigest = bytes32(uint256(digest) ^ (1 << (noise % 256)));
            evidence = abi.encode(abi.encodePacked(r, s, v));
        } else if (kind == 8) {
            // Non-zero ABI padding after the 65 signature bytes.
            evidence = abi.encode(abi.encodePacked(r, s, v));
            evidence[129 + (noise % 31)] = bytes1(uint8(1 + (noise >> 8) % 255));
        } else if (kind == 9) {
            // Non-canonical offset word: same bytes after it.
            evidence = abi.encode(abi.encodePacked(r, s, v));
            evidence[31] = bytes1(uint8(0x40));
        } else if (kind == 10) {
            // EIP-2098 compact signature (64 bytes) inside the ABI shell.
            bytes32 vs = bytes32(uint256(s) | (v == 28 ? (1 << 255) : 0));
            evidence = abi.encode(abi.encodePacked(r, vs));
        } else {
            // Raw 65 bytes, or the canonical encoding with a trailing byte.
            evidence = noise % 2 == 0 ? abi.encodePacked(r, s, v) : bytes.concat(_evidence(_keys[i], digest), hex"00");
        }

        bool got = _verify(checkDigest, evidence);
        (bool ok, address recovered) = verifier.recoverSigner(checkDigest, evidence);
        if (kind == 2 || kind == 7) {
            // These recover some address; it is never the signing key, and verify follows the signer set.
            if (ok && recovered == key) _mismatch("flipped v or other digest recovered the signing key");
            if (got != (ok && ghostSigner[recovered])) _mismatch("verify != signer set for a recovered address");
            if (kind == 2 && got) wrongVAccepted = true;
        } else {
            if (got || ok) {
                if (kind <= 1) malleableAccepted = true;
                else if (kind <= 4) wrongVAccepted = true;
                else nonCanonicalAccepted = true;
                _mismatch(string.concat("mutated evidence accepted, kind ", vm.toString(kind)));
            }
        }
        calls[string.concat("verifyMutated-", vm.toString(kind))]++;
    }

    // ------------------------------------------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------------------------------------------

    function _verify(bytes32 digest, bytes memory evidence) internal returns (bool) {
        try verifier.verify(digest, evidence) returns (bool ok) {
            return ok;
        } catch {
            verifyReverted = true;
            return false;
        }
    }

    function _evidence(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encode(abi.encodePacked(r, s, v));
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly ("memory-safe") {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
    }

    function _mismatch(string memory what) internal {
        unexpectedOutcome = true;
        lastMismatch = what;
    }
}
