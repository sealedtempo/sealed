// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Test} from "forge-std/Test.sol";

import {OracleSignatureVerifier} from "../src/OracleSignatureVerifier.sol";
import {OwnableNoRenounce} from "../src/utils/OwnableNoRenounce.sol";

contract OracleSignatureVerifierTest is Test {
    // secp256k1 group order, for building high-s signatures.
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    OracleSignatureVerifier internal verifier;
    address internal owner = makeAddr("owner");
    address internal stranger = makeAddr("stranger");
    address internal oracle;
    uint256 internal oracleKey;
    bytes32 internal digest = keccak256("some EIP-712 digest");

    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);

    function setUp() public {
        (oracle, oracleKey) = makeAddrAndKey("oracle");
        verifier = new OracleSignatureVerifier(owner);
        vm.prank(owner);
        verifier.addSigner(oracle);
    }

    function _sig(uint256 key, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, d);
        return abi.encodePacked(r, s, v);
    }

    function _evidence(uint256 key, bytes32 d) internal pure returns (bytes memory) {
        return abi.encode(_sig(key, d));
    }

    // ------------------------------------------------------------------------------------------------------
    // Metadata and ownership
    // ------------------------------------------------------------------------------------------------------

    function test_metadata() public view {
        assertEq(verifier.VERSION(), "1.0.0");
        assertEq(verifier.METHOD_ID(), 1);
        assertEq(verifier.owner(), owner);
        assertEq(verifier.signerCount(), 1);
        assertTrue(verifier.isSigner(oracle));
    }

    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new OracleSignatureVerifier(address(0));
    }

    function test_renounceOwnership_disabled() public {
        vm.prank(owner);
        vm.expectRevert(OwnableNoRenounce.RenounceOwnershipDisabled.selector);
        verifier.renounceOwnership();
    }

    function test_renounceOwnership_onlyOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        verifier.renounceOwnership();
    }

    function test_twoStepOwnershipTransfer() public {
        address multisig = makeAddr("multisig");
        vm.prank(owner);
        verifier.transferOwnership(multisig);
        assertEq(verifier.owner(), owner);
        assertEq(verifier.pendingOwner(), multisig);
        vm.prank(multisig);
        verifier.acceptOwnership();
        assertEq(verifier.owner(), multisig);
    }

    // ------------------------------------------------------------------------------------------------------
    // Signer management
    // ------------------------------------------------------------------------------------------------------

    function test_addSigner() public {
        address s = makeAddr("second");
        vm.expectEmit(address(verifier));
        emit SignerAdded(s);
        vm.prank(owner);
        verifier.addSigner(s);
        assertTrue(verifier.isSigner(s));
        assertEq(verifier.signerCount(), 2);
    }

    function test_addSigner_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        verifier.addSigner(stranger);
    }

    function test_addSigner_revertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(OracleSignatureVerifier.ZeroSigner.selector);
        verifier.addSigner(address(0));
    }

    function test_addSigner_revertsOnDuplicate() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(OracleSignatureVerifier.SignerAlreadyAdded.selector, oracle));
        verifier.addSigner(oracle);
    }

    function test_removeSigner() public {
        vm.expectEmit(address(verifier));
        emit SignerRemoved(oracle);
        vm.prank(owner);
        verifier.removeSigner(oracle);
        assertFalse(verifier.isSigner(oracle));
        assertEq(verifier.signerCount(), 0);
        assertFalse(verifier.verify(digest, _evidence(oracleKey, digest)));
    }

    function test_removeSigner_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        verifier.removeSigner(oracle);
    }

    function test_removeSigner_revertsWhenUnknown() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(OracleSignatureVerifier.SignerNotFound.selector, stranger));
        verifier.removeSigner(stranger);
    }

    // ------------------------------------------------------------------------------------------------------
    // verify
    // ------------------------------------------------------------------------------------------------------

    function test_verify_validSignature() public view {
        bytes memory evidence = _evidence(oracleKey, digest);
        assertEq(evidence.length, 160);
        assertTrue(verifier.verify(digest, evidence));
        (bool ok, address signer) = verifier.recoverSigner(digest, evidence);
        assertTrue(ok);
        assertEq(signer, oracle);
    }

    function test_verify_doesNotRehashDigest() public view {
        // A signature over keccak256(digest) or over the EIP-191 wrapped digest must not verify.
        assertFalse(verifier.verify(digest, _evidence(oracleKey, keccak256(abi.encode(digest)))));
        bytes32 eip191 = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        assertFalse(verifier.verify(digest, _evidence(oracleKey, eip191)));
    }

    function test_verify_unknownSigner() public {
        (, uint256 otherKey) = makeAddrAndKey("not-an-oracle");
        assertFalse(verifier.verify(digest, _evidence(otherKey, digest)));
        (bool ok,) = verifier.recoverSigner(digest, _evidence(otherKey, digest));
        assertTrue(ok);
    }

    function test_verify_wrongDigest() public view {
        assertFalse(verifier.verify(keccak256("other"), _evidence(oracleKey, digest)));
    }

    function test_verify_emptyEvidence() public view {
        assertFalse(verifier.verify(digest, ""));
    }

    function test_verify_rawSignatureNotAbiEncoded() public view {
        assertFalse(verifier.verify(digest, _sig(oracleKey, digest)));
    }

    function test_verify_wrongSignatureLength64() public view {
        (, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        assertFalse(verifier.verify(digest, abi.encode(abi.encodePacked(r, s))));
    }

    function test_verify_wrongSignatureLength66() public view {
        bytes memory sig = abi.encodePacked(_sig(oracleKey, digest), bytes1(0));
        bytes memory evidence = abi.encode(sig);
        assertEq(evidence.length, 160);
        assertFalse(verifier.verify(digest, evidence));
    }

    function test_verify_nonCanonicalOffset() public view {
        bytes memory evidence = _evidence(oracleKey, digest);
        evidence[31] = 0x40;
        assertFalse(verifier.verify(digest, evidence));
    }

    function test_verify_nonZeroPadding() public view {
        bytes memory evidence = _evidence(oracleKey, digest);
        evidence[159] = 0x01;
        assertFalse(verifier.verify(digest, evidence));
    }

    function test_verify_trailingBytes() public view {
        bytes memory evidence = abi.encodePacked(_evidence(oracleKey, digest), bytes32(0));
        assertFalse(verifier.verify(digest, evidence));
    }

    function test_verify_highSRejected() public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        bytes32 highS = bytes32(N - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        // The malleable twin recovers to the same key with the raw precompile ...
        assertEq(ecrecover(digest, flippedV, r, highS), oracle);
        // ... but the verifier rejects it.
        assertFalse(verifier.verify(digest, abi.encode(abi.encodePacked(r, highS, flippedV))));
    }

    function test_verify_invalidV() public view {
        (, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        assertFalse(verifier.verify(digest, abi.encode(abi.encodePacked(r, s, uint8(0)))));
        assertFalse(verifier.verify(digest, abi.encode(abi.encodePacked(r, s, uint8(1)))));
        assertFalse(verifier.verify(digest, abi.encode(abi.encodePacked(r, s, uint8(29)))));
    }

    function test_verify_zeroSignature() public view {
        assertFalse(verifier.verify(digest, abi.encode(new bytes(65))));
    }

    function testFuzz_verify_neverRevertsOnGarbage(bytes32 d, bytes calldata evidence) public view {
        // Must not revert, and garbage is never accepted by chance for this signer set.
        bool ok = verifier.verify(d, evidence);
        if (ok) {
            (, address signer) = verifier.recoverSigner(d, evidence);
            assertEq(signer, oracle);
        }
    }

    function testFuzz_verify_garbageInCanonicalShell(bytes32 d, bytes32 r, bytes32 s, uint8 v) public view {
        bytes memory evidence = abi.encode(abi.encodePacked(r, s, v));
        bool ok = verifier.verify(d, evidence);
        address recovered = ecrecover(d, v, r, s);
        if (ok) assertEq(recovered, oracle);
    }

    function testFuzz_verify_signedByOracle(uint256 seed) public view {
        bytes32 d = keccak256(abi.encode(seed));
        assertTrue(verifier.verify(d, _evidence(oracleKey, d)));
    }
}
