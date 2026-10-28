// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {DeploymentRegistry} from "../src/DeploymentRegistry.sol";
import {IDeploymentRegistry} from "../src/interfaces/IDeploymentRegistry.sol";
import {SealedTest} from "./utils/SealedTest.sol";

/// @notice Pins the exact EIP-712 typed-data layout of Record and Heartbeat. Every digest is recomputed by hand
///         (abi.encode of the typehash literal and fields, then "\x19\x01" || domainSeparator || structHash) and
///         compared to the contract, and a fixed known-answer vector computed independently with `cast` (see
///         README "EIP-712 vectors") is checked at a fixed address on chain id 4217.
contract DeploymentRegistryEIP712Test is SealedTest {
    string internal constant RECORD_TYPE =
        "Record(bytes32 deploymentId,address customer,bytes32 stackHash,bytes32 imageId,bytes32 quoteHash,bytes32 eventLogHash,bytes32 configHash,address enclaveSigner,uint64 attestedAt)";
    string internal constant HEARTBEAT_TYPE = "Heartbeat(bytes32 deploymentId,bytes32 quoteHash,uint64 attestedAt)";
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    // Known-answer vector (computed with cast, see README).
    address internal constant VECTOR_CONTRACT = 0x5EA1eD0000000000000000000000000000000001;
    uint256 internal constant VECTOR_CHAIN_ID = 4217;
    bytes32 internal constant VECTOR_DOMAIN_SEPARATOR =
        0x167ac8767ef1192a681f7e1f22a6805d72c9d61b38bd42836ede9c4cec7ceb62;
    bytes32 internal constant VECTOR_RECORD_TYPEHASH =
        0x5006c22389c5fdb42fd699c22f11658c5ea40d3486a5bb2f8e7639b99e136c09;
    bytes32 internal constant VECTOR_HEARTBEAT_TYPEHASH =
        0x5a6a40c52f1b097970a0b914f2d09952d22fea27be00600dacb989697a697750;
    bytes32 internal constant VECTOR_RECORD_DIGEST =
        0x5b22ad0f2f063b043d53295ce89d6b6bf35afed7ada6893a7cc27dfc4781dfcd;
    bytes32 internal constant VECTOR_HEARTBEAT_DIGEST =
        0xb12fb41b09faf4de1d741817dcb19ff0a34f7179feed00bb18f71e924006952d;
    /// @dev `cast wallet sign --no-hash <VECTOR_RECORD_DIGEST>` with anvil dev key #2.
    bytes internal constant VECTOR_ORACLE_SIG =
        hex"e1f5a46ede8037c8bb0b4a97fe91f07a4ca0a20558838f56fad1e6c2fd0e36a55d270090dcfe096cffa0ecf211b1f881c02bd09e7255ac17257b475d3e233f811b";
    address internal constant VECTOR_ORACLE = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;

    function _handDomainSeparator(address verifyingContract, uint256 chainId) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH, keccak256("Sealed DeploymentRegistry"), keccak256("1"), chainId, verifyingContract
            )
        );
    }

    function _handRecordDigest(IDeploymentRegistry.Record memory r, bytes32 domainSeparator)
        internal
        pure
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(bytes(RECORD_TYPE)),
                r.deploymentId,
                r.customer,
                r.stackHash,
                r.imageId,
                r.quoteHash,
                r.eventLogHash,
                r.configHash,
                r.enclaveSigner,
                r.attestedAt
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _handHeartbeatDigest(bytes32 id, bytes32 quoteHash, uint64 attestedAt, bytes32 domainSeparator)
        internal
        pure
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(keccak256(bytes(HEARTBEAT_TYPE)), id, quoteHash, attestedAt));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _vectorRecord() internal pure returns (IDeploymentRegistry.Record memory) {
        return IDeploymentRegistry.Record({
            deploymentId: keccak256("deployment"),
            customer: 0x1111111111111111111111111111111111111111,
            stackHash: keccak256("stack"),
            imageId: keccak256("image"),
            quoteHash: keccak256("quote"),
            eventLogHash: keccak256("eventlog"),
            configHash: keccak256("config"),
            enclaveSigner: 0x2222222222222222222222222222222222222222,
            attestedAt: 1_730_000_000
        });
    }

    // ------------------------------------------------------------------------------------------------------
    // Typehashes and domain
    // ------------------------------------------------------------------------------------------------------

    function test_typehashes() public view {
        assertEq(registry.RECORD_TYPEHASH(), keccak256(bytes(RECORD_TYPE)));
        assertEq(registry.HEARTBEAT_TYPEHASH(), keccak256(bytes(HEARTBEAT_TYPE)));
        assertEq(registry.RECORD_TYPEHASH(), VECTOR_RECORD_TYPEHASH);
        assertEq(registry.HEARTBEAT_TYPEHASH(), VECTOR_HEARTBEAT_TYPEHASH);
    }

    function test_domainSeparator() public view {
        assertEq(registry.domainSeparator(), _handDomainSeparator(address(registry), block.chainid));
    }

    function test_eip712Domain() public view {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = registry.eip712Domain();
        assertEq(fields, hex"0f");
        assertEq(name, "Sealed DeploymentRegistry");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(registry));
        assertEq(salt, bytes32(0));
        assertEq(extensions.length, 0);
    }

    function test_domainSeparator_tracksChainId() public {
        bytes32 before = registry.domainSeparator();
        vm.chainId(4217);
        assertTrue(registry.domainSeparator() != before);
        assertEq(registry.domainSeparator(), _handDomainSeparator(address(registry), 4217));
    }

    // ------------------------------------------------------------------------------------------------------
    // Digests
    // ------------------------------------------------------------------------------------------------------

    function test_recordDigest_matchesHandRolled() public view {
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(42)));
        assertEq(registry.recordDigest(r), _handRecordDigest(r, registry.domainSeparator()));
    }

    function test_heartbeatDigest_matchesHandRolled() public view {
        bytes32 id = keccak256("d");
        assertEq(
            registry.heartbeatDigest(id, keccak256("q"), 123),
            _handHeartbeatDigest(id, keccak256("q"), 123, registry.domainSeparator())
        );
    }

    function testFuzz_recordDigest_matchesHandRolled(IDeploymentRegistry.Record memory r) public view {
        assertEq(registry.recordDigest(r), _handRecordDigest(r, registry.domainSeparator()));
    }

    function testFuzz_heartbeatDigest_matchesHandRolled(bytes32 id, bytes32 q, uint64 t) public view {
        assertEq(registry.heartbeatDigest(id, q, t), _handHeartbeatDigest(id, q, t, registry.domainSeparator()));
    }

    function testFuzz_recordDigest_everyFieldMatters(IDeploymentRegistry.Record memory r, uint8 field) public view {
        bytes32 base = registry.recordDigest(r);
        field = uint8(bound(field, 0, 8));
        if (field == 0) r.deploymentId = ~r.deploymentId;
        if (field == 1) r.customer = address(~uint160(r.customer));
        if (field == 2) r.stackHash = ~r.stackHash;
        if (field == 3) r.imageId = ~r.imageId;
        if (field == 4) r.quoteHash = ~r.quoteHash;
        if (field == 5) r.eventLogHash = ~r.eventLogHash;
        if (field == 6) r.configHash = ~r.configHash;
        if (field == 7) r.enclaveSigner = address(~uint160(r.enclaveSigner));
        if (field == 8) r.attestedAt = ~r.attestedAt;
        assertTrue(registry.recordDigest(r) != base);
    }

    function test_recordAndHeartbeatDigestsDiffer() public view {
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(1)));
        assertTrue(registry.recordDigest(r) != registry.heartbeatDigest(r.deploymentId, r.quoteHash, r.attestedAt));
    }

    // ------------------------------------------------------------------------------------------------------
    // Signing with a generated oracle key
    // ------------------------------------------------------------------------------------------------------

    function test_oracleSignatureOverHandRolledDigestRegisters() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(9)));
        bytes32 digest = _handRecordDigest(r, _handDomainSeparator(address(registry), block.chainid));
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(oracleKey, digest);
        registry.registerDeployment(r, 1, abi.encode(abi.encodePacked(rr, s, v)));
        assertEq(registry.getDeployment(r.deploymentId).customer, customer);

        vm.warp(block.timestamp + 60);
        uint64 t = uint64(block.timestamp);
        bytes32 hb = _handHeartbeatDigest(r.deploymentId, keccak256("q2"), t, registry.domainSeparator());
        (v, rr, s) = vm.sign(oracleKey, hb);
        registry.heartbeat(r.deploymentId, keccak256("q2"), t, 1, abi.encode(abi.encodePacked(rr, s, v)));
        assertEq(registry.getDeployment(r.deploymentId).lastAttestedAt, t);
    }

    function test_signatureForOtherChainRejected() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(9)));
        bytes32 otherChain = _handRecordDigest(r, _handDomainSeparator(address(registry), 1));
        bytes memory evidence = _sign(oracleKey, otherChain);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidAttestation.selector, 1));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_signatureForOtherRegistryRejected() public {
        _approveDefault();
        DeploymentRegistry other = new DeploymentRegistry(owner, platform, apps);
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(9)));
        bytes memory evidence = _sign(oracleKey, other.recordDigest(r));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidAttestation.selector, 1));
        registry.registerDeployment(r, 1, evidence);
    }

    // ------------------------------------------------------------------------------------------------------
    // Known-answer vector (cross-checked with cast)
    // ------------------------------------------------------------------------------------------------------

    function test_knownAnswerVector() public {
        vm.chainId(VECTOR_CHAIN_ID);
        deployCodeTo("DeploymentRegistry.sol:DeploymentRegistry", abi.encode(owner, platform, apps), VECTOR_CONTRACT);
        DeploymentRegistry fixedRegistry = DeploymentRegistry(VECTOR_CONTRACT);

        assertEq(fixedRegistry.domainSeparator(), VECTOR_DOMAIN_SEPARATOR, "domain separator");
        IDeploymentRegistry.Record memory r = _vectorRecord();
        assertEq(fixedRegistry.recordDigest(r), VECTOR_RECORD_DIGEST, "record digest");
        assertEq(
            fixedRegistry.heartbeatDigest(r.deploymentId, keccak256("quote-2"), 1_730_003_600),
            VECTOR_HEARTBEAT_DIGEST,
            "heartbeat digest"
        );
        assertEq(_handRecordDigest(r, VECTOR_DOMAIN_SEPARATOR), VECTOR_RECORD_DIGEST);

        // The cast-produced signature verifies with the oracle verifier once its signer is allowed.
        vm.prank(owner);
        oracleVerifier.addSigner(VECTOR_ORACLE);
        assertTrue(oracleVerifier.verify(VECTOR_RECORD_DIGEST, abi.encode(VECTOR_ORACLE_SIG)));
    }
}
