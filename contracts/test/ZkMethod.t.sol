// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {AttestationMethods} from "../src/IAttestationVerifier.sol";
import {DeploymentRegistry} from "../src/DeploymentRegistry.sol";
import {IDeploymentRegistry} from "../src/interfaces/IDeploymentRegistry.sol";
import {MockZkDcapVerifier} from "./mocks/MockVerifier.sol";
import {SealedTest} from "./utils/SealedTest.sol";

/// @notice Method 2 (ZK_DCAP_V1) is reserved and unset at deploy, and a verifier for it plugs in with setVerifier
///         alone: no other contract, storage or interface change.
contract ZkMethodTest is SealedTest {
    bytes32 internal constant PROOF_TAG = keccak256("sp1-dcap-proof");
    MockZkDcapVerifier internal zk;

    function setUp() public override {
        super.setUp();
        zk = new MockZkDcapVerifier(PROOF_TAG);
    }

    function _zkEvidence(bytes32 digest) internal pure returns (bytes memory) {
        return abi.encode(digest, PROOF_TAG);
    }

    function test_methodIds() public view {
        assertEq(AttestationMethods.ORACLE_SIG_V1, 1);
        assertEq(AttestationMethods.ZK_DCAP_V1, 2);
        assertEq(registry.METHOD_ZK_DCAP_V1(), AttestationMethods.ZK_DCAP_V1);
    }

    function test_methodTwoUnsetAtDeploy() public {
        assertEq(address(registry.verifiers(2)), address(0));
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(1)));
        bytes memory evidence = _zkEvidence(registry.recordDigest(r));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.VerifierNotSet.selector, 2));
        registry.registerDeployment(r, 2, evidence);
    }

    function test_plugInZkVerifierForMethodTwo() public {
        vm.prank(owner);
        registry.setVerifier(2, address(zk));

        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(1)));
        registry.registerDeployment(r, 2, _zkEvidence(registry.recordDigest(r)));
        IDeploymentRegistry.Deployment memory d = registry.getDeployment(r.deploymentId);
        assertEq(d.method, 2);
        assertEq(d.lastMethod, 2);

        // Heartbeats may use either method; the oracle path keeps working unchanged.
        vm.warp(block.timestamp + 60);
        uint64 t1 = uint64(block.timestamp);
        bytes32 q1 = keccak256("q1");
        registry.heartbeat(r.deploymentId, q1, t1, 2, _zkEvidence(registry.heartbeatDigest(r.deploymentId, q1, t1)));
        assertEq(registry.getDeployment(r.deploymentId).lastMethod, 2);

        vm.warp(block.timestamp + 60);
        uint64 t2 = uint64(block.timestamp);
        bytes32 q2 = keccak256("q2");
        registry.heartbeat(r.deploymentId, q2, t2, 1, _heartbeatEvidence(r.deploymentId, q2, t2));
        assertEq(registry.getDeployment(r.deploymentId).lastMethod, 1);
        assertEq(registry.getDeployment(r.deploymentId).method, 2, "registration method kept");

        // A record registered with the oracle method coexists.
        IDeploymentRegistry.Record memory r2 = _record(bytes32(uint256(2)));
        _register(r2);
        assertEq(registry.getDeployment(r2.deploymentId).method, 1);
    }

    function test_zkEvidenceForOtherDigestRejected() public {
        vm.prank(owner);
        registry.setVerifier(2, address(zk));
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidAttestation.selector, 2));
        registry.registerDeployment(r, 2, _zkEvidence(keccak256("other")));
    }

    function test_oracleSignatureNotAcceptedAsZkEvidence() public {
        vm.prank(owner);
        registry.setVerifier(2, address(zk));
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(1)));
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidAttestation.selector, 2));
        registry.registerDeployment(r, 2, evidence);
    }

    function test_unpluggingMethodTwo() public {
        vm.startPrank(owner);
        registry.setVerifier(2, address(zk));
        registry.setVerifier(2, address(0));
        vm.stopPrank();
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(1)));
        bytes memory evidence = _zkEvidence(registry.recordDigest(r));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.VerifierNotSet.selector, 2));
        registry.registerDeployment(r, 2, evidence);
    }

    function test_disablingOracleMethodLeavesZkWorking() public {
        vm.startPrank(owner);
        registry.setVerifier(2, address(zk));
        registry.setVerifier(1, address(0));
        vm.stopPrank();
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(1)));
        bytes memory oracleEvidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.VerifierNotSet.selector, 1));
        registry.registerDeployment(r, 1, oracleEvidence);
        registry.registerDeployment(r, 2, _zkEvidence(registry.recordDigest(r)));
    }
}
