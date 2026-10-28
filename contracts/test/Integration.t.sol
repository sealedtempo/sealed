// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {DeploymentRegistry} from "../src/DeploymentRegistry.sol";
import {FeeSplitter} from "../src/FeeSplitter.sol";
import {IDeploymentRegistry} from "../src/interfaces/IDeploymentRegistry.sol";
import {SealedTest} from "./utils/SealedTest.sol";

/// @notice The whole lifecycle in one test: catalog, approval, attested registration, heartbeat, fees, withdrawals,
///         incident response (release revoke) and close.
contract IntegrationTest is SealedTest {
    function test_fullLifecycle() public {
        // Customer approves a stack of two releases on the approved image.
        _approveDefault();
        assertTrue(registry.isStackApproved(customer, stackHash));

        // The oracle attests; ops submits the record.
        IDeploymentRegistry.Record memory r = _record(keccak256("salt"));
        _register(r);
        bytes32 id = r.deploymentId;
        assertTrue(registry.appInDeployment(id, appA));

        // An hour later the agent heartbeats with a fresh quote.
        vm.warp(block.timestamp + 1 hours);
        bytes32 q2 = keccak256("quote-2");
        uint64 t2 = uint64(block.timestamp);
        registry.heartbeat(id, q2, t2, 1, _heartbeatEvidence(id, q2, t2));

        // The enclave signer settles usage for both apps.
        _fund(enclaveSigner, 10_000_000);
        bytes32 usage = keccak256("usage-report");
        vm.startPrank(enclaveSigner);
        splitter.payFees(id, appA, address(token), 2_500_000, usage);
        splitter.payFees(id, appB, address(token), 1_000_000, usage);
        vm.stopPrank();
        assertEq(splitter.credited(address(token), maintainer), 500_000 + 200_000);
        assertEq(splitter.credited(address(token), treasury), 2_000_000 + 800_000);

        // Maintainer and treasury withdraw.
        vm.prank(maintainer);
        splitter.withdraw(address(token));
        vm.prank(treasury);
        splitter.withdraw(address(token));
        assertEq(token.balanceOf(maintainer), 700_000);
        assertEq(token.balanceOf(treasury), 2_800_000);
        assertEq(token.balanceOf(address(splitter)), 0);

        // Incident: release B is revoked. The stack stops being approved and heartbeats fail.
        vm.prank(owner);
        apps.revokeRelease(releaseB, "CVE-2026-0001");
        assertFalse(registry.isStackApproved(customer, stackHash));
        vm.warp(block.timestamp + 1 hours);
        uint64 t3 = uint64(block.timestamp);
        bytes memory hb3 = _heartbeatEvidence(id, q2, t3);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.heartbeat(id, q2, t3, 1, hb3);

        // Outstanding usage can still be settled, then the customer closes the deployment.
        vm.prank(customer);
        token.approve(address(splitter), type(uint256).max);
        _fund(customer, 1_000_000);
        vm.prank(customer);
        splitter.payFees(id, appA, address(token), 100, keccak256("final-usage"));
        vm.prank(customer);
        registry.closeDeployment(id);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.DeploymentNotActive.selector, id));
        splitter.payFees(id, appA, address(token), 100, keccak256("late-usage"));
    }
}
