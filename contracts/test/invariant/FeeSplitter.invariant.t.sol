// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {SealedTest} from "../utils/SealedTest.sol";
import {FeeSplitterHandler} from "./FeeSplitterHandler.sol";

/// @notice For every token: sum of credited balances == totalCredited == balanceOf(FeeSplitter), and the balance
///         equals paid in + swept - withdrawn. Payments above the day's remaining allowance are always rejected.
///         Every leg's usagePaid equals what payFees and topUpFees pulled for it.
contract FeeSplitterInvariantTest is SealedTest {
    FeeSplitterHandler internal handler;
    MockERC20 internal token2;

    function setUp() public override {
        super.setUp();
        token2 = new MockERC20("USD Coin (mock)", "USDC");
        vm.prank(owner);
        splitter.setToken(address(token2), true, 3_000_000, 10_000_000);

        // Two customers, each with an approved stack and one deployment.
        _approveDefault();
        IDeploymentRegistry.Record memory r1 = _record(bytes32(uint256(1)));
        _register(r1);

        (address customer2,) = makeAddrAndKey("customer2");
        address signer2 = makeAddr("enclaveSigner2");
        bytes32 stack2 = keccak256("stack-2");
        _approve(customer2, stack2, _releases2(), imageId, 0);
        IDeploymentRegistry.Record memory r2 = IDeploymentRegistry.Record({
            deploymentId: _deploymentId(customer2, stack2, bytes32(uint256(2))),
            customer: customer2,
            stackHash: stack2,
            imageId: imageId,
            quoteHash: keccak256("q2"),
            eventLogHash: keccak256("e2"),
            configHash: keccak256("c2"),
            enclaveSigner: signer2,
            attestedAt: uint64(block.timestamp)
        });
        _register(r2);

        MockERC20[] memory ts = new MockERC20[](2);
        ts[0] = token;
        ts[1] = token2;
        bytes32[] memory ids = new bytes32[](2);
        ids[0] = r1.deploymentId;
        ids[1] = r2.deploymentId;
        address[2][] memory payers = new address[2][](2);
        payers[0] = [customer, enclaveSigner];
        payers[1] = [customer2, signer2];
        bytes32[] memory appIds = new bytes32[](2);
        appIds[0] = appA;
        appIds[1] = appB;
        address[] memory initial = new address[](2);
        initial[0] = maintainer;
        initial[1] = treasury;

        handler = new FeeSplitterHandler(splitter, apps, registry, owner, ts, ids, payers, appIds, initial);
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](10);
        selectors[0] = FeeSplitterHandler.payFees.selector;
        selectors[1] = FeeSplitterHandler.withdraw.selector;
        selectors[2] = FeeSplitterHandler.setMaintainer.selector;
        selectors[3] = FeeSplitterHandler.setMaintainerShare.selector;
        selectors[4] = FeeSplitterHandler.setTreasury.selector;
        selectors[5] = FeeSplitterHandler.setCaps.selector;
        selectors[6] = FeeSplitterHandler.directTransferAndSweep.selector;
        selectors[7] = FeeSplitterHandler.warp.selector;
        selectors[8] = FeeSplitterHandler.payFeesOverDailyCap.selector;
        selectors[9] = FeeSplitterHandler.topUpFees.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_creditsEqualTotalEqualBalance() public view {
        uint256 tokenCount = handler.tokenCount();
        uint256 accountCount = handler.accountCount();
        for (uint256 t; t < tokenCount; ++t) {
            address tk = address(handler.tokens(t));
            uint256 sum;
            for (uint256 a; a < accountCount; ++a) {
                sum += splitter.credited(tk, handler.accounts(a));
            }
            assertEq(sum, splitter.totalCredited(tk), "sum of credits == totalCredited");
            assertEq(splitter.totalCredited(tk), MockERC20(tk).balanceOf(address(splitter)), "totalCredited == balance");
        }
    }

    function invariant_balanceMatchesGhostFlows() public view {
        uint256 tokenCount = handler.tokenCount();
        for (uint256 t; t < tokenCount; ++t) {
            address tk = address(handler.tokens(t));
            assertEq(
                MockERC20(tk).balanceOf(address(splitter)),
                handler.ghostPaidIn(tk) + handler.ghostSwept(tk) - handler.ghostWithdrawn(tk),
                "balance == in + swept - out"
            );
        }
    }

    function invariant_withdrawPaysExactCredit() public view {
        assertFalse(handler.withdrawMismatch(), "withdraw paid a different amount than the credit");
    }

    function invariant_dailyCapNeverExceeded() public view {
        assertFalse(handler.capViolated(), "payment above the daily cap was accepted");
        assertFalse(handler.unexpectedRevert(), "over-cap payment failed for another reason");
    }

    function invariant_dailyPaidMatchesGhost() public view {
        uint256 tokenCount = handler.tokenCount();
        uint256 depCount = handler.deploymentCount();
        uint256 day = block.timestamp / 1 days;
        for (uint256 t; t < tokenCount; ++t) {
            address tk = address(handler.tokens(t));
            for (uint256 d; d < depCount; ++d) {
                bytes32 id = handler.deploymentIds(d);
                uint256 paid = splitter.dailyPaid(id, tk, day);
                assertEq(paid, handler.ghostDaily(keccak256(abi.encode(id, tk, day))), "daily total tracked");
            }
        }
    }

    function invariant_legPaidMatchesPulls() public view {
        uint256 n = handler.legCount();
        for (uint256 i; i < n; ++i) {
            FeeSplitterHandler.Leg memory l = handler.leg(i);
            assertEq(
                splitter.usagePaid(l.deploymentId, l.usageHash, l.appId),
                handler.ghostLegPaid(handler.legKey(l.deploymentId, l.usageHash, l.appId)),
                "usagePaid == payFees amount + top-up differences"
            );
            assertGt(splitter.usagePaid(l.deploymentId, l.usageHash, l.appId), 0, "an opened leg is never 0");
        }
    }

    function invariant_noCreditWithoutTracking() public view {
        // The treasury and every maintainer are tracked accounts, so no credit can hide outside the sum.
        assertTrue(handler.isAccount(splitter.treasury()));
        (address m1,) = apps.payoutInfo(appA);
        (address m2,) = apps.payoutInfo(appB);
        assertTrue(handler.isAccount(m1));
        assertTrue(handler.isAccount(m2));
    }
}
