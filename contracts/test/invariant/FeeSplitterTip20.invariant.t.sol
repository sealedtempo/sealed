// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {FeeSplitter} from "../../src/FeeSplitter.sol";
import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";
import {ITIP20, Tip20} from "../utils/Tip20.sol";
import {SealedTest} from "../utils/SealedTest.sol";
import {FeeSplitterTip20Handler} from "./FeeSplitterTip20Handler.sol";

/// @notice FeeSplitter on real TIP-20 tokens (local Tempo genesis precompiles) with TIP-403 blacklists and token
///         pauses: every credit equals the model (each payment split into exactly the maintainer's floor share and
///         the treasury's rest, nothing else moved), the sum of credits equals totalCredited and the token
///         balance, no credit is ever owed to an address that can never withdraw, and a payment or withdrawal
///         that a token failure stops reverts cleanly and can be retried.
contract FeeSplitterTip20InvariantTest is SealedTest {
    FeeSplitter internal tsplitter;
    FeeSplitterTip20Handler internal handler;

    function setUp() public override {
        super.setUp();
        ITIP20 alpha = Tip20.ALPHA_USD;
        ITIP20 beta = Tip20.BETA_USD;
        tsplitter = new FeeSplitter(owner, registry, apps, address(alpha), treasury, PER_PAYMENT_CAP, DAILY_CAP);
        vm.prank(owner);
        tsplitter.setToken(address(beta), true, 3_000_000, 10_000_000);

        // Two customers, each with an approved stack and one deployment.
        _approveDefault();
        IDeploymentRegistry.Record memory r1 = _record(bytes32(uint256(1)));
        _register(r1);
        (address customer2,) = makeAddrAndKey("tip20-customer2");
        address signer2 = makeAddr("tip20-enclaveSigner2");
        bytes32 stack2 = keccak256("tip20-stack-2");
        _approve(customer2, stack2, _releases2(), imageId, 0);
        IDeploymentRegistry.Record memory r2 = IDeploymentRegistry.Record({
            deploymentId: _deploymentId(customer2, stack2, bytes32(uint256(2))),
            customer: customer2,
            stackHash: stack2,
            imageId: imageId,
            quoteHash: keccak256("tq2"),
            eventLogHash: keccak256("te2"),
            configHash: keccak256("tc2"),
            enclaveSigner: signer2,
            attestedAt: uint64(block.timestamp)
        });
        _register(r2);

        ITIP20[] memory ts = new ITIP20[](2);
        ts[0] = alpha;
        ts[1] = beta;
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
        handler = new FeeSplitterTip20Handler(tsplitter, apps, owner, ts, ids, payers, appIds, initial);

        // This test contract is the genesis admin of the local TIP-20s. Fund the payers, give the handler the
        // issuer and pause roles, and bind each token to a fresh blacklist administered by the handler.
        for (uint256 t; t < ts.length; ++t) {
            ITIP20 token_ = ts[t];
            token_.grantRole(token_.ISSUER_ROLE(), address(this));
            token_.grantRole(token_.ISSUER_ROLE(), address(handler));
            token_.grantRole(token_.PAUSE_ROLE(), address(handler));
            token_.grantRole(token_.UNPAUSE_ROLE(), address(handler));
            for (uint256 d; d < payers.length; ++d) {
                for (uint256 p; p < 2; ++p) {
                    token_.mint(payers[d][p], 1e15);
                    vm.prank(payers[d][p]);
                    token_.approve(address(tsplitter), type(uint256).max);
                }
            }
            uint64 policyId = Tip20.REGISTRY.createPolicy(address(handler), Tip20.BLACKLIST);
            token_.changeTransferPolicyId(policyId);
            handler.setPolicy(address(token_), policyId);
        }

        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](20);
        selectors[0] = FeeSplitterTip20Handler.payFees.selector;
        selectors[1] = FeeSplitterTip20Handler.payFees.selector;
        selectors[2] = FeeSplitterTip20Handler.topUpFees.selector;
        selectors[3] = FeeSplitterTip20Handler.retryFailed.selector;
        selectors[4] = FeeSplitterTip20Handler.withdraw.selector;
        selectors[5] = FeeSplitterTip20Handler.withdraw.selector;
        selectors[6] = FeeSplitterTip20Handler.setBlocked.selector;
        selectors[7] = FeeSplitterTip20Handler.setBlocked.selector;
        selectors[8] = FeeSplitterTip20Handler.unblockAll.selector;
        selectors[9] = FeeSplitterTip20Handler.setTokenPaused.selector;
        selectors[10] = FeeSplitterTip20Handler.setSplitterPaused.selector;
        selectors[11] = FeeSplitterTip20Handler.setMaintainer.selector;
        selectors[12] = FeeSplitterTip20Handler.setMaintainerShare.selector;
        selectors[13] = FeeSplitterTip20Handler.setTreasury.selector;
        selectors[14] = FeeSplitterTip20Handler.setCaps.selector;
        selectors[15] = FeeSplitterTip20Handler.directTransferAndSweep.selector;
        selectors[16] = FeeSplitterTip20Handler.warp.selector;
        selectors[17] = FeeSplitterTip20Handler.retryFailed.selector;
        selectors[18] = FeeSplitterTip20Handler.setAllowance.selector;
        selectors[19] = FeeSplitterTip20Handler.setBalance.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_creditsMatchModel() public view {
        uint256 tokenCount = handler.tokenCount();
        uint256 accountCount = handler.accountCount();
        for (uint256 t; t < tokenCount; ++t) {
            address tk = address(handler.tokens(t));
            uint256 sum;
            for (uint256 a; a < accountCount; ++a) {
                address account = handler.accounts(a);
                uint256 c = tsplitter.credited(tk, account);
                assertEq(c, handler.ghostCredit(tk, account), "credit == sum of this account's shares");
                if (handler.cannotWithdraw(account)) assertEq(c, 0, "credit owed to an address that cannot withdraw");
                sum += c;
            }
            assertEq(sum, tsplitter.totalCredited(tk), "sum of credits == totalCredited");
            assertEq(tsplitter.totalCredited(tk), ITIP20(tk).balanceOf(address(tsplitter)), "totalCredited == balance");
            assertEq(
                ITIP20(tk).balanceOf(address(tsplitter)),
                handler.ghostPaidIn(tk) + handler.ghostSwept(tk) - handler.ghostWithdrawn(tk),
                "balance == paid in + swept - withdrawn"
            );
        }
    }

    function invariant_noCreditOutsideTrackedAccounts() public view {
        assertTrue(handler.isAccount(tsplitter.treasury()), "treasury tracked");
        (address m1,) = apps.payoutInfo(appA);
        (address m2,) = apps.payoutInfo(appB);
        assertTrue(handler.isAccount(m1), "maintainer A tracked");
        assertTrue(handler.isAccount(m2), "maintainer B tracked");
    }

    function invariant_legsMatchModel() public view {
        uint256 n = handler.legCount();
        for (uint256 i; i < n; ++i) {
            FeeSplitterTip20Handler.Leg memory l = handler.leg(i);
            assertEq(
                tsplitter.usagePaid(l.deploymentId, l.usageHash, l.appId),
                handler.ghostLegPaid(handler.legKey(l.deploymentId, l.usageHash, l.appId)),
                "usagePaid == accepted payments of the leg"
            );
            assertEq(tsplitter.usageToken(l.deploymentId, l.usageHash, l.appId), address(l.token), "leg token");
        }
        // A payment a token failure stopped never opened its leg.
        uint256 f = handler.failedCount();
        for (uint256 i; i < f; ++i) {
            FeeSplitterTip20Handler.Failed memory p = handler.failed(i);
            assertEq(tsplitter.usagePaid(p.deploymentId, p.usageHash, p.appId), 0, "failed payment opened a leg");
            assertEq(tsplitter.usageToken(p.deploymentId, p.usageHash, p.appId), address(0), "failed payment token");
        }
    }

    function invariant_handlerPredictionsHeld() public view {
        assertFalse(handler.unexpectedOutcome(), handler.lastMismatch());
        assertFalse(handler.splitMismatch(), handler.lastMismatch());
        assertFalse(handler.dirtyRevert(), handler.lastMismatch());
    }

    /// @dev Sanity check that the handler reaches the failure paths and the redirect and same-account cases.
    function test_handlerReachesEveryPath() public {
        for (uint256 i; i < 1200; ++i) {
            uint256 seed = uint256(keccak256(abi.encode("tip20-path", i)));
            uint256 action = seed % 14;
            if (action <= 2) handler.payFees(seed >> 8, seed >> 16, seed >> 24, seed >> 32, seed % 2 == 0);
            else if (action == 3) handler.topUpFees(seed >> 8, seed >> 16, seed % 2 == 0);
            else if (action == 4) handler.retryFailed(seed >> 8);
            else if (action == 5) handler.withdraw(seed >> 8, seed >> 16);
            else if (action == 6) handler.setBlocked(seed >> 8, seed >> 16, seed >> 24);
            else if (action == 7 && i % 5 == 0) handler.unblockAll(seed >> 8);
            else if (action == 8) handler.setTokenPaused(seed >> 8, seed >> 16);
            else if (action == 9) handler.setSplitterPaused(seed >> 8);
            else if (action == 10) handler.setMaintainer(seed >> 8, seed >> 16);
            else if (action == 11) handler.setMaintainerShare(seed >> 8, seed >> 16);
            else if (action == 12) handler.setTreasury(seed >> 8);
            else if (seed % 3 == 0) handler.setAllowance(seed >> 8, seed >> 16, seed >> 24);
            else if (seed % 3 == 1) handler.setBalance(seed >> 8, seed >> 16, seed >> 24);
            else handler.warp(seed >> 8);
        }
        invariant_creditsMatchModel();
        invariant_legsMatchModel();
        invariant_handlerPredictionsHeld();
        string[17] memory paths = [
            "payFees-error-2",
            "payFees-error-4",
            "payFees-error-8",
            "payFees-error-16",
            "withdraw-error-4",
            "payFees",
            "payFeesFailed",
            "topUpFees",
            "topUpFeesFailed",
            "retryFailed",
            "withdraw",
            "withdrawFailed",
            "shareRedirectedToTreasury",
            "maintainerIsTreasury",
            "setTreasuryRejected",
            "tokenPause",
            "splitterPause"
        ];
        for (uint256 i; i < paths.length; ++i) {
            assertGt(handler.calls(paths[i]), 0, paths[i]);
        }
    }
}
