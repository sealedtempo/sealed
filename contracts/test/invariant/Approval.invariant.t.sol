// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {SealedTest} from "../utils/SealedTest.sol";
import {ApprovalHandler} from "./ApprovalHandler.sol";

/// @notice isStackApproved matches an independent model at every step, and in particular is never true after the
///         approval was revoked, after it expired, after any of its releases was revoked, or after its image was
///         revoked (or deprecated, or is a debug image).
contract ApprovalInvariantTest is SealedTest {
    ApprovalHandler internal handler;

    function setUp() public override {
        super.setUp();
        bytes32 appC = _registerApp("scraper", 0);
        bytes32[] memory appIds = new bytes32[](3);
        appIds[0] = appA;
        appIds[1] = appB;
        appIds[2] = appC;

        bytes32[] memory rel = new bytes32[](5);
        rel[0] = releaseA;
        rel[1] = releaseB;
        rel[2] = _publish(appA, "1.1.0");
        rel[3] = _publish(appB, "1.1.0");
        rel[4] = _publish(appC, "1.0.0");

        bytes32[] memory imgs = new bytes32[](3);
        bool[] memory debug = new bool[](3);
        imgs[0] = imageId;
        imgs[1] = _addImage("sealed-os", "1.1.0", false);
        imgs[2] = _addImage("sealed-os-debug", "1.1.0", true);
        debug[2] = true;

        handler = new ApprovalHandler(registry, apps, platform, owner, ops, appIds, rel, imgs, debug);
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](10);
        selectors[0] = ApprovalHandler.approve.selector;
        selectors[1] = ApprovalHandler.revokeStack.selector;
        selectors[2] = ApprovalHandler.deprecateRelease.selector;
        selectors[3] = ApprovalHandler.revokeRelease.selector;
        selectors[4] = ApprovalHandler.publishRelease.selector;
        selectors[5] = ApprovalHandler.deprecateImage.selector;
        selectors[6] = ApprovalHandler.revokeImage.selector;
        selectors[7] = ApprovalHandler.addImage.selector;
        selectors[8] = ApprovalHandler.warp.selector;
        selectors[9] = ApprovalHandler.approve.selector; // weight approvals higher
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_isStackApprovedMatchesModel() public view {
        for (uint256 i; i < handler.customerCount(); ++i) {
            address c = handler.customers(i);
            for (uint256 j; j < handler.stackCount(); ++j) {
                bytes32 s = handler.stacks(j);
                assertEq(registry.isStackApproved(c, s), handler.expectedApproved(c, s), "model mismatch");
            }
        }
    }

    function invariant_neverApprovedAfterRevokeExpiryOrCatalogRevoke() public view {
        for (uint256 i; i < handler.customerCount(); ++i) {
            address c = handler.customers(i);
            for (uint256 j; j < handler.stackCount(); ++j) {
                bytes32 s = handler.stacks(j);
                if (!registry.isStackApproved(c, s)) continue;
                (bool exists, bool revoked, uint64 expiry, bytes32 img, bytes32[] memory ids) =
                    handler.ghostApproval(c, s);
                assertTrue(exists, "approved without approval");
                assertFalse(revoked, "approved after stack revoke");
                // forge-lint: disable-next-line(block-timestamp)
                assertTrue(expiry == 0 || block.timestamp < expiry, "approved after expiry");
                assertEq(uint8(handler.imageStatus(img)), uint8(ApprovalHandler.S.Active), "approved with bad image");
                assertFalse(handler.imageDebug(img), "approved with debug image");
                for (uint256 k; k < ids.length; ++k) {
                    assertTrue(
                        handler.releaseStatus(ids[k]) != ApprovalHandler.S.Revoked, "approved with revoked release"
                    );
                }
            }
        }
    }

    function invariant_storedApprovalMatchesModel() public view {
        for (uint256 i; i < handler.customerCount(); ++i) {
            address c = handler.customers(i);
            for (uint256 j; j < handler.stackCount(); ++j) {
                bytes32 s = handler.stacks(j);
                (bool exists, bool revoked, uint64 expiry, bytes32 img, bytes32[] memory ids) =
                    handler.ghostApproval(c, s);
                (bytes32[] memory gotIds, bytes32 gotImg, uint64 gotExpiry, bool gotRevoked, uint64 approvedAt) =
                    registry.getStackApproval(c, s);
                assertEq(approvedAt != 0, exists);
                assertEq(gotRevoked, revoked);
                assertEq(gotExpiry, expiry);
                assertEq(gotImg, img);
                assertEq(gotIds.length, ids.length);
                for (uint256 k; k < ids.length; ++k) {
                    assertEq(gotIds[k], ids[k]);
                }
            }
        }
    }

    function invariant_handlerPredictionsHeld() public view {
        assertFalse(handler.unexpectedOutcome(), "approveStack accepted or rejected unexpectedly");
    }

    /// @dev Sanity check that the handler reaches the positive path: one fixed sequence, counting successes.
    function test_handlerProducesApprovedStacks() public {
        uint256 approvedSeen;
        for (uint256 i; i < 200; ++i) {
            uint256 seed = uint256(keccak256(abi.encode(i)));
            uint256 action = seed % 6;
            if (action <= 2) {
                handler.approve(seed, seed >> 8, seed >> 16, seed >> 24, seed >> 32, (seed >> 40) % 2 == 0);
            } else if (action == 3) {
                handler.revokeStack(seed, seed >> 8);
            } else if (action == 4) {
                handler.revokeRelease(seed >> 8);
            } else {
                handler.warp(seed >> 8);
            }
            for (uint256 c; c < handler.customerCount(); ++c) {
                for (uint256 s; s < handler.stackCount(); ++s) {
                    bool got = registry.isStackApproved(handler.customers(c), handler.stacks(s));
                    assertEq(got, handler.expectedApproved(handler.customers(c), handler.stacks(s)));
                    if (got) ++approvedSeen;
                }
            }
        }
        assertGt(handler.calls("approve"), 20, "successful approvals");
        assertGt(handler.calls("approveRejected"), 0, "rejected approvals");
        assertGt(approvedSeen, 50, "approved states observed");
    }
}
