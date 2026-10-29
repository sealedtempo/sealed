// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {IAppRegistry} from "../../src/interfaces/IAppRegistry.sol";
import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";
import {IPlatformRegistry} from "../../src/interfaces/IPlatformRegistry.sol";
import {SealedTest} from "../utils/SealedTest.sol";
import {LifecycleHandler} from "./LifecycleHandler.sol";

/// @notice DeploymentRegistry as a state machine, with the real oracle verifier and FeeSplitter attached:
///         - a deployment is Active only after a record of a then-approved stack verified with a then-allowed
///           oracle signer, and every registration, heartbeat and close has the outcome the model predicts;
///         - Closed is terminal and release and image revocations are terminal;
///         - isStackApproved is false as soon as any release of the approval is revoked or its image is
///           deprecated, revoked or a debug image (and after revokeStack or expiry), and no heartbeat succeeds
///           on a stack that is not approved;
///         - usage legs never overlap: usagePaid of every (deployment, usageHash, app) equals what was paid on
///           exactly that key, although the same usageHash and app are paid on every deployment;
///         - payments are accepted only for Active deployments, from their customer or enclave signer, for apps
///           of their release set.
contract LifecycleInvariantTest is SealedTest {
    LifecycleHandler internal handler;

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

        handler = new LifecycleHandler(
            LifecycleHandler.Sys(registry, apps, platform, oracleVerifier, splitter, token, owner, ops),
            appIds,
            rel,
            imgs,
            debug
        );
        // Two of the three handler oracle keys start as signers; the third is a stranger until added.
        vm.startPrank(owner);
        oracleVerifier.addSigner(handler.oracleAddrs(0));
        oracleVerifier.addSigner(handler.oracleAddrs(1));
        vm.stopPrank();
        handler.seedSigners();
        // Every run starts with two live deployments of two approved stacks (valid seeds through the handler, so
        // the model stays exact).
        handler.approve(0, 0, 3, 0, 1, true);
        handler.approve(1, 1, 28, 1, 1, true);
        handler.register(0, 0, 0, 1, 0, 0);
        handler.register(0, 1, 0, 1, 0, 0);
        handler.register(0, 0, 1, 1, 0, 0);
        require(registry.deploymentCount() == 3 && !handler.unexpectedOutcome(), "seed deployments");

        targetContract(address(handler));
        // Weights: lifecycle steps often, catalog decay and admin changes rarely.
        bytes4[30] memory weighted = [
            LifecycleHandler.approve.selector,
            LifecycleHandler.approve.selector,
            LifecycleHandler.approve.selector,
            LifecycleHandler.revokeStack.selector,
            LifecycleHandler.register.selector,
            LifecycleHandler.register.selector,
            LifecycleHandler.register.selector,
            LifecycleHandler.register.selector,
            LifecycleHandler.register.selector,
            LifecycleHandler.heartbeat.selector,
            LifecycleHandler.heartbeat.selector,
            LifecycleHandler.heartbeat.selector,
            LifecycleHandler.heartbeat.selector,
            LifecycleHandler.close.selector,
            LifecycleHandler.pay.selector,
            LifecycleHandler.pay.selector,
            LifecycleHandler.pay.selector,
            LifecycleHandler.topUp.selector,
            LifecycleHandler.topUp.selector,
            LifecycleHandler.deprecateRelease.selector,
            LifecycleHandler.revokeRelease.selector,
            LifecycleHandler.publishRelease.selector,
            LifecycleHandler.deprecateImage.selector,
            LifecycleHandler.revokeImage.selector,
            LifecycleHandler.addImage.selector,
            LifecycleHandler.setSigner.selector,
            LifecycleHandler.pausePulse.selector,
            LifecycleHandler.setMaxAttestationAge.selector,
            LifecycleHandler.warp.selector,
            LifecycleHandler.warp.selector
        ];
        bytes4[] memory selectors = new bytes4[](weighted.length);
        for (uint256 i; i < weighted.length; ++i) {
            selectors[i] = weighted[i];
        }
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_handlerPredictionsHeld() public view {
        assertFalse(handler.unexpectedOutcome(), handler.lastMismatch());
        assertFalse(handler.registeredUnapproved(), "registered a deployment of an unapproved stack");
        assertFalse(handler.heartbeatOnUnapproved(), "heartbeat accepted for an unapproved stack");
        assertFalse(handler.paidWhileNotActive(), "payment accepted for a deployment that is not Active");
    }

    /// @dev Status and stored fields of every deployment equal the model; Closed stays Closed with its closedAt.
    function invariant_deploymentsMatchModel() public view {
        (,,,,, uint256 d) = handler.counts();
        assertEq(registry.deploymentCount(), d, "deploymentCount");
        for (uint256 i; i < d; ++i) {
            bytes32 id = handler.depIds(i);
            LifecycleHandler.GDep memory g = handler.dep(id);
            IDeploymentRegistry.Deployment memory got = registry.getDeployment(id);
            assertEq(uint8(got.status), g.status, "status");
            assertEq(got.deploymentId, id, "deploymentId");
            assertEq(got.customer, g.customer, "customer");
            assertEq(got.stackHash, g.stackHash, "stackHash");
            assertEq(got.imageId, g.imageId, "imageId");
            assertEq(got.enclaveSigner, g.enclaveSigner, "enclaveSigner");
            assertEq(got.attestedAt, g.attestedAt, "attestedAt");
            assertEq(got.lastAttestedAt, g.lastAttestedAt, "lastAttestedAt");
            assertGe(got.lastAttestedAt, got.attestedAt, "lastAttestedAt >= attestedAt");
            assertEq(got.quoteHash, g.quoteHash, "quoteHash");
            assertEq(got.configHash, g.configHash, "configHash");
            assertEq(got.registeredAt, g.registeredAt, "registeredAt");
            assertEq(got.closedAt, g.closedAt, "closedAt");
            assertEq(got.method, 1, "method");
            (IDeploymentRegistry.DeploymentStatus st, address c, address e) = registry.deploymentParties(id);
            assertEq(uint8(st), g.status, "deploymentParties status");
            assertEq(c, g.customer, "deploymentParties customer");
            assertEq(e, g.enclaveSigner, "deploymentParties enclaveSigner");
            if (g.status == 2) {
                assertEq(uint8(got.status), uint8(IDeploymentRegistry.DeploymentStatus.Closed), "Closed is final");
                assertGt(got.closedAt, 0, "closedAt set");
            }
        }
    }

    /// @dev Every deployment that exists was registered from a record of a stack approved at that moment, with
    ///      evidence from an allowed oracle signer. No other id of the (customer, stack, salt) space exists.
    function invariant_activeOnlyAfterVerifiedRecordOfApprovedStack() public view {
        (uint256 nc, uint256 ns, uint256 nsalt,,, uint256 d) = handler.counts();
        for (uint256 i; i < d; ++i) {
            LifecycleHandler.GDep memory g = handler.dep(handler.depIds(i));
            assertTrue(g.approvedAtRegistration, "registered while the stack was not approved");
            assertTrue(g.signerAtRegistration, "registered without an allowed signer's evidence");
        }
        for (uint256 c; c < nc; ++c) {
            for (uint256 s; s < ns; ++s) {
                for (uint256 k; k < nsalt; ++k) {
                    bytes32 id = handler.deploymentIdOf(handler.customers(c), handler.stacks(s), handler.salts(k));
                    if (handler.dep(id).status == 0) {
                        (IDeploymentRegistry.DeploymentStatus st,,) = registry.deploymentParties(id);
                        assertEq(uint8(st), 0, "a deployment exists that was never registered");
                    }
                }
            }
        }
    }

    /// @dev Release and image revocation are terminal; a release that was ever deprecated or revoked is never
    ///      approvable again.
    function invariant_revocationIsFinal() public view {
        uint256 n = handler.releaseCount();
        for (uint256 i; i < n; ++i) {
            bytes32 id = handler.releases(i);
            assertEq(uint8(apps.releaseStatus(id)), uint8(handler.releaseStatus(id)), "release status");
            if (handler.releaseStatus(id) == LifecycleHandler.S.Revoked) {
                assertEq(uint8(apps.releaseStatus(id)), uint8(IAppRegistry.ReleaseStatus.Revoked), "release revoked");
                assertFalse(apps.isActiveRelease(id), "revoked release active");
            }
            if (handler.releaseEverDeactivated(id)) assertFalse(apps.isApprovableRelease(id), "approvable again");
        }
        uint256 m = handler.imageCount();
        for (uint256 i; i < m; ++i) {
            bytes32 id = handler.images(i);
            assertEq(uint8(platform.imageStatus(id)), uint8(handler.imageStatus(id)), "image status");
            if (handler.imageStatus(id) == LifecycleHandler.S.Revoked) {
                assertEq(uint8(platform.imageStatus(id)), uint8(IPlatformRegistry.ImageStatus.Revoked), "revoked");
            }
            if (handler.imageDebug(id)) assertFalse(platform.isApprovedImage(id), "debug image approved");
        }
    }

    /// @dev isStackApproved equals the model, and is false whenever any release of the approval is revoked or its
    ///      image is not Active or is a debug image.
    function invariant_isStackApprovedFollowsCatalog() public view {
        (uint256 nc, uint256 ns,,,,) = handler.counts();
        for (uint256 c; c < nc; ++c) {
            address customer_ = handler.customers(c);
            for (uint256 s; s < ns; ++s) {
                bytes32 stack = handler.stacks(s);
                bool approved = registry.isStackApproved(customer_, stack);
                assertEq(approved, handler.expectedApproved(customer_, stack), "isStackApproved == model");
                if (!approved) continue;
                LifecycleHandler.GApproval memory g = handler.ghostApproval(customer_, stack);
                assertTrue(platform.isApprovedImage(g.imageId), "approved with an image that is not approved");
                for (uint256 k; k < g.releaseIds.length; ++k) {
                    assertTrue(apps.isActiveRelease(g.releaseIds[k]), "approved with an inactive release");
                }
            }
        }
    }

    /// @dev Usage legs never overlap: across every deployment, usage hash and app of the pools, usagePaid equals
    ///      the amount accepted on exactly that key, and appInDeployment equals the model.
    function invariant_usageLegsNeverOverlap() public view {
        (,,, uint256 nu, uint256 na, uint256 d) = handler.counts();
        for (uint256 i; i < d; ++i) {
            bytes32 id = handler.depIds(i);
            for (uint256 a; a < na; ++a) {
                bytes32 appId = handler.appIds(a);
                assertEq(registry.appInDeployment(id, appId), handler.expectedAppIn(id, appId), "appInDeployment");
                for (uint256 u; u < nu; ++u) {
                    bytes32 usageHash = handler.usagePool(u);
                    assertEq(
                        splitter.usagePaid(id, usageHash, appId),
                        handler.ghostLeg(handler.legKey(id, usageHash, appId)),
                        "usagePaid of one (deployment, usage, app) key"
                    );
                }
            }
        }
        assertEq(splitter.totalCredited(address(token)), token.balanceOf(address(splitter)), "solvency");
    }

    function invariant_signersMatchModel() public view {
        for (uint256 i; i < 3; ++i) {
            address a = handler.oracleAddrs(i);
            assertEq(oracleVerifier.isSigner(a), handler.ghostSigner(a), "signer set");
        }
        assertFalse(registry.paused(), "paused only inside a pause pulse");
        assertEq(registry.maxAttestationAge(), handler.maxAge(), "maxAttestationAge");
    }

    /// @dev Sanity check that the handler reaches the positive and negative paths of the state machine.
    function test_handlerReachesEveryPath() public {
        for (uint256 i; i < 2500; ++i) {
            uint256 seed = uint256(keccak256(abi.encode("lifecycle-path", i)));
            uint256 action = seed % 22;
            if (action <= 2) {
                handler.approve(seed >> 8, seed >> 16, seed >> 24, seed >> 32, seed >> 40, seed % 5 != 0);
            } else if (action == 3) {
                handler.revokeStack(seed >> 8, seed >> 16);
            } else if (action <= 7) {
                handler.register(seed >> 8, seed >> 16, seed >> 24, seed >> 32, seed >> 40, seed >> 48);
            } else if (action <= 10) {
                handler.heartbeat(seed >> 8, seed >> 16, seed >> 24, seed >> 32);
            } else if (action == 11) {
                handler.close(seed >> 8, seed >> 16);
            } else if (action <= 13) {
                handler.pay(seed >> 8, seed >> 16, seed >> 24, seed >> 32, seed >> 40);
            } else if (action == 14) {
                handler.topUp(seed >> 8, seed >> 16, seed >> 24, seed >> 32, seed >> 40);
            } else if (action == 15) {
                handler.revokeRelease(seed >> 8);
            } else if (action == 16) {
                handler.deprecateImage(seed >> 8);
            } else if (action == 17) {
                handler.setSigner(seed >> 8, seed % 2 == 0);
            } else if (action == 18) {
                handler.pausePulse(seed >> 8);
            } else if (action == 19) {
                handler.publishRelease(seed >> 8);
            } else if (action == 20 && i % 2 == 0) {
                handler.addImage(seed % 5 == 0);
            } else if (action == 20 && i % 7 == 1) {
                handler.setMaxAttestationAge(seed >> 8);
            } else {
                handler.warp(bound(seed >> 8, 1, 4 hours));
            }
        }
        invariant_handlerPredictionsHeld();
        invariant_deploymentsMatchModel();
        invariant_activeOnlyAfterVerifiedRecordOfApprovedStack();
        invariant_revocationIsFinal();
        invariant_isStackApprovedFollowsCatalog();
        invariant_usageLegsNeverOverlap();
        string[13] memory paths = [
            "approve",
            "reapprove",
            "approveRejected",
            "register",
            "registerRejected",
            "heartbeat",
            "heartbeatRejected",
            "close",
            "closeRejected",
            "pay",
            "payRejected",
            "topUp",
            "revokeStack"
        ];
        for (uint256 i; i < paths.length; ++i) {
            assertGt(handler.calls(paths[i]), 0, paths[i]);
        }
    }
}
