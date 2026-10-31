// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {PlatformRegistry} from "../../src/PlatformRegistry.sol";
import {IAppRegistry} from "../../src/interfaces/IAppRegistry.sol";
import {IPlatformRegistry} from "../../src/interfaces/IPlatformRegistry.sol";
import {CatalogHandler} from "./CatalogHandler.sol";

/// @notice AppRegistry and PlatformRegistry against a ghost model: every call by every actor has the outcome the
///         model predicts, state changes only through owner, registrar, maintainer (setMaintainer) or pending-owner
///         paths, a deprecated or revoked release is never approvable again, a debug, deprecated or revoked image
///         is never approved, revocation is terminal, and nobody ever holds DEFAULT_ADMIN_ROLE.
contract CatalogInvariantTest is Test {
    AppRegistry internal apps;
    PlatformRegistry internal platform;
    CatalogHandler internal handler;
    address internal owner = makeAddr("catalog-owner");

    function setUp() public {
        vm.warp(1_800_000_000);
        apps = new AppRegistry(owner);
        platform = new PlatformRegistry(owner);
        address[] memory others = new address[](6);
        others[0] = makeAddr("catalog-owner-2");
        others[1] = makeAddr("catalog-registrar-1");
        others[2] = makeAddr("catalog-registrar-2");
        others[3] = makeAddr("catalog-maintainer-1");
        others[4] = makeAddr("catalog-maintainer-2");
        others[5] = makeAddr("catalog-stranger");
        handler = new CatalogHandler(apps, platform, owner, others);

        // Seed through the handler so the model stays exact: a registrar, two apps, a release and two images.
        handler.grantRegistrar(0, 2, false);
        handler.registerApp(0, 1, false, false, 4 << 8 | 1, 2000);
        handler.registerApp(0, 2, false, false, 5 << 8 | 1, 0);
        handler.publishRelease(2, 1, 1, 1);
        handler.addImage(0, 1, 0, false, false, 1);
        handler.addImage(0, 2, 1, true, false, 1);
        require(!handler.unexpectedOutcome(), handler.lastMismatch());
        require(apps.appCount() == 2 && platform.imageCount() == 2, "seed");

        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](20);
        selectors[0] = CatalogHandler.registerApp.selector;
        selectors[1] = CatalogHandler.setMaintainer.selector;
        selectors[2] = CatalogHandler.setMaintainerShare.selector;
        selectors[3] = CatalogHandler.setMetadataURI.selector;
        selectors[4] = CatalogHandler.publishRelease.selector;
        selectors[5] = CatalogHandler.deprecateRelease.selector;
        selectors[6] = CatalogHandler.revokeRelease.selector;
        selectors[7] = CatalogHandler.grantRegistrar.selector;
        selectors[8] = CatalogHandler.revokeRegistrar.selector;
        selectors[9] = CatalogHandler.renounceRegistrar.selector;
        selectors[10] = CatalogHandler.rawRoleCall.selector;
        selectors[11] = CatalogHandler.appsTransferOwnership.selector;
        selectors[12] = CatalogHandler.appsAcceptOwnership.selector;
        selectors[13] = CatalogHandler.renounceOwnership.selector;
        selectors[14] = CatalogHandler.addImage.selector;
        selectors[15] = CatalogHandler.deprecateImage.selector;
        selectors[16] = CatalogHandler.revokeImage.selector;
        selectors[17] = CatalogHandler.platformTransferOwnership.selector;
        selectors[18] = CatalogHandler.platformAcceptOwnership.selector;
        selectors[19] = CatalogHandler.publishRelease.selector; // releases are the most consequential state
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_handlerPredictionsHeld() public view {
        assertFalse(handler.unexpectedOutcome(), handler.lastMismatch());
        assertFalse(handler.unauthorizedChange(), handler.lastMismatch());
    }

    function invariant_ownersAndRolesMatchModel() public view {
        assertEq(apps.owner(), handler.appsOwner(), "apps owner");
        assertEq(apps.pendingOwner(), handler.appsPending(), "apps pendingOwner");
        assertEq(platform.owner(), handler.platformOwner(), "platform owner");
        assertEq(platform.pendingOwner(), handler.platformPending(), "platform pendingOwner");
        uint256 n = handler.actorCount();
        for (uint256 i; i < n; ++i) {
            address a = handler.actors(i);
            assertEq(apps.hasRole(apps.REGISTRAR_ROLE(), a), handler.ghostRegistrar(a), "registrar role");
            assertFalse(apps.hasRole(bytes32(0), a), "DEFAULT_ADMIN_ROLE is never held");
        }
        assertFalse(apps.hasRole(bytes32(0), address(handler)), "DEFAULT_ADMIN_ROLE is never held");
        assertFalse(apps.hasRole(bytes32(0), address(this)), "DEFAULT_ADMIN_ROLE is never held");
        assertEq(apps.getRoleAdmin(apps.REGISTRAR_ROLE()), bytes32(0), "registrar admin role");
    }

    function invariant_appsMatchModel() public view {
        uint256 n = handler.slugCount();
        for (uint256 i; i < n; ++i) {
            bytes32 appId = handler.appIdOf(i);
            CatalogHandler.GApp memory g = handler.ghostApp(appId);
            assertEq(apps.appExists(appId), g.exists, "appExists");
            if (!g.exists) continue;
            IAppRegistry.App memory a = apps.getApp(appId);
            assertEq(a.maintainer, g.maintainer, "maintainer");
            assertEq(a.maintainerShareBps, g.share, "share");
            assertLe(a.maintainerShareBps, apps.MAX_MAINTAINER_SHARE_BPS(), "share cap");
            assertEq(keccak256(bytes(a.metadataURI)), g.metadataHash, "metadataURI");
            assertEq(keccak256(bytes(a.name)), g.nameHash, "name");
            assertEq(a.registeredAt, g.registeredAt, "registeredAt");
            assertTrue(a.maintainer != address(0), "maintainer is never zero");
            (address m, uint16 bps) = apps.payoutInfo(appId);
            assertEq(m, g.maintainer, "payoutInfo maintainer");
            assertEq(bps, g.share, "payoutInfo share");

            bytes32[] memory ids = handler.appReleases(appId);
            assertEq(apps.releaseCount(appId), ids.length, "releaseCount");
            for (uint256 j; j < ids.length; ++j) {
                assertEq(apps.releaseAt(appId, j), ids[j], "release order");
            }
            assertEq(apps.latestRelease(appId), handler.ghostLatest(appId), "latestRelease");
        }
        assertEq(apps.appCount(), handler.appOrderLength(), "appCount");
        for (uint256 i; i < handler.appOrderLength(); ++i) {
            assertEq(apps.appAt(i), handler.appOrder(i), "app order");
        }
    }

    /// @dev A release that was ever deprecated or revoked is never approvable again; revoked is terminal.
    function invariant_releasesMatchModel() public view {
        uint256 n = handler.releaseCount();
        for (uint256 i; i < n; ++i) {
            CatalogHandler.GRelease memory g = handler.releaseAtIndex(i);
            IAppRegistry.ReleaseStatus st = apps.releaseStatus(g.id);
            assertEq(uint8(st), uint8(g.status), "release status");
            assertEq(apps.isApprovableRelease(g.id), g.status == CatalogHandler.S.Active, "isApprovableRelease");
            assertEq(
                apps.isActiveRelease(g.id),
                g.status == CatalogHandler.S.Active || g.status == CatalogHandler.S.Deprecated,
                "isActiveRelease"
            );
            if (g.everDeactivated) assertFalse(apps.isApprovableRelease(g.id), "deactivated release approvable");
            assertEq(apps.appOfRelease(g.id), g.appId, "appOfRelease");
            assertEq(apps.releaseByVersion(g.appId, g.version), g.id, "releaseByVersion never cleared");
            assertEq(apps.releaseByBundle(g.appId, g.bundleHash), g.id, "releaseByBundle never cleared");
        }
    }

    /// @dev A debug image is never approved, an image that was ever deprecated or revoked is never approved
    ///      again, revoked is terminal, and each measurement set belongs to one image forever.
    function invariant_imagesMatchModel() public view {
        uint256 n = handler.imageCount();
        assertEq(platform.imageCount(), n, "imageCount");
        for (uint256 i; i < n; ++i) {
            CatalogHandler.GImage memory g = handler.imageAtIndex(i);
            assertEq(uint8(platform.imageStatus(g.id)), uint8(g.status), "image status");
            assertEq(
                platform.isApprovedImage(g.id), g.status == CatalogHandler.S.Active && !g.isDebug, "isApprovedImage"
            );
            if (g.isDebug) assertFalse(platform.isApprovedImage(g.id), "debug image approved");
            if (g.everDeactivated) assertFalse(platform.isApprovedImage(g.id), "deactivated image approved");
            IPlatformRegistry.Image memory img = platform.getImage(g.id);
            assertEq(img.measurementsHash, g.measurementsHash, "measurementsHash");
            assertEq(img.isDebug, g.isDebug, "isDebug");
            assertEq(platform.imageByMeasurements(g.measurementsHash), g.id, "imageByMeasurements never cleared");
        }
        for (uint256 i; i < handler.imagePoolLength(); ++i) {
            bytes32 id = handler.imagePool(i);
            if (platform.imageStatus(id) == IPlatformRegistry.ImageStatus.None) {
                assertFalse(platform.isApprovedImage(id), "unknown image approved");
            }
        }
        assertFalse(platform.isApprovedImage(bytes32(0)), "zero image approved");
    }

    /// @dev Sanity check that the handler reaches the positive paths of every function.
    function test_handlerReachesEveryPath() public {
        for (uint256 i; i < 1500; ++i) {
            uint256 seed = uint256(keccak256(abi.encode("catalog-path", i)));
            uint256 a = (seed >> 4) % 2 == 0 ? 0 : seed >> 8; // owner half the time
            uint256 action = seed % 19;
            if (action == 0) {
                handler.registerApp(a, seed >> 16, seed % 11 == 0, seed % 13 == 0, seed >> 24, seed >> 32);
            } else if (action == 1) {
                handler.setMaintainer(a, seed >> 16, seed >> 24);
            } else if (action == 2) {
                handler.setMaintainerShare(a, seed >> 16, seed >> 24);
            } else if (action == 3) {
                handler.setMetadataURI(a, seed >> 16, seed >> 24);
            } else if (action <= 5) {
                handler.publishRelease(seed >> 8, seed >> 16, seed >> 24, seed >> 32);
            } else if (action == 6) {
                handler.deprecateRelease(a, seed >> 16);
            } else if (action == 7) {
                handler.revokeRelease(a, seed >> 16);
            } else if (action == 8) {
                handler.grantRegistrar(a, seed >> 16, seed % 17 == 0);
            } else if (action == 9) {
                handler.revokeRegistrar(a, seed >> 16);
            } else if (action == 10) {
                handler.renounceRegistrar(seed >> 8, seed >> 16);
            } else if (action == 11) {
                handler.rawRoleCall(seed >> 8, seed >> 16, seed % 2 == 0, seed % 3 == 0);
            } else if (action == 12) {
                handler.addImage(a, seed >> 16, seed >> 24, seed % 3 == 0, seed % 11 == 0, seed);
            } else if (action == 13) {
                handler.deprecateImage(a, seed >> 16);
            } else if (action == 14) {
                handler.revokeImage(a, seed >> 16);
            } else if (action == 15) {
                handler.renounceOwnership(seed >> 8, seed % 2 == 0);
            } else if (action == 16) {
                handler.warp(seed >> 8);
            } else if (action == 17 && i % 300 == 17) {
                handler.appsTransferOwnership(0, 1 << 8 | 1);
            } else if (action == 18) {
                handler.appsAcceptOwnership(seed >> 8);
            }
        }
        invariant_handlerPredictionsHeld();
        invariant_ownersAndRolesMatchModel();
        invariant_appsMatchModel();
        invariant_releasesMatchModel();
        invariant_imagesMatchModel();
        string[16] memory paths = [
            "registerApp-ok",
            "registerApp-rejected",
            "setMaintainer-ok",
            "setMaintainer-rejected",
            "setMaintainerShare-ok",
            "publishRelease-ok",
            "publishRelease-rejected",
            "deprecateRelease-ok",
            "revokeRelease-ok",
            "grantRegistrar-ok",
            "revokeRegistrar-ok",
            "renounceRole-ok",
            "addImage-ok",
            "addImage-rejected",
            "deprecateImage-ok",
            "revokeImage-ok"
        ];
        for (uint256 i; i < paths.length; ++i) {
            assertGt(handler.calls(paths[i]), 0, paths[i]);
        }
    }
}
