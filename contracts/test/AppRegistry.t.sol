// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {AppRegistry} from "../src/AppRegistry.sol";
import {IAppRegistry} from "../src/interfaces/IAppRegistry.sol";
import {OwnableNoRenounce} from "../src/utils/OwnableNoRenounce.sol";
import {SealedTest} from "./utils/SealedTest.sol";

contract AppRegistryTest is SealedTest {
    event AppRegistered(
        bytes32 indexed appId,
        address indexed maintainer,
        string slug,
        string name,
        string licenseSpdx,
        uint16 maintainerShareBps,
        string metadataURI
    );
    event MaintainerChanged(
        bytes32 indexed appId, address indexed previousMaintainer, address indexed newMaintainer, address changedBy
    );
    event MaintainerShareChanged(bytes32 indexed appId, uint16 previousShareBps, uint16 newShareBps);
    event MetadataURIChanged(bytes32 indexed appId, string metadataURI);
    event ReleasePublished(
        bytes32 indexed releaseId,
        bytes32 indexed appId,
        address indexed publisher,
        string version,
        bytes32 bundleHash,
        bytes32 egressPolicyHash,
        bytes32 sbomHash,
        string provenanceURI,
        string signatureURI
    );
    event ReleaseDeprecated(bytes32 indexed releaseId, bytes32 indexed appId);
    event ReleaseRevoked(
        bytes32 indexed releaseId, bytes32 indexed appId, IAppRegistry.ReleaseStatus previousStatus, string reason
    );
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    bytes32 internal REGISTRAR;
    bytes32 internal scraper = keccak256(bytes("scraper"));

    function setUp() public override {
        super.setUp();
        REGISTRAR = apps.REGISTRAR_ROLE();
    }

    function _register(string memory slug, address m, uint16 bps) internal {
        vm.prank(owner);
        apps.registerApp(keccak256(bytes(slug)), slug, "Name", "MIT", m, bps, "meta");
    }

    function _publishAs(address who, bytes32 appId, string memory version, bytes32 bundleHash)
        internal
        returns (bytes32)
    {
        vm.prank(who);
        return apps.publishRelease(appId, version, bundleHash, bytes32(uint256(2)), bytes32(uint256(3)), "p", "s");
    }

    // ------------------------------------------------------------------------------------------------------
    // Metadata, ownership, roles
    // ------------------------------------------------------------------------------------------------------

    function test_metadata() public view {
        assertEq(apps.VERSION(), "1.0.0");
        assertEq(apps.REGISTRAR_ROLE(), keccak256("REGISTRAR_ROLE"));
        assertEq(apps.MAX_MAINTAINER_SHARE_BPS(), 5000);
        assertEq(apps.owner(), owner);
        assertTrue(apps.hasRole(REGISTRAR, ops));
        assertFalse(apps.hasRole(apps.DEFAULT_ADMIN_ROLE(), owner));
        assertEq(apps.getRoleAdmin(REGISTRAR), apps.DEFAULT_ADMIN_ROLE());
    }

    function test_supportsInterface() public view {
        assertTrue(apps.supportsInterface(type(IAccessControl).interfaceId));
        assertFalse(apps.supportsInterface(0xdeadbeef));
    }

    function test_renounceOwnership_disabled() public {
        vm.prank(owner);
        vm.expectRevert(OwnableNoRenounce.RenounceOwnershipDisabled.selector);
        apps.renounceOwnership();
    }

    function test_grantRegistrar() public {
        address r = makeAddr("ci");
        vm.expectEmit(address(apps));
        emit RoleGranted(REGISTRAR, r, owner);
        vm.prank(owner);
        apps.grantRegistrar(r);
        assertTrue(apps.hasRole(REGISTRAR, r));
    }

    function test_grantRegistrar_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        apps.grantRegistrar(stranger);
    }

    function test_grantRegistrar_revertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(AppRegistry.ZeroAddress.selector);
        apps.grantRegistrar(address(0));
    }

    function test_grantRegistrar_revertsWhenAlreadyGranted() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.AlreadyRegistrar.selector, ops));
        apps.grantRegistrar(ops);
    }

    function test_revokeRegistrar() public {
        vm.expectEmit(address(apps));
        emit RoleRevoked(REGISTRAR, ops, owner);
        vm.prank(owner);
        apps.revokeRegistrar(ops);
        assertFalse(apps.hasRole(REGISTRAR, ops));
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, ops, REGISTRAR)
        );
        _publishAs(ops, appA, "9.9.9", bytes32(uint256(1)));
    }

    function test_revokeRegistrar_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        apps.revokeRegistrar(ops);
    }

    function test_revokeRegistrar_revertsWhenNotRegistrar() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.NotRegistrar.selector, stranger));
        apps.revokeRegistrar(stranger);
    }

    function test_accessControlGrantRole_unusableEvenByOwner() public {
        bytes32 admin = apps.DEFAULT_ADMIN_ROLE();
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, owner, admin));
        apps.grantRole(REGISTRAR, stranger);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, owner, admin));
        apps.revokeRole(REGISTRAR, ops);
    }

    function test_registrarCanRenounceItself() public {
        vm.expectEmit(address(apps));
        emit RoleRevoked(REGISTRAR, ops, ops);
        vm.prank(ops);
        apps.renounceRole(REGISTRAR, ops);
        assertFalse(apps.hasRole(REGISTRAR, ops));
    }

    function test_registrarRoleSurvivesOwnershipTransfer() public {
        address multisig = makeAddr("multisig");
        vm.prank(owner);
        apps.transferOwnership(multisig);
        vm.prank(multisig);
        apps.acceptOwnership();
        assertTrue(apps.hasRole(REGISTRAR, ops));
        vm.prank(multisig);
        apps.revokeRegistrar(ops);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, owner));
        apps.grantRegistrar(ops);
    }

    // ------------------------------------------------------------------------------------------------------
    // registerApp
    // ------------------------------------------------------------------------------------------------------

    function test_registerApp() public {
        vm.expectEmit(address(apps));
        emit AppRegistered(scraper, maintainer, "scraper", "Scraper", "AGPL-3.0-only", 1234, "ipfs://meta");
        vm.prank(owner);
        apps.registerApp(scraper, "scraper", "Scraper", "AGPL-3.0-only", maintainer, 1234, "ipfs://meta");

        IAppRegistry.App memory a = apps.getApp(scraper);
        assertEq(a.slug, "scraper");
        assertEq(a.name, "Scraper");
        assertEq(a.licenseSpdx, "AGPL-3.0-only");
        assertEq(a.metadataURI, "ipfs://meta");
        assertEq(a.maintainer, maintainer);
        assertEq(a.maintainerShareBps, 1234);
        assertEq(a.registeredAt, block.timestamp);
        assertTrue(apps.appExists(scraper));
        assertEq(apps.appCount(), 3);
        assertEq(apps.appAt(2), scraper);
        (address m, uint16 bps) = apps.payoutInfo(scraper);
        assertEq(m, maintainer);
        assertEq(bps, 1234);
        assertEq(apps.computeAppId("scraper"), scraper);
    }

    function test_registerApp_maxShareAllowed() public {
        _register("scraper", maintainer, 5000);
        assertEq(apps.getApp(scraper).maintainerShareBps, 5000);
    }

    function test_registerApp_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        apps.registerApp(scraper, "scraper", "n", "MIT", maintainer, 0, "");
    }

    function test_registerApp_revertsOnAppIdMismatch() public {
        bytes32 wrong = keccak256("Scraper");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.AppIdMismatch.selector, wrong, scraper));
        apps.registerApp(wrong, "scraper", "n", "MIT", maintainer, 0, "");
    }

    function test_registerApp_revertsOnEmptySlug() public {
        vm.prank(owner);
        vm.expectRevert(AppRegistry.EmptyField.selector);
        apps.registerApp(keccak256(""), "", "n", "MIT", maintainer, 0, "");
    }

    function test_registerApp_revertsOnEmptyName() public {
        vm.prank(owner);
        vm.expectRevert(AppRegistry.EmptyField.selector);
        apps.registerApp(scraper, "scraper", "", "MIT", maintainer, 0, "");
    }

    function test_registerApp_revertsOnDuplicate() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.AppAlreadyRegistered.selector, appA));
        apps.registerApp(appA, "llm-gateway", "n", "MIT", maintainer, 0, "");
    }

    function test_registerApp_revertsOnZeroMaintainer() public {
        vm.prank(owner);
        vm.expectRevert(AppRegistry.ZeroAddress.selector);
        apps.registerApp(scraper, "scraper", "n", "MIT", address(0), 0, "");
    }

    function test_registerApp_revertsOnShareAboveMax() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.MaintainerShareTooHigh.selector, uint16(5001)));
        apps.registerApp(scraper, "scraper", "n", "MIT", maintainer, 5001, "");
    }

    function testFuzz_registerApp_shareBound(uint16 bps) public {
        vm.prank(owner);
        if (bps > 5000) {
            vm.expectRevert(abi.encodeWithSelector(AppRegistry.MaintainerShareTooHigh.selector, bps));
        }
        apps.registerApp(scraper, "scraper", "n", "MIT", maintainer, bps, "");
    }

    function test_appAt_revertsOutOfBounds() public {
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.IndexOutOfBounds.selector, 2, 2));
        apps.appAt(2);
    }

    function test_getApp_revertsWhenUnknown() public {
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.AppNotFound.selector, scraper));
        apps.getApp(scraper);
    }

    function test_payoutInfo_revertsWhenUnknown() public {
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.AppNotFound.selector, scraper));
        apps.payoutInfo(scraper);
    }

    // ------------------------------------------------------------------------------------------------------
    // setMaintainer / setMaintainerShare / setMetadataURI
    // ------------------------------------------------------------------------------------------------------

    function test_setMaintainer_byMaintainer() public {
        address next = makeAddr("next");
        vm.expectEmit(address(apps));
        emit MaintainerChanged(appA, maintainer, next, maintainer);
        vm.prank(maintainer);
        apps.setMaintainer(appA, next);
        assertEq(apps.getApp(appA).maintainer, next);
        // The previous maintainer has lost control.
        vm.prank(maintainer);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.NotMaintainerOrOwner.selector, maintainer));
        apps.setMaintainer(appA, maintainer);
    }

    function test_setMaintainer_byOwner() public {
        address next = makeAddr("next");
        vm.expectEmit(address(apps));
        emit MaintainerChanged(appA, maintainer, next, owner);
        vm.prank(owner);
        apps.setMaintainer(appA, next);
        assertEq(apps.getApp(appA).maintainer, next);
    }

    function test_setMaintainer_revertsForStranger() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.NotMaintainerOrOwner.selector, stranger));
        apps.setMaintainer(appA, stranger);
    }

    function test_setMaintainer_revertsOnZero() public {
        vm.prank(maintainer);
        vm.expectRevert(AppRegistry.ZeroAddress.selector);
        apps.setMaintainer(appA, address(0));
    }

    function test_setMaintainer_revertsWhenUnknownApp() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.AppNotFound.selector, scraper));
        apps.setMaintainer(scraper, stranger);
    }

    function test_setMaintainerShare() public {
        vm.expectEmit(address(apps));
        emit MaintainerShareChanged(appA, DEFAULT_SHARE_BPS, 0);
        vm.prank(owner);
        apps.setMaintainerShare(appA, 0);
        assertEq(apps.getApp(appA).maintainerShareBps, 0);
    }

    function test_setMaintainerShare_revertsAboveMax() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.MaintainerShareTooHigh.selector, uint16(5001)));
        apps.setMaintainerShare(appA, 5001);
    }

    function test_setMaintainerShare_revertsForMaintainer() public {
        vm.prank(maintainer);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, maintainer));
        apps.setMaintainerShare(appA, 100);
    }

    function test_setMaintainerShare_revertsWhenUnknownApp() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.AppNotFound.selector, scraper));
        apps.setMaintainerShare(scraper, 100);
    }

    function test_setMetadataURI() public {
        vm.expectEmit(address(apps));
        emit MetadataURIChanged(appA, "ipfs://new");
        vm.prank(owner);
        apps.setMetadataURI(appA, "ipfs://new");
        assertEq(apps.getApp(appA).metadataURI, "ipfs://new");
    }

    function test_setMetadataURI_revertsForNonOwner() public {
        vm.prank(maintainer);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, maintainer));
        apps.setMetadataURI(appA, "x");
    }

    function test_setMetadataURI_revertsWhenUnknownApp() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.AppNotFound.selector, scraper));
        apps.setMetadataURI(scraper, "x");
    }

    // ------------------------------------------------------------------------------------------------------
    // publishRelease
    // ------------------------------------------------------------------------------------------------------

    function test_publishRelease() public {
        bytes32 bundle = keccak256("bundle-2");
        bytes32 expectedId = keccak256(abi.encode(appA, "2.0.0", bundle));
        vm.expectEmit(address(apps));
        emit ReleasePublished(
            expectedId, appA, ops, "2.0.0", bundle, bytes32(uint256(2)), bytes32(uint256(3)), "p", "s"
        );
        bytes32 id = _publishAs(ops, appA, "2.0.0", bundle);
        assertEq(id, expectedId);
        assertEq(apps.computeReleaseId(appA, "2.0.0", bundle), expectedId);

        IAppRegistry.Release memory r = apps.getRelease(id);
        assertEq(r.appId, appA);
        assertEq(r.bundleHash, bundle);
        assertEq(r.egressPolicyHash, bytes32(uint256(2)));
        assertEq(r.sbomHash, bytes32(uint256(3)));
        assertEq(uint8(r.status), uint8(IAppRegistry.ReleaseStatus.Active));
        assertEq(r.publishedAt, block.timestamp);
        assertEq(r.version, "2.0.0");
        assertEq(r.provenanceURI, "p");
        assertEq(r.signatureURI, "s");

        assertEq(apps.releaseCount(appA), 2);
        assertEq(apps.releaseAt(appA, 0), releaseA);
        assertEq(apps.releaseAt(appA, 1), id);
        assertEq(apps.releaseByVersion(appA, "2.0.0"), id);
        assertEq(apps.appOfRelease(id), appA);
        assertEq(apps.latestRelease(appA), id);
        assertTrue(apps.isActiveRelease(id));
        assertTrue(apps.isApprovableRelease(id));
    }

    function test_publishRelease_revertsForNonRegistrar() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, owner, REGISTRAR)
        );
        _publishAs(owner, appA, "2.0.0", bytes32(uint256(1)));
    }

    function test_publishRelease_revertsForUnknownApp() public {
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.AppNotFound.selector, scraper));
        _publishAs(ops, scraper, "1.0.0", bytes32(uint256(1)));
    }

    function test_publishRelease_revertsOnEmptyVersion() public {
        vm.expectRevert(AppRegistry.EmptyField.selector);
        _publishAs(ops, appA, "", bytes32(uint256(1)));
    }

    function test_publishRelease_revertsOnZeroBundleHash() public {
        vm.expectRevert(AppRegistry.ZeroBundleHash.selector);
        _publishAs(ops, appA, "2.0.0", bytes32(0));
    }

    function test_publishRelease_revertsOnDuplicateRelease() public {
        bytes32 bundle = keccak256(abi.encode("bundle", appA, "1.0.0"));
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.ReleaseAlreadyExists.selector, releaseA));
        _publishAs(ops, appA, "1.0.0", bundle);
    }

    function test_publishRelease_revertsOnDuplicateVersionWithOtherBundle() public {
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.VersionAlreadyPublished.selector, appA, "1.0.0"));
        _publishAs(ops, appA, "1.0.0", keccak256("other bundle"));
    }

    function test_publishRelease_sameVersionAllowedAcrossApps() public {
        bytes32 bundle = keccak256("shared");
        bytes32 a = _publishAs(ops, appA, "3.0.0", bundle);
        bytes32 b = _publishAs(ops, appB, "3.0.0", bundle);
        assertTrue(a != b);
    }

    function test_publishRelease_revokedVersionCannotBeReused() public {
        vm.prank(owner);
        apps.revokeRelease(releaseA, "bad");
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.VersionAlreadyPublished.selector, appA, "1.0.0"));
        _publishAs(ops, appA, "1.0.0", keccak256("fixed bundle"));
    }

    function test_releaseAt_revertsOutOfBounds() public {
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.IndexOutOfBounds.selector, 1, 1));
        apps.releaseAt(appA, 1);
    }

    function test_getRelease_revertsWhenUnknown() public {
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.ReleaseNotFound.selector, bytes32(uint256(7))));
        apps.getRelease(bytes32(uint256(7)));
    }

    function test_unknownReleaseViews() public view {
        bytes32 unknown = bytes32(uint256(7));
        assertFalse(apps.isActiveRelease(unknown));
        assertFalse(apps.isApprovableRelease(unknown));
        assertEq(apps.appOfRelease(unknown), bytes32(0));
        assertEq(uint8(apps.releaseStatus(unknown)), uint8(IAppRegistry.ReleaseStatus.None));
        assertEq(apps.releaseByVersion(appA, "9.9.9"), bytes32(0));
        assertEq(apps.releaseCount(scraper), 0);
        assertEq(apps.latestRelease(scraper), bytes32(0));
    }

    function testFuzz_computeReleaseId(bytes32 appId, string calldata version, bytes32 bundleHash) public view {
        assertEq(apps.computeReleaseId(appId, version, bundleHash), keccak256(abi.encode(appId, version, bundleHash)));
    }

    // ------------------------------------------------------------------------------------------------------
    // deprecateRelease / revokeRelease (D-013)
    // ------------------------------------------------------------------------------------------------------

    function test_deprecateRelease() public {
        vm.expectEmit(address(apps));
        emit ReleaseDeprecated(releaseA, appA);
        vm.prank(owner);
        apps.deprecateRelease(releaseA);
        assertEq(uint8(apps.releaseStatus(releaseA)), uint8(IAppRegistry.ReleaseStatus.Deprecated));
        assertTrue(apps.isActiveRelease(releaseA), "deprecated stays active");
        assertFalse(apps.isApprovableRelease(releaseA), "deprecated is not approvable");
        assertEq(apps.latestRelease(appA), bytes32(0), "latestRelease skips deprecated");
    }

    function test_deprecateRelease_revertsForNonOwner() public {
        vm.prank(ops);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, ops));
        apps.deprecateRelease(releaseA);
    }

    function test_deprecateRelease_revertsWhenUnknown() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.ReleaseNotFound.selector, bytes32(uint256(7))));
        apps.deprecateRelease(bytes32(uint256(7)));
    }

    function test_deprecateRelease_revertsWhenDeprecated() public {
        vm.startPrank(owner);
        apps.deprecateRelease(releaseA);
        vm.expectRevert(
            abi.encodeWithSelector(
                AppRegistry.InvalidReleaseStatus.selector, releaseA, IAppRegistry.ReleaseStatus.Deprecated
            )
        );
        apps.deprecateRelease(releaseA);
        vm.stopPrank();
    }

    function test_deprecateRelease_revertsWhenRevoked() public {
        vm.startPrank(owner);
        apps.revokeRelease(releaseA, "x");
        vm.expectRevert(
            abi.encodeWithSelector(
                AppRegistry.InvalidReleaseStatus.selector, releaseA, IAppRegistry.ReleaseStatus.Revoked
            )
        );
        apps.deprecateRelease(releaseA);
        vm.stopPrank();
    }

    function test_revokeRelease_fromActive() public {
        vm.expectEmit(address(apps));
        emit ReleaseRevoked(releaseA, appA, IAppRegistry.ReleaseStatus.Active, "CVE");
        vm.prank(owner);
        apps.revokeRelease(releaseA, "CVE");
        assertEq(uint8(apps.releaseStatus(releaseA)), uint8(IAppRegistry.ReleaseStatus.Revoked));
        assertFalse(apps.isActiveRelease(releaseA));
        assertFalse(apps.isApprovableRelease(releaseA));
    }

    function test_revokeRelease_fromDeprecated() public {
        vm.startPrank(owner);
        apps.deprecateRelease(releaseA);
        vm.expectEmit(address(apps));
        emit ReleaseRevoked(releaseA, appA, IAppRegistry.ReleaseStatus.Deprecated, "eol");
        apps.revokeRelease(releaseA, "eol");
        vm.stopPrank();
        assertFalse(apps.isActiveRelease(releaseA));
    }

    function test_revokeRelease_revertsForNonOwner() public {
        vm.prank(ops);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, ops));
        apps.revokeRelease(releaseA, "x");
    }

    function test_revokeRelease_revertsWhenUnknown() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.ReleaseNotFound.selector, bytes32(uint256(7))));
        apps.revokeRelease(bytes32(uint256(7)), "x");
    }

    function test_revokeRelease_isTerminal() public {
        vm.startPrank(owner);
        apps.revokeRelease(releaseA, "x");
        vm.expectRevert(
            abi.encodeWithSelector(
                AppRegistry.InvalidReleaseStatus.selector, releaseA, IAppRegistry.ReleaseStatus.Revoked
            )
        );
        apps.revokeRelease(releaseA, "again");
        vm.stopPrank();
    }

    // ------------------------------------------------------------------------------------------------------
    // latestRelease
    // ------------------------------------------------------------------------------------------------------

    function test_latestRelease_newestActiveSkippingDeprecatedAndRevoked() public {
        bytes32 r2 = _publishAs(ops, appA, "2.0.0", keccak256("b2"));
        bytes32 r3 = _publishAs(ops, appA, "3.0.0", keccak256("b3"));
        bytes32 r4 = _publishAs(ops, appA, "4.0.0", keccak256("b4"));
        assertEq(apps.latestRelease(appA), r4);

        vm.startPrank(owner);
        apps.revokeRelease(r4, "bad");
        assertEq(apps.latestRelease(appA), r3);
        apps.deprecateRelease(r3);
        assertEq(apps.latestRelease(appA), r2);
        apps.deprecateRelease(r2);
        assertEq(apps.latestRelease(appA), releaseA);
        apps.revokeRelease(releaseA, "bad");
        assertEq(apps.latestRelease(appA), bytes32(0));
        vm.stopPrank();
        assertEq(apps.releaseCount(appA), 4);
    }
}
