// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {PlatformRegistry} from "../../src/PlatformRegistry.sol";
import {IAppRegistry} from "../../src/interfaces/IAppRegistry.sol";
import {IPlatformRegistry} from "../../src/interfaces/IPlatformRegistry.sol";

/// @notice Calls every state-changing function of AppRegistry and PlatformRegistry from a random actor (owner,
///         owner candidate, registrars, former registrars, maintainers, strangers) with arguments drawn from
///         small pools, so duplicates, unknown ids and bad values are frequent. Each call's outcome is checked
///         against a ghost model, and a fingerprint of all observable state is compared before and after the
///         call: state may only change through an owner path, a registrar path (publishRelease, renounceRole of
///         its own role), the app maintainer's setMaintainer, or the pending owner's acceptOwnership.
contract CatalogHandler is Test {
    enum S {
        None,
        Active,
        Deprecated,
        Revoked
    }

    struct GApp {
        bool exists;
        address maintainer;
        uint16 share;
        bytes32 metadataHash;
        bytes32 nameHash;
        uint64 registeredAt;
    }

    struct GRelease {
        bytes32 id;
        bytes32 appId;
        string version;
        bytes32 bundleHash;
        S status;
        bool everDeactivated;
    }

    struct GImage {
        bytes32 id;
        bytes32 measurementsHash;
        bool isDebug;
        S status;
        bool everDeactivated;
    }

    AppRegistry public immutable apps;
    PlatformRegistry public immutable platform;
    bytes32 public immutable REGISTRAR;

    address[] public actors;

    address public appsOwner;
    address public appsPending;
    address public platformOwner;
    address public platformPending;
    mapping(address account => bool) public ghostRegistrar;

    string[] internal _slugs;
    string[] internal _versions;
    bytes32[] internal _bundles;
    mapping(bytes32 appId => GApp) internal _gApp;
    bytes32[] public appOrder;

    GRelease[] internal _releases;
    mapping(bytes32 releaseId => uint256 indexPlusOne) internal _releaseIndex;
    mapping(bytes32 appId => bytes32[] releaseIds) internal _appReleases;
    mapping(bytes32 appId => mapping(bytes32 versionHash => bytes32 releaseId)) public ghostByVersion;
    mapping(bytes32 appId => mapping(bytes32 bundleHash => bytes32 releaseId)) public ghostByBundle;

    bytes32[] internal _imageIdPool;
    bytes[4][] internal _measurementSets;
    GImage[] internal _images;
    mapping(bytes32 imageId => uint256 indexPlusOne) internal _imageIndex;
    mapping(bytes32 measurementsHash => bytes32 imageId) public ghostByMeasurements;

    bool public unexpectedOutcome;
    bool public unauthorizedChange;
    string public lastMismatch;
    mapping(string name => uint256) public calls;

    constructor(AppRegistry apps_, PlatformRegistry platform_, address owner_, address[] memory others) {
        apps = apps_;
        platform = platform_;
        REGISTRAR = apps_.REGISTRAR_ROLE();
        appsOwner = owner_;
        platformOwner = owner_;
        actors.push(owner_);
        for (uint256 i; i < others.length; ++i) {
            actors.push(others[i]);
        }

        _slugs.push("");
        _slugs.push("llm-gateway");
        _slugs.push("scraper");
        _slugs.push("crm");
        _slugs.push("coding-agent");
        _slugs.push("internal-tools");

        _versions.push("");
        _versions.push("1.0.0");
        _versions.push("1.1.0");
        _versions.push("2.0.0");
        _versions.push("v2.0.0");

        _bundles.push(bytes32(0));
        for (uint256 i = 1; i < 6; ++i) {
            _bundles.push(keccak256(abi.encode("catalog-bundle", i)));
        }

        _imageIdPool.push(bytes32(0));
        for (uint256 i = 1; i < 7; ++i) {
            _imageIdPool.push(keccak256(abi.encode("catalog-image", i)));
        }
        for (uint256 i; i < 5; ++i) {
            bytes[4] memory set;
            for (uint256 j; j < 4; ++j) {
                bytes32 a = keccak256(abi.encode("catalog-measurement", i, j, 0));
                // Truncating to bytes16 is intended: 32 + 16 = 48 bytes, one TDX register.
                // forge-lint: disable-next-line(unsafe-typecast)
                set[j] = abi.encodePacked(a, bytes16(keccak256(abi.encode("catalog-measurement", i, j, 1))));
            }
            _measurementSets.push(set);
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Views for the invariant contract
    // ------------------------------------------------------------------------------------------------------

    function actorCount() external view returns (uint256) {
        return actors.length;
    }

    function slugCount() external view returns (uint256) {
        return _slugs.length;
    }

    function appIdOf(uint256 i) public view returns (bytes32) {
        return keccak256(bytes(_slugs[i]));
    }

    function ghostApp(bytes32 appId) external view returns (GApp memory) {
        return _gApp[appId];
    }

    function appOrderLength() external view returns (uint256) {
        return appOrder.length;
    }

    function releaseCount() external view returns (uint256) {
        return _releases.length;
    }

    function releaseAtIndex(uint256 i) external view returns (GRelease memory) {
        return _releases[i];
    }

    function appReleases(bytes32 appId) external view returns (bytes32[] memory) {
        return _appReleases[appId];
    }

    /// @notice Newest Active release of an app per the model.
    function ghostLatest(bytes32 appId) external view returns (bytes32) {
        bytes32[] storage ids = _appReleases[appId];
        for (uint256 i = ids.length; i > 0; --i) {
            if (_releases[_releaseIndex[ids[i - 1]] - 1].status == S.Active) return ids[i - 1];
        }
        return bytes32(0);
    }

    function imagePoolLength() external view returns (uint256) {
        return _imageIdPool.length;
    }

    function imagePool(uint256 i) external view returns (bytes32) {
        return _imageIdPool[i];
    }

    function imageCount() external view returns (uint256) {
        return _images.length;
    }

    function imageAtIndex(uint256 i) external view returns (GImage memory) {
        return _images[i];
    }

    /// @notice Hash of every observable value of both registries over the pools the handler uses.
    function fingerprint() public view returns (bytes32 h) {
        h = keccak256(abi.encode(apps.owner(), apps.pendingOwner(), platform.owner(), platform.pendingOwner()));
        for (uint256 i; i < actors.length; ++i) {
            h = keccak256(abi.encode(h, apps.hasRole(REGISTRAR, actors[i]), apps.hasRole(bytes32(0), actors[i])));
        }
        h = keccak256(abi.encode(h, apps.appCount(), platform.imageCount()));
        for (uint256 i; i < _slugs.length; ++i) {
            bytes32 appId = appIdOf(i);
            if (!apps.appExists(appId)) continue;
            IAppRegistry.App memory a = apps.getApp(appId);
            h = keccak256(abi.encode(h, appId, a.maintainer, a.maintainerShareBps, a.metadataURI, a.name));
            uint256 n = apps.releaseCount(appId);
            for (uint256 j; j < n; ++j) {
                h = keccak256(abi.encode(h, apps.releaseStatus(apps.releaseAt(appId, j))));
            }
        }
        for (uint256 i; i < _imageIdPool.length; ++i) {
            h = keccak256(abi.encode(h, platform.imageStatus(_imageIdPool[i])));
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // AppRegistry
    // ------------------------------------------------------------------------------------------------------

    function registerApp(
        uint256 actorSeed,
        uint256 slugSeed,
        bool emptyName,
        bool wrongId,
        uint256 maintainerSeed,
        uint256 share
    ) external {
        address actor = _actor(actorSeed);
        string memory slug = _slugs[slugSeed % _slugs.length];
        bytes32 appId = wrongId ? keccak256(abi.encode(slug)) : keccak256(bytes(slug));
        address maintainer = maintainerSeed % 9 == 0 ? address(0) : _actor(maintainerSeed >> 8);
        uint16 bps = uint16(bound(share, 0, 6000));
        string memory name = emptyName ? "" : string.concat("App ", slug);
        string memory uri = string.concat("ipfs://", slug, vm.toString(maintainerSeed % 3));
        bool expected = actor == appsOwner && bytes(slug).length != 0 && !emptyName && !wrongId && !_gApp[appId].exists
            && maintainer != address(0) && bps <= 5000;

        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.registerApp(appId, slug, name, "MIT", maintainer, bps, uri) {
            _expect(expected, true, "registerApp");
            _gApp[appId] =
                GApp(true, maintainer, bps, keccak256(bytes(uri)), keccak256(bytes(name)), uint64(block.timestamp));
            appOrder.push(appId);
        } catch {
            _expect(expected, false, "registerApp");
        }
        _checkChange(before, actor == appsOwner, "registerApp");
    }

    function setMaintainer(uint256 actorSeed, uint256 slugSeed, uint256 newSeed) external {
        address actor = _actor(actorSeed);
        bytes32 appId = appIdOf(slugSeed % _slugs.length);
        GApp storage g = _gApp[appId];
        address next = newSeed % 9 == 0 ? address(0) : _actor(newSeed >> 8);
        bool authorized = actor == appsOwner || (g.exists && actor == g.maintainer);
        bool expected = g.exists && authorized && next != address(0);

        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.setMaintainer(appId, next) {
            _expect(expected, true, "setMaintainer");
            g.maintainer = next;
        } catch {
            _expect(expected, false, "setMaintainer");
        }
        _checkChange(before, authorized, "setMaintainer");
    }

    function setMaintainerShare(uint256 actorSeed, uint256 slugSeed, uint256 share) external {
        address actor = _actor(actorSeed);
        bytes32 appId = appIdOf(slugSeed % _slugs.length);
        uint16 bps = uint16(bound(share, 0, 6000));
        bool expected = actor == appsOwner && _gApp[appId].exists && bps <= 5000;

        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.setMaintainerShare(appId, bps) {
            _expect(expected, true, "setMaintainerShare");
            _gApp[appId].share = bps;
        } catch {
            _expect(expected, false, "setMaintainerShare");
        }
        _checkChange(before, actor == appsOwner, "setMaintainerShare");
    }

    function setMetadataURI(uint256 actorSeed, uint256 slugSeed, uint256 uriSeed) external {
        address actor = _actor(actorSeed);
        bytes32 appId = appIdOf(slugSeed % _slugs.length);
        string memory uri = string.concat("https://example.org/meta/", vm.toString(uriSeed % 5));
        bool expected = actor == appsOwner && _gApp[appId].exists;

        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.setMetadataURI(appId, uri) {
            _expect(expected, true, "setMetadataURI");
            _gApp[appId].metadataHash = keccak256(bytes(uri));
        } catch {
            _expect(expected, false, "setMetadataURI");
        }
        _checkChange(before, actor == appsOwner, "setMetadataURI");
    }

    function publishRelease(uint256 actorSeed, uint256 slugSeed, uint256 versionSeed, uint256 bundleSeed) external {
        address actor = _actor(actorSeed);
        bytes32 appId = appIdOf(slugSeed % _slugs.length);
        string memory version = _versions[versionSeed % _versions.length];
        bytes32 bundleHash = _bundles[bundleSeed % _bundles.length];
        bytes32 id = keccak256(abi.encode(appId, version, bundleHash));
        bytes32 vh = keccak256(bytes(version));
        bool expected = ghostRegistrar[actor] && _gApp[appId].exists && bytes(version).length != 0
            && bundleHash != bytes32(0) && _releaseIndex[id] == 0 && ghostByVersion[appId][vh] == bytes32(0)
            && ghostByBundle[appId][bundleHash] == bytes32(0);

        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.publishRelease(appId, version, bundleHash, bytes32(0), bytes32(0), "", "") returns (bytes32 got) {
            _expect(expected, true, "publishRelease");
            if (got != id) _mismatch("publishRelease returned another id");
            _releases.push(GRelease(id, appId, version, bundleHash, S.Active, false));
            _releaseIndex[id] = _releases.length;
            _appReleases[appId].push(id);
            ghostByVersion[appId][vh] = id;
            ghostByBundle[appId][bundleHash] = id;
        } catch {
            _expect(expected, false, "publishRelease");
        }
        _checkChange(before, ghostRegistrar[actor], "publishRelease");
    }

    function deprecateRelease(uint256 actorSeed, uint256 releaseSeed) external {
        address actor = _actor(actorSeed);
        (bytes32 id, uint256 idx) = _pickRelease(releaseSeed);
        bool expected = actor == appsOwner && idx != 0 && _releases[idx - 1].status == S.Active;

        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.deprecateRelease(id) {
            _expect(expected, true, "deprecateRelease");
            _releases[idx - 1].status = S.Deprecated;
            _releases[idx - 1].everDeactivated = true;
        } catch {
            _expect(expected, false, "deprecateRelease");
        }
        _checkChange(before, actor == appsOwner, "deprecateRelease");
    }

    function revokeRelease(uint256 actorSeed, uint256 releaseSeed) external {
        address actor = _actor(actorSeed);
        (bytes32 id, uint256 idx) = _pickRelease(releaseSeed);
        bool expected = actor == appsOwner && idx != 0 && _releases[idx - 1].status != S.Revoked;

        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.revokeRelease(id, "invariant") {
            _expect(expected, true, "revokeRelease");
            _releases[idx - 1].status = S.Revoked;
            _releases[idx - 1].everDeactivated = true;
        } catch {
            _expect(expected, false, "revokeRelease");
        }
        _checkChange(before, actor == appsOwner, "revokeRelease");
    }

    function grantRegistrar(uint256 actorSeed, uint256 accountSeed, bool zero) external {
        address actor = _actor(actorSeed);
        address account = zero ? address(0) : _actor(accountSeed);
        bool expected = actor == appsOwner && account != address(0) && !ghostRegistrar[account];

        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.grantRegistrar(account) {
            _expect(expected, true, "grantRegistrar");
            ghostRegistrar[account] = true;
        } catch {
            _expect(expected, false, "grantRegistrar");
        }
        _checkChange(before, actor == appsOwner, "grantRegistrar");
    }

    function revokeRegistrar(uint256 actorSeed, uint256 accountSeed) external {
        address actor = _actor(actorSeed);
        address account = _actor(accountSeed);
        bool expected = actor == appsOwner && ghostRegistrar[account];

        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.revokeRegistrar(account) {
            _expect(expected, true, "revokeRegistrar");
            ghostRegistrar[account] = false;
        } catch {
            _expect(expected, false, "revokeRegistrar");
        }
        _checkChange(before, actor == appsOwner, "revokeRegistrar");
    }

    /// @dev AccessControl.renounceRole: only for the caller itself (callerConfirmation), never for another account.
    function renounceRegistrar(uint256 actorSeed, uint256 confirmSeed) external {
        address actor = _actor(actorSeed);
        address confirmation = confirmSeed % 3 == 0 ? _actor(confirmSeed >> 8) : actor;
        bool expected = confirmation == actor;

        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.renounceRole(REGISTRAR, confirmation) {
            _expect(expected, true, "renounceRole");
            ghostRegistrar[actor] = false;
        } catch {
            _expect(expected, false, "renounceRole");
        }
        _checkChange(before, expected, "renounceRole");
    }

    /// @dev grantRole and revokeRole need DEFAULT_ADMIN_ROLE, which nobody ever holds: they always revert.
    function rawRoleCall(uint256 actorSeed, uint256 accountSeed, bool adminRole, bool grant) external {
        address actor = _actor(actorSeed);
        address account = _actor(accountSeed);
        bytes32 role = adminRole ? bytes32(0) : REGISTRAR;
        bytes32 before = fingerprint();
        vm.prank(actor);
        if (grant) {
            try apps.grantRole(role, account) {
                _mismatch("grantRole succeeded");
            } catch {}
        } else {
            try apps.revokeRole(role, account) {
                _mismatch("revokeRole succeeded");
            } catch {}
        }
        _checkChange(before, false, "rawRoleCall");
        calls["rawRoleCall"]++;
    }

    function appsTransferOwnership(uint256 actorSeed, uint256 newSeed) external {
        address actor = _actor(actorSeed);
        address next = newSeed % 7 == 0 ? address(0) : _actor(newSeed >> 8);
        bool expected = actor == appsOwner;
        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.transferOwnership(next) {
            _expect(expected, true, "appsTransferOwnership");
            appsPending = next;
        } catch {
            _expect(expected, false, "appsTransferOwnership");
        }
        _checkChange(before, expected, "appsTransferOwnership");
    }

    function appsAcceptOwnership(uint256 actorSeed) external {
        address actor = _actor(actorSeed);
        bool expected = appsPending != address(0) && actor == appsPending;
        bytes32 before = fingerprint();
        vm.prank(actor);
        try apps.acceptOwnership() {
            _expect(expected, true, "appsAcceptOwnership");
            appsOwner = actor;
            appsPending = address(0);
        } catch {
            _expect(expected, false, "appsAcceptOwnership");
        }
        _checkChange(before, expected, "appsAcceptOwnership");
    }

    function renounceOwnership(uint256 actorSeed, bool onPlatform) external {
        address actor = _actor(actorSeed);
        bytes32 before = fingerprint();
        vm.prank(actor);
        if (onPlatform) {
            try platform.renounceOwnership() {
                _mismatch("platform renounceOwnership succeeded");
            } catch {}
        } else {
            try apps.renounceOwnership() {
                _mismatch("apps renounceOwnership succeeded");
            } catch {}
        }
        _checkChange(before, false, "renounceOwnership");
        calls["renounceOwnership"]++;
    }

    // ------------------------------------------------------------------------------------------------------
    // PlatformRegistry
    // ------------------------------------------------------------------------------------------------------

    struct AddImageCall {
        address actor;
        bytes32 id;
        bytes[4] m;
        bool isDebug;
        string name;
        bytes32 mh;
        bool expected;
    }

    function addImage(
        uint256 actorSeed,
        uint256 idSeed,
        uint256 setSeed,
        bool isDebug,
        bool emptyName,
        uint256 badLengthSeed
    ) external {
        AddImageCall memory c;
        c.actor = _actor(actorSeed);
        c.id = _imageIdPool[idSeed % _imageIdPool.length];
        c.m = _measurementSets[setSeed % _measurementSets.length];
        c.isDebug = isDebug;
        c.name = emptyName ? "" : "sealed-os";
        bool badLength = badLengthSeed % 8 == 0;
        if (badLength) c.m[(badLengthSeed >> 8) % 4] = new bytes(badLengthSeed % 2 == 0 ? 47 : 49);
        else c.mh = keccak256(abi.encodePacked(c.m[0], c.m[1], c.m[2], c.m[3]));
        c.expected = c.actor == platformOwner && c.id != bytes32(0) && _imageIndex[c.id] == 0 && !emptyName
            && !badLength && ghostByMeasurements[c.mh] == bytes32(0);
        _addImage(c);
    }

    function _addImage(AddImageCall memory c) internal {
        bytes32 before = fingerprint();
        (bool ok, bytes32 got) = _tryAddImage(c);
        _expect(c.expected, ok, "addImage");
        if (ok) {
            if (got != c.mh) _mismatch("addImage returned another measurementsHash");
            _images.push(GImage(c.id, c.mh, c.isDebug, S.Active, false));
            _imageIndex[c.id] = _images.length;
            ghostByMeasurements[c.mh] = c.id;
        }
        _checkChange(before, c.actor == platformOwner, "addImage");
    }

    function _tryAddImage(AddImageCall memory c) internal returns (bool ok, bytes32 got) {
        vm.prank(c.actor);
        try platform.addImage(c.id, c.name, "1.0.0", c.m[0], c.m[1], c.m[2], c.m[3], c.isDebug, "") returns (
            bytes32 h
        ) {
            return (true, h);
        } catch {
            return (false, bytes32(0));
        }
    }

    function deprecateImage(uint256 actorSeed, uint256 idSeed) external {
        address actor = _actor(actorSeed);
        bytes32 id = _imageIdPool[idSeed % _imageIdPool.length];
        uint256 idx = _imageIndex[id];
        bool expected = actor == platformOwner && idx != 0 && _images[idx - 1].status == S.Active;

        bytes32 before = fingerprint();
        vm.prank(actor);
        try platform.deprecateImage(id) {
            _expect(expected, true, "deprecateImage");
            _images[idx - 1].status = S.Deprecated;
            _images[idx - 1].everDeactivated = true;
        } catch {
            _expect(expected, false, "deprecateImage");
        }
        _checkChange(before, actor == platformOwner, "deprecateImage");
    }

    function revokeImage(uint256 actorSeed, uint256 idSeed) external {
        address actor = _actor(actorSeed);
        bytes32 id = _imageIdPool[idSeed % _imageIdPool.length];
        uint256 idx = _imageIndex[id];
        bool expected = actor == platformOwner && idx != 0 && _images[idx - 1].status != S.Revoked;

        bytes32 before = fingerprint();
        vm.prank(actor);
        try platform.revokeImage(id, "invariant") {
            _expect(expected, true, "revokeImage");
            _images[idx - 1].status = S.Revoked;
            _images[idx - 1].everDeactivated = true;
        } catch {
            _expect(expected, false, "revokeImage");
        }
        _checkChange(before, actor == platformOwner, "revokeImage");
    }

    function platformTransferOwnership(uint256 actorSeed, uint256 newSeed) external {
        address actor = _actor(actorSeed);
        address next = newSeed % 7 == 0 ? address(0) : _actor(newSeed >> 8);
        bool expected = actor == platformOwner;
        bytes32 before = fingerprint();
        vm.prank(actor);
        try platform.transferOwnership(next) {
            _expect(expected, true, "platformTransferOwnership");
            platformPending = next;
        } catch {
            _expect(expected, false, "platformTransferOwnership");
        }
        _checkChange(before, expected, "platformTransferOwnership");
    }

    function platformAcceptOwnership(uint256 actorSeed) external {
        address actor = _actor(actorSeed);
        bool expected = platformPending != address(0) && actor == platformPending;
        bytes32 before = fingerprint();
        vm.prank(actor);
        try platform.acceptOwnership() {
            _expect(expected, true, "platformAcceptOwnership");
            platformOwner = actor;
            platformPending = address(0);
        } catch {
            _expect(expected, false, "platformAcceptOwnership");
        }
        _checkChange(before, expected, "platformAcceptOwnership");
    }

    function warp(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 1, 3 days));
    }

    // ------------------------------------------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------------------------------------------

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    /// @dev A known release most of the time, an unknown id otherwise. Returns its model index plus one (0 when
    ///      unknown).
    function _pickRelease(uint256 seed) internal view returns (bytes32 id, uint256 idx) {
        if (_releases.length == 0 || seed % 6 == 0) return (keccak256(abi.encode("unknown-release", seed)), 0);
        idx = (seed >> 8) % _releases.length + 1;
        id = _releases[idx - 1].id;
    }

    function _expect(bool expected, bool succeeded, string memory what) internal {
        if (expected != succeeded) {
            _mismatch(string.concat(what, succeeded ? " succeeded unexpectedly" : " reverted unexpectedly"));
        }
        calls[string.concat(what, succeeded ? "-ok" : "-rejected")]++;
    }

    function _checkChange(bytes32 before, bool authorizedPath, string memory what) internal {
        if (fingerprint() != before && !authorizedPath) {
            unauthorizedChange = true;
            lastMismatch = string.concat(what, " changed state from an unauthorized caller");
        }
    }

    function _mismatch(string memory what) internal {
        unexpectedOutcome = true;
        lastMismatch = what;
    }
}
