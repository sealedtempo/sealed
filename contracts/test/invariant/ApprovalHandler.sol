// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {DeploymentRegistry} from "../../src/DeploymentRegistry.sol";
import {PlatformRegistry} from "../../src/PlatformRegistry.sol";

/// @notice Drives stack approvals and every catalog transition that can invalidate them (stack revoke, expiry,
///         release deprecate/revoke, image deprecate/revoke, re-approval), keeping an independent ghost model of
///         what isStackApproved must return.
contract ApprovalHandler is Test {
    enum S {
        None,
        Active,
        Deprecated,
        Revoked
    }

    struct GhostApproval {
        bool exists;
        bool revoked;
        uint64 expiry;
        bytes32 imageId;
        bytes32[] releaseIds;
    }

    DeploymentRegistry public immutable registry;
    AppRegistry public immutable apps;
    PlatformRegistry public immutable platform;
    address public immutable owner;
    address public immutable registrar;

    address[] public customers;
    bytes32[] public stacks;
    bytes32[] public releases;
    bytes32[] public images;
    bytes32[] internal _appIds;

    mapping(bytes32 releaseId => S) public releaseStatus;
    mapping(bytes32 imageId => S) public imageStatus;
    mapping(bytes32 imageId => bool) public imageDebug;
    mapping(address customer => mapping(bytes32 stackHash => GhostApproval)) internal _ghost;

    uint256 internal _nonce;
    mapping(string name => uint256) public calls;
    bool public unexpectedOutcome;

    constructor(
        DeploymentRegistry registry_,
        AppRegistry apps_,
        PlatformRegistry platform_,
        address owner_,
        address registrar_,
        bytes32[] memory appIds_,
        bytes32[] memory releases_,
        bytes32[] memory images_,
        bool[] memory imageDebug_
    ) {
        registry = registry_;
        apps = apps_;
        platform = platform_;
        owner = owner_;
        registrar = registrar_;
        for (uint256 i; i < appIds_.length; ++i) {
            _appIds.push(appIds_[i]);
        }
        for (uint256 i; i < releases_.length; ++i) {
            releases.push(releases_[i]);
            releaseStatus[releases_[i]] = S.Active;
        }
        for (uint256 i; i < images_.length; ++i) {
            images.push(images_[i]);
            imageStatus[images_[i]] = S.Active;
            imageDebug[images_[i]] = imageDebug_[i];
        }
        for (uint256 i; i < 3; ++i) {
            customers.push(makeAddr(string.concat("approval-customer-", vm.toString(i))));
            stacks.push(keccak256(abi.encode("approval-stack", i)));
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Model
    // ------------------------------------------------------------------------------------------------------

    function customerCount() external view returns (uint256) {
        return customers.length;
    }

    function stackCount() external view returns (uint256) {
        return stacks.length;
    }

    function ghostApproval(address c, bytes32 s)
        external
        view
        returns (bool exists, bool revoked, uint64 expiry, bytes32 imageId, bytes32[] memory releaseIds)
    {
        GhostApproval storage g = _ghost[c][s];
        return (g.exists, g.revoked, g.expiry, g.imageId, g.releaseIds);
    }

    /// @notice What isStackApproved must return according to the model.
    function expectedApproved(address c, bytes32 s) public view returns (bool) {
        GhostApproval storage g = _ghost[c][s];
        if (!g.exists || g.revoked) return false;
        // forge-lint: disable-next-line(block-timestamp)
        if (g.expiry != 0 && block.timestamp >= g.expiry) return false;
        if (imageStatus[g.imageId] != S.Active || imageDebug[g.imageId]) return false;
        for (uint256 i; i < g.releaseIds.length; ++i) {
            S st = releaseStatus[g.releaseIds[i]];
            if (st != S.Active && st != S.Deprecated) return false;
        }
        return true;
    }

    // ------------------------------------------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------------------------------------------

    /// @param pickValid When true, only currently approvable releases and an approved image are chosen (if any
    ///        exist), so successful approvals stay frequent even after many revocations.
    function approve(
        uint256 cSeed,
        uint256 sSeed,
        uint256 releaseMask,
        uint256 imageSeed,
        uint256 expirySeed,
        bool pickValid
    ) external {
        address c = customers[cSeed % customers.length];
        bytes32 s = stacks[sSeed % stacks.length];
        bytes32 imageId = images[imageSeed % images.length];
        releaseMask = bound(releaseMask, 1, 2 ** releases.length - 1);
        if (pickValid) {
            uint256 validMask;
            for (uint256 i; i < releases.length; ++i) {
                if (releaseStatus[releases[i]] == S.Active) validMask |= 2 ** i;
            }
            if (validMask & releaseMask != 0) releaseMask &= validMask;
            else if (validMask != 0) releaseMask = validMask;
            for (uint256 i; i < images.length; ++i) {
                bytes32 candidate = images[(imageSeed % images.length + i) % images.length];
                if (imageStatus[candidate] == S.Active && !imageDebug[candidate]) {
                    imageId = candidate;
                    break;
                }
            }
        }
        uint256 n;
        for (uint256 i; i < releases.length; ++i) {
            if (releaseMask & 2 ** i != 0) ++n;
        }
        bytes32[] memory ids = new bytes32[](n);
        uint256 k;
        bool approvable = true;
        for (uint256 i; i < releases.length; ++i) {
            if (releaseMask & 2 ** i != 0) {
                ids[k++] = releases[i];
                if (releaseStatus[releases[i]] != S.Active) approvable = false;
            }
        }
        uint64 expiry = expirySeed % 3 == 0 ? 0 : uint64(block.timestamp + bound(expirySeed, 1, 3 days));
        bool imageOk = imageStatus[imageId] == S.Active && !imageDebug[imageId];
        bool shouldSucceed = approvable && imageOk && n <= 16;

        vm.prank(c);
        try registry.approveStack(s, ids, imageId, expiry) {
            if (!shouldSucceed) unexpectedOutcome = true;
            GhostApproval storage g = _ghost[c][s];
            g.exists = true;
            g.revoked = false;
            g.expiry = expiry;
            g.imageId = imageId;
            g.releaseIds = ids;
            calls["approve"]++;
        } catch {
            if (shouldSucceed) unexpectedOutcome = true;
            calls["approveRejected"]++;
        }
    }

    function revokeStack(uint256 cSeed, uint256 sSeed) external {
        address c = customers[cSeed % customers.length];
        bytes32 s = stacks[sSeed % stacks.length];
        GhostApproval storage g = _ghost[c][s];
        if (!g.exists || g.revoked) return;
        vm.prank(c);
        registry.revokeStack(s);
        g.revoked = true;
        calls["revokeStack"]++;
    }

    function deprecateRelease(uint256 seed) external {
        if (seed % 3 != 0) return; // keep catalog revocations rarer than approvals
        bytes32 id = releases[seed % releases.length];
        if (releaseStatus[id] != S.Active) return;
        vm.prank(owner);
        apps.deprecateRelease(id);
        releaseStatus[id] = S.Deprecated;
        calls["deprecateRelease"]++;
    }

    function revokeRelease(uint256 seed) external {
        if (seed % 3 != 0) return; // keep catalog revocations rarer than approvals
        bytes32 id = releases[seed % releases.length];
        if (releaseStatus[id] == S.Revoked) return;
        vm.prank(owner);
        apps.revokeRelease(id, "invariant");
        releaseStatus[id] = S.Revoked;
        calls["revokeRelease"]++;
    }

    function publishRelease(uint256 appSeed) external {
        if (releases.length >= 10) return;
        bytes32 appId = _appIds[appSeed % _appIds.length];
        string memory version = string.concat("inv-", vm.toString(++_nonce));
        vm.prank(registrar);
        bytes32 id = apps.publishRelease(appId, version, keccak256(bytes(version)), bytes32(0), bytes32(0), "", "");
        releases.push(id);
        releaseStatus[id] = S.Active;
        calls["publishRelease"]++;
    }

    function deprecateImage(uint256 seed) external {
        if (seed % 3 != 0) return; // keep catalog revocations rarer than approvals
        bytes32 id = images[seed % images.length];
        if (imageStatus[id] != S.Active) return;
        vm.prank(owner);
        platform.deprecateImage(id);
        imageStatus[id] = S.Deprecated;
        calls["deprecateImage"]++;
    }

    function revokeImage(uint256 seed) external {
        if (seed % 3 != 0) return; // keep catalog revocations rarer than approvals
        bytes32 id = images[seed % images.length];
        if (imageStatus[id] == S.Revoked) return;
        vm.prank(owner);
        platform.revokeImage(id, "invariant");
        imageStatus[id] = S.Revoked;
        calls["revokeImage"]++;
    }

    function addImage(bool isDebug) external {
        if (images.length >= 6) return;
        bytes32 id = keccak256(abi.encode("inv-image", ++_nonce));
        bytes memory m = new bytes(48);
        vm.prank(owner);
        platform.addImage(id, "inv", vm.toString(_nonce), m, m, m, m, isDebug, "");
        images.push(id);
        imageStatus[id] = S.Active;
        imageDebug[id] = isDebug;
        calls["addImage"]++;
    }

    function warp(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 1, 1 days));
        calls["warp"]++;
    }
}
