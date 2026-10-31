// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {DeploymentRegistry} from "../../src/DeploymentRegistry.sol";
import {FeeSplitter} from "../../src/FeeSplitter.sol";
import {OracleSignatureVerifier} from "../../src/OracleSignatureVerifier.sol";
import {PlatformRegistry} from "../../src/PlatformRegistry.sol";
import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";
import {MockERC20} from "../mocks/MockERC20.sol";

/// @notice Drives the whole deployment lifecycle with the real OracleSignatureVerifier: stack approvals and
///         revocations, registrations and heartbeats with valid and invalid records (stale, future, before the
///         approval, wrong image, bad or malleated evidence, non-signer keys, unset methods), closes by every
///         kind of caller, catalog deactivations, signer changes, pauses, attestation-age changes, and FeeSplitter
///         payments and top-ups on usage keys drawn from a small shared pool (so the same usageHash and app meet
///         on every deployment). Every outcome is checked against an independent model.
contract LifecycleHandler is Test {
    enum S {
        None,
        Active,
        Deprecated,
        Revoked
    }

    uint8 internal constant D_NONE = 0;
    uint8 internal constant D_ACTIVE = 1;
    uint8 internal constant D_CLOSED = 2;
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint64 internal constant SKEW = 5 minutes;

    struct GApproval {
        bool exists;
        bool revoked;
        uint64 expiry;
        uint64 approvedAt;
        bytes32 imageId;
        bytes32[] releaseIds;
    }

    struct GDep {
        uint8 status;
        address customer;
        bytes32 stackHash;
        bytes32 imageId;
        address enclaveSigner;
        uint64 attestedAt;
        uint64 lastAttestedAt;
        bytes32 quoteHash;
        bytes32 configHash;
        uint64 registeredAt;
        uint64 closedAt;
        bool approvedAtRegistration;
        bool signerAtRegistration;
    }

    struct Sys {
        DeploymentRegistry registry;
        AppRegistry apps;
        PlatformRegistry platform;
        OracleSignatureVerifier verifier;
        FeeSplitter splitter;
        MockERC20 token;
        address owner;
        address ops;
    }

    DeploymentRegistry public immutable registry;
    AppRegistry public immutable apps;
    PlatformRegistry public immutable platform;
    OracleSignatureVerifier public immutable verifier;
    FeeSplitter public immutable splitter;
    MockERC20 public immutable token;
    address public immutable owner;
    address public immutable ops;
    address public immutable stranger;

    address[] public customers;
    address[] public enclaves;
    bytes32[] public stacks;
    bytes32[] public salts;
    bytes32[] public usagePool;
    bytes32[] public appIds;

    uint256[] internal _oracleKeys;
    address[] public oracleAddrs;
    mapping(address signer => bool) public ghostSigner;

    bytes32[] public releases;
    mapping(bytes32 releaseId => S) public releaseStatus;
    mapping(bytes32 releaseId => bytes32 appId) public releaseApp;
    mapping(bytes32 releaseId => bool) public releaseEverDeactivated;
    bytes32[] public images;
    mapping(bytes32 imageId => S) public imageStatus;
    mapping(bytes32 imageId => bool) public imageDebug;

    mapping(address customer => mapping(bytes32 stackHash => GApproval)) internal _ghost;
    bytes32[] public depIds;
    mapping(bytes32 deploymentId => GDep) internal _dep;
    mapping(bytes32 legKey => uint256) public ghostLeg;

    struct Leg {
        bytes32 id;
        bytes32 usageHash;
        bytes32 appId;
    }

    Leg[] internal _legs;

    bool public registryPaused;
    uint64 public maxAge;
    uint256 internal _nonce;

    bool public unexpectedOutcome;
    bool public registeredUnapproved;
    bool public heartbeatOnUnapproved;
    bool public paidWhileNotActive;
    string public lastMismatch;
    mapping(string name => uint256) public calls;
    /// @notice Revert selectors seen by registerDeployment and heartbeat, for tuning the handler.
    mapping(bytes4 selector => uint256) public errors;

    constructor(
        Sys memory s,
        bytes32[] memory appIds_,
        bytes32[] memory releases_,
        bytes32[] memory images_,
        bool[] memory debug_
    ) {
        registry = s.registry;
        apps = s.apps;
        platform = s.platform;
        verifier = s.verifier;
        splitter = s.splitter;
        token = s.token;
        owner = s.owner;
        ops = s.ops;
        stranger = makeAddr("lifecycle-stranger");
        maxAge = s.registry.maxAttestationAge();
        for (uint256 i; i < appIds_.length; ++i) {
            appIds.push(appIds_[i]);
        }
        for (uint256 i; i < releases_.length; ++i) {
            releases.push(releases_[i]);
            releaseStatus[releases_[i]] = S.Active;
            releaseApp[releases_[i]] = s.apps.appOfRelease(releases_[i]);
        }
        for (uint256 i; i < images_.length; ++i) {
            images.push(images_[i]);
            imageStatus[images_[i]] = S.Active;
            imageDebug[images_[i]] = debug_[i];
        }
        for (uint256 i; i < 2; ++i) {
            customers.push(makeAddr(string.concat("lifecycle-customer-", vm.toString(i))));
            enclaves.push(makeAddr(string.concat("lifecycle-enclave-", vm.toString(i))));
        }
        for (uint256 i; i < 4; ++i) {
            stacks.push(keccak256(abi.encode("lifecycle-stack", i)));
        }
        for (uint256 i; i < 5; ++i) {
            salts.push(bytes32(i + 1));
        }
        for (uint256 i; i < 3; ++i) {
            usagePool.push(keccak256(abi.encode("lifecycle-usage", i)));
            (address a, uint256 k) = makeAddrAndKey(string.concat("lifecycle-oracle-", vm.toString(i)));
            oracleAddrs.push(a);
            _oracleKeys.push(k);
        }
    }

    /// @notice Copies the signer set the test's setUp configured into the model.
    function seedSigners() external {
        for (uint256 i; i < oracleAddrs.length; ++i) {
            ghostSigner[oracleAddrs[i]] = verifier.isSigner(oracleAddrs[i]);
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Model views
    // ------------------------------------------------------------------------------------------------------

    function counts() external view returns (uint256 c, uint256 s, uint256 salt, uint256 u, uint256 a, uint256 d) {
        return (customers.length, stacks.length, salts.length, usagePool.length, appIds.length, depIds.length);
    }

    function releaseCount() external view returns (uint256) {
        return releases.length;
    }

    function imageCount() external view returns (uint256) {
        return images.length;
    }

    function dep(bytes32 id) external view returns (GDep memory) {
        return _dep[id];
    }

    function ghostApproval(address c, bytes32 s) external view returns (GApproval memory) {
        return _ghost[c][s];
    }

    function deploymentIdOf(address c, bytes32 s, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(c, s, salt));
    }

    function legKey(bytes32 id, bytes32 usageHash, bytes32 appId) public pure returns (bytes32) {
        return keccak256(abi.encode(id, usageHash, appId));
    }

    function expectedApproved(address c, bytes32 s) public view returns (bool) {
        GApproval storage g = _ghost[c][s];
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

    function expectedAppIn(bytes32 id, bytes32 appId) public view returns (bool) {
        GDep storage d = _dep[id];
        if (d.status == D_NONE || appId == bytes32(0)) return false;
        bytes32[] storage ids = _ghost[d.customer][d.stackHash].releaseIds;
        for (uint256 i; i < ids.length; ++i) {
            if (releaseApp[ids[i]] == appId) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------------------------------------------
    // Approvals
    // ------------------------------------------------------------------------------------------------------

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
        GApproval storage g = _ghost[c][s];
        bytes32 imageId;
        bytes32[] memory ids;
        if (g.exists && pickValid) {
            imageId = g.imageId;
            ids = g.releaseIds;
        } else {
            (imageId, ids) = _pickContent(releaseMask, imageSeed, pickValid);
        }
        uint64 expiry = expirySeed % 3 != 0 ? 0 : uint64(block.timestamp + bound(expirySeed, 1, 3 days));
        bool expected = _approvalShouldSucceed(g, imageId, ids);
        bool reapproval = g.exists;
        vm.prank(c);
        try registry.approveStack(s, ids, imageId, expiry) {
            if (!expected) _mismatch("approveStack succeeded");
            if (!reapproval) {
                g.exists = true;
                g.imageId = imageId;
                g.releaseIds = ids;
            }
            g.revoked = false;
            g.expiry = expiry;
            g.approvedAt = uint64(block.timestamp);
            calls[reapproval ? "reapprove" : "approve"]++;
        } catch {
            if (expected) _mismatch("approveStack reverted");
            calls["approveRejected"]++;
        }
    }

    function revokeStack(uint256 cSeed, uint256 sSeed) external {
        address c = customers[cSeed % customers.length];
        bytes32 s = stacks[sSeed % stacks.length];
        GApproval storage g = _ghost[c][s];
        bool expected = g.exists && !g.revoked;
        vm.prank(c);
        try registry.revokeStack(s) {
            if (!expected) _mismatch("revokeStack succeeded");
            g.revoked = true;
            calls["revokeStack"]++;
        } catch {
            if (expected) _mismatch("revokeStack reverted");
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Registration and heartbeats
    // ------------------------------------------------------------------------------------------------------

    struct RegisterCall {
        IDeploymentRegistry.Record r;
        uint8 method;
        bytes evidence;
        address oracleAddr;
        bool evidenceOk;
        bool expected;
        address submitter;
    }

    function register(
        uint256 cSeed,
        uint256 sSeed,
        uint256 saltSeed,
        uint256 keySeed,
        uint256 timeSeed,
        uint256 mutation
    ) external {
        RegisterCall memory c;
        (address customer, bytes32 s) = _pickStack(cSeed, sSeed);
        GApproval storage g = _ghost[customer][s];
        uint256 k = _pickKey(keySeed);
        c.oracleAddr = oracleAddrs[k];
        c.method = 1;
        c.evidenceOk = true;
        c.submitter = (keySeed >> 8) % 2 == 0 ? ops : stranger;
        mutation = mutation % 40; // 10..19 are the invalid records, the rest are valid

        c.r.deploymentId = mutation == 10 ? bytes32(0) : deploymentIdOf(customer, s, salts[saltSeed % salts.length]);
        c.r.customer = customer;
        c.r.stackHash = s;
        c.r.imageId = g.exists ? g.imageId : images[0];
        if (mutation == 11) c.r.imageId = images[(imageIndexOf(c.r.imageId) + 1) % images.length];
        c.r.quoteHash = keccak256(abi.encode("lifecycle-quote", ++_nonce));
        c.r.eventLogHash = keccak256(abi.encode("lifecycle-eventlog", _nonce));
        c.r.configHash = keccak256(abi.encode("lifecycle-config", _nonce));
        c.r.enclaveSigner = mutation == 12 ? address(0) : enclaves[(saltSeed >> 8) % enclaves.length];
        c.r.attestedAt = _registrationTime(g.approvedAt, timeSeed, mutation);

        bytes32 digest = registry.recordDigest(c.r);
        if (mutation == 16) digest = registry.heartbeatDigest(c.r.deploymentId, c.r.quoteHash, c.r.attestedAt);
        (c.evidence, c.evidenceOk) = _evidence(_oracleKeys[k], digest, mutation);
        if (mutation == 16) c.evidenceOk = false;
        if (mutation == 19) c.method = (timeSeed >> 8) % 2 == 0 ? 0 : 2;

        bool fresh =
            uint256(c.r.attestedAt) <= block.timestamp + SKEW && uint256(c.r.attestedAt) + maxAge >= block.timestamp;
        c.expected = !registryPaused && c.r.deploymentId != bytes32(0) && _dep[c.r.deploymentId].status == D_NONE
            && c.r.enclaveSigner != address(0) && expectedApproved(customer, s) && c.r.imageId == g.imageId && fresh
            && uint256(c.r.attestedAt) + SKEW >= g.approvedAt && c.method == 1 && c.evidenceOk
            && ghostSigner[c.oracleAddr];
        _register(c);
    }

    function _register(RegisterCall memory c) internal {
        vm.prank(c.submitter);
        try registry.registerDeployment(c.r, c.method, c.evidence) {
            if (!c.expected) _mismatch("registerDeployment succeeded");
            bool approved = expectedApproved(c.r.customer, c.r.stackHash);
            if (!approved) registeredUnapproved = true;
            GDep storage d = _dep[c.r.deploymentId];
            d.status = D_ACTIVE;
            d.customer = c.r.customer;
            d.stackHash = c.r.stackHash;
            d.imageId = c.r.imageId;
            d.enclaveSigner = c.r.enclaveSigner;
            d.attestedAt = c.r.attestedAt;
            d.lastAttestedAt = c.r.attestedAt;
            d.quoteHash = c.r.quoteHash;
            d.configHash = c.r.configHash;
            d.registeredAt = uint64(block.timestamp);
            d.approvedAtRegistration = approved;
            d.signerAtRegistration = c.evidenceOk && ghostSigner[c.oracleAddr];
            depIds.push(c.r.deploymentId);
            calls["register"]++;
        } catch (bytes memory reason) {
            if (c.expected) _mismatch("registerDeployment reverted");
            calls["registerRejected"]++;
            // forge-lint: disable-next-line(unsafe-typecast)
            errors[bytes4(reason)]++;
        }
    }

    /// @dev Half of the time the first currently approved (customer, stack) from a random start, so registrations
    ///      keep succeeding while the catalog decays; otherwise any pair.
    function _pickStack(uint256 cSeed, uint256 sSeed) internal view returns (address, bytes32) {
        uint256 nc = customers.length;
        uint256 ns = stacks.length;
        if (cSeed % 2 == 0) {
            for (uint256 i; i < nc * ns; ++i) {
                uint256 j = (sSeed % (nc * ns) + i) % (nc * ns);
                if (expectedApproved(customers[j / ns], stacks[j % ns])) return (customers[j / ns], stacks[j % ns]);
            }
        }
        return (customers[(cSeed >> 1) % nc], stacks[sSeed % ns]);
    }

    /// @dev A time inside every window most of the time; mutations 13..15 leave the freshness or approval window.
    function _registrationTime(uint64 approvedAt, uint256 seed, uint256 mutation) internal view returns (uint64) {
        uint256 lo = block.timestamp > maxAge ? block.timestamp - maxAge : 0;
        if (uint256(approvedAt) > lo + SKEW) lo = uint256(approvedAt) - SKEW;
        uint256 hi = block.timestamp + SKEW;
        if (mutation == 13) return uint64(block.timestamp - maxAge - 1 - seed % 1 days);
        if (mutation == 14) return uint64(hi + 1 + seed % 1 days);
        if (mutation == 15 && approvedAt > 1 days) return uint64(approvedAt - SKEW - 1 - seed % 1 hours);
        if (lo > hi) return uint64(hi);
        return uint64(bound(seed, lo, hi));
    }

    struct HeartbeatCall {
        bytes32 id;
        bytes32 quoteHash;
        uint64 attestedAt;
        uint8 method;
        bytes evidence;
        bool evidenceOk;
        address oracleAddr;
        bool expected;
    }

    function heartbeat(uint256 depSeed, uint256 keySeed, uint256 timeSeed, uint256 mutation) external {
        HeartbeatCall memory c;
        mutation = mutation % 40; // 10..19 are the invalid heartbeats, the rest are valid
        if (depIds.length == 0 || mutation == 10) {
            c.id = keccak256(abi.encode("unknown-deployment", depSeed));
        } else {
            c.id = _pickDeployment(depSeed);
        }
        GDep storage d = _dep[c.id];
        uint256 k = _pickKey(keySeed);
        c.oracleAddr = oracleAddrs[k];
        c.method = 1;
        c.quoteHash = mutation == 11 ? d.quoteHash : keccak256(abi.encode("lifecycle-hb-quote", ++_nonce));
        c.attestedAt = _heartbeatTime(d.lastAttestedAt, timeSeed, mutation);
        (c.evidence, c.evidenceOk) =
            _evidence(_oracleKeys[k], registry.heartbeatDigest(c.id, c.quoteHash, c.attestedAt), mutation);
        if (mutation == 19) c.method = (timeSeed >> 8) % 2 == 0 ? 0 : 2;

        bool fresh =
            uint256(c.attestedAt) <= block.timestamp + SKEW && uint256(c.attestedAt) + maxAge >= block.timestamp;
        c.expected = !registryPaused && d.status == D_ACTIVE && expectedApproved(d.customer, d.stackHash)
            && c.attestedAt > d.lastAttestedAt && c.quoteHash != d.quoteHash && fresh && c.method == 1 && c.evidenceOk
            && ghostSigner[c.oracleAddr];

        vm.prank((keySeed >> 8) % 2 == 0 ? ops : stranger);
        try registry.heartbeat(c.id, c.quoteHash, c.attestedAt, c.method, c.evidence) {
            if (!c.expected) _mismatch("heartbeat succeeded");
            if (!expectedApproved(d.customer, d.stackHash)) heartbeatOnUnapproved = true;
            d.lastAttestedAt = c.attestedAt;
            d.quoteHash = c.quoteHash;
            calls["heartbeat"]++;
        } catch (bytes memory reason) {
            if (c.expected) _mismatch("heartbeat reverted");
            calls["heartbeatRejected"]++;
            // forge-lint: disable-next-line(unsafe-typecast)
            errors[bytes4(reason)]++;
        }
    }

    function _heartbeatTime(uint64 last, uint256 seed, uint256 mutation) internal view returns (uint64) {
        uint256 hi = block.timestamp + SKEW;
        if (mutation == 12) return last; // stale
        if (mutation == 13) return uint64(block.timestamp - maxAge - 1 - seed % 1 days);
        if (mutation == 14) return uint64(hi + 1 + seed % 1 days);
        uint256 lo = uint256(last) + 1;
        uint256 oldest = block.timestamp > maxAge ? block.timestamp - maxAge : 0;
        if (lo < oldest) lo = oldest;
        if (lo > hi) return uint64(hi);
        return uint64(bound(seed, lo, hi));
    }

    function close(uint256 depSeed, uint256 actorSeed) external {
        bytes32 id = depIds.length == 0 || depSeed % 9 == 0
            ? keccak256(abi.encode("unknown-deployment", depSeed))
            : depIds[depSeed % depIds.length];
        GDep storage d = _dep[id];
        uint256 pick = actorSeed % 4;
        address actor = pick == 0
            ? d.customer
            : pick == 1 ? owner : pick == 2 ? stranger : customers[(actorSeed >> 8) % customers.length];
        if (actor == address(0)) actor = stranger;
        bool expected = d.status == D_ACTIVE && (actor == d.customer || actor == owner);
        vm.prank(actor);
        try registry.closeDeployment(id) {
            if (!expected) _mismatch("closeDeployment succeeded");
            d.status = D_CLOSED;
            d.closedAt = uint64(block.timestamp);
            calls["close"]++;
        } catch {
            if (expected) _mismatch("closeDeployment reverted");
            calls["closeRejected"]++;
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Usage payments
    // ------------------------------------------------------------------------------------------------------

    function pay(uint256 depSeed, uint256 appSeed, uint256 usageSeed, uint256 amount, uint256 payerSeed) external {
        if (depIds.length == 0) return;
        bytes32 id = _pickDeployment(depSeed);
        GDep storage d = _dep[id];
        bytes32 appId = appIds[appSeed % appIds.length];
        bytes32 usageHash = usagePool[usageSeed % usagePool.length];
        uint256 maxAmount = _payable(id, 0);
        if (maxAmount == 0) return;
        amount = bound(amount, 1, maxAmount);
        address payer = _payer(d, payerSeed);
        bytes32 k = legKey(id, usageHash, appId);
        bool expected = d.status == D_ACTIVE && (payer == d.customer || payer == d.enclaveSigner)
            && expectedAppIn(id, appId) && ghostLeg[k] == 0;

        token.mint(payer, amount);
        vm.prank(payer);
        token.approve(address(splitter), amount);
        vm.prank(payer);
        try splitter.payFees(id, appId, address(token), amount, usageHash) {
            if (!expected) _mismatch("payFees succeeded");
            if (d.status != D_ACTIVE) paidWhileNotActive = true;
            ghostLeg[k] = amount;
            _legs.push(Leg(id, usageHash, appId));
            calls["pay"]++;
        } catch {
            if (expected) _mismatch("payFees reverted");
            calls["payRejected"]++;
        }
        vm.prank(payer);
        token.approve(address(splitter), 0);
    }

    function topUp(uint256 depSeed, uint256 appSeed, uint256 usageSeed, uint256 total, uint256 payerSeed) external {
        if (depIds.length == 0) return;
        bytes32 id = _pickDeployment(depSeed);
        bytes32 appId = appIds[appSeed % appIds.length];
        bytes32 usageHash = usagePool[usageSeed % usagePool.length];
        if (_legs.length != 0 && appSeed % 3 != 0) {
            // Mostly an opened leg; otherwise any key, which exercises UsageNotPaid.
            Leg memory l = _legs[(appSeed >> 8) % _legs.length];
            (id, usageHash, appId) = (l.id, l.usageHash, l.appId);
        }
        GDep storage d = _dep[id];
        bytes32 k = legKey(id, usageHash, appId);
        uint256 paid = ghostLeg[k];
        uint256 maxTotal = _payable(id, paid);
        if (maxTotal <= paid) return;
        total = bound(total, paid + 1, maxTotal);
        address payer = _payer(d, payerSeed);
        bool expected = d.status == D_ACTIVE && (payer == d.customer || payer == d.enclaveSigner)
            && expectedAppIn(id, appId) && paid != 0;

        token.mint(payer, total - paid);
        vm.prank(payer);
        token.approve(address(splitter), total - paid);
        vm.prank(payer);
        try splitter.topUpFees(id, appId, address(token), total, usageHash) {
            if (!expected) _mismatch("topUpFees succeeded");
            if (d.status != D_ACTIVE) paidWhileNotActive = true;
            ghostLeg[k] = total;
            calls["topUp"]++;
        } catch {
            if (expected) _mismatch("topUpFees reverted");
            calls["topUpRejected"]++;
        }
        vm.prank(payer);
        token.approve(address(splitter), 0);
    }

    /// @dev Half of the time the first Active deployment from a random start, otherwise any deployment.
    function _pickDeployment(uint256 seed) internal view returns (bytes32) {
        uint256 n = depIds.length;
        if (seed % 2 == 0) {
            for (uint256 i; i < n; ++i) {
                bytes32 id = depIds[((seed >> 1) % n + i) % n];
                if (_dep[id].status == D_ACTIVE) return id;
            }
        }
        return depIds[(seed >> 1) % n];
    }

    function _payer(GDep storage d, uint256 seed) internal view returns (address) {
        uint256 pick = seed % 4;
        if (pick == 0 && d.customer != address(0)) return d.customer;
        if (pick == 1 && d.enclaveSigner != address(0)) return d.enclaveSigner;
        if (pick == 2) return customers[(seed >> 8) % customers.length];
        return enclaves[(seed >> 8) % enclaves.length];
    }

    function _payable(bytes32 id, uint256 paid) internal view returns (uint256) {
        FeeSplitter.TokenConfig memory cfg = splitter.tokenConfig(address(token));
        uint256 maxTotal = paid + splitter.remainingDailyAllowance(id, address(token));
        return maxTotal < cfg.perPaymentCap ? maxTotal : cfg.perPaymentCap;
    }

    // ------------------------------------------------------------------------------------------------------
    // Catalog, signers and admin
    // ------------------------------------------------------------------------------------------------------

    function deprecateRelease(uint256 seed) external {
        if (seed % 6 != 0) return; // keep catalog decay slower than approvals
        bytes32 id = releases[(seed >> 8) % releases.length];
        if (releaseStatus[id] != S.Active) return;
        vm.prank(owner);
        apps.deprecateRelease(id);
        releaseStatus[id] = S.Deprecated;
        releaseEverDeactivated[id] = true;
        calls["deprecateRelease"]++;
    }

    function revokeRelease(uint256 seed) external {
        if (seed % 6 != 0) return;
        bytes32 id = releases[(seed >> 8) % releases.length];
        if (releaseStatus[id] == S.Revoked) return;
        vm.prank(owner);
        apps.revokeRelease(id, "invariant");
        releaseStatus[id] = S.Revoked;
        releaseEverDeactivated[id] = true;
        calls["revokeRelease"]++;
    }

    function publishRelease(uint256 appSeed) external {
        if (releases.length >= 12) return;
        bytes32 appId = appIds[appSeed % appIds.length];
        string memory version = string.concat("lifecycle-", vm.toString(++_nonce));
        vm.prank(ops);
        bytes32 id = apps.publishRelease(appId, version, keccak256(bytes(version)), bytes32(0), bytes32(0), "", "");
        releases.push(id);
        releaseStatus[id] = S.Active;
        releaseApp[id] = appId;
        calls["publishRelease"]++;
    }

    function deprecateImage(uint256 seed) external {
        if (seed % 8 != 0) return;
        bytes32 id = images[(seed >> 8) % images.length];
        if (imageStatus[id] != S.Active) return;
        vm.prank(owner);
        platform.deprecateImage(id);
        imageStatus[id] = S.Deprecated;
        calls["deprecateImage"]++;
    }

    function revokeImage(uint256 seed) external {
        if (seed % 8 != 0) return;
        bytes32 id = images[(seed >> 8) % images.length];
        if (imageStatus[id] == S.Revoked) return;
        vm.prank(owner);
        platform.revokeImage(id, "invariant");
        imageStatus[id] = S.Revoked;
        calls["revokeImage"]++;
    }

    function addImage(bool isDebug) external {
        if (images.length >= 8) return;
        bytes32 id = keccak256(abi.encode("lifecycle-image", ++_nonce));
        // Truncating to bytes16 is intended: 32 + 16 = 48 bytes, one TDX register.
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory m = abi.encodePacked(id, bytes16(id));
        vm.prank(owner);
        platform.addImage(id, "lifecycle", vm.toString(_nonce), m, m, m, m, isDebug, "");
        images.push(id);
        imageStatus[id] = S.Active;
        imageDebug[id] = isDebug;
        calls["addImage"]++;
    }

    function setSigner(uint256 keySeed, bool allow) external {
        address a = oracleAddrs[keySeed % oracleAddrs.length];
        if (ghostSigner[a] == allow) return;
        vm.prank(owner);
        if (allow) verifier.addSigner(a);
        else verifier.removeSigner(a);
        ghostSigner[a] = allow;
        calls[allow ? "addSigner" : "removeSigner"]++;
    }

    /// @dev Pauses the registry for one step: a registration and a heartbeat attempt must revert EnforcedPause and
    ///      a close must still work, then the registry is unpaused again (a long pause would starve the campaign).
    function pausePulse(uint256 seed) external {
        vm.prank(owner);
        registry.pause();
        registryPaused = true;
        this.register(seed, seed >> 8, seed >> 16, seed >> 24, seed >> 32, seed >> 40);
        this.heartbeat(seed >> 4, seed >> 12, seed >> 20, seed >> 28);
        if (seed % 4 == 0) this.close(seed >> 2, 0);
        vm.prank(owner);
        registry.unpause();
        registryPaused = false;
        calls["pausePulse"]++;
    }

    function setMaxAttestationAge(uint256 seed) external {
        uint64[3] memory choices = [uint64(1 hours), uint64(1 days), uint64(7 days)];
        uint64 next = choices[seed % 3];
        vm.prank(owner);
        registry.setMaxAttestationAge(next);
        maxAge = next;
        calls["setMaxAttestationAge"]++;
    }

    function warp(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 1, 1 days));
        calls["warp"]++;
    }

    // ------------------------------------------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------------------------------------------

    /// @dev Three times in four the first current signer from a random start, otherwise any key.
    function _pickKey(uint256 seed) internal view returns (uint256) {
        uint256 n = _oracleKeys.length;
        if (seed % 4 != 0) {
            for (uint256 i; i < n; ++i) {
                uint256 k = ((seed >> 2) % n + i) % n;
                if (ghostSigner[oracleAddrs[k]]) return k;
            }
        }
        return (seed >> 2) % n;
    }

    function imageIndexOf(bytes32 id) public view returns (uint256) {
        for (uint256 i; i < images.length; ++i) {
            if (images[i] == id) return i;
        }
        return 0;
    }

    /// @dev Canonical evidence for mutations other than 17 (high-s twin) and 18 (wrong v).
    function _evidence(uint256 key, bytes32 digest, uint256 mutation) internal pure returns (bytes memory, bool) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        if (mutation == 17) {
            return (abi.encode(abi.encodePacked(r, bytes32(N - uint256(s)), v == 27 ? uint8(28) : uint8(27))), false);
        }
        if (mutation == 18) return (abi.encode(abi.encodePacked(r, s, v - 27)), false);
        return (abi.encode(abi.encodePacked(r, s, v)), true);
    }

    function _approvalShouldSucceed(GApproval storage g, bytes32 imageId, bytes32[] memory ids)
        internal
        view
        returns (bool)
    {
        if (ids.length == 0 || ids.length > 16) return false;
        if (imageStatus[imageId] != S.Active || imageDebug[imageId]) return false;
        if (!g.exists) {
            for (uint256 i; i < ids.length; ++i) {
                if (releaseStatus[ids[i]] != S.Active) return false;
            }
            return true;
        }
        if (imageId != g.imageId || ids.length != g.releaseIds.length) return false;
        for (uint256 i; i < ids.length; ++i) {
            if (ids[i] != g.releaseIds[i]) return false;
            S st = releaseStatus[ids[i]];
            if (st != S.Active && st != S.Deprecated) return false;
        }
        return true;
    }

    function _pickContent(uint256 releaseMask, uint256 imageSeed, bool pickValid)
        internal
        view
        returns (bytes32 imageId, bytes32[] memory ids)
    {
        imageId = images[imageSeed % images.length];
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
        ids = new bytes32[](n);
        uint256 j;
        for (uint256 i; i < releases.length; ++i) {
            if (releaseMask & 2 ** i != 0) ids[j++] = releases[i];
        }
    }

    function _mismatch(string memory what) internal {
        unexpectedOutcome = true;
        lastMismatch = what;
    }
}
