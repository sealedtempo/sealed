// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Script, console} from "forge-std/Script.sol";

import {AppRegistry} from "../src/AppRegistry.sol";
import {PlatformRegistry} from "../src/PlatformRegistry.sol";
import {IPlatformRegistry} from "../src/interfaces/IPlatformRegistry.sol";

/// @title RegisterCatalog
/// @notice Registers platform images (addImage) and apps (registerApp) listed in a JSON catalog file, as OWNER.
///         Idempotent: images and apps that already exist are skipped, so the script can be re-run after adding
///         entries.
/// @dev Environment:
///      OWNER_PRIVATE_KEY           the owner's key; or, without it,
///      OWNER_ADDRESS               the owner's address, signed for by the wallet on forge's command line, e.g.
///                                  `--ledger --sender $OWNER_ADDRESS` (hardware wallet) or `--unlocked --sender
///                                  $OWNER_ADDRESS` (an anvil fork that impersonates the owner). When both are set
///                                  they must name the same account. Either way the account must own AppRegistry
///                                  and PlatformRegistry, or the script stops before sending anything.
///      CATALOG_FILE                default catalog/catalog.mainnet.json (forge reads only under ./catalog and
///                                  ./test/fixtures).
///      DEPLOYMENTS_FILE            default deployments/<network>.json (addresses are read from it).
///      MAINTAINER_DEFAULT_ADDRESS  used for apps whose "maintainer" is missing or zero.
///
///      Catalog format (see catalog/catalog.mainnet.json; test/fixtures/catalog.example.json has an image):
///      { "images": [ { "name", "version", "mrtd", "rtmr0", "rtmr1", "rtmr2", "isDebug", "sourceURI",
///                      "imageId" (optional; default keccak256(abi.encode(name, version, measurementsHash))) } ],
///        "apps":   [ { "slug", "name", "licenseSpdx", "maintainer" (optional), "maintainerShareBps",
///                      "metadataURI", "appId" (optional; must equal keccak256(slug)) } ] }
///      Keys starting with "_" are comments, except "_pending": an app that carries it is not ready, and the
///      whole file is refused before anything is sent (slug, name and licenseSpdx are permanent onchain).
///      An image whose measurementsHash is already registered under another imageId is skipped too: PlatformRegistry
///      keeps one image per measurement set (CR-5), so two machine shapes that measured the same (D-070, D-078) share
///      the first one's imageId.
contract RegisterCatalog is Script {
    struct ImageEntry {
        bytes32 imageId;
        string name;
        string version;
        bytes mrtd;
        bytes rtmr0;
        bytes rtmr1;
        bytes rtmr2;
        bool isDebug;
        string sourceURI;
    }

    struct AppEntry {
        string slug;
        string name;
        string licenseSpdx;
        address maintainer;
        uint16 maintainerShareBps;
        string metadataURI;
    }

    error NoMaintainer(string slug);
    /// @notice The entry's "appId" is not keccak256(slug).
    error AppIdMismatch(string slug, bytes32 appId, bytes32 expected);
    /// @notice The entry carries "_pending": a value is still a placeholder.
    error PendingEntry(string slug);
    /// @notice Neither OWNER_PRIVATE_KEY nor OWNER_ADDRESS is set.
    error NoOwner();
    /// @notice OWNER_ADDRESS is not the address of OWNER_PRIVATE_KEY.
    error OwnerMismatch(address ownerAddress, address keyAddress);
    /// @notice The broadcasting account does not own both registries.
    error NotOwner(address sender, address appRegistryOwner, address platformRegistryOwner);

    function run() external {
        address owner = resolveOwner(vm.envOr("OWNER_PRIVATE_KEY", uint256(0)), vm.envOr("OWNER_ADDRESS", address(0)));
        string memory catalog = vm.readFile(vm.envOr("CATALOG_FILE", string("catalog/catalog.mainnet.json")));
        string memory deployments = vm.readFile(vm.envOr("DEPLOYMENTS_FILE", _defaultDeploymentsFile()));
        AppRegistry apps = AppRegistry(vm.parseJsonAddress(deployments, ".contracts.AppRegistry.address"));
        PlatformRegistry platform =
            PlatformRegistry(vm.parseJsonAddress(deployments, ".contracts.PlatformRegistry.address"));
        address defaultMaintainer = vm.envOr("MAINTAINER_DEFAULT_ADDRESS", address(0));
        registerAs(catalog, apps, platform, owner, defaultMaintainer);
    }

    /// @notice The account that broadcasts. With a key, its address, and forge remembers the key to sign with it.
    ///         Without one, `ownerAddress`, which forge signs for with the wallet given on its command line.
    function resolveOwner(uint256 ownerKey, address ownerAddress) public returns (address owner) {
        if (ownerKey == 0) {
            if (ownerAddress == address(0)) revert NoOwner();
            return ownerAddress;
        }
        owner = vm.rememberKey(ownerKey);
        if (ownerAddress != address(0) && ownerAddress != owner) revert OwnerMismatch(ownerAddress, owner);
    }

    /// @notice registerAs with the account of `ownerKey`.
    function register(
        string memory catalog,
        AppRegistry apps,
        PlatformRegistry platform,
        uint256 ownerKey,
        address defaultMaintainer
    ) public returns (uint256 imagesAdded, uint256 appsAdded) {
        return registerAs(catalog, apps, platform, resolveOwner(ownerKey, address(0)), defaultMaintainer);
    }

    /// @notice Registers, from `owner`, every image and app of `catalog` that is not registered yet.
    /// @return imagesAdded Number of images added.
    /// @return appsAdded Number of apps registered.
    function registerAs(
        string memory catalog,
        AppRegistry apps,
        PlatformRegistry platform,
        address owner,
        address defaultMaintainer
    ) public returns (uint256 imagesAdded, uint256 appsAdded) {
        ImageEntry[] memory images = parseImages(catalog);
        AppEntry[] memory appEntries = parseApps(catalog, defaultMaintainer);
        if (apps.owner() != owner || platform.owner() != owner) {
            revert NotOwner(owner, apps.owner(), platform.owner());
        }

        vm.startBroadcast(owner);
        for (uint256 i; i < images.length; ++i) {
            ImageEntry memory e = images[i];
            if (platform.imageStatus(e.imageId) != IPlatformRegistry.ImageStatus.None) {
                console.log("image exists, skipping:", e.name, e.version);
                continue;
            }
            bytes32 registered =
                platform.imageByMeasurements(keccak256(abi.encodePacked(e.mrtd, e.rtmr0, e.rtmr1, e.rtmr2)));
            if (registered != bytes32(0)) {
                console.log("image measurements already registered under another imageId, skipping:", e.name, e.version);
                console.logBytes32(registered);
                continue;
            }
            platform.addImage(e.imageId, e.name, e.version, e.mrtd, e.rtmr0, e.rtmr1, e.rtmr2, e.isDebug, e.sourceURI);
            console.log("image added:", e.name, e.version);
            console.logBytes32(e.imageId);
            ++imagesAdded;
        }
        for (uint256 i; i < appEntries.length; ++i) {
            AppEntry memory a = appEntries[i];
            bytes32 appId = keccak256(bytes(a.slug));
            if (apps.appExists(appId)) {
                console.log("app exists, skipping:", a.slug);
                continue;
            }
            apps.registerApp(appId, a.slug, a.name, a.licenseSpdx, a.maintainer, a.maintainerShareBps, a.metadataURI);
            console.log("app registered:", a.slug);
            ++appsAdded;
        }
        vm.stopBroadcast();
    }

    /// @notice Parses the "images" array of a catalog.
    function parseImages(string memory catalog) public view returns (ImageEntry[] memory images) {
        uint256 n = _count(catalog, ".images");
        images = new ImageEntry[](n);
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat(".images[", vm.toString(i), "]");
            ImageEntry memory e = images[i];
            e.name = vm.parseJsonString(catalog, string.concat(p, ".name"));
            e.version = vm.parseJsonString(catalog, string.concat(p, ".version"));
            e.mrtd = vm.parseJsonBytes(catalog, string.concat(p, ".mrtd"));
            e.rtmr0 = vm.parseJsonBytes(catalog, string.concat(p, ".rtmr0"));
            e.rtmr1 = vm.parseJsonBytes(catalog, string.concat(p, ".rtmr1"));
            e.rtmr2 = vm.parseJsonBytes(catalog, string.concat(p, ".rtmr2"));
            e.isDebug = vm.parseJsonBool(catalog, string.concat(p, ".isDebug"));
            e.sourceURI = vm.parseJsonString(catalog, string.concat(p, ".sourceURI"));
            bytes32 measurementsHash = keccak256(abi.encodePacked(e.mrtd, e.rtmr0, e.rtmr1, e.rtmr2));
            e.imageId = vm.keyExistsJson(catalog, string.concat(p, ".imageId"))
                ? vm.parseJsonBytes32(catalog, string.concat(p, ".imageId"))
                : keccak256(abi.encode(e.name, e.version, measurementsHash));
        }
    }

    /// @notice Parses the "apps" array of a catalog.
    function parseApps(string memory catalog, address defaultMaintainer) public view returns (AppEntry[] memory list) {
        uint256 n = _count(catalog, ".apps");
        list = new AppEntry[](n);
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat(".apps[", vm.toString(i), "]");
            AppEntry memory a = list[i];
            a.slug = vm.parseJsonString(catalog, string.concat(p, ".slug"));
            if (vm.keyExistsJson(catalog, string.concat(p, "._pending"))) revert PendingEntry(a.slug);
            if (vm.keyExistsJson(catalog, string.concat(p, ".appId"))) {
                bytes32 given = vm.parseJsonBytes32(catalog, string.concat(p, ".appId"));
                bytes32 expected = keccak256(bytes(a.slug));
                if (given != expected) revert AppIdMismatch(a.slug, given, expected);
            }
            a.name = vm.parseJsonString(catalog, string.concat(p, ".name"));
            a.licenseSpdx = vm.parseJsonString(catalog, string.concat(p, ".licenseSpdx"));
            a.maintainerShareBps = uint16(vm.parseJsonUint(catalog, string.concat(p, ".maintainerShareBps")));
            a.metadataURI = vm.parseJsonString(catalog, string.concat(p, ".metadataURI"));
            if (vm.keyExistsJson(catalog, string.concat(p, ".maintainer"))) {
                a.maintainer = vm.parseJsonAddress(catalog, string.concat(p, ".maintainer"));
            }
            if (a.maintainer == address(0)) a.maintainer = defaultMaintainer;
            if (a.maintainer == address(0)) revert NoMaintainer(a.slug);
        }
    }

    function _count(string memory json, string memory key) internal view returns (uint256 n) {
        if (!vm.keyExistsJson(json, key)) return 0;
        while (vm.keyExistsJson(json, string.concat(key, "[", vm.toString(n), "]"))) {
            ++n;
        }
    }

    function _defaultDeploymentsFile() internal view returns (string memory) {
        if (block.chainid == 4217) return "deployments/tempo-mainnet.json";
        if (block.chainid == 31_337) return "deployments/local.json";
        return string.concat("deployments/chain-", vm.toString(block.chainid), ".json");
    }
}
