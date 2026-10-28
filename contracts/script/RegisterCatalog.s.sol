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
///      OWNER_PRIVATE_KEY           required.
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

    function run() external {
        uint256 ownerKey = vm.envUint("OWNER_PRIVATE_KEY");
        string memory catalog = vm.readFile(vm.envOr("CATALOG_FILE", string("catalog/catalog.mainnet.json")));
        string memory deployments = vm.readFile(vm.envOr("DEPLOYMENTS_FILE", _defaultDeploymentsFile()));
        AppRegistry apps = AppRegistry(vm.parseJsonAddress(deployments, ".contracts.AppRegistry.address"));
        PlatformRegistry platform =
            PlatformRegistry(vm.parseJsonAddress(deployments, ".contracts.PlatformRegistry.address"));
        address defaultMaintainer = vm.envOr("MAINTAINER_DEFAULT_ADDRESS", address(0));
        register(catalog, apps, platform, ownerKey, defaultMaintainer);
    }

    /// @notice Registers every image and app of `catalog` that is not registered yet.
    /// @return imagesAdded Number of images added.
    /// @return appsAdded Number of apps registered.
    function register(
        string memory catalog,
        AppRegistry apps,
        PlatformRegistry platform,
        uint256 ownerKey,
        address defaultMaintainer
    ) public returns (uint256 imagesAdded, uint256 appsAdded) {
        ImageEntry[] memory images = parseImages(catalog);
        AppEntry[] memory appEntries = parseApps(catalog, defaultMaintainer);

        vm.startBroadcast(ownerKey);
        for (uint256 i; i < images.length; ++i) {
            ImageEntry memory e = images[i];
            if (platform.imageStatus(e.imageId) != IPlatformRegistry.ImageStatus.None) {
                console.log("image exists, skipping:", e.name, e.version);
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
