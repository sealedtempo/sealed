// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Script, console} from "forge-std/Script.sol";
import {VmSafe} from "forge-std/Vm.sol";

import {AppRegistry} from "../src/AppRegistry.sol";
import {DeploymentRegistry} from "../src/DeploymentRegistry.sol";
import {FeeSplitter} from "../src/FeeSplitter.sol";
import {AttestationMethods} from "../src/IAttestationVerifier.sol";
import {OracleSignatureVerifier} from "../src/OracleSignatureVerifier.sol";
import {PlatformRegistry} from "../src/PlatformRegistry.sol";

/// @title Deploy
/// @notice Deploys, in order, PlatformRegistry, AppRegistry, OracleSignatureVerifier, DeploymentRegistry and
///         FeeSplitter from OWNER, then wires REGISTRAR_ROLE to OPS, the oracle signer, verifier method 1, the
///         treasury and the fee caps. Writes deployments/<network>.json.
/// @dev Environment:
///      OWNER_PRIVATE_KEY          required. Deployer and owner of every contract. Never printed.
///      OPS_ADDRESS                registrar (release CI / ops key). If unset, derived from OPS_PRIVATE_KEY.
///      ORACLE_ADDRESS             required. Allowed oracle signer for method 1.
///      TREASURY_ADDRESS           required. FeeSplitter treasury.
///      FEE_TOKEN_ADDRESS          default pathUSD 0x20c0000000000000000000000000000000000000.
///      PER_PAYMENT_CAP            default 5000000 (5 USD, 6 decimals).
///      PER_DEPLOYMENT_DAILY_CAP   default 20000000 (20 USD).
///      DEPLOYMENTS_NETWORK        default tempo-mainnet on 4217, local on 31337, chain-<id> otherwise.
///      DEPLOYMENTS_FILE           default deployments/<network>.json (dry runs write <network>.dry-run.json).
///      Transaction hashes and block numbers are merged in after broadcast by script/record-deployment.sh.
contract Deploy is Script {
    address internal constant PATH_USD = 0x20C0000000000000000000000000000000000000;
    uint256 internal constant DEFAULT_PER_PAYMENT_CAP = 5_000_000;
    uint256 internal constant DEFAULT_DAILY_CAP = 20_000_000;

    struct Config {
        uint256 ownerKey;
        address owner;
        address ops;
        address oracle;
        address treasury;
        address feeToken;
        uint256 perPaymentCap;
        uint256 perDeploymentDailyCap;
        string network;
        string outFile;
    }

    struct Deployed {
        PlatformRegistry platformRegistry;
        AppRegistry appRegistry;
        OracleSignatureVerifier oracleVerifier;
        DeploymentRegistry deploymentRegistry;
        FeeSplitter feeSplitter;
        uint256 startBlock;
    }

    error MissingOps();
    error InvalidConfig(string what);

    function run() external returns (Deployed memory d) {
        Config memory c = loadConfig();
        d = deploy(c);
        writeDeployment(c, d);
    }

    /// @notice Reads the configuration from the environment.
    function loadConfig() public view returns (Config memory c) {
        c.ownerKey = vm.envUint("OWNER_PRIVATE_KEY");
        c.owner = vm.addr(c.ownerKey);
        c.ops = vm.envOr("OPS_ADDRESS", address(0));
        if (c.ops == address(0)) {
            uint256 opsKey = vm.envOr("OPS_PRIVATE_KEY", uint256(0));
            if (opsKey == 0) revert MissingOps();
            c.ops = vm.addr(opsKey);
        }
        c.oracle = vm.envAddress("ORACLE_ADDRESS");
        c.treasury = vm.envAddress("TREASURY_ADDRESS");
        c.feeToken = vm.envOr("FEE_TOKEN_ADDRESS", PATH_USD);
        c.perPaymentCap = vm.envOr("PER_PAYMENT_CAP", DEFAULT_PER_PAYMENT_CAP);
        c.perDeploymentDailyCap = vm.envOr("PER_DEPLOYMENT_DAILY_CAP", DEFAULT_DAILY_CAP);
        c.network = vm.envOr("DEPLOYMENTS_NETWORK", defaultNetwork());
        string memory defaultFile = string.concat("deployments/", c.network, _isDryRun() ? ".dry-run.json" : ".json");
        c.outFile = vm.envOr("DEPLOYMENTS_FILE", defaultFile);
    }

    /// @notice Deploys and wires everything with `c`. Validates the result before returning.
    function deploy(Config memory c) public returns (Deployed memory d) {
        _validate(c);
        d.startBlock = block.number;

        vm.startBroadcast(c.ownerKey);
        d.platformRegistry = new PlatformRegistry(c.owner);
        d.appRegistry = new AppRegistry(c.owner);
        d.oracleVerifier = new OracleSignatureVerifier(c.owner);
        d.deploymentRegistry = new DeploymentRegistry(c.owner, d.platformRegistry, d.appRegistry);
        d.feeSplitter = new FeeSplitter(
            c.owner,
            d.deploymentRegistry,
            d.appRegistry,
            c.feeToken,
            c.treasury,
            c.perPaymentCap,
            c.perDeploymentDailyCap
        );
        d.appRegistry.grantRegistrar(c.ops);
        d.oracleVerifier.addSigner(c.oracle);
        d.deploymentRegistry.setVerifier(AttestationMethods.ORACLE_SIG_V1, address(d.oracleVerifier));
        vm.stopBroadcast();

        _check(c, d);
        console.log("PlatformRegistry       ", address(d.platformRegistry));
        console.log("AppRegistry            ", address(d.appRegistry));
        console.log("OracleSignatureVerifier", address(d.oracleVerifier));
        console.log("DeploymentRegistry     ", address(d.deploymentRegistry));
        console.log("FeeSplitter            ", address(d.feeSplitter));
    }

    /// @notice Writes the deployment file (addresses, constructor args, config, compiler settings).
    function writeDeployment(Config memory c, Deployed memory d) public {
        string memory json = _deploymentJson(c, d);
        vm.writeJson(json, c.outFile);
        console.log("wrote", c.outFile);
    }

    function defaultNetwork() public view returns (string memory) {
        if (block.chainid == 4217) return "tempo-mainnet";
        if (block.chainid == 31_337) return "local";
        return string.concat("chain-", vm.toString(block.chainid));
    }

    // ------------------------------------------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------------------------------------------

    function _isDryRun() internal view returns (bool) {
        return vm.isContext(VmSafe.ForgeContext.ScriptDryRun);
    }

    function _validate(Config memory c) internal view {
        if (c.ops == address(0)) revert InvalidConfig("ops");
        if (c.oracle == address(0)) revert InvalidConfig("oracle");
        if (c.treasury == address(0)) revert InvalidConfig("treasury");
        if (c.feeToken.code.length == 0) revert InvalidConfig("fee token has no code");
        if (c.perPaymentCap == 0 || c.perDeploymentDailyCap < c.perPaymentCap) revert InvalidConfig("caps");
    }

    function _check(Config memory c, Deployed memory d) internal view {
        require(d.platformRegistry.owner() == c.owner, "platform owner");
        require(d.appRegistry.owner() == c.owner, "apps owner");
        require(d.oracleVerifier.owner() == c.owner, "verifier owner");
        require(d.deploymentRegistry.owner() == c.owner, "registry owner");
        require(d.feeSplitter.owner() == c.owner, "splitter owner");
        require(d.appRegistry.hasRole(d.appRegistry.REGISTRAR_ROLE(), c.ops), "registrar");
        require(d.oracleVerifier.isSigner(c.oracle), "oracle signer");
        require(address(d.deploymentRegistry.verifiers(1)) == address(d.oracleVerifier), "method 1");
        require(address(d.deploymentRegistry.verifiers(2)) == address(0), "method 2 must stay unset");
        require(d.feeSplitter.treasury() == c.treasury, "treasury");
        require(d.feeSplitter.isTokenAllowed(c.feeToken), "fee token");
    }

    function _deploymentJson(Config memory c, Deployed memory d) internal returns (string memory) {
        string memory contracts = "contracts";
        _contractJson(contracts, "PlatformRegistry", address(d.platformRegistry), abi.encode(c.owner));
        _contractJson(contracts, "AppRegistry", address(d.appRegistry), abi.encode(c.owner));
        _contractJson(contracts, "OracleSignatureVerifier", address(d.oracleVerifier), abi.encode(c.owner));
        _contractJson(
            contracts,
            "DeploymentRegistry",
            address(d.deploymentRegistry),
            abi.encode(c.owner, address(d.platformRegistry), address(d.appRegistry))
        );
        string memory contractsJson = _contractJson(
            contracts,
            "FeeSplitter",
            address(d.feeSplitter),
            abi.encode(
                c.owner,
                address(d.deploymentRegistry),
                address(d.appRegistry),
                c.feeToken,
                c.treasury,
                c.perPaymentCap,
                c.perDeploymentDailyCap
            )
        );

        string memory cfg = "config";
        vm.serializeAddress(cfg, "owner", c.owner);
        vm.serializeAddress(cfg, "ops", c.ops);
        vm.serializeAddress(cfg, "oracleSigner", c.oracle);
        vm.serializeAddress(cfg, "treasury", c.treasury);
        vm.serializeAddress(cfg, "feeToken", c.feeToken);
        vm.serializeString(cfg, "perPaymentCap", vm.toString(c.perPaymentCap));
        vm.serializeString(cfg, "perDeploymentDailyCap", vm.toString(c.perDeploymentDailyCap));
        vm.serializeUint(cfg, "maxAttestationAge", d.deploymentRegistry.maxAttestationAge());
        vm.serializeAddress(cfg, "verifierMethod1", address(d.oracleVerifier));
        string memory cfgJson = vm.serializeAddress(cfg, "verifierMethod2", address(0));

        string memory compiler = "compiler";
        vm.serializeString(compiler, "solc", "0.8.38");
        vm.serializeString(compiler, "evmVersion", "osaka");
        vm.serializeBool(compiler, "optimizer", true);
        vm.serializeUint(compiler, "optimizerRuns", 200);
        vm.serializeBool(compiler, "viaIR", false);
        string memory compilerJson = vm.serializeString(compiler, "openzeppelin", "5.7.0");

        string memory root = "deployment";
        vm.serializeString(root, "network", c.network);
        vm.serializeUint(root, "chainId", block.chainid);
        vm.serializeAddress(root, "deployer", c.owner);
        vm.serializeUint(root, "startBlock", d.startBlock);
        vm.serializeUint(root, "scriptTimestamp", block.timestamp);
        vm.serializeString(root, "version", "1.0.0");
        vm.serializeString(root, "compiler", compilerJson);
        vm.serializeString(root, "config", cfgJson);
        return vm.serializeString(root, "contracts", contractsJson);
    }

    function _contractJson(string memory parent, string memory name, address addr, bytes memory args)
        internal
        returns (string memory)
    {
        string memory key = string.concat("contract-", name);
        vm.serializeAddress(key, "address", addr);
        vm.serializeBytes(key, "constructorArgs", args);
        vm.serializeString(key, "txHash", "");
        string memory obj = vm.serializeUint(key, "blockNumber", 0);
        return vm.serializeString(parent, name, obj);
    }
}
