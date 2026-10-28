// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Script, console} from "forge-std/Script.sol";

/// @notice Shared helpers: the five owned contracts, read from the deployments file.
abstract contract OwnedContracts is Script {
    string[5] internal NAMES =
        ["PlatformRegistry", "AppRegistry", "OracleSignatureVerifier", "DeploymentRegistry", "FeeSplitter"];

    function owned(string memory deployments) public view returns (Ownable2Step[5] memory list) {
        for (uint256 i; i < 5; ++i) {
            list[i] =
                Ownable2Step(vm.parseJsonAddress(deployments, string.concat(".contracts.", NAMES[i], ".address")));
        }
    }

    function _deployments() internal view returns (string memory) {
        string memory def = block.chainid == 4217
            ? "deployments/tempo-mainnet.json"
            : block.chainid == 31_337 ? "deployments/local.json" : string.concat("deployments/chain-", vm.toString(block.chainid), ".json");
        return vm.readFile(vm.envOr("DEPLOYMENTS_FILE", def));
    }
}

/// @title TransferOwnership
/// @notice Step 1 of the Ownable2Step handover (for example to a Safe multisig): the current OWNER calls
///         transferOwnership(NEW_OWNER) on all five contracts. Nothing changes until step 2.
/// @dev Environment: OWNER_PRIVATE_KEY (current owner), NEW_OWNER (the multisig), DEPLOYMENTS_FILE (optional).
///      Step 2: NEW_OWNER calls acceptOwnership() on each contract. For a Safe, create one batch in the
///      Transaction Builder with five calls to `acceptOwnership()` (selector 0x79ba5097, no arguments), one per
///      address printed below; or, for an EOA new owner, run AcceptOwnership with NEW_OWNER_PRIVATE_KEY.
///      Until accepted, OWNER keeps full control and can re-point the transfer by calling it again.
///      AppRegistry's REGISTRAR_ROLE, the oracle signers and FeeSplitter credits are unaffected.
contract TransferOwnership is OwnedContracts {
    error ZeroNewOwner();

    function run() external {
        uint256 ownerKey = vm.envUint("OWNER_PRIVATE_KEY");
        address newOwner = vm.envAddress("NEW_OWNER");
        start(_deployments(), ownerKey, newOwner);
    }

    function start(string memory deployments, uint256 ownerKey, address newOwner) public {
        if (newOwner == address(0)) revert ZeroNewOwner();
        Ownable2Step[5] memory list = owned(deployments);
        vm.startBroadcast(ownerKey);
        for (uint256 i; i < 5; ++i) {
            list[i].transferOwnership(newOwner);
        }
        vm.stopBroadcast();
        console.log("pending owner:", newOwner);
        console.log("next: NEW_OWNER calls acceptOwnership() (0x79ba5097) on each of:");
        for (uint256 i; i < 5; ++i) {
            console.log(NAMES[i], address(list[i]));
        }
    }
}

/// @title AcceptOwnership
/// @notice Step 2 for an EOA new owner: calls acceptOwnership() on all five contracts.
/// @dev Environment: NEW_OWNER_PRIVATE_KEY, DEPLOYMENTS_FILE (optional). Safes use the Transaction Builder instead.
contract AcceptOwnership is OwnedContracts {
    function run() external {
        accept(_deployments(), vm.envUint("NEW_OWNER_PRIVATE_KEY"));
    }

    function accept(string memory deployments, uint256 newOwnerKey) public {
        Ownable2Step[5] memory list = owned(deployments);
        vm.startBroadcast(newOwnerKey);
        for (uint256 i; i < 5; ++i) {
            list[i].acceptOwnership();
        }
        vm.stopBroadcast();
        for (uint256 i; i < 5; ++i) {
            require(list[i].owner() == vm.addr(newOwnerKey), "ownership not accepted");
        }
        console.log("owner is now", vm.addr(newOwnerKey));
    }
}
