// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title OwnableNoRenounce
/// @notice Ownable2Step with renounceOwnership disabled, so an admin mistake cannot strand a registry or the
///         fee splitter without an owner. Ownership moves only through transferOwnership + acceptOwnership.
abstract contract OwnableNoRenounce is Ownable2Step {
    /// @notice Thrown by renounceOwnership, which is disabled.
    error RenounceOwnershipDisabled();

    /// @param initialOwner The first owner (OWNER).
    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Disabled. Always reverts with RenounceOwnershipDisabled.
    function renounceOwnership() public view override onlyOwner {
        revert RenounceOwnershipDisabled();
    }
}
