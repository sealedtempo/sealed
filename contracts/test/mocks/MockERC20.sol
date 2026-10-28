// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Plain 6-decimal ERC-20 with open minting, standing in for pathUSD in unit tests.
contract MockERC20 is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @notice Burns 1% of every transfer, so the receiver gets less than `amount`.
contract FeeOnTransferERC20 is ERC20 {
    constructor() ERC20("Fee On Transfer", "FOT") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0)) {
            uint256 fee = value / 100;
            super._update(from, address(0), fee);
            super._update(from, to, value - fee);
        } else {
            super._update(from, to, value);
        }
    }
}

/// @notice Calls back into a target during transfers to test reentrancy guards.
contract ReentrantERC20 is ERC20 {
    address public target;
    bytes public payload;
    bool public reenterOnTransferFrom;
    bool public reenterOnTransfer;
    bytes public lastRevertData;

    constructor() ERC20("Reentrant", "REE") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function arm(address target_, bytes calldata payload_, bool onTransferFrom, bool onTransfer) external {
        target = target_;
        payload = payload_;
        reenterOnTransferFrom = onTransferFrom;
        reenterOnTransfer = onTransfer;
    }

    function transferFrom(address from, address to, uint256 value) public override returns (bool) {
        if (reenterOnTransferFrom) _reenter();
        return super.transferFrom(from, to, value);
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        if (reenterOnTransfer) _reenter();
        return super.transfer(to, value);
    }

    function _reenter() private {
        (bool ok, bytes memory data) = target.call(payload);
        // Bubble up the revert so the outer call fails with the guard's error.
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(data, 0x20), mload(data))
            }
        }
    }
}
