// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

/// @notice The parts of the TIP-20 token precompile the tests use. Role functions take (role, account), and
///         hasRole takes (account, role), unlike OpenZeppelin.
interface ITIP20 {
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function mint(address to, uint256 amount) external;
    function grantRole(bytes32 role, address account) external;
    function hasRole(address account, bytes32 role) external view returns (bool);
    function ISSUER_ROLE() external view returns (bytes32);
    function PAUSE_ROLE() external view returns (bytes32);
    function UNPAUSE_ROLE() external view returns (bytes32);
    function pause() external;
    function unpause() external;
    function paused() external view returns (bool);
    function changeTransferPolicyId(uint64 policyId) external;
    function transferPolicyId() external view returns (uint64);
}

/// @notice The parts of the TIP-403 policy registry precompile the tests use. policyType 1 is BLACKLIST.
interface ITIP403 {
    function createPolicy(address admin, uint8 policyType) external returns (uint64 policyId);
    function modifyPolicyBlacklist(uint64 policyId, address account, bool restricted) external;
    function isAuthorized(uint64 policyId, address user) external view returns (bool);
}

/// @notice Addresses and error selectors of the Tempo precompiles. Under `network = "tempo"` a local forge test
///         runs Tempo genesis: AlphaUSD and BetaUSD exist with the test contract as their admin.
library Tip20 {
    ITIP20 internal constant ALPHA_USD = ITIP20(0x20C0000000000000000000000000000000000001);
    ITIP20 internal constant BETA_USD = ITIP20(0x20C0000000000000000000000000000000000002);
    ITIP403 internal constant REGISTRY = ITIP403(0x403c000000000000000000000000000000000000);
    uint8 internal constant BLACKLIST = 1;
    /// @dev `PolicyForbids()`: a TIP-403 policy rejects the sender or the recipient.
    bytes4 internal constant POLICY_FORBIDS = 0x54cfe659;
    /// @dev `ContractPaused()`: the token is paused.
    bytes4 internal constant CONTRACT_PAUSED = 0xab35696f;
}
