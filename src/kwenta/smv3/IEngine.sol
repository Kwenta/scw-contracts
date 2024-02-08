// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.18;

/// @title Kwenta Smart Margin v3: Engine Interface
/// @dev Simplified to include only permitted functions
/// @notice Conditional Order -> "co"
/// @author JaredBorders (jaredborders@pm.me)
interface IEngine {
    /// @dev Apply `DELEGATECALL` with the current contract to each calldata in `data`,
    /// and store the `abi.encode` formatted results of each `DELEGATECALL` into `results`.
    /// If any of the `DELEGATECALL`s reverts, the entire context is reverted,
    /// and the error is bubbled up.
    ///
    /// This function *was* deliberately made non-payable to guard against double-spending, however
    /// now it *is* payable to support multicalls including EIP7412.fulfillOracleQuery().
    /// (See: https://www.paradigm.xyz/2021/08/two-rights-might-make-a-wrong)
    ///
    /// In the context of the SMv3 Engine, double-spending is not possible.
    /// Only EIP7412.fulfillOracleQuery() is payable, and although it uses msg.value
    /// to pay for the oracle query fulfillment, it is not possible to double-spend
    ///
    /// For efficiency, this function will directly return the results, terminating the context.
    /// If called internally, it must be called at the end of a function
    /// that returns `(bytes[] memory)`.
    function multicall(bytes[] calldata data)
        external
        payable
        returns (bytes[] memory);
}
