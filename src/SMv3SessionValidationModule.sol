// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.18;

import {ECDSA} from "src/openzeppelin/ECDSA.sol";
import {IEngine} from "src/kwenta/smv3/IEngine.sol";
import {EIP7412} from "src/kwenta/smv3/EIP7412.sol";
import {
    ISessionValidationModule,
    UserOperation
} from "src/biconomy/interfaces/ISessionValidationModule.sol";

/**
 * @title Kwenta Smart Margin v3 Session Validation Module for Biconomy Smart Accounts
 * @author Fil Makarov - <filipp.makarov@biconomy.io>
 * @author JaredBorders (jaredborders@pm.me)
 */
contract SMv3SessionValidationModule is ISessionValidationModule {
    error InvalidSelector();
    error InvalidSMv3Selector();
    error InvalidDestinationContract();
    error InvalidCallValue();

    /**
     * @dev validates that the call (destinationContract, callValue, funcCallData)
     * complies with the Session Key permissions represented by sessionKeyData
     * @param destinationContract address of the contract to be called
     * @param callValue value to be sent with the call
     * @param _funcCallData the data for the call. is parsed inside the SVM
     * @param _sessionKeyData SessionKey data, that describes sessionKey permissions
     */
    function validateSessionParams(
        address destinationContract,
        uint256 callValue,
        bytes calldata _funcCallData,
        bytes calldata _sessionKeyData,
        bytes calldata /*_callSpecificData*/
    ) external pure override returns (address) {
        (address sessionKey, address smv3Engine) =
            abi.decode(_sessionKeyData, (address, address));

        /// @dev ensure destinationContract is the smv3Engine
        if (destinationContract != smv3Engine) {
            revert InvalidDestinationContract();
        }

        /// @dev ensure the function selector is the a valid IEngine selector
        bytes4 funcSelector = bytes4(_funcCallData[0:4]);

        // sanitize the selector; ensure it is a valid selector
        // that can be called on the smv3Engine)
        _sanitizeSelector(funcSelector);

        // sanitize the call value; ensure it is zero unless calling
        // IEngine.depositEth or EIP7412.fulfillOracleQuery
        _sanitizeCallValue(funcSelector, callValue);

        return sessionKey;
    }

    /**
     * @dev validates if the _op (UserOperation) matches the SessionKey permissions
     * and that _op has been signed by this SessionKey
     * Please mind the decimals of your exact token when setting maxAmount
     * @param _op User Operation to be validated.
     * @param _userOpHash Hash of the User Operation to be validated.
     * @param _sessionKeyData SessionKey data, that describes sessionKey permissions
     * @param _sessionKeySignature Signature over the the _userOpHash.
     * @return true if the _op is valid, false otherwise.
     */
    function validateSessionUserOp(
        UserOperation calldata _op,
        bytes32 _userOpHash,
        bytes calldata _sessionKeyData,
        bytes calldata _sessionKeySignature
    ) external pure override returns (bool) {
        /// @dev ensure function selector either
        /// `execute(address,uint256,bytes)`
        /// or
        /// `execute_ncC(address,uint256,bytes)`
        if (
            bytes4(_op.callData[0:4]) != EXECUTE_SELECTOR
                && bytes4(_op.callData[0:4]) != EXECUTE_OPTIMIZED_SELECTOR
        ) {
            revert InvalidSelector();
        }

        (address sessionKey, address smv3Engine) =
            abi.decode(_sessionKeyData, (address, address));

        (address destinationContract, uint256 callValue,) = abi.decode(
            _op.callData[4:], // skip selector; already checked
            (address, uint256, bytes)
        );

        /// @dev ensure destinationContract is the smv3Engine
        if (destinationContract != smv3Engine) {
            revert InvalidDestinationContract();
        }

        // working with userOp.callData
        // check if the call is conforms to valid smv3Engine selectors
        bytes calldata data;
        {
            uint256 offset = uint256(bytes32(_op.callData[4 + 64:4 + 96]));
            uint256 length =
                uint256(bytes32(_op.callData[4 + offset:4 + offset + 32]));
            data = _op.callData[4 + offset + 32:4 + offset + 32 + length];
        }

        // define the function selector
        bytes4 funcSelector = bytes4(data[0:4]);

        // sanitize the selector; ensure it is a valid selector
        // that can be called on the smv3Engine)
        _sanitizeSelector(funcSelector);

        // sanitize the call value; ensure it is zero unless calling
        // IEngine.depositEth or EIP7412.fulfillOracleQuery
        _sanitizeCallValue(funcSelector, callValue);

        /// @dev this method of signature validation is out-of-date
        /// see https://github.com/OpenZeppelin/openzeppelin-sdk/blob/7d96de7248ae2e7e81a743513ccc617a2e6bba21/packages/lib/contracts/cryptography/ECDSA.sol#L6
        return ECDSA.recover(
            ECDSA.toEthSignedMessageHash(_userOpHash), _sessionKeySignature
        ) == sessionKey;
    }

    /// @notice sanitize the selector to ensure it is a
    /// valid selector that can be called on the smv3Engine
    /// @param _selector the selector to sanitize
    /// @dev will revert if the selector is not valid
    function _sanitizeSelector(bytes4 _selector) internal pure {
        if (
            _selector != IEngine.modifyCollateral.selector
                && _selector != IEngine.commitOrder.selector
                && _selector != IEngine.invalidateUnorderedNonces.selector
                && _selector != EIP7412.fulfillOracleQuery.selector
                && _selector != IEngine.depositEth.selector
                && _selector != IEngine.withdrawEth.selector
        ) {
            revert InvalidSMv3Selector();
        }
    }

    /// @notice sanitize the call value to ensure it is zero unless calling
    /// IEngine.depositEth or EIP7412.fulfillOracleQuery
    /// @param _selector the selector to sanitize
    /// @dev will revert if the call value is not valid
    function _sanitizeCallValue(bytes4 _selector, uint256 _callValue)
        internal
        pure
    {
        if (
            _selector == IEngine.depositEth.selector
                || _selector == EIP7412.fulfillOracleQuery.selector
        ) {
            if (_callValue == 0) {
                revert InvalidCallValue();
            }
        } else if (_callValue != 0) {
            revert InvalidCallValue();
        }
    }
}
