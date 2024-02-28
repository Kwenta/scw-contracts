// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.18;

import {
    Bootstrap, SMv3SessionValidationModule
} from "test/utils/Bootstrap.sol";
import {
    UserOperationSignature,
    UserOperation,
    UserOperationLib
} from "test/utils/UserOperationSignature.sol";
import {IEngine} from "src/kwenta/smv3/IEngine.sol";

contract SMv3SessionValidationModuleTest is Bootstrap {
    address signer;
    uint256 signerPrivateKey;

    address sessionKey;
    address smv3Engine;
    address destinationContract;
    uint256 callValue;
    bytes funcCallData;
    bytes sessionKeyData;
    bytes sessionKeySignature;
    bytes callSpecificData;

    bytes4 public constant EXECUTE_SELECTOR = 0xb61d27f6;
    bytes4 public constant EXECUTE_OPTIMIZED_SELECTOR = 0x0000189a;

    UserOperationSignature userOpSignature;
    UserOperation op;
    bytes32 userOpHash;
    bytes data;

    function setUp() public {
        initializeOptimismSepolia();

        userOpSignature = new UserOperationSignature();

        // signers
        signerPrivateKey = 0x12341234;
        signer = vm.addr(signerPrivateKey);

        // session key data
        sessionKey = signer;
        smv3Engine = address(0x2);

        // validateSessionParams params
        destinationContract = smv3Engine;
        callValue = 0;

        bytes[] memory calls = new bytes[](0);

        funcCallData = abi.encodeWithSelector(IEngine.multicall.selector, calls);

        sessionKeyData = abi.encode(sessionKey, smv3Engine);
        callSpecificData = "";

        // validateSessionUserOp params
        op.callData = abi.encodeWithSelector(
            EXECUTE_SELECTOR, destinationContract, callValue, funcCallData
        );
        userOpHash = userOpSignature.hashUserOperation(op);
        sessionKeySignature =
            userOpSignature.getUserOperationSignature(op, signerPrivateKey);
    }
}

contract ValidateSessionParams is SMv3SessionValidationModuleTest {
    function test_validateSessionParams() public {
        address retSessionKey = smv3SessionValidationModule
            .validateSessionParams(
            destinationContract,
            callValue,
            funcCallData,
            sessionKeyData,
            callSpecificData
        );

        assertEq(sessionKey, retSessionKey);
    }

    function test_validateSessionParams_destinationContract_invalid(
        address invalid_destinationContract
    ) public {
        vm.assume(invalid_destinationContract != destinationContract);

        vm.expectRevert(
            abi.encodeWithSelector(
                SMv3SessionValidationModule.InvalidDestinationContract.selector
            )
        );

        smv3SessionValidationModule.validateSessionParams(
            invalid_destinationContract,
            callValue,
            funcCallData,
            sessionKeyData,
            callSpecificData
        );
    }

    function test_validateSessionParams_funcCallData_invalid() public {
        bytes4 invalid_selector = 0x12345678;

        funcCallData = abi.encodeWithSelector(bytes4(""), invalid_selector);

        vm.expectRevert(
            abi.encodeWithSelector(
                SMv3SessionValidationModule.InvalidSMv3Selector.selector
            )
        );

        smv3SessionValidationModule.validateSessionParams(
            destinationContract,
            callValue,
            funcCallData,
            sessionKeyData,
            callSpecificData
        );
    }

    function test_validateSessionParams_sessionKeyData_invalid(
        address invalid_sessionKey,
        address invalid_destinationContract
    ) public {
        vm.assume(invalid_sessionKey != sessionKey);

        bytes memory invalid_sessionKeyData =
            abi.encode(invalid_sessionKey, destinationContract);

        address retSessionKey = smv3SessionValidationModule
            .validateSessionParams(
            destinationContract,
            callValue,
            funcCallData,
            invalid_sessionKeyData,
            callSpecificData
        );

        assertFalse(retSessionKey == sessionKey);

        vm.assume(invalid_destinationContract != destinationContract);

        invalid_sessionKeyData =
            abi.encode(sessionKey, invalid_destinationContract);

        vm.expectRevert(
            abi.encodeWithSelector(
                SMv3SessionValidationModule.InvalidDestinationContract.selector
            )
        );

        smv3SessionValidationModule.validateSessionParams(
            destinationContract,
            callValue,
            funcCallData,
            invalid_sessionKeyData,
            callSpecificData
        );
    }
}

contract ValidateSessionUserOp is SMv3SessionValidationModuleTest {
    function test_validateSessionUserOp() public {
        op.callData = abi.encodeWithSelector(
            EXECUTE_SELECTOR, destinationContract, callValue, funcCallData
        );

        userOpHash = userOpSignature.hashUserOperation(op);

        sessionKeySignature =
            userOpSignature.getUserOperationSignature(op, signerPrivateKey);

        bool ret = smv3SessionValidationModule.validateSessionUserOp(
            op, userOpHash, sessionKeyData, sessionKeySignature
        );

        assertTrue(ret);
    }

    function test_validateSessionUserOp_op_callData_invalid(
        address invalid_destinationContract,
        uint256 invalid_callValue
    ) public {
        bytes4 invalid_selector = 0x12345678;

        op.callData = abi.encodeWithSelector(
            invalid_selector, destinationContract, 1, funcCallData
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SMv3SessionValidationModule.InvalidSelector.selector
            )
        );

        smv3SessionValidationModule.validateSessionUserOp(
            op, userOpHash, sessionKeyData, sessionKeySignature
        );

        vm.assume(invalid_destinationContract != destinationContract);

        op.callData = abi.encodeWithSelector(
            EXECUTE_SELECTOR,
            invalid_destinationContract,
            callValue,
            funcCallData
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SMv3SessionValidationModule.InvalidDestinationContract.selector
            )
        );

        smv3SessionValidationModule.validateSessionUserOp(
            op, userOpHash, sessionKeyData, sessionKeySignature
        );

        vm.assume(invalid_callValue != callValue);

        bytes memory invalid_funcCallData =
            abi.encode(invalid_selector, bytes32(""));

        op.callData = abi.encodeWithSelector(
            EXECUTE_SELECTOR,
            destinationContract,
            callValue,
            invalid_funcCallData
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SMv3SessionValidationModule.InvalidSMv3Selector.selector
            )
        );

        smv3SessionValidationModule.validateSessionUserOp(
            op, userOpHash, sessionKeyData, sessionKeySignature
        );
    }

    function test_validateSessionUserOp_userOpHash_invalid(
        bytes32 invalid_userOpHash
    ) public {
        vm.assume(invalid_userOpHash != userOpHash);

        bool ret = smv3SessionValidationModule.validateSessionUserOp(
            op, invalid_userOpHash, sessionKeyData, sessionKeySignature
        );

        assertFalse(ret);
    }

    function test_validateSessionUserOp_sessionKeyData_invalid(
        address invalid_sessionKey,
        address invalid_destinationContract
    ) public {
        vm.assume(invalid_sessionKey != sessionKey);

        bytes memory invalid_sessionKeyData =
            abi.encode(invalid_sessionKey, smv3Engine);

        bool isValid = smv3SessionValidationModule.validateSessionUserOp(
            op, userOpHash, invalid_sessionKeyData, sessionKeySignature
        );

        assertFalse(isValid);

        vm.assume(invalid_destinationContract != destinationContract);

        sessionKeyData = abi.encode(sessionKey, invalid_destinationContract);

        vm.expectRevert(
            abi.encodeWithSelector(
                SMv3SessionValidationModule.InvalidDestinationContract.selector
            )
        );

        smv3SessionValidationModule.validateSessionUserOp(
            op, userOpHash, sessionKeyData, sessionKeySignature
        );
    }

    function test_validateSessionUserOp_sessionKeySignature_invalid(
        uint256 invalid_privateKey
    ) public {
        // restrictions enforced by foundry
        vm.assume(invalid_privateKey != 0);
        vm.assume(invalid_privateKey < secp256k1_curve_order);

        // test specific
        vm.assume(invalid_privateKey != signerPrivateKey);

        bytes memory invalidSessionKeySignature =
            userOpSignature.getUserOperationSignature(op, invalid_privateKey);

        bool isValid = smv3SessionValidationModule.validateSessionUserOp(
            op, userOpHash, sessionKeyData, invalidSessionKeySignature
        );

        assertFalse(isValid);
    }
}
