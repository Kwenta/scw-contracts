// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.18;

import {
    Bootstrap, SMv2SessionValidationModule
} from "test/utils/Bootstrap.sol";
import {
    UserOperationSignature,
    UserOperation,
    UserOperationLib
} from "test/utils/UserOperationSignature.sol";
import {IAccount} from "src/kwenta/smv2/IAccount.sol";

contract SMv2SessionValidationModuleTest is Bootstrap {
    address signer;
    uint256 signerPrivateKey;

    address sessionKey;
    address smv2ProxyAccount;
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
        smv2ProxyAccount = address(0x2);

        // validateSessionParams params
        destinationContract = smv2ProxyAccount;
        callValue = 0;
        funcCallData = abi.encode(IAccount.execute.selector, bytes32(""));
        sessionKeyData = abi.encode(sessionKey, destinationContract);
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

contract ValidateSessionParams is SMv2SessionValidationModuleTest {
    function test_validateSessionParams() public {
        address retSessionKey = smv2SessionValidationModule
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
                SMv2SessionValidationModule.InvalidDestinationContract.selector
            )
        );

        smv2SessionValidationModule.validateSessionParams(
            invalid_destinationContract,
            callValue,
            funcCallData,
            sessionKeyData,
            callSpecificData
        );
    }

    function test_validateSessionParams_funcCallData_invalid() public {
        bytes4 invalid_selector = 0x12345678;

        bytes memory invalid_funcCallData =
            abi.encode(invalid_selector, bytes32(""));

        vm.expectRevert(
            abi.encodeWithSelector(
                SMv2SessionValidationModule.InvalidSMv2Selector.selector
            )
        );

        smv2SessionValidationModule.validateSessionParams(
            destinationContract,
            callValue,
            invalid_funcCallData,
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

        address retSessionKey = smv2SessionValidationModule
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
                SMv2SessionValidationModule.InvalidDestinationContract.selector
            )
        );

        smv2SessionValidationModule.validateSessionParams(
            destinationContract,
            callValue,
            funcCallData,
            invalid_sessionKeyData,
            callSpecificData
        );
    }
}

contract ValidateSessionUserOp is SMv2SessionValidationModuleTest {
    function test_validateSessionUserOp() public {
        bool isValid = smv2SessionValidationModule.validateSessionUserOp(
            op, userOpHash, sessionKeyData, sessionKeySignature
        );

        assertTrue(isValid);
    }

    function test_validateSessionUserOp_op_callData_invalid(
        address invalid_destinationContract
    ) public {
        bytes4 invalid_selector = 0x12345678;

        op.callData = abi.encodeWithSelector(
            invalid_selector, destinationContract, callValue, funcCallData
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SMv2SessionValidationModule.InvalidSelector.selector
            )
        );

        smv2SessionValidationModule.validateSessionUserOp(
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
                SMv2SessionValidationModule.InvalidDestinationContract.selector
            )
        );

        smv2SessionValidationModule.validateSessionUserOp(
            op, userOpHash, sessionKeyData, sessionKeySignature
        );

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
                SMv2SessionValidationModule.InvalidSMv2Selector.selector
            )
        );

        smv2SessionValidationModule.validateSessionUserOp(
            op, userOpHash, sessionKeyData, sessionKeySignature
        );
    }

    function test_validateSessionUserOp_userOpHash_invalid(
        bytes32 invalid_userOpHash
    ) public {
        vm.assume(invalid_userOpHash != userOpHash);

        bool isValid = smv2SessionValidationModule.validateSessionUserOp(
            op, invalid_userOpHash, sessionKeyData, sessionKeySignature
        );

        assertFalse(isValid);
    }

    function test_validateSessionUserOp_sessionKeyData_invalid(
        address invalid_sessionKey,
        address invalid_destinationContract
    ) public {
        vm.assume(invalid_sessionKey != sessionKey);

        bytes memory invalid_sessionKeyData =
            abi.encode(invalid_sessionKey, destinationContract);

        bool isValid = smv2SessionValidationModule.validateSessionUserOp(
            op, userOpHash, invalid_sessionKeyData, sessionKeySignature
        );

        assertFalse(isValid);

        vm.assume(invalid_destinationContract != destinationContract);

        sessionKeyData = abi.encode(sessionKey, invalid_destinationContract);

        vm.expectRevert(
            abi.encodeWithSelector(
                SMv2SessionValidationModule.InvalidDestinationContract.selector
            )
        );

        smv2SessionValidationModule.validateSessionUserOp(
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

        bool isValid = smv2SessionValidationModule.validateSessionUserOp(
            op, userOpHash, sessionKeyData, invalidSessionKeySignature
        );

        assertFalse(isValid);
    }
}
