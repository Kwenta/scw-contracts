// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.18;

import {console2} from "lib/forge-std/src/console2.sol";
import {
    SMv2SessionValidationModule,
    SMv3SessionValidationModule,
    OptimismSepoliaParameters,
    OptimismParameters,
    Setup
} from "script/Deploy.s.sol";
import {Test} from "lib/forge-std/src/Test.sol";

contract Bootstrap is Test {
    using console2 for *;

    uint256 public secp256k1_curve_order =
        115_792_089_237_316_195_423_570_985_008_687_907_852_837_564_279_074_904_382_605_163_141_518_161_494_337;

    SMv2SessionValidationModule public smv2SessionValidationModule;
    SMv3SessionValidationModule public smv3SessionValidationModule;

    function initializeOptimismSepolia() public {
        BootstrapOptimismSepolia bootstrap = new BootstrapOptimismSepolia();
        (
            address smv2SessionValidationModuleAddress,
            address smv3SessionValidationModuleAddress
        ) = bootstrap.init();

        smv2SessionValidationModule =
            SMv2SessionValidationModule(smv2SessionValidationModuleAddress);
        smv3SessionValidationModule =
            SMv3SessionValidationModule(smv3SessionValidationModuleAddress);
    }

    /// @dev add other networks here as needed (ex: Base, BaseSepolia)
}

contract BootstrapOptimismSepolia is Setup, OptimismSepoliaParameters {
    function init() public returns (address, address) {
        (
            address smv2SessionValidationModuleAddress,
            address smv3SessionValidationModuleAddress
        ) = Setup.deploySystem();

        return (
            smv2SessionValidationModuleAddress,
            smv3SessionValidationModuleAddress
        );
    }
}

// add other networks here as needed (ex: Base, BaseSepolia)
