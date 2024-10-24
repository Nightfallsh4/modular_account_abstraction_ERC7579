// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { BaseSetup } from "./BaseSetup.t.sol";
import { ISafe2 as ISafe } from "src/interfaces/ISafe2.sol";
import "src/utils/Errors.sol";
import { IPasskeySigner } from "src/interfaces/IPasskeySigner.sol";
import "safe7579/test/dependencies/EntryPoint.sol";

contract PasskeyValidatorTest is BaseSetup {
    function setUp() external {
        setUpEssentialContracts();

        createAndInitialseModules();
    }

    modifier setUpAccount() {
        setupAccountWithTx();
        _;
    }

    function test_PasskeySetAsValidator() setUpAccount external {
        // Check if module installed correctly in user account
        bool isInstalled = userAccount.isModuleInstalled(1, address(passkeyValidator), "");
        assert(isInstalled);

        // Check if module configured correctly in validator
        IPasskeySigner passkeySigner = passkeyValidator.accountToPasskeySigner(address(userAccount));

        assert(address(passkeySigner) != address(0));

    }

    function test_PasskeySignature() setUpAccount external {
        PackedUserOperation memory _userOp = getDefaultUserOp(address(userAccount), address(passkeyValidator));
        _userOp.signature = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        passkeyValidator.checkSignature(_userOp);
    }


}
