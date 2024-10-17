// SPDX-License-Identifier: GPL-v3
pragma solidity 0.8.25;

import { Script } from "forge-std/Script.sol";
import { MockRegistry } from "safe7579/test/mocks/MockRegistry.sol";
import { TokenshieldSafe7579 } from "src/TokenshieldSafe7579.sol";
import { Safe7579Launchpad } from "safe7579/src/Safe7579Launchpad.sol";
import { BlockGuardSetter } from "src/guard/BlockGuardSetter.sol";
import { BlockSafeGuard } from "src/guard/BlockSafeGuard.sol";
import { GuardianValidator } from "src/modules/GuardianValidator.sol";
import { RecoveryModule } from "src/modules/RecoveryModule.sol";
import { MockERC20Target } from "../test/unit/mocks/MockERC20Target.sol";
import { BaseSetup } from "test/unit/BaseSetup.t.sol";
import { IERC7484 } from "safe7579/src/interfaces/IERC7484.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { Safe } from "@safe-global/safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { TokenshieldKernal } from "src/TokenshieldKernal.sol";
import { HelpersConfig } from "script/helpers/HelpersConfig.s.sol";
import "src/utils/Roles.sol";
import { console } from "forge-std/console.sol";


contract Deploy is Script, BaseSetup, HelpersConfig {
    ChainConfig config;

    function run() external {
        config = getConfig();
        uint256 deployerPrivateKey = config.deployerPrivateKey;
        vm.startBroadcast(deployerPrivateKey);
        deployContracts();
        vm.stopBroadcast();

        // Initialise GuardianValidator
        (address[] memory guardians, bool[] memory isEnabled) = getGuardiansList(address(defaultValidator), config.guardian);
        
        console.log(mfaSetterAdmin.addr);
        console.log(mfaSetter.addr);
        console.log(moduleSetter.addr);
        
        vm.broadcast(mfaSetterAdmin.key);
        kernal.grantRole(MFA_SETTER, mfaSetter.addr);

        vm.broadcast(mfaSetter.key);
        kernal.setGuardian(guardians, isEnabled);

        // Initialise Executor
        vm.broadcast(moduleSetter.key);
        kernal.grantRole(TOKENSHIELD_RECOVERY_EXECUTOR, address(defaultExecutor));
    }

    function deployContracts() internal {
        entrypoint = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
        // ERC7484 Registry for ERC7579
        registry = new MockRegistry{ salt: config.salt }();

        // ERC7579 Adapter for Safe
        tsSafe = new TokenshieldSafe7579{ salt: config.salt }();
        launchpad = new Safe7579Launchpad{ salt: config.salt }(address(entrypoint), IERC7484(address(registry)));
        singleton = new Safe{ salt: config.salt }();
        safeProxyFactory = new SafeProxyFactory{ salt: config.salt }();
        // Setting Up Guard and guard Setter
        guardSetter = new BlockGuardSetter{ salt: config.salt }();
        blockSafeGuard = new BlockSafeGuard{ salt: config.salt }();

        // Create Kernal
        kernal = new TokenshieldKernal(defaultAdmin.addr, mfaSetterAdmin.addr, moduleSetter.addr);

        // Create Guardian Validator
        defaultValidator = new GuardianValidator{ salt: config.salt }(address(kernal));

        // create executor
        defaultExecutor = new RecoveryModule{ salt: config.salt }(address(kernal));

        // setExecutors(address(defaultExecutor));

        target = new MockERC20Target{ salt: config.salt }();
    }
}
