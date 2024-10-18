// SPDX-License-Identifier: GPL-v3
pragma solidity 0.8.26;

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
import { SafeProxy, SafeProxyFactory } from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";

contract SendTx is Script, BaseSetup {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        sendTx();
        vm.stopBroadcast();
    }

    function sendTx() internal {
        entrypoint = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
        // ERC7484 Registry for ERC7579
        registry = MockRegistry(0x09635F643e140090A9A8Dcd712eD6285858ceBef);

        // ERC7579 Adapter for Safe
        tsSafe = TokenshieldSafe7579(payable(0x0FEe82b61e6350014017DeCc164ad11b2059970A));
        launchpad = Safe7579Launchpad(payable(0x6786E8D9322eA4765E111942547BF2DF81957F2a));
        singleton = Safe(payable(0x2f59c237Bbf6fc5369b58FcD3e8A6705011FC0c2));
        // Setting Up Guard and guard Setter
        guardSetter = BlockGuardSetter(0xDeeb4b8b4F2985A15c684952b89E2ed000a9Ce5B);
        blockSafeGuard = BlockSafeGuard(0xdbCDD5f0BA1e92cA8e6F24f724997938D346f1E6);

        // Create Guardian Validator
        defaultValidator = GuardianValidator(0xF0a555c30a448E480b22A623E3Fc7D8d76F064c6);

        // Initialise GuardianValidator
        // setGuardiansForGuardianValidator(address(defaultValidator), guardian1);

        // create executor
        defaultExecutor = RecoveryModule(0x8391F27Fd88a1F254A5Bca68282ec098169bF63F);

        target = MockERC20Target(0x40391Fa3Bec4affD73E5e1f54BD14676AB609dB8);
        safeProxyFactory = SafeProxyFactory(0x84f46193CD92f7250a95aC815Aa8B2FB09E4641D);

        setupAccountWithTx();
    }

    // function setGuardiansForGuardianValidator(address _validator, Account memory _guardian) public virtual {
    //     // Initialise Validator
    //     address[] memory guardians = new address[](1);
    //     guardians[0] = _guardian.addr;

    //     bool[] memory isEnabled = new bool[](1);
    //     isEnabled[0] = true;
    //     GuardianValidator(_validator).setGuardian(guardians, isEnabled);
    // }
}
