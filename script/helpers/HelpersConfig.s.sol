// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import { Script } from "forge-std/Script.sol";
import { Accounts } from "test/unit/utils/Accounts.t.sol";
abstract contract HelpersConfig is Script, Accounts {

    struct ChainConfig {
        Account defaultAdmin;
        Account mfaSetterAdmin;
        Account mfaSetter;
        Account moduleSetter;
        Account guardian;
        Account guardianDefaultNominee;
        uint256 deployerPrivateKey;
        string salt;
        address ethPriceFeed;
        address automationRegistry;
    }

    // ChainConfig private config;
    uint256 public chainId;

    constructor() {
        chainId = block.chainid;
    }

    function getConfig() public view returns (ChainConfig memory) {
        ChainConfig memory config;
        if (chainId == 31_337) {
            config = getAnvilConfig();
        }
        // if (chainId == 11_155_111) {
        //     config = getSepoliaConfig();
        // }
        // if (chainId == 534_351) {
        //     config = getScrollConfig();
        // }

        return config;
    }

    function getAnvilConfig() internal view returns (ChainConfig memory) {
        return ChainConfig({
            defaultAdmin: defaultAdmin,
            mfaSetterAdmin: mfaSetterAdmin,
            mfaSetter: mfaSetter,
            moduleSetter:  moduleSetter,
            guardian: guardian1,
            guardianDefaultNominee: guardianDefaultNominee,
            deployerPrivateKey: vm.envUint("PRIVATE_KEY"),
            salt: "123",
            ethPriceFeed: 0x694AA1769357215DE4FAC081bf1f309aDC325306,
            automationRegistry: 0x86EFBD0b6736Bed994962f9797049422A3A8E8Ad
        });
    }

    // function getSepoliaConfig() internal view returns (ChainConfig memory) {
    //     address adminAddress = vm.envAddress("SEPOLIA_DEFAULT_ADMIN_ADDRESS");
    //     address guardSigner = vm.envAddress("SEPOLIA_GUARDIAN_SIGNER");
    //     address guardSetter = vm.envAddress("SEPOLIA_GUARDIAN_SETTER");
    //     return ChainConfig({
    //         contractAdmin: adminAddress,
    //         guardianSigner: guardSigner,
    //         guardianSetter: guardSetter,
    //         accountRecoveryManager: vm.addr(4),
    //         ethPriceFeed: 0x694AA1769357215DE4FAC081bf1f309aDC325306,
    //         automationRegistry: 0x86EFBD0b6736Bed994962f9797049422A3A8E8Ad,
    //         domainName: "TokenShield",
    //         domainVersion: "1"
    //     });
    // }

    // function getScrollConfig() internal view returns (ChainConfig memory) {
    //     address adminAddress = vm.envAddress("SEPOLIA_DEFAULT_ADMIN_ADDRESS");
    //     address guardSigner = vm.envAddress("SEPOLIA_GUARDIAN_SIGNER");
    //     address guardSetter = vm.envAddress("SEPOLIA_GUARDIAN_SETTER");
    //     return ChainConfig({
    //         contractAdmin: adminAddress,
    //         guardianSigner: guardSigner,
    //         guardianSetter: guardSetter,
    //         accountRecoveryManager: vm.addr(4),
    //         ethPriceFeed: 0x694AA1769357215DE4FAC081bf1f309aDC325306,
    //         automationRegistry: 0x86EFBD0b6736Bed994962f9797049422A3A8E8Ad,
    //         domainName: "TokenShield",
    //         domainVersion: "1"
    //     });
    // }
}
