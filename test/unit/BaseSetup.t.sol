// SPDX-License-Identifier: GPL-v3
pragma solidity 0.8.25;

import { Test } from "forge-std/Test.sol";

import "safe7579/test/dependencies/EntryPoint.sol";

import "safe7579/src/DataTypes.sol";

import { Safe } from "@safe-global/safe-contracts/contracts/Safe.sol";
import { SafeProxy, SafeProxyFactory } from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { TokenshieldSafe7579 } from "../../src/TokenshieldSafe7579.sol";
import { Safe7579Launchpad } from "safe7579/src/Safe7579Launchpad.sol";

import { MockGuardianValidator } from "./mocks/MockGuardianValidator.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { IERC7484 } from "safe7579/src/interfaces/IERC7484.sol";
import { MockRegistry } from "safe7579/test/mocks/MockRegistry.sol";
import { RecoveryModule } from "src/modules/RecoveryModule.sol";
import { console2 } from "forge-std/console2.sol";

import { ISafe7579 } from "safe7579/src/ISafe7579.sol";

import { MockERC20Target } from "./mocks/MockERC20Target.sol";
import { Solarray } from "solarray/Solarray.sol";

import { ISafe7579 } from "safe7579/src/ISafe7579.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";

contract BaseSetup is Test {
    Account guardian1 = makeAccount("GUARDIAN_1");
    Account guardianSigner = makeAccount("GUARDIAN_SIGNER");
    Account guardianDefaultNominee = makeAccount("GUARDIAN_NOMINEE");

    // Safe
    Safe singleton;
    SafeProxyFactory safeProxyFactory;
    TokenshieldSafe7579 tsSafe;
    Safe7579Launchpad launchpad;

    // Account
    Account signer1 = makeAccount("SIGNER_1");

    // ERC4337
    IEntryPoint entrypoint;

    // ERC7579 Validators & Executors
    MockGuardianValidator defaultValidator;
    RecoveryModule defaultExecutor;
    MockRegistry registry;

    // Target
    MockERC20Target target;

    // UserAccount
    TokenshieldSafe7579 userAccount;

    function setUpEssentialContracts() internal virtual {
        // Setting Up

        // Set up EntryPoint
        entrypoint = etchEntrypoint();

        // Setup Safe contracts
        singleton = new Safe();
        safeProxyFactory = new SafeProxyFactory();

        // ERC7484 Registry for ERC7579
        registry = new MockRegistry();

        // ERC7579 Adapter for Safe
        tsSafe = new TokenshieldSafe7579();
        launchpad = new Safe7579Launchpad(address(entrypoint), IERC7484(address(registry)));
    }

    function setupAccountWithTx() internal virtual {
        // Have to build user op First but to build user op we need the safe address which is gonna be doing the
        // transaction ir the sender.
        // but if the sender is not created yet then we need to predict the creator address and predict it.

        // We have a predict safe address function in launchpad we can call to the predict the safe address, but we need
        // the creation code and factory initializer for that

        // address predictedAddress = launchpad.predictSafeAddress(address(singleton), address(safeProxyFactory),
        // /**creationcode */,"0x44444",/**factoryInitialiser */);

        (
            ModuleInit[] memory validators,
            ModuleInit[] memory executors,
            ModuleInit[] memory fallbacks,
            ModuleInit[] memory hooks
        ) = getValidatorExecutorsEtc();

        // Create a UserOp with sender and validator, still have to fill initCode, calldata and signature
        PackedUserOperation memory userOp = getDefaultUserOp(address(0), address(defaultValidator));

        // Setup Calldata in UserOp
        Safe7579Launchpad.InitData memory initData = Safe7579Launchpad.InitData({
            singleton: address(singleton),
            owners: Solarray.addresses(signer1.addr),
            threshold: 1,
            setupTo: address(launchpad),
            setupData: getSetupData(executors, fallbacks, hooks),
            safe7579: ISafe7579(tsSafe),
            validators: validators,
            callData: getCallExecutionData()
        });

        userOp.callData = abi.encodeCall(Safe7579Launchpad.setupSafe, (initData));

        // Set up init Code for UserOp
        bytes32 salt = keccak256("TestAccount");

        bytes32 initHash = launchpad.hash(initData);

        bytes memory factoryInitializer =
            abi.encodeCall(Safe7579Launchpad.preValidationSetup, (initHash, address(0), ""));

        userOp.initCode = abi.encodePacked(
            address(safeProxyFactory),
            abi.encodeCall(
                SafeProxyFactory.createProxyWithNonce, (address(launchpad), factoryInitializer, uint256(salt))
            )
        );

        address predict =
            predictAccount(payable(address(launchpad)), address(safeProxyFactory), salt, factoryInitializer);

        userOp.sender = predict;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;
        deal(address(userOp.sender), 1 ether);

        entrypoint.handleOps(userOps, payable(address(0x69)));

        assertEq(13 ether, target.balanceOf(predict));

        userAccount = TokenshieldSafe7579(payable(userOp.sender));
    }

    function createAndInitialseModules() internal virtual {
        // Create Guardian Validator
        defaultValidator = new MockGuardianValidator();

        // Initialise GuardianValidator
        setGuardiansForGuardianValidator(address(defaultValidator), guardian1);

        // create executor
        defaultExecutor = new RecoveryModule();

        target = new MockERC20Target();
    }

    function getDefaultUserOp(
        address account,
        address validator
    )
        internal
        view
        virtual
        returns (PackedUserOperation memory userOp)
    {
        userOp = PackedUserOperation({
            sender: account,
            nonce: tsSafe.getNonce(account, address(validator)),
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            preVerificationGas: 2e6,
            gasFees: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            paymasterAndData: bytes(""),
            signature: abi.encodePacked(hex"41414141")
        });
    }

    function getValidatorExecutorsEtc()
        internal
        view
        virtual
        returns (
            ModuleInit[] memory validators,
            ModuleInit[] memory executors,
            ModuleInit[] memory fallbacks,
            ModuleInit[] memory hooks
        )
    {
        validators = new ModuleInit[](1);
        validators[0] = ModuleInit({ module: address(defaultValidator), initData: bytes("") });
        executors = new ModuleInit[](1);
        executors[0] = ModuleInit({ module: address(defaultExecutor), initData: bytes("") });
        fallbacks = new ModuleInit[](0);
        hooks = new ModuleInit[](0);
    }

    function getSetupData(
        ModuleInit[] memory executors,
        ModuleInit[] memory fallbacks,
        ModuleInit[] memory hooks
    )
        public
        virtual
        returns (bytes memory)
    {
        return abi.encodeCall(
            Safe7579Launchpad.initSafe7579,
            (
                address(tsSafe),
                executors,
                fallbacks,
                hooks,
                Solarray.addresses(makeAddr("attester1"), makeAddr("attester2")),
                2
            )
        );
    }

    function getCallExecutionData() public view virtual returns (bytes memory) {
        return abi.encodeCall(
            IERC7579Account.execute,
            (
                ModeLib.encodeSimpleSingle(),
                ExecutionLib.encodeSingle({
                    target: address(target),
                    value: 0,
                    callData: abi.encodeCall(MockERC20Target.mint, (13 ether))
                })
            )
        );
    }

    function setGuardiansForGuardianValidator(address _validator, Account memory _guardian) public virtual {
        // Initialise Validator
        address[] memory guardians = new address[](1);
        guardians[0] = _guardian.addr;

        bool[] memory isEnabled = new bool[](1);
        isEnabled[0] = true;
        MockGuardianValidator(_validator).setGuardian(guardians, isEnabled);
    }

    function predictAccount(
        address payable _launchpad,
        address _safeProxyFactory,
        bytes32 _salt,
        bytes memory _factoryInitializer
    )
        public
        pure
        returns (address predict)
    {
        // Predict address, now we have h=salt and factory initializer to predict the address
        predict = Safe7579Launchpad(_launchpad).predictSafeAddress({
            singleton: _launchpad,
            safeProxyFactory: _safeProxyFactory,
            creationCode: type(SafeProxy).creationCode,
            salt: _salt,
            factoryInitializer: _factoryInitializer
        });
    }
}
