// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.26;

import { BaseSetup } from "./BaseSetup.t.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { MockERC20Target } from "./mocks/MockERC20Target.sol";

import { MockDepositTarget } from "./mocks/MockDepositTarget.sol";

import "safe7579/test/dependencies/EntryPoint.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { console } from "forge-std/console.sol";

contract TokenshieldSafe7579Test is BaseSetup {
    Account receiverAddress = makeAccount("RECEIVER_ADDRESS");

    function setUp() public {
        // super.setUp();
        setUpEssentialContracts();
        // Create and Initialise Modules

        createAndInitialseModules();
    }

    function test_IsGuardianValidatorSet() external view {
        bool isEnabled = kernal.isApprovedGuardian(guardian1.addr);
        assert(isEnabled);
    }

    function test_MockERC20_Mint() external {
        setupAccountWithTx();
    }

    function test_GuardSet() external {
        setupAccountWithTx();
        // keccak256("guard_manager.guard.address")
        bytes32 GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
        bytes32 slotData = vm.load(address(userAccount), GUARD_STORAGE_SLOT);
        address guardAddress = address(uint160(uint256(slotData)));
        // console.logBytes32(slotData);
        // console.log(guardAddress);

        assertEq(guardAddress, address(blockSafeGuard));
    }

    modifier setUpAccount() {
        // createAndInitialseModules();
        setupAccountWithTx();
        _;
    }

    function test_TestERC20Transfer() external setUpAccount {
        uint256 amountToTransfer = 3 ether;

        uint256 priorBalance = target.balanceOf(address(userAccount));
        // Create calldata for the account to execute
        bytes memory targetCalldata = abi.encodeCall(IERC20.transfer, (receiverAddress.addr, amountToTransfer));

        // Encode the call into the calldata for the userOp
        bytes memory userOpCalldata = abi.encodeCall(
            IERC7579Account.execute,
            (ModeLib.encodeSimpleSingle(), ExecutionLib.encodeSingle(address(target), uint256(0), targetCalldata))
        );

        PackedUserOperation memory userOp = getDefaultUserOp(address(userAccount), address(defaultValidator));

        userOp.initCode = "";
        userOp.callData = userOpCalldata;

        userOp.signature = getSignature(userOp, signer1, guardian1, address(defaultValidator));

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));
        uint256 postBalance = target.balanceOf(address(userAccount));
        assertEq(priorBalance, postBalance + amountToTransfer);
    }

    function test_BatchERC20Transfer() external setUpAccount {
        uint256 amountToTransfer1 = 1 ether;
        uint256 amountToTransfer2 = 2 ether;
        uint256 amountToTransfer3 = 3 ether;

        Account memory receiver1 = makeAccount("RECEIVER_1");
        Account memory receiver2 = makeAccount("RECEIVER_2");
        Account memory receiver3 = makeAccount("RECEIVER_3");

        uint256 priorBalance = target.balanceOf(address(userAccount));

        // Create Transactions
        Execution[] memory txs = new Execution[](3);
        txs[0] = Execution({
            target: address(target),
            value: uint256(0),
            callData: abi.encodeCall(IERC20.transfer, (receiver1.addr, amountToTransfer1))
        });
        txs[1] = Execution({
            target: address(target),
            value: uint256(0),
            callData: abi.encodeCall(IERC20.transfer, (receiver2.addr, amountToTransfer2))
        });
        txs[2] = Execution({
            target: address(target),
            value: uint256(0),
            callData: abi.encodeCall(IERC20.transfer, (receiver3.addr, amountToTransfer3))
        });

        // Encode the call into the calldata for the userOp
        bytes memory userOpCalldata =
            abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(txs)));

        PackedUserOperation memory userOp = getDefaultUserOp(address(userAccount), address(defaultValidator));

        userOp.initCode = "";
        userOp.callData = userOpCalldata;

        userOp.signature = getSignature(userOp, signer1, guardian1, address(defaultValidator));

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));

        assertEq(priorBalance, target.balanceOf(address(userAccount)) + 6 ether);

        assertEq(target.balanceOf(receiver1.addr), amountToTransfer1);
        assertEq(target.balanceOf(receiver2.addr), amountToTransfer2);
        assertEq(target.balanceOf(receiver3.addr), amountToTransfer3);
    }

    function test_BatchApproveAndDeposit() external setUpAccount {
        uint256 amountToDeposit = 2 ether;

        MockDepositTarget depositTarget = new MockDepositTarget();

        uint256 priorBalance = target.balanceOf(address(userAccount));

        // Create Transactions
        Execution[] memory txs = new Execution[](2);
        txs[0] = Execution({
            target: address(target),
            value: uint256(0),
            callData: abi.encodeCall(IERC20.approve, (address(depositTarget), amountToDeposit))
        });
        txs[1] = Execution({
            target: address(depositTarget),
            value: uint256(0),
            callData: abi.encodeCall(MockDepositTarget.deposit, (address(target), address(userAccount), amountToDeposit))
        });

        // Encode the call into the calldata for the userOp
        bytes memory userOpCalldata =
            abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(txs)));

        PackedUserOperation memory userOp = getDefaultUserOp(address(userAccount), address(defaultValidator));

        userOp.initCode = "";
        userOp.callData = userOpCalldata;

        userOp.signature = getSignature(userOp, signer1, guardian1,  address(defaultValidator));

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));

        assertEq(priorBalance, target.balanceOf(address(userAccount)) + amountToDeposit);
        assertEq(depositTarget.depositedAmount(address(userAccount)), amountToDeposit);
        assertEq(target.balanceOf(address(depositTarget)), amountToDeposit);
    }

    function test_CheckThreshold() external {
        setupAccountWithTx();
        // keccak256("guard_manager.guard.address")
        bytes32 SLOT3 = bytes32(uint256(0x03));
        bytes32 SLOT4 = bytes32(uint256(0x04));
        bytes32 SLOT5 = bytes32(uint256(0x05));
        bytes32 slotData3 = vm.load(address(userAccount), SLOT3);
        // console.logBytes32(slotData3);
        bytes32 slotData4 = vm.load(address(userAccount), SLOT4);
        // console.logBytes32(slotData4);
        bytes32 slotData5 = vm.load(address(userAccount), SLOT5);
        // console.logBytes32(slotData5);
        // address guardAddress = address(uint160(uint256(slotData)));
        // console.log(guardAddress);

        // assertEq(guardAddress, address(blockSafeGuard));
    }
}
