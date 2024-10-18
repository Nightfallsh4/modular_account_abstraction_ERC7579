// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.26;

import { BaseSetup } from "./BaseSetup.t.sol";
import { ISafe2 as ISafe } from "src/interfaces/ISafe2.sol";
import { RecoveryModule } from "src/modules/RecoveryModule.sol";
import "src/utils/Errors.sol";

contract TokenshieldSafe7579Test is BaseSetup {
    Account receiverAddress = makeAccount("RECEIVER_ADDRESS");
    Account newOwner = makeAccount("NEW_OWNER");

    uint64 constant THREE_DAYS = 3 days;

    function setUp() public {
        // super.setUp();
        setUpEssentialContracts();
        // Create and Initialise Modules

        createAndInitialseModules();
    }

    modifier setUpAccount() {
        // createAndInitialseModules();
        setupAccountWithTx();
        _;
    }

    /////////////////////////////////////
    ///////// Start Recovery ////////////
    /////////////////////////////////////

    function test_StartRecovery() external setUpAccount {
        uint64 recoveryEndTime = uint64(block.timestamp) + THREE_DAYS + 1 hours;

        bytes32 digest = getRecoveryDigest(address(userAccount), newOwner.addr, recoveryEndTime);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardianDefaultNominee.key, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1.key, digest);

        bytes memory signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        defaultExecutor.startRecovery(address(userAccount), newOwner.addr, signer1.addr, recoveryEndTime, signatures);

        RecoveryModule.AccountStatus memory accountStatus = defaultExecutor.getAccountStatus(address(userAccount));
        assertEq(accountStatus.newOwner, newOwner.addr);
        assertEq(accountStatus.oldOwner, signer1.addr);
        assert(accountStatus.recoveryEndTime != 0);
    }

    modifier startRecovery() {
        uint64 recoveryEndTime = uint64(block.timestamp) + THREE_DAYS + 1 hours;

        bytes32 digest = getRecoveryDigest(address(userAccount), newOwner.addr, recoveryEndTime);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardianDefaultNominee.key, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1.key, digest);

        bytes memory signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        defaultExecutor.startRecovery(address(userAccount), newOwner.addr, signer1.addr, recoveryEndTime, signatures);
        _;
    }

    function test_StartRecovery_RevertsIfAccountNotInitialised() external setUpAccount {
        uint64 recoveryEndTime = uint64(block.timestamp) + THREE_DAYS + 1 hours;

        bytes32 digest = getRecoveryDigest(address(userAccount), newOwner.addr, recoveryEndTime);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardianDefaultNominee.key, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1.key, digest);

        bytes memory signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        vm.expectRevert(Tokenshield_Executor_Recovery_AccountNotInitialized.selector);
        defaultExecutor.startRecovery(receiverAddress.addr, newOwner.addr, signer1.addr, recoveryEndTime, signatures);
    }

    function test_StartRecovery_RevertsWhenAlreadyRecovering() external setUpAccount startRecovery {
        uint64 recoveryEndTime = uint64(block.timestamp) + THREE_DAYS + 1 hours;

        bytes32 digest = getRecoveryDigest(address(userAccount), newOwner.addr, recoveryEndTime);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardianDefaultNominee.key, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1.key, digest);

        bytes memory signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        vm.expectRevert(Tokenshield_Account_Already_Recoverying.selector);
        defaultExecutor.startRecovery(address(userAccount), newOwner.addr, signer1.addr, recoveryEndTime, signatures);
    }

    function test_StartRecovery_RevertsWhenZeroAddress() external setUpAccount {
        uint64 recoveryEndTime = uint64(block.timestamp) + THREE_DAYS + 1 hours;

        bytes32 digest = getRecoveryDigest(address(userAccount), newOwner.addr, recoveryEndTime);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardianDefaultNominee.key, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1.key, digest);

        bytes memory signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        // vm.expectRevert(Tokenshield_ZeroAddress.selector);
        // defaultExecutor.startRecovery(address(0), newOwner.addr, signer1.addr, recoveryEndTime, signatures);

        vm.expectRevert(Tokenshield_ZeroAddress.selector);
        defaultExecutor.startRecovery(address(userAccount), address(0), signer1.addr, recoveryEndTime, signatures);

        vm.expectRevert(Tokenshield_ZeroAddress.selector);
        defaultExecutor.startRecovery(address(userAccount), newOwner.addr, address(0), recoveryEndTime, signatures);

        vm.expectRevert(Tokenshield_ZeroAddress.selector);
        defaultExecutor.startRecovery(address(userAccount), address(0), address(0), recoveryEndTime, signatures);
    }

    function test_StartRecovery_RevertsWhenOldOwnerNotValid() external setUpAccount {
        uint64 recoveryEndTime = uint64(block.timestamp) + THREE_DAYS + 1 hours;

        bytes32 digest = getRecoveryDigest(address(userAccount), newOwner.addr, recoveryEndTime);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardianDefaultNominee.key, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1.key, digest);

        bytes memory signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        vm.expectRevert(Tokenshield_NotValidOwner.selector);
        defaultExecutor.startRecovery(
            address(userAccount), newOwner.addr, receiverAddress.addr, recoveryEndTime, signatures
        );
    }

    function test_StartRecovery_RevertsWhenNewOwnerIsNominee() external setUpAccount {
        uint64 recoveryEndTime = uint64(block.timestamp) + THREE_DAYS + 1 hours;

        bytes32 digest = getRecoveryDigest(address(userAccount), newOwner.addr, recoveryEndTime);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardianDefaultNominee.key, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1.key, digest);

        bytes memory signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        vm.expectRevert(Tokenshield_OwnerCantBeNominee.selector);
        defaultExecutor.startRecovery(
            address(userAccount), guardianDefaultNominee.addr, signer1.addr, recoveryEndTime, signatures
        );
    }

    function test_StartRecovery_RevertsWhenInvalidNominee() external setUpAccount {
        uint64 recoveryEndTime = uint64(block.timestamp) + THREE_DAYS + 1 hours;

        bytes32 digest = getRecoveryDigest(address(userAccount), newOwner.addr, recoveryEndTime);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardianDefaultNominee.key, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1.key, digest);

        bytes memory signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        vm.expectRevert(Tokenshield_New_Owner_Not_Valid.selector);
        defaultExecutor.startRecovery(
            address(userAccount), address(userAccount), signer1.addr, recoveryEndTime, signatures
        );

        vm.expectRevert(Tokenshield_New_Owner_Not_Valid.selector);
        defaultExecutor.startRecovery(
            address(userAccount), signer1.addr, signer1.addr, recoveryEndTime, signatures
        );
    }

    function test_StartRecovery_RevertsWhenTimeNotValid() external setUpAccount {
        uint64 recoveryEndTime = uint64(block.timestamp) + 2 days;

        bytes32 digest = getRecoveryDigest(address(userAccount), newOwner.addr, recoveryEndTime);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(guardianDefaultNominee.key, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1.key, digest);

        bytes memory signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        vm.expectRevert(Tokenshield_Recovery_Time_NotValid.selector);
        defaultExecutor.startRecovery(address(userAccount), newOwner.addr, signer1.addr, recoveryEndTime, signatures);
    }

    function test_StartRecovery_() external { }

    /////////////////////////////////////
    ////////// Stop Recovery ////////////
    /////////////////////////////////////

    function test_StopRecovery() external setUpAccount startRecovery {
        uint64 recoveryEndTime = uint64(block.timestamp) + THREE_DAYS + 1 hours;
        bytes32 digest = getRecoveryDigest(address(userAccount), newOwner.addr, recoveryEndTime);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(signer1.key, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian1.key, digest);

        bytes memory signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        defaultExecutor.stopRecovery(address(userAccount), signatures);

        RecoveryModule.AccountStatus memory accountStatus = defaultExecutor.getAccountStatus(address(userAccount));
        assertEq(accountStatus.newOwner, address(0));
        assertEq(accountStatus.oldOwner, address(0));
        assertEq(accountStatus.recoveryEndTime, 0);
    }

    /////////////////////////////////////
    //////// Complete Recovery //////////
    /////////////////////////////////////
    function test_CompleteRecovery() external setUpAccount startRecovery {
        // Skipping recovery time
        skip(4 days);
        defaultExecutor.completeRecovery(address(userAccount));

        RecoveryModule.AccountStatus memory accountStatus = defaultExecutor.getAccountStatus(address(userAccount));
        assertEq(accountStatus.newOwner, address(0));
        assertEq(accountStatus.oldOwner, address(0));
        assertEq(accountStatus.recoveryEndTime, 0);

        bool isNewOwnerSet = ISafe(address(userAccount)).isOwner(newOwner.addr);
        bool isOldOwnerRemoved = ISafe(address(userAccount)).isOwner(signer1.addr);
        assertEq(isNewOwnerSet, true);
        assertEq(isOldOwnerRemoved, false);
    }

    function getRecoveryDigest(
        address _account,
        address _newOwner,
        uint64 _recoveryEndTime
    )
        internal
        returns (bytes32 digest)
    {
        // // Get the EIP712 Hash
        bytes32 recoveryHash = getRecoveryHash(_account, _newOwner, _recoveryEndTime);
        digest = getRecoveryHashWithDomainSeperator(recoveryHash, address(defaultExecutor));
    }

    function getRecoveryHash(
        address _account,
        address _newOwner,
        uint64 _recoveryEndTime
    )
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                keccak256("Recovery(address account,address newOwner,uint64 recoveryNonce)"),
                _account,
                _newOwner,
                _recoveryEndTime
            )
        );
    }

    function recoveryDomainSeparator(address verifyingContract) internal view returns (bytes32 domainSeperator) {
        domainSeperator = getDomainHash(
            EIP712Domain({
                name: "Tokenshield Recovery",
                version: "1",
                chainId: block.chainid,
                verifyingContract: verifyingContract
            })
        );
    }

    function getRecoveryHashWithDomainSeperator(
        bytes32 transactionHash,
        address verifyingContract
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", recoveryDomainSeparator(verifyingContract), transactionHash));
        return digest;
    }
}
