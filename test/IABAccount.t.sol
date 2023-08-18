// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// import { PRBTest } from "prb-test/PRBTest.sol";
import { console2 } from "forge-std/console2.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { InsureaBag } from "src/InsureaBag.sol";
import { ERC6551Registry } from "src/registry/ERC6551Registry.sol";
import { Proxy } from "src/proxies/Proxy.sol";
import { AccountProxy } from "src/proxies/AccountProxy.sol";
import { MockNFT } from "src/mock/MockNFT.sol";
import { IABGuardian } from "src/IABGuardian.sol";
import { EntryPoint } from "src/EntryPoint.sol";
import { InsureaBag as InsureaBagNft } from "src/InsureaBag.sol";
import { IABAccount } from "src/IABAccount.sol";
import { Test } from "forge-std/Test.sol";
import { Deploy } from "../script/Deploy.s.sol";
import { DeployCreateAccount } from "../script/DeployCreateAccount.s.sol";
import { Vm } from "forge-std/Vm.sol";
import { ECDSA } from "openzeppelin-contracts/utils/cryptography/ECDSA.sol";
import { IERC1271 } from "openzeppelin-contracts/interfaces/IERC1271.sol";
import { console } from "forge-std/console.sol";

contract IABAccountTest is Test {
    using ECDSA for bytes32;

    Deploy private deploy;
    DeployCreateAccount private deployCreate;
    ERC6551Registry private registry;
    EntryPoint private entrypoint;
    IABGuardian private guardian;
    InsureaBagNft private nftPolicy;
    IABAccount private accountImpl;
    IABAccount private account;
    MockNFT private nft;

    address guardianOwner = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address guardianSigner = vm.addr(2);
    address guardianSetter = vm.addr(3);
    address accountOwner = vm.addr(4);
    address receiverAddress = vm.addr(5);
    address accountOwner2 = vm.addr(6);

    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    struct Tx {
        address to;
        uint256 value;
        uint256 nonce;
        bytes data;
    }

    string constant domainName = "Tokenshield";
    string constant domainVersion = "1";
    bytes32 DOMAIN_SEPARATOR;

    function setUp() public {
        // deploy = new Deploy();
        // (registry, entrypoint, guardian, nftPolicy, account) = deploy.deploy();
        deployCreate = new DeployCreateAccount();
        (registry, entrypoint, guardian, nftPolicy, accountImpl) = deployCreate.deploy();
        // startHoax(guardianOwner, 10 ether);
        startHoax(guardianOwner);
        nftPolicy.toggleMint();
        nftPolicy.setImplementationAddress(address(accountImpl));
        nftPolicy.setRegistryAddress(address(registry));
        vm.recordLogs();
        hoax(accountOwner);
        nftPolicy.createInsurance();
        Vm.Log[] memory entries = vm.getRecordedLogs();
        address tbAccount = abi.decode(entries[1].data, (address));
        // stopHoax()
        account = IABAccount(payable(tbAccount));
        account.setDomainSeperator(domainName, domainVersion);
        DOMAIN_SEPARATOR = getDomainHash(
            EIP712Domain({
                name: domainName,
                version: domainVersion,
                chainId: block.chainid,
                verifyingContract: address(account)
            })
        );
    }

    function testVerifyDeploy() public {
        address actualOwner = guardian.getOwnerAddress();
        assertEq(actualOwner, guardianOwner);
    }

    function testOwnerIsSetInAccount() public {
        address actualOwner = account.owner();
        assertEq(actualOwner, accountOwner);
    }

    function testIsValidSignature() public {
        Tx memory transaction = Tx({ to: accountOwner, value: 1 ether, nonce: 0, data: "" });
        bytes32 hash = getTransactionHash(transaction);
        bytes32 digest = getTransactionHashWithDomainSeperator(hash);
        // bytes32 digestMessageHash = digest.toEthSignedMessageHash();
        // console2.logBytes32(digest);
        // since 4 is the private key for the accountOwner address, we have 4 passed below
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(4, digest);
        // since 2 is the private key for the accountOwner address, we have 2 passed below
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, digest);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);
        bytes memory signature = bytes.concat(signature1, signature2);
        bytes4 actualSig = account.isValidSignature(digest, signature);
        bytes4 expectedSig = IERC1271.isValidSignature.selector;
        assertEq(actualSig, expectedSig);
    }

    function testSendETH() public {
        uint256 nonce = account.nonce();
        // console.log(nonce);
        Tx memory transaction = Tx({ to: address(10), value: 1 ether, nonce: nonce, data: "" });
        bytes32 hash = getTransactionHash(transaction);
        bytes32 digest = getTransactionHashWithDomainSeperator(hash);
        // bytes32 digestMessageHash = digest.toEthSignedMessageHash();
        // since 4 is the private key for the accountOwner address, we have 4 passed below
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(4, digest);
        // since 2 is the private key for the accountOwner address, we have 2 passed below
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, digest);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);
        bytes memory signature = bytes.concat(signature1, signature2);
        // console.log("Digest Outside- ");
        // console.logBytes32(digest);
        // console.log("Signature-");
        // console.logBytes(signature);
        // console.log(transaction.nonce);
        // console.log(transaction.value);
        // console.log(transaction.to);
        // console.logBytes(transaction.data);
        bytes memory data = abi.encode(transaction, signature);
        uint256 preBalance = address(10).balance;
        // account.isValidSignature(digest, signature);
        hoax(accountOwner, 10 ether);
        vm.deal(address(account), 10 ether);
        account.executeCall(address(10), 1 ether, data);
        uint256 postBalance = address(10).balance;
        assertEq(postBalance, preBalance + 1 ether);
    }

    modifier nftDeploy() {
        nft = new MockNFT();
        nft.safeMint(address(account), 1);

        _;
    }

    function testSendERC721() public nftDeploy {
        uint256 nonce = account.nonce();
        bytes memory message =
            abi.encodeWithSignature("safeTransferFrom(address,address,uint256)", address(account), receiverAddress, 1);
        // bytes memory message = "";
        Tx memory transaction = Tx({ to: address(nft), value: 0, nonce: nonce, data: message });
        bytes32 hash = getTransactionHash(transaction);
        bytes32 digest = getTransactionHashWithDomainSeperator(hash);
        // bytes32 digestMessageHash = digest.toEthSignedMessageHash();
        // console2.logBytes32(digest);
        // since 4 is the private key for the accountOwner address, we have 4 passed below
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(4, digest);
        // since 2 is the private key for the accountOwner address, we have 2 passed below
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, digest);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);
        bytes memory signature = bytes.concat(signature1, signature2);

        bytes memory data = abi.encode(transaction, signature);
        // uint256 preBalance = address(10).balance;
        address priorOwner = nft.ownerOf(1);
        hoax(accountOwner, 10 ether);
        vm.deal(address(account), 10 ether);
        account.executeCall(address(nft), 0, data);
        address actualNftOwner = nft.ownerOf(1);
        assertEq(actualNftOwner, receiverAddress);
        assertEq(priorOwner, address(account));
    }

    function testOwnerTransfer() public {
        hoax(accountOwner, 10 ether);
        nftPolicy.safeTransferFrom(accountOwner, accountOwner2, 0);
        uint256 nonce = account.nonce();
        Tx memory transaction = Tx({ to: address(10), value: 1 ether, nonce: nonce, data: "" });
        bytes32 hash = getTransactionHash(transaction);
        bytes32 digest = getTransactionHashWithDomainSeperator(hash);
        // bytes32 digestMessageHash = digest.toEthSignedMessageHash();
        // console2.logBytes32(digest);
        // since 6 is the private key for the accountOwner2 address, we have 6 passed below
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(6, digest);
        // since 2 is the private key for the accountOwner address, we have 2 passed below
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, digest);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);
        bytes memory signature = bytes.concat(signature2, signature1);

        bytes memory data = abi.encode(transaction, signature);
        uint256 preBalance = address(10).balance;
        hoax(accountOwner2, 10 ether);
        vm.deal(address(account), 10 ether);
        account.executeCall(address(10), 1 ether, data);
        uint256 postBalance = address(10).balance;
        assertEq(postBalance, preBalance + 1 ether);
    }

    function testRevertWithWrongNonce() public {
        uint256 nonce = account.nonce() + 1;
        Tx memory transaction = Tx({ to: address(10), value: 1 ether, nonce: nonce, data: "" });
        bytes32 hash = getTransactionHash(transaction);
        bytes32 digest = getTransactionHashWithDomainSeperator(hash);
        // bytes32 digestMessageHash = digest.toEthSignedMessageHash();
        // console2.logBytes32(digest);
        // since 4 is the private key for the accountOwner address, we have 4 passed below
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(4, digest);
        // since 2 is the private key for the accountOwner address, we have 2 passed below
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, digest);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);
        bytes memory signature = bytes.concat(signature1, signature2);

        bytes memory data = abi.encode(transaction, signature);

        hoax(accountOwner, 10 ether);
        vm.expectRevert("Nonce not same!");
        account.executeCall(address(10), 1 ether, data);
    }

    function testRevertWithWrongSignature() public {
        uint256 nonce = account.nonce();
        Tx memory transaction = Tx({ to: address(10), value: 1 ether, nonce: nonce, data: "" });
        bytes32 hash = getTransactionHash(transaction);
        bytes32 digest = getTransactionHashWithDomainSeperator(hash);
        // bytes32 digestMessageHash = digest.toEthSignedMessageHash();
        // console2.logBytes32(digest);
        // since 6 is the private key for the accountOwner2 address, we have 6 passed below,
        //  this is the wrong private key for the account so it should revert
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(6, digest);
        // since 2 is the private key for the accountOwner address, we have 2 passed below
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, digest);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);
        bytes memory signature = bytes.concat(signature1, signature2);

        bytes memory data = abi.encode(transaction, signature);
        hoax(accountOwner, 10 ether);
        vm.expectRevert("verify not owner");
        account.executeCall(address(10), 1 ether, data);
    }

    function testRevertWithSameSigner() public {
        uint256 nonce = account.nonce();
        Tx memory transaction = Tx({ to: address(10), value: 1 ether, nonce: nonce, data: "" });
        bytes32 hash = getTransactionHash(transaction);
        bytes32 digest = getTransactionHashWithDomainSeperator(hash);
        // bytes32 digestMessageHash = digest.toEthSignedMessageHash();
        // console2.logBytes32(digest);
        // since 4 is the private key for the accountOwner address, we have 4 passed below,
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(4, digest);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);
        bytes memory signature = bytes.concat(signature1, signature1);

        bytes memory data = abi.encode(transaction, signature);
        hoax(accountOwner, 10 ether);
        vm.expectRevert("verify failed");
        account.executeCall(address(10), 1 ether, data);
    }

    function testRevertIfToAddressDoesntMatch() public nftDeploy {
        uint256 nonce = account.nonce();
        bytes memory message =
            abi.encodeWithSignature("safeTransferFrom(address,address,uint256)", address(account), receiverAddress, 1);
        // bytes memory message = "";
        Tx memory transaction = Tx({ to: address(nft), value: 0, nonce: nonce, data: message });
        bytes32 hash = getTransactionHash(transaction);
        bytes32 digest = getTransactionHashWithDomainSeperator(hash);
        // bytes32 digestMessageHash = digest.toEthSignedMessageHash();
        // console2.logBytes32(digest);
        // since 4 is the private key for the accountOwner address, we have 4 passed below
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(4, digest);
        // since 2 is the private key for the accountOwner address, we have 2 passed below
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, digest);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);
        bytes memory signature = bytes.concat(signature1, signature2);

        bytes memory data = abi.encode(transaction, signature);
        hoax(accountOwner, 10 ether);
        vm.deal(address(account), 10 ether);
        vm.expectRevert("Receiving Address is wrong");
        account.executeCall(address(10), 0, data); //Here the 'to' address should be address of NFT
    }

    function testRevertIfValueDoesntMatch() public nftDeploy {
        uint256 nonce = account.nonce();
        bytes memory message =
            abi.encodeWithSignature("safeTransferFrom(address,address,uint256)", address(account), receiverAddress, 1);
        // bytes memory message = "";
        Tx memory transaction = Tx({ to: address(nft), value: 0, nonce: nonce, data: message });
        bytes32 hash = getTransactionHash(transaction);
        bytes32 digest = getTransactionHashWithDomainSeperator(hash);
        // bytes32 digestMessageHash = digest.toEthSignedMessageHash();
        // console2.logBytes32(digest);
        // since 4 is the private key for the accountOwner address, we have 4 passed below
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(4, digest);
        // since 2 is the private key for the accountOwner address, we have 2 passed below
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, digest);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);
        bytes memory signature = bytes.concat(signature1, signature2);

        bytes memory data = abi.encode(transaction, signature);
        hoax(accountOwner, 10 ether);
        vm.deal(address(account), 10 ether);
        vm.expectRevert("Sending Value is wrong");
        account.executeCall(address(nft), 10, data); //Here the 'value' should be 0 as we arent sending any ETH
    }

    // function testvalidateUserOp() public {

    // }

    function getDomainHash(EIP712Domain memory domain) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(domain.name)),
                keccak256(bytes(domain.version)),
                domain.chainId,
                domain.verifyingContract
            )
        );
    }

    function getTransactionHash(Tx memory _transaction) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("Tx(address to,uint256 value, uint256 nonce, bytes data)"),
                _transaction.to,
                _transaction.value,
                _transaction.nonce,
                _transaction.data
            )
        );
    }

    function getTransactionHashWithDomainSeperator(bytes32 transactionHash) internal view returns (bytes32) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, transactionHash));
        return digest;
    }
}
