// SPDX-License-Identifier: GPL-v3
pragma solidity 0.8.26;

import { UnsignedUserOperation } from "src/utils/DataTypes.sol";
import "safe7579/src/DataTypes.sol";
import "safe7579/test/dependencies/EntryPoint.sol";
import { Test } from "forge-std/Test.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SignatureUtils } from "src/utils/SignatureUtils.sol";

abstract contract SignatureTestUtils is Test, SignatureUtils {
    function getSignature(
        PackedUserOperation memory _userOp,
        Account memory signer,
        Account memory guardian,
        address guardianValidator
    )
        internal
        returns (bytes memory signature)
    {
        bytes32 digest = getDigest(_userOp, guardianValidator);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(signer.key, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(guardian.key, digest);
        // console.log(guardian.key);
        signature = abi.encodePacked(r1, s1, v1, r2, s2, v2);

        // console.logBytes32(digest);
        // console.logBytes32(r2);
        // console.logBytes32(s2);
        // console.logUint(v2);

        (address _guardian,,) = ECDSA.tryRecover(digest, v2, r2, s2);
        assertEq(guardian.addr, _guardian);
    }
}
