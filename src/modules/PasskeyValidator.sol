// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IValidator } from "erc7579/interfaces/IERC7579Module.sol";
import { PackedUserOperation } from "module-bases/external/ERC4337.sol";
import { ITokenshieldKernal } from "src/interfaces/ITokenshieldKernal.sol";
import { SafeWebAuthnSignerProxy } from
    "@safe-global/safe-modules/modules/passkey/contracts/SafeWebAuthnSignerProxy.sol";
import { SafeWebAuthnSignerFactory } from
    "@safe-global/safe-modules/modules/passkey/contracts/SafeWebAuthnSignerFactory.sol";
import { P256 } from "@safe-global/safe-modules/modules/passkey/contracts/libraries/P256.sol";

contract PasskeyValidator is IValidator {
    type Validation is uint256;

    ITokenshieldKernal immutable kernal;
    SafeWebAuthnSignerFactory immutable signerFactory;

    Validation internal constant VALIDATION_SUCCESS = Validation.wrap(0);
    Validation internal constant VALIDATION_FAILED = Validation.wrap(1);

    mapping(address account => SafeWebAuthnSignerProxy passkeySigner) public accountToPasskeySigner;

    constructor(address _kernal, address _signerFactory) {
        kernal = ITokenshieldKernal(_kernal);
        signerFactory = SafeWebAuthnSignerFactory(_signerFactory);
    }

    /**
     * @dev called by ERC7579 account during install
     * @param data contains the data needed to install this validator
     */
    function onInstall(bytes calldata data) external override {
        // Check if installed already
        SafeWebAuthnSignerProxy passkeyVerifier = accountToPasskeySigner[msg.sender];
        (uint256 x, uint256 y, P256.Verifiers verifiers) = abi.decode(data, (uint256, uint256, P256.Verifiers));

        if (address(passkeyVerifier) == address(0)) {
            accountToPasskeySigner[msg.sender] =
                SafeWebAuthnSignerProxy(payable(signerFactory.createSigner(x, y, verifiers)));
        }
    }

    function onUninstall(bytes calldata data) external override { }

    function isModuleType(uint256 moduleTypeId) external view override returns (bool) { }

    function isInitialized(address smartAccount) external view override returns (bool) { }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        override
        returns (uint256)
    {
        return Validation.unwrap(VALIDATION_SUCCESS);
    }

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        override
        returns (bytes4)
    { }
}
