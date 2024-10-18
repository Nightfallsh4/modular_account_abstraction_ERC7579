// SPDX-License-Identifier: GPL-v3
pragma solidity 0.8.26;

import { Test } from "forge-std/Test.sol";

contract Accounts is Test {

    // Guardian which signer the transaction
    Account guardian1 = makeAccount("GUARDIAN_1");


    Account guardianSigner = makeAccount("GUARDIAN_SIGNER");

    // Nominee
    Account guardianDefaultNominee = makeAccount("GUARDIAN_NOMINEE");

    // Default overall Admin for everything
    Account defaultAdmin = makeAccount("DEFAULT_ADMIN");

    // Admin of the MFA setter Role
    Account mfaSetterAdmin = makeAccount("MFA_SETTER_ADMIN");

    // MFASetter sets the account eligible to approve the transactions
    Account mfaSetter = makeAccount("MFA_SETTER");

    // Can Set Modules
    Account moduleSetter = makeAccount("MODULE_SETTER");

    // User owner account
    Account signer1 = makeAccount("SIGNER_1");

}
