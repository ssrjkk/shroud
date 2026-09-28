// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IBLS
/// @notice BLS signature verification. Pairing-friendly curve (BN254/BLS12-381) precompile
///         or a verifier contract. Kept as an interface so the curve choice is deploy-time.
interface IBLS {
    /// @param message 32-byte digest of the request
    /// @param signature 96-byte aggregated BLS signature (G1 point)
    /// @param pubkeyAgg 96-byte aggregated public key (G2 point)
    function verifyAggregate(bytes32 message, bytes calldata signature, bytes calldata pubkeyAgg) external view returns (bool);
}

/// @title IDecryptionGate
interface IDecryptionGate {
    function requestReveal(uint256 taskId, bytes32 weightsCid, bytes calldata blsAggregateSig) external;
    function submitPartialDecryption(uint256 taskId, bytes32 partialDecryption) external;
    function canDecrypt(uint256 taskId) external view returns (bool);
}
