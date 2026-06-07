// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ShadowRepoProof
 * @dev Stores proof hashes of repository scans for verifiability and integrity.
 * Core Philosophy: "Your code stays on your device. Only proof goes on-chain."
 */
contract ShadowRepoProof {
    struct Proof {
        bytes32 repoHash;
        bytes32 reportHash;
        uint8 riskScore;
        address scanner;
        uint256 timestamp;
        bool exists;
    }

    // Maps reportHash to Proof
    mapping(bytes32 => Proof) private proofs;

    event ProofSubmitted(
        bytes32 indexed reportHash,
        bytes32 repoHash,
        uint8 riskScore,
        address indexed scanner,
        uint256 timestamp
    );

    /**
     * @dev Submits a new scan proof to the blockchain.
     * @param _repoHash The SHA-256 hash of the scanned repository structure.
     * @param _reportHash The SHA-256 hash of the final JSON report.
     * @param _riskScore The calculated risk score of the scan (0 to 100).
     */
    function submitProof(
        bytes32 _repoHash,
        bytes32 _reportHash,
        uint8 _riskScore
    ) external {
        require(_reportHash != bytes32(0), "Invalid report hash");
        require(!proofs[_reportHash].exists, "Proof already exists for this report");
        require(_riskScore <= 100, "Risk score must be between 0 and 100");

        proofs[_reportHash] = Proof({
            repoHash: _repoHash,
            reportHash: _reportHash,
            riskScore: _riskScore,
            scanner: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });

        emit ProofSubmitted(_reportHash, _repoHash, _riskScore, msg.sender, block.timestamp);
    }

    /**
     * @dev Verifies a scan proof and retrieves its details.
     * @param _reportHash The report hash to verify.
     * @return repoHash The associated repository hash.
     * @return reportHash The matching report hash.
     * @return riskScore The security risk score of the report.
     * @return scanner The address that submitted this proof.
     * @return timestamp The block timestamp when the proof was submitted.
     * @return exists True if the proof was found and verified.
     */
    function verifyProof(
        bytes32 _reportHash
    )
        external
        view
        returns (
            bytes32 repoHash,
            bytes32 reportHash,
            uint8 riskScore,
            address scanner,
            uint256 timestamp,
            bool exists
        )
    {
        Proof memory proof = proofs[_reportHash];
        return (
            proof.repoHash,
            proof.reportHash,
            proof.riskScore,
            proof.scanner,
            proof.timestamp,
            proof.exists
        );
    }
}
