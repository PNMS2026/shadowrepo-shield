const { ethers } = require("hardhat");

async function main() {
  const contractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
  console.log("Connecting to ShadowRepoProof at:", contractAddress);

  const ShadowRepoProof = await ethers.getContractFactory("ShadowRepoProof");
  const contract = ShadowRepoProof.attach(contractAddress);

  // Use dummy hashes for verification
  const repoHash = ethers.keccak256(ethers.toUtf8Bytes("mock-repo-content-v1"));
  const reportHash = ethers.keccak256(ethers.toUtf8Bytes("mock-report-v1"));
  const riskScore = 97;

  console.log("Submitting proof...");
  console.log("Repo Hash:", repoHash);
  console.log("Report Hash:", reportHash);
  console.log("Risk Score:", riskScore);

  const tx = await contract.submitProof(repoHash, reportHash, riskScore);
  const receipt = await tx.wait();
  console.log("Proof submitted! Tx Hash:", tx.hash);
  console.log("Gas used:", receipt.gasUsed.toString());

  console.log("Verifying proof on-chain...");
  const proof = await contract.verifyProof(reportHash);
  
  console.log("On-chain Verified Details:");
  console.log("  Repo Hash:", proof.repoHash);
  console.log("  Report Hash:", proof.reportHash);
  console.log("  Risk Score:", proof.riskScore.toString());
  console.log("  Scanner Address:", proof.scanner);
  console.log("  Timestamp:", new Date(Number(proof.timestamp) * 1000).toISOString());
  console.log("  Exists:", proof.exists);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
