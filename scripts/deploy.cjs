const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contract with account:", deployer.address);

  const ShadowRepoProof = await ethers.getContractFactory("ShadowRepoProof");
  const contract = await ShadowRepoProof.deploy();
  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();
  console.log("ShadowRepoProof contract deployed to:", contractAddress);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
