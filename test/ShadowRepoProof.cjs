const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ShadowRepoProof", function () {
  let contract;
  let owner, addr1;

  beforeEach(async function () {
    [owner, addr1] = await ethers.getSigners();
    const ShadowRepoProof = await ethers.getContractFactory("ShadowRepoProof");
    contract = await ShadowRepoProof.deploy();
  });

  it("Should submit and verify a scan proof successfully", async function () {
    const repoHash = ethers.keccak256(ethers.toUtf8Bytes("repo-contents-1"));
    const reportHash = ethers.keccak256(ethers.toUtf8Bytes("report-json-1"));
    const riskScore = 45;

    await expect(contract.connect(addr1).submitProof(repoHash, reportHash, riskScore))
      .to.emit(contract, "ProofSubmitted")
      .withArgs(reportHash, repoHash, riskScore, addr1.address, any => any > 0);

    const proof = await contract.verifyProof(reportHash);
    expect(proof.exists).to.be.true;
    expect(proof.repoHash).to.equal(repoHash);
    expect(proof.reportHash).to.equal(reportHash);
    expect(proof.riskScore).to.equal(riskScore);
    expect(proof.scanner).to.equal(addr1.address);
    expect(proof.timestamp).to.be.above(0);
  });

  it("Should fail when submitting the same proof twice", async function () {
    const repoHash = ethers.keccak256(ethers.toUtf8Bytes("repo-contents-1"));
    const reportHash = ethers.keccak256(ethers.toUtf8Bytes("report-json-1"));
    const riskScore = 45;

    await contract.submitProof(repoHash, reportHash, riskScore);

    await expect(
      contract.submitProof(repoHash, reportHash, riskScore)
    ).to.be.revertedWith("Proof already exists for this report");
  });

  it("Should fail when risk score exceeds 100", async function () {
    const repoHash = ethers.keccak256(ethers.toUtf8Bytes("repo-contents-1"));
    const reportHash = ethers.keccak256(ethers.toUtf8Bytes("report-json-1"));
    const invalidScore = 101;

    await expect(
      contract.submitProof(repoHash, reportHash, invalidScore)
    ).to.be.revertedWith("Risk score must be between 0 and 100");
  });

  it("Should fail for an invalid report hash", async function () {
    const repoHash = ethers.keccak256(ethers.toUtf8Bytes("repo-contents-1"));
    const invalidReportHash = "0x" + "0".repeat(64);
    const riskScore = 45;

    await expect(
      contract.submitProof(repoHash, invalidReportHash, riskScore)
    ).to.be.revertedWith("Invalid report hash");
  });
});
