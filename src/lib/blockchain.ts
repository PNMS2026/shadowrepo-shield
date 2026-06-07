import { ethers } from "ethers";
import type { BlockchainProof } from "../types";

// ============================================================
// Blockchain interaction helpers using ethers.js v6
// ============================================================

const CONTRACT_ABI = [
  "function submitProof(bytes32 _repoHash, bytes32 _reportHash, uint8 _riskScore) external",
  "function verifyProof(bytes32 _reportHash) external view returns (bytes32 repoHash, bytes32 reportHash, uint8 riskScore, address scanner, uint256 timestamp, bool exists)",
  "event ProofSubmitted(bytes32 indexed reportHash, bytes32 repoHash, uint8 riskScore, address indexed scanner, uint256 timestamp)",
];

export function getProvider(rpcUrl: string): ethers.JsonRpcProvider {
  return new ethers.JsonRpcProvider(rpcUrl);
}

export async function connectWallet(): Promise<ethers.BrowserProvider | null> {
  if (typeof window !== "undefined" && (window as any).ethereum) {
    const provider = new ethers.BrowserProvider((window as any).ethereum);
    await provider.send("eth_requestAccounts", []);
    return provider;
  }
  return null;
}

export function getContract(
  contractAddress: string,
  signerOrProvider: ethers.Signer | ethers.Provider
): ethers.Contract {
  return new ethers.Contract(contractAddress, CONTRACT_ABI, signerOrProvider);
}

export async function submitProof(
  contractAddress: string,
  rpcUrl: string,
  repoHash: string,
  reportHash: string,
  riskScore: number
): Promise<{ txHash: string; blockNumber: number }> {
  // Try browser wallet first, fall back to JSON-RPC
  let signer: ethers.Signer;

  const browserProvider = await connectWallet();
  if (browserProvider) {
    signer = await browserProvider.getSigner();
  } else {
    // Fall back to first account on local node (for development)
    const provider = getProvider(rpcUrl);
    const accounts = await provider.listAccounts();
    if (accounts.length === 0) {
      throw new Error(
        "No wallet connected and no accounts available on the network"
      );
    }
    signer = accounts[0];
  }

  const contract = getContract(contractAddress, signer);

  // Ensure hashes are bytes32 format
  const repoHashBytes32 = repoHash.startsWith("0x")
    ? repoHash
    : "0x" + repoHash;
  const reportHashBytes32 = reportHash.startsWith("0x")
    ? reportHash
    : "0x" + reportHash;

  const tx = await contract.submitProof(
    repoHashBytes32,
    reportHashBytes32,
    riskScore
  );

  const receipt = await tx.wait();

  return {
    txHash: receipt.hash,
    blockNumber: receipt.blockNumber,
  };
}

export async function verifyProof(
  contractAddress: string,
  rpcUrl: string,
  reportHash: string
): Promise<BlockchainProof> {
  const provider = getProvider(rpcUrl);
  const contract = getContract(contractAddress, provider);

  const reportHashBytes32 = reportHash.startsWith("0x")
    ? reportHash
    : "0x" + reportHash;

  const result = await contract.verifyProof(reportHashBytes32);

  return {
    repo_hash: result.repoHash,
    report_hash: result.reportHash,
    risk_score: Number(result.riskScore),
    scanner: result.scanner,
    timestamp: Number(result.timestamp),
    exists: result.exists,
  };
}

export function shortenHash(hash: string, chars = 6): string {
  if (!hash) return "";
  if (hash.length <= chars * 2 + 2) return hash;
  return `${hash.slice(0, chars + 2)}...${hash.slice(-chars)}`;
}

export function getExplorerUrl(
  txHash: string,
  network: string
): string | null {
  switch (network) {
    case "sepolia":
      return `https://sepolia.etherscan.io/tx/${txHash}`;
    case "mainnet":
      return `https://etherscan.io/tx/${txHash}`;
    case "polygon":
      return `https://polygonscan.com/tx/${txHash}`;
    default:
      return null;
  }
}
