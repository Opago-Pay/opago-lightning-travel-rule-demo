#!/usr/bin/env node

import { SparkWallet } from "@buildonspark/spark-sdk";
import { BitcoinFaucet } from "@buildonspark/spark-sdk/test-utils";

function normalize(value) {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (value instanceof Map) {
    return Object.fromEntries(
      Array.from(value.entries(), ([key, mapValue]) => [String(key), normalize(mapValue)]),
    );
  }
  if (Array.isArray(value)) {
    return value.map((entry) => normalize(entry));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, objectValue]) => [key, normalize(objectValue)]),
    );
  }
  return value;
}

function networkName(rawNetwork) {
  const normalized = String(rawNetwork ?? "REGTEST").trim().toUpperCase();
  if (!["MAINNET", "REGTEST", "SIGNET", "LOCAL"].includes(normalized)) {
    throw new Error(`Unsupported Spark network: ${rawNetwork}`);
  }
  return normalized;
}

async function withWallet(payload, handler) {
  const initParams = {
    options: {
      network: networkName(payload.network),
    },
  };

  if (payload.mnemonicOrSeed) {
    initParams.mnemonicOrSeed = payload.mnemonicOrSeed;
  }

  const initResult = await SparkWallet.initialize(initParams);

  try {
    return await handler(initResult.wallet, initResult.mnemonic ?? null);
  } finally {
    await initResult.wallet.cleanupConnections();
  }
}

const operations = {
  initialize: async (payload) =>
    withWallet(payload, async (wallet, mnemonic) => ({
      mnemonic,
      identityPublicKey: await wallet.getIdentityPublicKey(),
      sparkAddress: await wallet.getSparkAddress(),
    })),

  "get-balance": async (payload) =>
    withWallet(payload, async (wallet) => {
      const balance = await wallet.getBalance();
      return {
        balanceSats: balance.balance.toString(),
        tokenBalances: normalize(balance.tokenBalances),
      };
    }),

  "create-lightning-invoice": async (payload) =>
    withWallet(payload, async (wallet) =>
      normalize(await wallet.createLightningInvoice(payload.params ?? {})),
    ),

  "pay-lightning-invoice": async (payload) =>
    withWallet(payload, async (wallet) =>
      normalize(await wallet.payLightningInvoice(payload.params ?? {})),
    ),

  "get-transfers": async (payload) =>
    withWallet(payload, async (wallet) =>
      normalize(
        await wallet.getTransfers(
          payload.limit ?? 20,
          payload.offset ?? 0,
          payload.createdAfter ? new Date(payload.createdAfter) : undefined,
          payload.createdBefore ? new Date(payload.createdBefore) : undefined,
        ),
      ),
    ),

  "get-identity-public-key": async (payload) =>
    withWallet(payload, async (wallet) => ({
      identityPublicKey: await wallet.getIdentityPublicKey(),
    })),

  "get-static-deposit-address": async (payload) =>
    withWallet(payload, async (wallet) => ({
      depositAddress: await wallet.getStaticDepositAddress(),
    })),

  "get-utxos-for-deposit-address": async (payload) =>
    withWallet(payload, async (wallet) => ({
      utxos: normalize(
        await wallet.getUtxosForDepositAddress(
          payload.depositAddress,
          payload.limit ?? 100,
          payload.offset ?? 0,
          payload.excludeClaimed ?? false,
        ),
      ),
    })),

  "claim-static-deposit-with-max-fee": async (payload) =>
    withWallet(payload, async (wallet) =>
      normalize(
        await wallet.claimStaticDepositWithMaxFee({
          transactionId: payload.transactionId,
          maxFee: payload.maxFee,
          ...(payload.outputIndex !== undefined
            ? { outputIndex: payload.outputIndex }
            : {}),
        }),
      ),
    ),

  "sign-message": async (payload) =>
    withWallet(payload, async (wallet) => ({
      signature: await wallet.signMessageWithIdentityKey(payload.message),
    })),

  "validate-message": async (payload) =>
    withWallet(payload, async (wallet) => ({
      valid: await wallet.validateMessageWithIdentityKey(
        payload.message,
        payload.signature,
      ),
    })),

  "create-sats-invoice": async (payload) =>
    withWallet(payload, async (wallet) =>
      normalize(await wallet.createSatsInvoice(payload.params ?? {})),
    ),

  "fulfill-spark-invoice": async (payload) =>
    withWallet(payload, async (wallet) =>
      normalize(await wallet.fulfillSparkInvoice(payload.params ?? {})),
    ),

  "fund-regtest-wallet": async (payload) =>
    withWallet(payload, async (wallet) => {
      const amountSats = BigInt(payload.amountSats ?? 0);
      if (amountSats <= 0n) {
        throw new Error("fund-regtest-wallet requires a positive amountSats");
      }
      const observeDelayMs = Number(payload.observeDelayMs ?? 3000);
      const faucet = BitcoinFaucet.getInstance();
      const depositAddress = await wallet.getSingleUseDepositAddress();
      const signedTx = await faucet.sendToAddress(
        depositAddress,
        amountSats,
        Number(payload.mineBlocks ?? 6),
      );
      // Give the chain watcher time to observe the mined deposit before claiming it.
      await new Promise((resolve) => setTimeout(resolve, observeDelayMs));
      await wallet.claimDeposit(signedTx.id);
      return {
        depositAddress,
        txId: signedTx.id,
        amountSats: String(amountSats),
        minedBlocks: Number(payload.mineBlocks ?? 6),
        observeDelayMs,
      };
    }),
};

async function main() {
  const [, , operation, rawPayload = "{}"] = process.argv;
  if (!operation || !(operation in operations)) {
    throw new Error(`Unsupported spark wallet bridge operation: ${operation ?? "<missing>"}`);
  }

  const payload = JSON.parse(rawPayload);
  const result = await operations[operation](payload);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
