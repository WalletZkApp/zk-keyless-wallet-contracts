/**
 * This script can be used to interact with the Add contract, after deploying it.
 *
 * We call the update() method on the contract, create a proof and send it to the chain.
 * The endpoint that we interact with is read from your config.json.
 *
 * This simulates a user interacting with the zkApp from a browser, except that here, sending the transaction happens
 * from the script and we're using your pre-funded zkApp account to pay the transaction fee. In a real web app, the user's wallet
 * would send the transaction and pay the fee.
 *
 * To run locally:
 * Build the project: `$ npm run build`
 * Run with node:     `$ node build/src/interact.js <deployAlias>`.
 */
import { Mina, PrivateKey, PublicKey, UInt64, fetchAccount } from 'o1js';
import fs from 'fs/promises';
import { GuardianZkApp } from './GuardianZkApp.js';

// check command line arg
let deployAlias = process.argv[2];
if (!deployAlias)
  throw Error(`Missing <deployAlias> argument.

Usage:
node build/src/interact.js <deployAlias>
`);
Error.stackTraceLimit = 1000;

// parse config and private key from file
type Config = {
  deployAliases: Record<
    string,
    {
      url: string;
      keyPath: string;
      fee: string;
      feepayerKeyPath: string;
      feepayerAlias: string;
    }
  >;
};
let configJson: Config = JSON.parse(await fs.readFile('config.json', 'utf8'));
let config = configJson.deployAliases[deployAlias];
let senderKeysBase58: { privateKey: string; publicKey: string } = JSON.parse(
  await fs.readFile(config.feepayerKeyPath, 'utf8')
);

let zkAppKeysBase58: { privateKey: string; publicKey: string } = JSON.parse(
  await fs.readFile(config.keyPath, 'utf8')
);

let zkAppKey = PrivateKey.fromBase58(zkAppKeysBase58.privateKey);
let senderKey = PrivateKey.fromBase58(senderKeysBase58.privateKey);

// set up Mina instance and contract we interact with
const Network = Mina.Network(config.url);
//const fee = Number(config.fee) * 1e9; // in nanomina (1 billion = 1.0 mina)
Mina.setActiveInstance(Network);
let zkAppAddress = zkAppKey.toPublicKey();
let zkApp = new GuardianZkApp(zkAppAddress);
console.log('zkAppAddress: ', zkAppAddress.toBase58());

// compile the contract to create prover keys
console.log('compile the contract...');
await GuardianZkApp.compile();
fetchAccount({ publicKey: zkAppAddress }).then(async () => {
  let owner: PublicKey = await zkApp.owner.getAndAssertEquals();
  console.log(`owner: ${owner.toBase58()}`);
  owner.assertEquals(senderKey.toPublicKey());
  const balance: UInt64 = zkApp.account.balance.get();
  console.log(`balance: ${balance}`);
});

// console.log('send MINA to owner');
// const transactionFee = 100_000_000;
// const tx = await Mina.transaction(
//   { sender: zkAppAddress, fee: transactionFee },
//   () => {
//     let accountUpdate: AccountUpdate;
//     accountUpdate = AccountUpdate.createSigned(zkAppAddress);

//     accountUpdate.send({ to: senderKey.toPublicKey(), amount: 1e9 * 50 });
//   },
// );
// await tx.prove();
// // send the transaction to the graphql endpoint
// console.log('Sending the transaction...');
// await tx.sign([zkAppKey]).send();
