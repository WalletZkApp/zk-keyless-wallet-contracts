import { AccountUpdate, Mina, PrivateKey } from 'o1js';
import fs from 'fs/promises';
import { RecoveryZkApp } from './RecoveryZkApp';

// check command line arg
let deployAlias = process.argv[2];
if (!deployAlias)
  throw Error(`Missing <deployAlias> argument.

Usage:
node build/src/deploy.js <deployAlias>
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
let feepayerKeysBase58: { privateKey: string; publicKey: string } = JSON.parse(
  await fs.readFile(config.feepayerKeyPath, 'utf8')
);

let walletZkAppKeysBase58: { privateKey: string; publicKey: string } =
  JSON.parse(await fs.readFile(config.keyPath, 'utf8'));

let feepayerKey = PrivateKey.fromBase58(feepayerKeysBase58.privateKey);
let zkAppKey = PrivateKey.random();
let walletZkAppKey = PrivateKey.fromBase58(walletZkAppKeysBase58.privateKey);

// set up Mina instance and contract we interact with
const Network = Mina.Network(config.url);
const fee = Number(config.fee) * 1e9; // in nanomina (1 billion = 1.0 mina)
Mina.setActiveInstance(Network);
let feepayerAddress = feepayerKey.toPublicKey();
let zkAppAddress = zkAppKey.toPublicKey();
let zkApp = new RecoveryZkApp(zkAppAddress);
console.log('zkAppAddress: ', zkAppAddress.toBase58());

let sentTx;
// compile the contract to create prover keys
console.log('compile the contract...');
await RecoveryZkApp.compile();
try {
  console.log('build transaction and create proof...');
  let tx = await Mina.transaction({ sender: feepayerAddress, fee }, () => {
    AccountUpdate.createSigned(feepayerAddress);
    zkApp.deploy({ zkappKey: zkAppKey });
    zkApp.owner.set(walletZkAppKey.toPublicKey());
  });
  await tx.prove();
  console.log('send transaction...');
  sentTx = await tx.sign([feepayerKey]).send();

  const owner = await zkApp.owner.getAndAssertEquals();
  console.log('owner: ', owner.toBase58());
} catch (err) {
  console.log(err);
}
if (sentTx?.hash() !== undefined) {
  console.log(`
Success! Update transaction sent.

Your smart contract state will be updated
as soon as the transaction is included in a block:
https://berkeley.minaexplorer.com/transaction/${sentTx.hash()}
`);
}
