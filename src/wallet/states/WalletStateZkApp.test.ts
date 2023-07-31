import {
  AccountUpdate,
  Bool,
  Field,
  MerkleTree,
  Mina,
  PrivateKey,
  PublicKey,
  UInt64,
  UInt32,
} from 'snarkyjs';
import { TokenGenerator } from 'totp-generator-ts';
import {
  DEFAULT_TRANSACTION_LIMIT,
  DEFAULT_DAILY_LIMIT,
  DEFAULT_PERIOD,
  TEST_TOTP_SECRET,
} from '../../constant';
import { WalletZkApp } from '../WalletZkApp.js';
import { WalletStateZkApp, PackedLimits } from './WalletStateZkApp.js';
import { Password } from '../../passwords/index.js';
import { MerkleWitnessClass } from '../../general.js';
import { DEFAULT_NULLIFIER_MESSAGE } from '../../constant.js';
import { Otp } from '../../otps/index.js';

let proofsEnabled = false;

describe('WalletState', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    walletStatesZkApp: WalletStateZkApp,
    walletStatesZkAppAddress: PublicKey,
    walletStatesZkAppPrivateKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: WalletZkApp;

  let passwordTree = new MerkleTree(32);
  let otpTree = new MerkleTree(32);
  const SALT = Math.floor(Math.random() * 999999);

  let defaultCurrentPeriodEnd = UInt64.from(Date.now() - DEFAULT_PERIOD);

  let time;
  const startTime = Math.floor(Date.now() / 30000 - 1) * 30000;

  beforeAll(async () => {
    if (proofsEnabled) {
      await WalletStateZkApp.compile();
      await WalletZkApp.compile();
    }
  });

  beforeEach(() => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);

    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new WalletZkApp(zkAppAddress);
    walletStatesZkAppPrivateKey = PrivateKey.random();
    walletStatesZkAppAddress = walletStatesZkAppPrivateKey.toPublicKey();
    walletStatesZkApp = new WalletStateZkApp(walletStatesZkAppAddress);

    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
  });

  async function localDeploy() {
    for (let i = 0; i < 5; i++) {
      const password = Password.from(
        Field(i + 1),
        DEFAULT_NULLIFIER_MESSAGE,
        UInt64.from(i + 1),
        Field(SALT)
      );
      passwordTree.setLeaf(BigInt(i), password.hash());
    }
    for (let i = 0; i < 32; i++) {
      time = startTime + i * 30000;
      const tokenGen = new TokenGenerator({
        algorithm: 'SHA-512',
        period: 60,
        digits: 8,
        timestamp: time,
      });
      const token = tokenGen.getToken(TEST_TOTP_SECRET);
      const otp = Otp.from(UInt64.from(time), Field(token));
      otpTree.setLeaf(BigInt(i), otp.hash());
    }
    const txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount, 2);

      walletStatesZkApp.deploy({ zkappKey: walletStatesZkAppPrivateKey });
      walletStatesZkApp.owner.set(zkAppAddress);
      walletStatesZkApp.currentPeriodEnd.set(defaultCurrentPeriodEnd);

      zkApp.deploy({ zkappKey: zkAppPrivateKey });
      zkApp.committedPasswords.set(passwordTree.getRoot());
      zkApp.committedOtps.set(otpTree.getRoot());
    });
    await txn.prove();
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }
  it('generates and deploys the `WalletStatesZkApp` smart contract', async () => {
    await localDeploy();

    const owner = walletStatesZkApp.owner.getAndAssertEquals();
    expect(owner).toEqual(zkAppAddress);

    const paused = walletStatesZkApp.paused.getAndAssertEquals();
    expect(paused).toEqual(Bool(false));

    const currentPeriodEnd =
      await walletStatesZkApp.currentPeriodEnd.getAndAssertEquals();
    expect(currentPeriodEnd).toEqual(defaultCurrentPeriodEnd);

    const packedLimits: PackedLimits =
      walletStatesZkApp.packedLimits.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));

    const period: UInt32 = unpacked[0];
    expect(period).toEqual(UInt32.from(DEFAULT_PERIOD));

    const transactionLimit: UInt32 = unpacked[1];
    expect(transactionLimit).toEqual(UInt32.from(DEFAULT_TRANSACTION_LIMIT));

    const dailyLimit: UInt32 = unpacked[2];
    expect(dailyLimit).toEqual(UInt32.from(DEFAULT_DAILY_LIMIT));

    const currentPeriodAmount: UInt32 = unpacked[3];
    expect(currentPeriodAmount).toEqual(UInt32.from(0));
  });
  it('generates and deploys the `WalletZkApp` smart contract', async () => {
    await localDeploy();

    const committedGuardians = zkApp.committedGuardians.getAndAssertEquals();
    expect(committedGuardians).toEqual(Field(0));

    const committedNominees = zkApp.committedNominees.getAndAssertEquals();
    expect(committedNominees).toEqual(Field(0));

    const committedPasswords = zkApp.committedPasswords.getAndAssertEquals();
    expect(committedPasswords).toEqual(passwordTree.getRoot());

    const committedOtps = zkApp.committedOtps.getAndAssertEquals();
    expect(committedOtps).toEqual(otpTree.getRoot());
  });
  describe('#setTransactionLimit', () => {
    it('wallet smart contract should be able to set transaction limit', async () => {
      await localDeploy();

      time = startTime + 0 * 30000;
      const tokenGen = new TokenGenerator({
        algorithm: 'SHA-512',
        period: 60,
        digits: 8,
        timestamp: time,
      });
      const token = tokenGen.getToken(TEST_TOTP_SECRET);
      const otp = Otp.from(UInt64.from(time), Field(token));

      let w = otpTree.getWitness(0n);
      let witness = new MerkleWitnessClass(w);

      const txn = await Mina.transaction(zkAppAddress, () => {
        zkApp.setTransactionLimit(
          walletStatesZkAppAddress,
          otp,
          witness,
          UInt32.from(100)
        );
      });
      await txn.prove();
      await txn.sign([zkAppPrivateKey]).send();

      const transactionLimit = await walletStatesZkApp.getTransactionLimit();
      expect(transactionLimit).toEqual(UInt64.from(100));
    });
  });
  describe('#setDailyLimit', () => {
    it('wallet smart contract should be able to set daily limit', async () => {
      await localDeploy();

      time = startTime + 0 * 30000;
      const tokenGen = new TokenGenerator({
        algorithm: 'SHA-512',
        period: 60,
        digits: 8,
        timestamp: time,
      });
      const token = tokenGen.getToken(TEST_TOTP_SECRET);
      const otp = Otp.from(UInt64.from(time), Field(token));

      let w = otpTree.getWitness(0n);
      let witness = new MerkleWitnessClass(w);

      const txn = await Mina.transaction(zkAppAddress, () => {
        zkApp.setDailyLimit(
          walletStatesZkAppAddress,
          otp,
          witness,
          UInt32.from(100)
        );
      });
      await txn.prove();
      await txn.sign([zkAppPrivateKey]).send();

      const dailyLimit = await walletStatesZkApp.getDailyLimit();
      expect(dailyLimit).toEqual(UInt64.from(100));
    });
  });
  describe('#pause', () => {
    it('wallet smart contract should be able to pause', async () => {
      await localDeploy();

      time = startTime + 0 * 30000;
      const tokenGen = new TokenGenerator({
        algorithm: 'SHA-512',
        period: 60,
        digits: 8,
        timestamp: time,
      });
      const token = tokenGen.getToken(TEST_TOTP_SECRET);
      const otp = Otp.from(UInt64.from(time), Field(token));

      let w = otpTree.getWitness(0n);
      let witness = new MerkleWitnessClass(w);

      const txn = await Mina.transaction(zkAppAddress, () => {
        zkApp.pause(walletStatesZkAppAddress, otp, witness);
      });
      await txn.prove();
      await txn.sign([zkAppPrivateKey]).send();

      const paused = await walletStatesZkApp.paused.getAndAssertEquals();
      expect(paused).toEqual(Bool(true));
    });
  });
  describe('#unpause', () => {
    it('wallet smart contract should be able to unpause', async () => {
      await localDeploy();

      time = startTime + 0 * 30000;
      const tokenGen = new TokenGenerator({
        algorithm: 'SHA-512',
        period: 60,
        digits: 8,
        timestamp: time,
      });
      const token = tokenGen.getToken(TEST_TOTP_SECRET);
      const otp = Otp.from(UInt64.from(time), Field(token));

      let w = otpTree.getWitness(0n);
      let witness = new MerkleWitnessClass(w);

      const txn = await Mina.transaction(zkAppAddress, () => {
        zkApp.pause(walletStatesZkAppAddress, otp, witness);
      });
      await txn.prove();
      await txn.sign([zkAppPrivateKey]).send();

      let paused = await walletStatesZkApp.paused.getAndAssertEquals();
      expect(paused).toEqual(Bool(true));

      const txn2 = await Mina.transaction(zkAppAddress, () => {
        zkApp.unpause(walletStatesZkAppAddress, otp, witness);
      });
      await txn2.prove();
      await txn2.sign([zkAppPrivateKey]).send();

      paused = await walletStatesZkApp.paused.getAndAssertEquals();
      expect(paused).toEqual(Bool(false));
    });
  });
});
