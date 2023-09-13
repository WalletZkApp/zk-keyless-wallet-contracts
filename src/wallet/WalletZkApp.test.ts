import {
  AccountUpdate,
  Bool,
  Field,
  MerkleTree,
  Mina,
  PrivateKey,
  PublicKey,
  UInt32,
  UInt64,
} from 'o1js';
import { TokenGenerator } from 'totp-generator-ts';
import {
  DEFAULT_DAILY_LIMIT,
  DEFAULT_NULLIFIER,
  DEFAULT_TRANSACTION_LIMIT,
  RECOVERY_STATUS,
  DEFAULT_PERIOD,
  MAX_MERKLE_TREE_HEIGHT,
  TEST_TOTP_SECRET,
} from '../constant';
import { MerkleWitnessClass } from '../general';
import { Guardian, GuardianZkApp } from '../guardians/index.js';
import { Candidate, CandidateWitness } from '../candidates/index.js';
import { WalletZkApp } from './WalletZkApp.js';
import { Password } from '../passwords/index.js';
import { WalletStateZkApp } from './states/index.js';
import { RecoveryZkApp } from '../recovery/index.js';
import { PackedLimits } from './states/WalletStateZkApp.js';
import { Otp } from '../otps/index.js';
import { MerkleWitness8, MerkleWitness32 } from '../storage/offchain-storage';

let proofsEnabled = false;

describe('WalletZkApp', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    guardian1Account: PublicKey,
    guardian1Key: PrivateKey, //@typescript-eslint/no-unused-vars
    guardian2Account: PublicKey,
    guardian2Key: PrivateKey, //@typescript-eslint/no-unused-vars
    guardian3Account: PublicKey,
    guardian3Key: PrivateKey, //@typescript-eslint/no-unused-vars
    guardian4Account: PublicKey,
    guardian4Key: PrivateKey, //@typescript-eslint/no-unused-vars
    walletStatesZkApp: WalletStateZkApp,
    walletStatesZkAppAddress: PublicKey,
    walletStatesZkAppPrivateKey: PrivateKey,
    guardianZkAppAddress: PublicKey,
    guardianZkAppPrivateKey: PrivateKey,
    guardianZkApp: GuardianZkApp,
    recoveryZkAppAddress: PublicKey,
    recoveryZkAppPrivateKey: PrivateKey,
    recoveryZkApp: RecoveryZkApp,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: WalletZkApp;

  let guardianTree = new MerkleTree(8);
  let passwordTree = new MerkleTree(32);
  let otpTree = new MerkleTree(32);
  const SALT = Math.floor(Math.random() * 999999);

  let defaultCurrentPeriodEnd = UInt64.from(Date.now() - DEFAULT_PERIOD);

  let time;
  const startTime = Math.floor(Date.now() / 30000 - 1) * 30000;

  beforeAll(async () => {
    if (proofsEnabled) {
      await GuardianZkApp.compile();
      await RecoveryZkApp.compile();
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

    guardianZkAppPrivateKey = PrivateKey.random();
    guardianZkAppAddress = guardianZkAppPrivateKey.toPublicKey();
    guardianZkApp = new GuardianZkApp(guardianZkAppAddress);

    recoveryZkAppPrivateKey = PrivateKey.random();
    recoveryZkAppAddress = recoveryZkAppPrivateKey.toPublicKey();
    recoveryZkApp = new RecoveryZkApp(recoveryZkAppAddress);

    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);

    ({ privateKey: guardian1Key, publicKey: guardian1Account } =
      Local.testAccounts[1]);
    ({ privateKey: guardian2Key, publicKey: guardian2Account } =
      Local.testAccounts[2]);
    ({ privateKey: guardian3Key, publicKey: guardian3Account } =
      Local.testAccounts[3]);
    ({ privateKey: guardian4Key, publicKey: guardian4Account } =
      Local.testAccounts[4]);
    ({ privateKey: senderKey, publicKey: senderAccount } =
      Local.testAccounts[5]);
  });

  async function localDeploy() {
    for (let i = 0; i < 5; i++) {
      const password = Password.from(
        Field(i + 1),
        DEFAULT_NULLIFIER,
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
      AccountUpdate.fundNewAccount(deployerAccount, 4);

      guardianZkApp.deploy({ zkappKey: guardianZkAppPrivateKey });
      guardianZkApp.owner.set(deployerAccount);

      walletStatesZkApp.deploy({ zkappKey: walletStatesZkAppPrivateKey });
      walletStatesZkApp.owner.set(zkAppAddress);
      walletStatesZkApp.currentPeriodEnd.set(defaultCurrentPeriodEnd);

      recoveryZkApp.deploy({ zkappKey: recoveryZkAppPrivateKey });
      recoveryZkApp.owner.set(zkAppAddress);

      zkApp.deploy({ zkappKey: zkAppPrivateKey });
      zkApp.committedPasswords.set(passwordTree.getRoot());
      zkApp.committedOtps.set(otpTree.getRoot());
      zkApp.owner.set(recoveryZkAppAddress);
    });
    await txn.prove();
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  it('generates and deploys the `GuardianZkApp` smart contract', async () => {
    await localDeploy();

    const owner = guardianZkApp.owner.getAndAssertEquals();
    expect(owner).toEqual(deployerAccount);

    const committedGuardians =
      guardianZkApp.committedGuardians.getAndAssertEquals();
    expect(committedGuardians).toEqual(Field(0));

    const counters: UInt32[] = guardianZkApp.getCounters();
    expect(counters).toEqual([UInt32.from(0), UInt32.from(0)]);
  });
  it('generates and deploys the `RecoveryZkApp` smart contract', async () => {
    await localDeploy();

    const owner = recoveryZkApp.owner.getAndAssertEquals();
    expect(owner).toEqual(zkAppAddress);

    const status = recoveryZkApp.status.getAndAssertEquals();
    expect(status).toEqual(Field(RECOVERY_STATUS.DEPLOYED));
  });
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

    const guardianCounter = zkApp.guardianCounter.getAndAssertEquals();
    expect(guardianCounter).toEqual(UInt32.from(0));
  });
  describe('#verifyPassword', () => {
    it('should return true when the password is correct', async () => {
      await localDeploy();

      let password = Password.from(
        Field(1),
        DEFAULT_NULLIFIER,
        UInt64.from(1),
        Field(SALT)
      );
      let w = passwordTree.getWitness(0n);
      let witness = new MerkleWitnessClass(w);
      let result = await zkApp.verifyPassword(password, witness);
      expect(result).toEqual(Bool(true));

      password = Password.from(
        Field(2),
        DEFAULT_NULLIFIER,
        UInt64.from(2),
        Field(SALT)
      );
      w = passwordTree.getWitness(1n);
      witness = new MerkleWitnessClass(w);
      result = await zkApp.verifyPassword(password, witness);
      expect(result).toEqual(Bool(true));
    });
  });
  describe('#addGuardian', () => {
    it('should able to add a guardian', async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(0n, guardian.hash());

      _registerGuardian(guardian1Key, guardian.hash(), guardianTree.getRoot());

      // const tx = await Mina.transaction(deployerAccount, () => {
      //   guardianZkApp.registerGuardian(
      //     guardian.hash(),
      //     guardianTree.getRoot()
      //   );
      // });
      // await tx.prove();
      // await tx.sign([deployerKey]).send();

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

      let w2 = guardianTree.getWitness(0n);
      let witness2 = new MerkleWitness8(w2);

      const txn = await Mina.transaction(zkAppAddress, () => {
        zkApp.addGuardian(
          guardianZkAppAddress,
          otp,
          guardian,
          witness,
          witness2
        );
      });
      await txn.prove();
      await txn.sign([zkAppPrivateKey]).send();

      const committedGuardians = zkApp.committedGuardians.getAndAssertEquals();
      expect(committedGuardians).toEqual(guardianTree.getRoot());

      const counter = zkApp.guardianCounter.getAndAssertEquals();
      expect(counter).toEqual(UInt32.from(1));
    });
  });
  describe('send Mina', () => {
    it('should able to send Mina', async () => {
      await localDeploy();

      const amount = 2_000_000_000;
      const transactionFee = 100_000_000;

      const tx = await Mina.transaction(
        { sender: senderAccount, fee: transactionFee },
        () => {
          let accountUpdate: AccountUpdate =
            AccountUpdate.createSigned(senderAccount);
          accountUpdate.send({ to: zkAppAddress, amount: amount });
        }
      );
      await tx.prove();
      await tx.sign([senderKey]).send();

      const updatedBalance = Mina.getBalance(zkAppAddress);
      expect(updatedBalance).toEqual(UInt64.from(1e9 * 2));
    });
    it('should be able to send Mina from wallet', async () => {
      await localDeploy();

      const amount = 2_000_000_000;
      const transactionFee = 100_000_000;

      const tx = await Mina.transaction(
        { sender: senderAccount, fee: transactionFee },
        () => {
          let accountUpdate: AccountUpdate =
            AccountUpdate.createSigned(senderAccount);
          accountUpdate.send({ to: zkAppAddress, amount: amount });
        }
      );
      await tx.prove();
      await tx.sign([senderKey]).send();

      const tx2 = await Mina.transaction(
        { sender: zkAppAddress, fee: transactionFee },
        () => {
          let accountUpdate: AccountUpdate =
            AccountUpdate.createSigned(zkAppAddress);
          accountUpdate.send({ to: senderAccount, amount: 1e9 * 1 });
        }
      );
      await tx2.prove();
      await tx2.sign([zkAppPrivateKey]).send();

      const updatedBalance = Mina.getBalance(senderAccount);
      expect(updatedBalance).toEqual(UInt64.from(998900000000));
    });
  });
  describe('#transfer', () => {
    it('should able to transfer Mina', async () => {
      await localDeploy();

      const amount = 2_000_000_000;
      const transactionFee = 100_000_000;

      const tx = await Mina.transaction(
        { sender: senderAccount, fee: transactionFee },
        () => {
          let accountUpdate: AccountUpdate =
            AccountUpdate.createSigned(senderAccount);
          accountUpdate.send({ to: zkAppAddress, amount: amount });
        }
      );
      await tx.prove();
      await tx.sign([senderKey]).send();

      let updatedBalance = Mina.getBalance(zkAppAddress);
      expect(updatedBalance).toEqual(UInt64.from(1e9 * 2));

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
        zkApp.transfer(
          walletStatesZkAppAddress,
          otp,
          witness,
          deployerAccount,
          UInt64.from(1e9)
        );
      });
      await txn.prove();
      await txn.sign([zkAppPrivateKey]).send();

      // updatedBalance = Mina.getBalance(zkApp.address);
      // expect(updatedBalance).toEqual(UInt64.from(1e9 * 1));

      // we want to make sure to update the period after the transfer
      // const txn2 = await Mina.transaction(zkAppAddress, () => {
      //   walletStatesZkApp.updatePeriod(zkAppAddress);
      // });

      // await txn2.prove();
      // await txn2.sign([zkAppPrivateKey]).send();

      // const packedLimits: PackedLimits = walletStatesZkApp.packedLimits.getAndAssertEquals();
      // const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
      // packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));

      // let period = unpacked[0].toUInt64();
      // expect(period).toEqual(UInt32.from(DEFAULT_PERIOD));

      // const transactionLimit: UInt32 = unpacked[1];
      // expect(transactionLimit).toEqual(UInt32.from(DEFAULT_TRANSACTION_LIMIT));

      // const dailyLimit: UInt32 = unpacked[2];
      // expect(dailyLimit).toEqual(UInt32.from(DEFAULT_DAILY_LIMIT));

      // const currentPeriodAmount: UInt32 = unpacked[3];
      // expect(currentPeriodAmount).toEqual(UInt32.from(1));
    });
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

      const packedLimits = await walletStatesZkApp.getPackedLimits();
      expect(packedLimits).toEqual([
        UInt64.from(DEFAULT_PERIOD),
        UInt64.from(100),
        UInt64.from(DEFAULT_DAILY_LIMIT),
        UInt64.from(0),
      ]);
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

      const packedLimits = await walletStatesZkApp.getPackedLimits();
      expect(packedLimits).toEqual([
        UInt64.from(DEFAULT_PERIOD),
        UInt64.from(DEFAULT_TRANSACTION_LIMIT),
        UInt64.from(100),
        UInt64.from(0),
      ]);
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

      let paused: Bool = await walletStatesZkApp.paused.getAndAssertEquals();
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
  describe('#changeOtpByPassword', () => {
    it('should able to change otp by password', async () => {
      await localDeploy();

      const password1 = Password.from(
        Field(1),
        DEFAULT_NULLIFIER,
        UInt64.from(1),
        Field(SALT)
      );
      let w = passwordTree.getWitness(0n);
      let witness = new MerkleWitnessClass(w);

      for (let i = 0; i < 32; i++) {
        time = startTime + i * 30000;
        const tokenGen = new TokenGenerator({
          algorithm: 'SHA-512',
          period: 60,
          digits: 8,
          timestamp: time,
        });
        const token = tokenGen.getToken('CHANGEOTP');
        const otp = Otp.from(UInt64.from(time), Field(token));
        otpTree.setLeaf(BigInt(i), otp.hash());
      }

      const txn = await Mina.transaction(zkAppAddress, () => {
        zkApp.changeOtpByPassword(password1, witness, otpTree.getRoot());
      });
      await txn.prove();
      await txn.sign([zkAppPrivateKey]).send();

      const committedOtps = zkApp.committedOtps.getAndAssertEquals();
      expect(committedOtps).toEqual(otpTree.getRoot());
    });
  });
  describe('#startRecovery', () => {
    beforeEach(async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(0n, guardian.hash());
      await _registerGuardian(
        guardian1Key,
        guardian.hash(),
        guardianTree.getRoot()
      );
      const guardian2 = Guardian.from(guardian2Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(1n, guardian2.hash());
      await _registerGuardian(
        guardian2Key,
        guardian2.hash(),
        guardianTree.getRoot()
      );
      const guardian3 = Guardian.from(guardian3Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(2n, guardian3.hash());
      await _registerGuardian(
        guardian3Key,
        guardian3.hash(),
        guardianTree.getRoot()
      );
      const guardian4 = Guardian.from(guardian4Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(3n, guardian4.hash());
      await _registerGuardian(
        guardian4Key,
        guardian4.hash(),
        guardianTree.getRoot()
      );

      const committedGuardians =
        await guardianZkApp.committedGuardians.getAndAssertEquals();
      expect(committedGuardians).toEqual(guardianTree.getRoot());
      const counters = await guardianZkApp.getCounters();
      expect(counters).toEqual([UInt32.from(4), UInt32.from(0)]);

      time = startTime + 0 * 30000;
      const tokenGen = new TokenGenerator({
        algorithm: 'SHA-512',
        period: 60,
        digits: 8,
        timestamp: time,
      });
      const token = tokenGen.getToken(TEST_TOTP_SECRET);
      const otp = Otp.from(UInt64.from(time), Field(token));

      let wOtp = otpTree.getWitness(0n);
      let otpWitness = new MerkleWitnessClass(wOtp);

      const txn = await Mina.transaction(zkAppAddress, () => {
        zkApp.addGuardians(otp, committedGuardians, otpWitness, UInt32.from(4));
      });
      await txn.prove();
      await txn.sign([zkAppPrivateKey]).send();

      const committedGuardiansZkApp =
        zkApp.committedGuardians.getAndAssertEquals();
      committedGuardiansZkApp.assertEquals(committedGuardians);

      const guardianCounter = zkApp.guardianCounter.getAndAssertEquals();
      expect(guardianCounter).toEqual(UInt32.from(4));
    });
    it('should able to start recovery by guardian', async () => {
      const guardian = Guardian.from(guardian1Account, DEFAULT_NULLIFIER);

      let w = guardianTree.getWitness(0n);
      let witness = new MerkleWitness8(w);

      const txn2 = await Mina.transaction(guardian1Account, () => {
        AccountUpdate.createSigned(guardian1Account);
        recoveryZkApp.startAndVote(
          zkAppAddress,
          guardian1Key,
          guardian,
          witness,
          senderAccount
        );
      });
      await txn2.prove();
      await txn2.sign([guardian1Key]).send();
      const status = await recoveryZkApp.status.getAndAssertEquals();
      expect(status).toEqual(Field(RECOVERY_STATUS.STARTED));

      const newVoter = guardian.vote();
      const newVotersTree = witness.calculateRoot(newVoter.hash());
      const newVoters = zkApp.committedGuardians.getAndAssertEquals();
      expect(newVoters).toEqual(newVotersTree);

      const voteCount = recoveryZkApp.voteCount.getAndAssertEquals();
      expect(voteCount).toEqual(UInt32.from(1));

      const owner = zkApp.owner.getAndAssertEquals();
      expect(owner).toEqual(senderAccount);
    });
    it('should able to start recovery by password', async () => {
      //await localDeploy();

      const password1 = Password.from(
        Field(1),
        DEFAULT_NULLIFIER,
        UInt64.from(1),
        Field(SALT)
      );
      let w = passwordTree.getWitness(0n);
      let witness = new MerkleWitnessClass(w);
      const txn = await Mina.transaction(zkAppAddress, () => {
        zkApp.startRecoveryUsingPassword(
          recoveryZkAppAddress,
          password1,
          witness
        );
      });
      await txn.prove();
      await txn.sign([zkAppPrivateKey]).send();
      const status = await recoveryZkApp.status.getAndAssertEquals();
      expect(status).toEqual(Field(RECOVERY_STATUS.STARTED));
    });
  });
  describe('#tally', () => {
    it('should able to tally after 50%+1 votes', async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(0n, guardian.hash());
      await _registerGuardian(
        guardian1Key,
        guardian.hash(),
        guardianTree.getRoot()
      );
      const guardian2 = Guardian.from(guardian2Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(1n, guardian2.hash());
      await _registerGuardian(
        guardian2Key,
        guardian2.hash(),
        guardianTree.getRoot()
      );
      const guardian3 = Guardian.from(guardian3Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(2n, guardian3.hash());
      await _registerGuardian(
        guardian3Key,
        guardian3.hash(),
        guardianTree.getRoot()
      );
      const guardian4 = Guardian.from(guardian4Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(3n, guardian4.hash());
      await _registerGuardian(
        guardian4Key,
        guardian4.hash(),
        guardianTree.getRoot()
      );

      const committedGuardians =
        await guardianZkApp.committedGuardians.getAndAssertEquals();
      expect(committedGuardians).toEqual(guardianTree.getRoot());
      const counters = await guardianZkApp.getCounters();
      expect(counters).toEqual([UInt32.from(4), UInt32.from(0)]);

      time = startTime + 0 * 30000;
      const tokenGen = new TokenGenerator({
        algorithm: 'SHA-512',
        period: 60,
        digits: 8,
        timestamp: time,
      });
      const token = tokenGen.getToken(TEST_TOTP_SECRET);
      const otp = Otp.from(UInt64.from(time), Field(token));

      let wOtp = otpTree.getWitness(0n);
      let otpWitness = new MerkleWitnessClass(wOtp);

      const txn = await Mina.transaction(zkAppAddress, () => {
        zkApp.addGuardians(otp, committedGuardians, otpWitness, UInt32.from(4));
      });
      await txn.prove();
      await txn.sign([zkAppPrivateKey]).send();

      const committedGuardiansZkApp =
        zkApp.committedGuardians.getAndAssertEquals();
      committedGuardiansZkApp.assertEquals(committedGuardians);

      const guardianCounter = zkApp.guardianCounter.getAndAssertEquals();
      expect(guardianCounter).toEqual(UInt32.from(4));

      let w = guardianTree.getWitness(0n);
      let witness = new MerkleWitness8(w);

      const txn2 = await Mina.transaction(guardian1Account, () => {
        //AccountUpdate.createSigned(guardian1Account);
        recoveryZkApp.startAndVote(
          zkAppAddress,
          guardian1Key,
          guardian,
          witness,
          senderAccount
        );
      });
      await txn2.prove();
      await txn2.sign([guardian1Key]).send();
      const status = await recoveryZkApp.status.getAndAssertEquals();
      expect(status).toEqual(Field(RECOVERY_STATUS.STARTED));

      let voteCount = recoveryZkApp.voteCount.getAndAssertEquals();
      expect(voteCount).toEqual(UInt32.from(1));

      let newVoter = guardian.vote();
      guardianTree.setLeaf(0n, newVoter.hash());
      let newVotersTree = witness.calculateRoot(newVoter.hash());
      let newVoters = zkApp.committedGuardians.getAndAssertEquals();
      expect(newVoters).toEqual(newVotersTree);
      expect(newVoters).toEqual(guardianTree.getRoot());

      let w2 = guardianTree.getWitness(1n);
      let witness2 = new MerkleWitness8(w2);

      const txn3 = await Mina.transaction(guardian2Account, () => {
        recoveryZkApp.vote(zkAppAddress, guardian2Key, guardian2, witness2);
      });
      await txn3.prove();
      await txn3.sign([guardian2Key]).send();
      voteCount = recoveryZkApp.voteCount.getAndAssertEquals();
      expect(voteCount).toEqual(UInt32.from(2));

      newVoter = guardian2.vote();
      guardianTree.setLeaf(1n, newVoter.hash());
      newVotersTree = witness2.calculateRoot(newVoter.hash());
      newVoters = zkApp.committedGuardians.getAndAssertEquals();
      expect(newVoters).toEqual(newVotersTree);
      expect(newVoters).toEqual(guardianTree.getRoot());

      let w3 = guardianTree.getWitness(2n);
      let witness3 = new MerkleWitness8(w3);

      const txn4 = await Mina.transaction(guardian3Account, () => {
        recoveryZkApp.vote(zkAppAddress, guardian3Key, guardian3, witness3);
      });
      await txn4.prove();
      await txn4.sign([guardian3Key]).send();

      voteCount = recoveryZkApp.voteCount.getAndAssertEquals();
      expect(voteCount).toEqual(UInt32.from(3));

      newVoter = guardian3.vote();
      guardianTree.setLeaf(2n, newVoter.hash());
      newVotersTree = witness3.calculateRoot(newVoter.hash());
      newVoters = zkApp.committedGuardians.getAndAssertEquals();
      expect(newVoters).toEqual(newVotersTree);
      expect(newVoters).toEqual(guardianTree.getRoot());
      const txn5 = await Mina.transaction(senderAccount, () => {
        recoveryZkApp.tally(zkAppAddress);
      });
      await txn5.prove();
      await txn5.sign([senderKey]).send();
    });
  });
  describe('#recover', () => {
    it('should able to recover', async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(0n, guardian.hash());
      await _registerGuardian(
        guardian1Key,
        guardian.hash(),
        guardianTree.getRoot()
      );
      const guardian2 = Guardian.from(guardian2Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(1n, guardian2.hash());
      await _registerGuardian(
        guardian2Key,
        guardian2.hash(),
        guardianTree.getRoot()
      );
      const guardian3 = Guardian.from(guardian3Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(2n, guardian3.hash());
      await _registerGuardian(
        guardian3Key,
        guardian3.hash(),
        guardianTree.getRoot()
      );
      const guardian4 = Guardian.from(guardian4Account, DEFAULT_NULLIFIER);
      guardianTree.setLeaf(3n, guardian4.hash());
      await _registerGuardian(
        guardian4Key,
        guardian4.hash(),
        guardianTree.getRoot()
      );

      // const committedGuardians =
      //   await guardianZkApp.committedGuardians.getAndAssertEquals();
      // expect(committedGuardians).toEqual(guardianTree.getRoot());
      // const counter = await guardianZkApp.counter.getAndAssertEquals();
      // expect(counter).toEqual(Field(4));

      time = startTime + 0 * 30000;
      const tokenGen = new TokenGenerator({
        algorithm: 'SHA-512',
        period: 60,
        digits: 8,
        timestamp: time,
      });
      const token = tokenGen.getToken(TEST_TOTP_SECRET);
      const otp = Otp.from(UInt64.from(time), Field(token));

      let wOtp = otpTree.getWitness(0n);
      let otpWitness = new MerkleWitnessClass(wOtp);

      const txn = await Mina.transaction(zkAppAddress, () => {
        zkApp.addGuardians(
          otp,
          guardianTree.getRoot(),
          otpWitness,
          UInt32.from(4)
        );
      });
      await txn.prove();
      await txn.sign([zkAppPrivateKey]).send();

      // const committedGuardiansZkApp =
      //   zkApp.committedGuardians.getAndAssertEquals();
      // committedGuardiansZkApp.assertEquals(committedGuardians);

      // const guardianCounter = zkApp.guardianCounter.getAndAssertEquals();
      // expect(guardianCounter).toEqual(UInt32.from(4));

      let w = guardianTree.getWitness(0n);
      let witness = new MerkleWitness8(w);

      const txn2 = await Mina.transaction(guardian1Account, () => {
        //AccountUpdate.createSigned(guardian1Account);
        recoveryZkApp.startAndVote(
          zkAppAddress,
          guardian1Key,
          guardian,
          witness,
          senderAccount
        );
      });
      await txn2.prove();
      await txn2.sign([guardian1Key]).send();
      // const status = await recoveryZkApp.status.getAndAssertEquals();
      // expect(status).toEqual(Field(RECOVERY_STATUS.STARTED));

      // let voteCount = recoveryZkApp.voteCount.getAndAssertEquals();
      // expect(voteCount).toEqual(UInt32.from(1));

      let newVoter = guardian.vote();
      guardianTree.setLeaf(0n, newVoter.hash());
      // let newVotersTree = witness.calculateRoot(newVoter.hash());
      // let newVoters = zkApp.committedGuardians.getAndAssertEquals();
      // expect(newVoters).toEqual(newVotersTree);
      // expect(newVoters).toEqual(guardianTree.getRoot());

      let w2 = guardianTree.getWitness(1n);
      let witness2 = new MerkleWitness8(w2);

      const txn3 = await Mina.transaction(guardian2Account, () => {
        recoveryZkApp.vote(zkAppAddress, guardian2Key, guardian2, witness2);
      });
      await txn3.prove();
      await txn3.sign([guardian2Key]).send();
      // voteCount = recoveryZkApp.voteCount.getAndAssertEquals();
      // expect(voteCount).toEqual(UInt32.from(2));

      newVoter = guardian2.vote();
      guardianTree.setLeaf(1n, newVoter.hash());
      // newVotersTree = witness2.calculateRoot(newVoter.hash());
      // newVoters = zkApp.committedGuardians.getAndAssertEquals();
      // expect(newVoters).toEqual(newVotersTree);
      // expect(newVoters).toEqual(guardianTree.getRoot());

      let w3 = guardianTree.getWitness(2n);
      let witness3 = new MerkleWitness8(w3);

      const txn4 = await Mina.transaction(guardian3Account, () => {
        recoveryZkApp.vote(zkAppAddress, guardian3Key, guardian3, witness3);
      });
      await txn4.prove();
      await txn4.sign([guardian3Key]).send();

      // voteCount = recoveryZkApp.voteCount.getAndAssertEquals();
      // expect(voteCount).toEqual(UInt32.from(3));

      newVoter = guardian3.vote();
      guardianTree.setLeaf(2n, newVoter.hash());
      // newVotersTree = witness3.calculateRoot(newVoter.hash());
      // newVoters = zkApp.committedGuardians.getAndAssertEquals();
      // expect(newVoters).toEqual(newVotersTree);
      // expect(newVoters).toEqual(guardianTree.getRoot());
      const txn5 = await Mina.transaction(senderAccount, () => {
        recoveryZkApp.tally(zkAppAddress);
      });
      await txn5.prove();
      await txn5.sign([senderKey]).send();

      for (let i = 0; i < 32; i++) {
        time = startTime + i * 30000;
        const tokenGen = new TokenGenerator({
          algorithm: 'SHA-512',
          period: 60,
          digits: 8,
          timestamp: time,
        });
        const token = tokenGen.getToken('CHANGEOTP');
        const otp = Otp.from(UInt64.from(time), Field(token));
        otpTree.setLeaf(BigInt(i), otp.hash());
      }

      const txn6 = await Mina.transaction(senderAccount, () => {
        zkApp.recover(
          senderAccount,
          recoveryZkAppAddress,
          otpTree.getRoot(),
          Field(0)
        );
      });
      await txn6.prove();
      await txn6.sign([senderKey]).send();
    });
  });

  async function _registerGuardian(
    _senderKey: PrivateKey,
    _guardianHash: Field,
    _guardianRoot: Field
  ) {
    const tx = await Mina.transaction(_senderKey.toPublicKey(), () => {
      guardianZkApp.registerGuardian(_guardianHash, _guardianRoot);
    });
    await tx.prove();
    await tx.sign([_senderKey]).send();
  }
});
