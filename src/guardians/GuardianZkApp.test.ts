import {
  AccountUpdate,
  Field,
  MerkleTree,
  Mina,
  PrivateKey,
  PublicKey,
  Provable,
  UInt32,
} from 'o1js';
import { GuardianZkApp } from './GuardianZkApp.js';
import { Guardian } from './Guardian.js';
import { DEFAULT_NULLIFIER } from '../constant.js';
import { MerkleWitness32 } from '../storage/offchain-storage.js';

let proofsEnabled = false;
const GUARDIAN_TREE = new MerkleTree(32);

describe('GuardianZkApp', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    guardian1Account: PublicKey,
    guardian1Key: PrivateKey,
    guardian2Account: PublicKey,
    guardian2Key: PrivateKey,
    guardian3Account: PublicKey,
    guardian3Key: PrivateKey,
    guardian4Account: PublicKey,
    guardian4Key: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: GuardianZkApp;

  beforeAll(async () => {
    if (proofsEnabled) await GuardianZkApp.compile();
  });

  beforeEach(() => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);

    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new GuardianZkApp(zkAppAddress);

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
    const txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkApp.deploy({ zkappKey: zkAppPrivateKey });
      zkApp.owner.set(deployerAccount);
    });
    await txn.prove();
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  it('generates and deploys the `GuardianZkApp` smart contract', async () => {
    await localDeploy();
    const owner = zkApp.owner.getAndAssertEquals();
    expect(owner).toEqual(deployerAccount);

    const nullifierRoot = zkApp.nullifierRoot.getAndAssertEquals();
    expect(nullifierRoot).toEqual(Field(0));

    const committedGuardians = zkApp.committedGuardians.getAndAssertEquals();
    expect(committedGuardians).toEqual(Field(0));

    const approvedGuardians = zkApp.approvedGuardians.getAndAssertEquals();
    expect(approvedGuardians).toEqual(Field(0));

    let counters: UInt32[] = await zkApp.getCounters();
    expect(counters).toEqual([UInt32.from(0), UInt32.from(0)]);

    const fooVerificationKey =
      Mina.getAccount(zkAppAddress).zkapp?.verificationKey;
    Provable.log('original verification key', fooVerificationKey);
  });
  describe('#registerGuardian', () => {
    it('should add guardian', async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, DEFAULT_NULLIFIER);
      GUARDIAN_TREE.setLeaf(0n, guardian.hash());
      await _registerGuardian(
        guardian1Key,
        guardian.hash(),
        GUARDIAN_TREE.getRoot()
      );

      const committedGuardians = zkApp.committedGuardians.getAndAssertEquals();
      expect(committedGuardians).toEqual(GUARDIAN_TREE.getRoot());

      const counters = await zkApp.getCounters();
      expect(counters).toEqual([UInt32.from(1), UInt32.from(0)]);
    });
    it('should add 4 guardians', async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, DEFAULT_NULLIFIER);
      GUARDIAN_TREE.setLeaf(0n, guardian.hash());
      await _registerGuardian(
        guardian1Key,
        guardian.hash(),
        GUARDIAN_TREE.getRoot()
      );
      const guardian2 = Guardian.from(guardian2Account, DEFAULT_NULLIFIER);
      GUARDIAN_TREE.setLeaf(1n, guardian2.hash());
      await _registerGuardian(
        guardian2Key,
        guardian2.hash(),
        GUARDIAN_TREE.getRoot()
      );
      const guardian3 = Guardian.from(guardian3Account, DEFAULT_NULLIFIER);
      GUARDIAN_TREE.setLeaf(2n, guardian3.hash());
      await _registerGuardian(
        guardian3Key,
        guardian3.hash(),
        GUARDIAN_TREE.getRoot()
      );
      const guardian4 = Guardian.from(guardian4Account, DEFAULT_NULLIFIER);
      GUARDIAN_TREE.setLeaf(3n, guardian4.hash());
      await _registerGuardian(
        guardian4Key,
        guardian4.hash(),
        GUARDIAN_TREE.getRoot()
      );

      const committedGuardians =
        await zkApp.committedGuardians.getAndAssertEquals();
      expect(committedGuardians).toEqual(GUARDIAN_TREE.getRoot());

      const counters = await zkApp.getCounters();
      expect(counters).toEqual([UInt32.from(4), UInt32.from(0)]);
    });
  });
  describe('#addGuardians', () => {
    it('should add guardians', async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, DEFAULT_NULLIFIER);
      GUARDIAN_TREE.setLeaf(0n, guardian.hash());
      const guardian2 = Guardian.from(guardian2Account, DEFAULT_NULLIFIER);
      GUARDIAN_TREE.setLeaf(1n, guardian2.hash());
      const guardian3 = Guardian.from(guardian3Account, DEFAULT_NULLIFIER);
      GUARDIAN_TREE.setLeaf(2n, guardian3.hash());
      const guardian4 = Guardian.from(guardian4Account, DEFAULT_NULLIFIER);
      GUARDIAN_TREE.setLeaf(3n, guardian4.hash());
      await _addGuardians(deployerKey, GUARDIAN_TREE.getRoot(), UInt32.from(4));

      const committedGuardians = zkApp.committedGuardians.getAndAssertEquals();
      expect(committedGuardians).toEqual(GUARDIAN_TREE.getRoot());

      const counters = await zkApp.getCounters();
      expect(counters).toEqual([UInt32.from(4), UInt32.from(0)]);
    });
  });
  describe('#verifyGuardian', () => {
    let guardian: Guardian;
    beforeEach(async () => {
      await localDeploy();

      guardian = Guardian.from(guardian1Account, DEFAULT_NULLIFIER);
      GUARDIAN_TREE.setLeaf(0n, guardian.hash());
      await _registerGuardian(
        guardian1Key,
        guardian.hash(),
        GUARDIAN_TREE.getRoot()
      );
    });
    it('should verify guardian', async () => {
      let w = GUARDIAN_TREE.getWitness(0n);
      let witness = new MerkleWitness32(w);

      const tx = await Mina.transaction(senderAccount, () => {
        zkApp.verifyGuardian(
          guardian.publicKey,
          guardian.nullifierMessage,
          witness
        );
      });
      await tx.prove();
      await tx.sign([senderKey]).send();
    });
  });
  describe('#transferOwnership', () => {
    it('should transferOwnership', async () => {
      await localDeploy();

      const tx = await Mina.transaction(deployerAccount, () => {
        AccountUpdate.createSigned(deployerAccount);

        zkApp.transferOwnership(deployerKey, senderAccount);
      });
      await tx.prove();
      await tx.sign([deployerKey]).send();

      // const newOwner = zkApp.owner.getAndAssertEquals();
      // expect(newOwner).toEqual(senderAccount);
    });
  });
  describe('#generateNullifier', () => {
    it('should generateNullifier', async () => {
      const result = zkApp.generateNullifier(deployerKey, DEFAULT_NULLIFIER);
      console.log('result', result);
    });
  });

  async function _registerGuardian(
    _senderKey: PrivateKey,
    _guardianHash: Field,
    _guardianRoot: Field
  ) {
    const tx = await Mina.transaction(_senderKey.toPublicKey(), () => {
      zkApp.registerGuardian(_guardianHash, _guardianRoot);
    });
    await tx.prove();
    await tx.sign([_senderKey]).send();
  }

  async function _addGuardians(
    _senderKey: PrivateKey,
    _guardianRoot: Field,
    amountOfGuardians: UInt32
  ) {
    const tx = await Mina.transaction(_senderKey.toPublicKey(), () => {
      zkApp.addGuardians(_senderKey, _guardianRoot, amountOfGuardians);
    });
    await tx.prove();
    await tx.sign([_senderKey]).send();
  }
});
