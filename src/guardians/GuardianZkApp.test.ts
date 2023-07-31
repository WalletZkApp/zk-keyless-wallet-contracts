import {
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  MerkleTree,
  Provable,
} from 'snarkyjs';
import {
  GuardianWitness,
  GuardianZkApp,
  GuardianZkAppUpdate,
} from './GuardianZkApp.js';
import { Guardian } from './Guardian.js';

let proofsEnabled = false;

describe('GuardianZkApp', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    guardian1Account: PublicKey,
    guardian1Key: PrivateKey, //@typescript-eslint/no-unused-vars
    guardian2Account: PublicKey,
    guardian2Key: PrivateKey, //@typescript-eslint/no-unused-vars
    guardian3Account: PublicKey,
    guardian3Key: PrivateKey, //@typescript-eslint/no-unused-vars
    guardian4Account: PublicKey,
    guardian4Key: PrivateKey, //@typescript-eslint/no-unused-vars
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: GuardianZkApp,
    zkAppUpdate: GuardianZkAppUpdate;

  const guardianTree = new MerkleTree(8);
  const nullifierMessage = Field(777);

  beforeAll(async () => {
    if (proofsEnabled) await GuardianZkApp.compile();
  });

  beforeEach(() => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);

    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new GuardianZkApp(zkAppAddress);
    zkAppUpdate = new GuardianZkAppUpdate(zkAppAddress);

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

  async function deployUpdate() {
    const txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkApp.deploy({ zkappKey: zkAppPrivateKey });
      zkAppUpdate.deploy({ zkappKey: zkAppPrivateKey });
      zkApp.owner.set(deployerAccount);
    });
    await txn.prove();
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  it('generates and deploys the `GuardianZkApp` smart contract', async () => {
    await localDeploy();
    const owner = zkApp.owner.getAndAssertEquals();
    expect(owner).toEqual(deployerAccount);

    const committedGuardians = zkApp.committedGuardians.getAndAssertEquals();
    expect(committedGuardians).toEqual(Field(0));

    const counter = zkApp.counter.getAndAssertEquals();
    expect(counter).toEqual(Field(0));

    const fooVerificationKey =
      Mina.getAccount(zkAppAddress).zkapp?.verificationKey;
    Provable.log('original verification key', fooVerificationKey);
  });
  describe('#addGuardian', () => {
    it('should add guardian', async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, nullifierMessage);
      guardianTree.setLeaf(0n, guardian.hash());
      await _addGuardian(deployerAccount, guardian);

      const committedGuardians = zkApp.committedGuardians.getAndAssertEquals();
      expect(committedGuardians).toEqual(guardianTree.getRoot());
      const counter = zkApp.counter.getAndAssertEquals();
      expect(counter).toEqual(Field(1));
    });

    it('should add 4 guardians', async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, nullifierMessage);
      guardianTree.setLeaf(0n, guardian.hash());
      await _addGuardian(deployerAccount, guardian);
      const guardian2 = Guardian.from(guardian2Account, nullifierMessage);
      guardianTree.setLeaf(1n, guardian2.hash());
      await _addGuardian(deployerAccount, guardian2);
      const guardian3 = Guardian.from(guardian3Account, nullifierMessage);
      guardianTree.setLeaf(2n, guardian3.hash());
      await _addGuardian(deployerAccount, guardian3);
      const guardian4 = Guardian.from(guardian4Account, nullifierMessage);
      guardianTree.setLeaf(3n, guardian4.hash());
      await _addGuardian(deployerAccount, guardian4);

      //console.log('guardianTree', guardianTree);

      const committedGuardians =
        await zkApp.committedGuardians.getAndAssertEquals();
      expect(committedGuardians).toEqual(guardianTree.getRoot());
      const counter = await zkApp.counter.getAndAssertEquals();
      expect(counter).toEqual(Field(4));
    });
  });
  describe('#verifyGuardian', () => {
    it('should verify guardian', async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, nullifierMessage);
      guardianTree.setLeaf(0n, guardian.hash());
      await _addGuardian(deployerAccount, guardian);

      let w = guardianTree.getWitness(0n);
      let witness = new GuardianWitness(w);

      const tx = await Mina.transaction(zkAppAddress, () => {
        zkApp.verifyGuardian(guardian, witness);
      });
      await tx.prove();
      await tx.sign([zkAppPrivateKey]).send();
    });
  });
  describe('editGuardian', () => {
    it('should able to edit nullifier message', async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, nullifierMessage);
      guardianTree.setLeaf(0n, guardian.hash());
      await _addGuardian(deployerAccount, guardian);

      const committedGuardians = zkApp.committedGuardians.getAndAssertEquals();
      expect(committedGuardians).toEqual(guardianTree.getRoot());
      const counter = zkApp.counter.getAndAssertEquals();
      expect(counter).toEqual(Field(1));

      let w = guardianTree.getWitness(0n);
      let witness = new GuardianWitness(w);

      const newNullifierMessage = Field(888);

      const tx = await Mina.transaction(deployerAccount, () => {
        zkApp.editGuardian(
          deployerAccount,
          guardian,
          newNullifierMessage,
          witness
        );
      });
      await tx.prove();
      await tx.sign([deployerKey]).send();

      const editedGuardian = guardian.setNullifierMessage(newNullifierMessage);
      guardianTree.setLeaf(0n, editedGuardian.hash());

      const editedCommittedGuardians =
        zkApp.committedGuardians.getAndAssertEquals();
      expect(editedCommittedGuardians).toEqual(guardianTree.getRoot());
    });
  });
  describe('#resetCounter', () => {
    it('should reset counter', async () => {
      await localDeploy();

      const guardian = Guardian.from(guardian1Account, nullifierMessage);
      guardianTree.setLeaf(0n, guardian.hash());
      await _addGuardian(deployerAccount, guardian);

      const committedGuardians = zkApp.committedGuardians.getAndAssertEquals();
      expect(committedGuardians).toEqual(guardianTree.getRoot());
      let counter = zkApp.counter.getAndAssertEquals();
      expect(counter).toEqual(Field(1));

      const tx = await Mina.transaction(deployerAccount, () => {
        zkApp.resetCounter(deployerAccount);
      });
      await tx.prove();
      await tx.sign([deployerKey]).send();
      counter = zkApp.counter.getAndAssertEquals();
      expect(counter).toEqual(Field(0));
    });
  });
  describe('#transferOwnership', () => {
    it('should transferOwnership', async () => {
      await localDeploy();

      const tx = await Mina.transaction(deployerAccount, () => {
        zkApp.transferOwnership(deployerAccount, senderAccount);
      });
      await tx.prove();
      await tx.sign([deployerKey]).send();

      const newOwner = zkApp.owner.getAndAssertEquals();
      expect(newOwner).toEqual(senderAccount);
    });
  });
  // TODO: ask #zkapp-hangout
  describe('#replaceVerificationKey', () => {
    it('should replaceVerificationKey', async () => {
      await deployUpdate();

      const modified = await GuardianZkAppUpdate.compile();
      const tx = await Mina.transaction(zkAppAddress, () => {
        zkApp.replaceVerificationKey(modified.verificationKey);
      });
      await tx.prove();
      await tx.sign([zkAppPrivateKey]).send();

      const updatedVerificationKey =
        Mina.getAccount(zkAppAddress).zkapp?.verificationKey;
      Provable.log('updated verification key', updatedVerificationKey);
    });
  });

  async function _addGuardian(sender: PublicKey, guardian: Guardian) {
    const tx = await Mina.transaction(deployerAccount, () => {
      zkApp.addGuardian(sender, guardian, guardianTree.getRoot());
    });
    await tx.prove();
    await tx.sign([deployerKey]).send();
  }
});
