import {
  Bool,
  DeployArgs,
  Field,
  method,
  SmartContract,
  state,
  State,
  Permissions,
  provablePure,
  ProvablePure,
  PublicKey,
  UInt32,
  VerificationKey,
  PrivateKey,
  Nullifier,
  MerkleMap,
  Mina,
  AccountUpdate,
  MerkleTree,
  UInt64,
} from 'snarkyjs';
import { Guardian } from './Guardian.js';
import { MerkleWitness32 } from '../storage/offchain-storage.js';
import { DEFAULT_NULLIFIER } from '../constant.js';
import { PackedUInt32Factory } from 'snarkyjs-pack';

export { GuardianZkApp, IGuardianZkApp, PackedLimits };

const NULLIFIER_TREE = new MerkleMap();
const GUARDIAN_TREE = new MerkleTree(32);
const APPROVED_GUARDIAN_TREE = new MerkleTree(32);

class PackedLimits extends PackedUInt32Factory(2) {}

type IGuardianZkApp = {
  onlyOwner(sender: PublicKey): void;
  getCounters(): UInt32[];
  verifyGuardian(
    guardianAccount: PublicKey,
    nullifierMessage: Field,
    path: MerkleWitness32
  ): Bool;
  registerGuardian(guardianHash: Field, guardianRoot: Field): Bool; // emits "GuardianRegistered" event
  addGuardians(
    senderKey: PrivateKey,
    guardianRoot: Field,
    amountOfGuardians: UInt32
  ): Bool; // emits "GuardiansAdded" event
  approveGuardian(
    senderKey: PrivateKey,
    guardianHash: Field,
    guardianRoot: Field
  ): Bool; // emits "GuardianApproved" event
  transferOwnership(senderKey: PrivateKey, newOwner: PublicKey): Bool; // emits "OwnershipTransferred" event
  // events
  events: {
    GuardianRegistered: ProvablePure<{
      guardianHash: Field;
      committedGuardians: Field;
      guardiansCounter: UInt32;
    }>;
    GuardiansAdded: ProvablePure<{
      committedGuardians: Field;
      guardiansCounter: UInt32;
    }>;
    GuardianApproved: ProvablePure<{
      guardianHash: Field;
      approvedGuardians: Field;
      guardiansCounter: UInt32;
    }>;
    Transfer: ProvablePure<{
      from: PublicKey;
      to: PublicKey;
      amount: UInt64;
    }>;
    OwnershipTransferred: ProvablePure<{
      previousOwner: PublicKey;
      newOwner: PublicKey;
    }>;
  };
};

class GuardianZkApp extends SmartContract implements IGuardianZkApp {
  @state(PublicKey) owner = State<PublicKey>();
  @state(Field) nullifierRoot = State<Field>();
  @state(Field) committedGuardians = State<Field>();
  @state(Field) approvedGuardians = State<Field>();
  // committedGuardiansCounter and approvedGuardiansCounter are packed into PackedLimits
  @state(PackedLimits) counters = State<PackedLimits>();

  events = {
    GuardianRegistered: provablePure({
      guardianHash: Field,
      committedGuardians: Field,
      guardiansCounter: UInt32,
    }),
    GuardiansAdded: provablePure({
      committedGuardians: Field,
      guardiansCounter: UInt32,
    }),
    GuardianApproved: provablePure({
      guardianHash: Field,
      approvedGuardians: Field,
      guardiansCounter: UInt32,
    }),
    Transfer: provablePure({
      from: PublicKey,
      to: PublicKey,
      amount: UInt64,
    }),
    OwnershipTransferred: provablePure({
      previousOwner: PublicKey,
      newOwner: PublicKey,
    }),
  };

  init() {
    super.init();
    this.account.permissions.set({
      ...Permissions.default(),
      editActionState: Permissions.proofOrSignature(),
      editState: Permissions.proofOrSignature(),
      setVerificationKey: Permissions.proofOrSignature(),
      send: Permissions.proofOrSignature(),
      incrementNonce: Permissions.proofOrSignature(),
    });
    this.nullifierRoot.set(Field(0));
    this.committedGuardians.set(Field(0));
    this.approvedGuardians.set(Field(0));
    this.counters.set(PackedLimits.fromBigInts([BigInt(0), BigInt(0)]));
  }

  deploy(args: DeployArgs) {
    super.deploy(args);
  }

  /**
   * @notice Throws if called by any account other than the owner.
   */
  @method
  onlyOwner(sender: PublicKey) {
    const owner = this.owner.getAndAssertEquals();
    owner.assertEquals(sender);
  }

  /**
   * @returns counters of committedGuardians and approvedGuardians
   */
  @method
  public getCounters(): UInt32[] {
    const packedLimits: PackedLimits = this.counters.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    return unpacked;
  }

  /**
   * @notice Verify the guardian
   * @param guardianAccount a guardian account
   * @param nullifierMessage a nullifier message
   * @param path a guardian witness
   * @returns Bool true if the guardian is verified successfully
   */
  @method
  public verifyGuardian(
    guardianAccount: PublicKey,
    nullifierMessage: Field,
    path: MerkleWitness32
  ): Bool {
    const guardian = Guardian.from(guardianAccount, nullifierMessage);
    const committedGuardians = this.committedGuardians.getAndAssertEquals();
    committedGuardians.assertEquals(path.calculateRoot(guardian.hash()));

    return Bool(true);
  }

  /**
   * @notice: Register a guardian to the Guardian smart contract
   * @param guardianHash the hash of the guardian
   * @param guardianRoot the Merkle root of the guardian
   * @returns Bool true if the guardian is added successfully
   */
  @method
  public registerGuardian(guardianHash: Field, guardianRoot: Field): Bool {
    this._updateCommittedGuardians(guardianRoot);
    this._incrementGuardiansCounter();

    const packedLimits: PackedLimits = this.counters.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    const guardiansCounter: UInt32 = unpacked[0];

    this.emitEvent('GuardianRegistered', {
      guardianHash: guardianHash,
      committedGuardians: guardianRoot,
      guardiansCounter: guardiansCounter,
    });
    return Bool(true);
  }

  /**
   * @notice: Approve a guardian to the Guardian smart contract
   * @param senderKey the sender key
   * @param guardianHash the hash of the guardian
   * @param guardianRoot the Merkle root of the guardian
   * @returns Bool true if the guardian is added successfully
   */
  @method
  public approveGuardian(
    senderKey: PrivateKey,
    guardianHash: Field,
    guardianRoot: Field
  ): Bool {
    this.onlyOwner(senderKey.toPublicKey());

    this._updateApprovedGuardians(guardianRoot);
    this._incrementApprovedGuardiansCounter();

    const packedLimits: PackedLimits = this.counters.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    const guardiansCounter: UInt32 = unpacked[0];

    this.emitEvent('GuardianApproved', {
      guardianHash: guardianHash,
      approvedGuardians: guardianRoot,
      guardiansCounter: guardiansCounter,
    });
    return Bool(true);
  }

  /**
   * @notice: Add guardians to the Guardian smart contract
   * @param senderKey the private key of the sender
   * @param guardianRoot the Merkle root of the guardian
   * @param amountOfGuardians the amount of guardians to add
   * @returns Bool true if the guardians are added successfully
   */
  @method
  public addGuardians(
    senderKey: PrivateKey,
    guardianRoot: Field,
    amountOfGuardians: UInt32
  ): Bool {
    this.onlyOwner(senderKey.toPublicKey());
    // const owner = this.owner.getAndAssertEquals();
    // owner.assertEquals(senderKey.toPublicKey());

    this._updateCommittedGuardians(guardianRoot);
    this._updateGuardiansCounter(amountOfGuardians);

    const packedLimits: PackedLimits = this.counters.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    const guardiansCounter: UInt32 = unpacked[0];

    this.emitEvent('GuardiansAdded', {
      committedGuardians: guardianRoot,
      guardiansCounter: guardiansCounter,
    });
    return Bool(true);
  }

  @method
  public transfer(senderKey: PrivateKey, to: PublicKey, amount: UInt64): Bool {
    this.onlyOwner(senderKey.toPublicKey());
    // const owner = this.owner.getAndAssertEquals();
    // owner.assertEquals(senderKey.toPublicKey());

    const balance = this.account.balance.getAndAssertEquals();
    // Should have enough balance
    balance.assertGreaterThanOrEqual(amount);

    this.send({ to: to, amount: amount });

    this.emitEvent('Transfer', {
      from: this.address,
      to: to,
      amount: amount,
    });

    return Bool(true);
  }

  @method
  public transferOwnership(senderKey: PrivateKey, newOwner: PublicKey): Bool {
    const sender = senderKey.toPublicKey();
    const owner = this.owner.getAndAssertEquals();
    owner.assertEquals(sender);

    this.owner.set(newOwner);
    this.emitEvent('OwnershipTransferred', {
      previousOwner: sender,
      newOwner: newOwner,
    });
    return Bool(true);
  }

  /**
   * @notice: Set the verification key
   * @param verificationKey the updated verification key
   */
  @method
  public replaceVerificationKey(verificationKey: VerificationKey) {
    this.account.verificationKey.set(verificationKey);
  }

  public generateNullifier(
    accountkey: PrivateKey,
    nullifierMessage: Field
  ): any {
    return Nullifier.createTestNullifier([nullifierMessage], accountkey);
  }

  /**
   * @notice: private function Update the committedGuardians
   * @param guardianRoot a Merkle root of the guardian
   */
  private _updateCommittedGuardians(guardianRoot: Field) {
    this.committedGuardians.getAndAssertEquals();
    this.committedGuardians.set(guardianRoot);
  }

  /**
   * @notice: private function Update the approvedGuardians
   * @param guardianRoot a Merkle root of the guardian
   */
  private _updateApprovedGuardians(guardianRoot: Field) {
    this.approvedGuardians.getAndAssertEquals();
    this.approvedGuardians.set(guardianRoot);
  }

  /**
   * @notice: private function Increment the guardiansCounter
   */
  private _incrementGuardiansCounter() {
    const packedLimits: PackedLimits = this.counters.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    const guardiansCounter: UInt32 = unpacked[0];
    unpacked[0] = guardiansCounter.add(1);

    const newPackedLimits: PackedLimits = PackedLimits.fromAuxiliary(unpacked);
    this.counters.set(newPackedLimits);
  }

  /**
   * @notice: private function Increment the approvedGuardiansCounter
   */
  private _incrementApprovedGuardiansCounter() {
    const packedLimits: PackedLimits = this.counters.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    const approvedGuardiansCounter: UInt32 = unpacked[1];
    unpacked[1] = approvedGuardiansCounter.add(1);

    const newPackedLimits: PackedLimits = PackedLimits.fromAuxiliary(unpacked);
    this.counters.set(newPackedLimits);
  }

  /**
   * @notice: private function Update the guardiansCounter
   * @param amount the amount to update the guardiansCounter
   */
  private _updateGuardiansCounter(amount: UInt32) {
    const packedLimits: PackedLimits = this.counters.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    const guardiansCounter: UInt32 = unpacked[0];
    unpacked[0] = guardiansCounter.add(amount);

    const newPackedLimits: PackedLimits = PackedLimits.fromAuxiliary(unpacked);
    this.counters.set(newPackedLimits);
  }

  /**
   * @notice: private function Update the approvedGuardiansCounter
   * @param amount the amount to update the approvedGuardiansCounter
   */
  private _updateApprovedGuardiansCounter(amount: UInt32) {
    const packedLimits: PackedLimits = this.counters.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    const approvedGuardiansCounter: UInt32 = unpacked[1];
    unpacked[1] = approvedGuardiansCounter.add(amount);

    const newPackedLimits: PackedLimits = PackedLimits.fromAuxiliary(unpacked);
    this.counters.set(newPackedLimits);
  }
}

async function main() {
  console.log('------TESTING GuardianZkApp------');
  let Local = Mina.LocalBlockchain({ proofsEnabled: true });
  Mina.setActiveInstance(Local);

  // a test account that pays all the fees, and puts additional funds into the zkapp
  let sender: PublicKey,
    senderKey: PrivateKey,
    guardianAccount: PublicKey,
    guardianKey: PrivateKey,
    guardian2Account: PublicKey,
    guardian2Key: PrivateKey;

  ({ privateKey: senderKey, publicKey: sender } = Local.testAccounts[0]);
  console.log(`sender: ${sender.toBase58()}`);

  ({ privateKey: guardianKey, publicKey: guardianAccount } =
    Local.testAccounts[1]);
  console.log(`guardian: ${guardianAccount.toBase58()}`);
  ({ privateKey: guardian2Key, publicKey: guardian2Account } =
    Local.testAccounts[2]);
  console.log(`guardian2: ${guardian2Account.toBase58()}`);

  // the zkapp account
  let zkappKey = PrivateKey.random();
  let zkappAddress = zkappKey.toPublicKey();

  let initialBalance = 10_000_000_000;

  let zkApp = new GuardianZkApp(zkappAddress);

  console.log('compile');
  await GuardianZkApp.compile();

  console.log('deploy');
  let tx = await Mina.transaction(sender, () => {
    let senderUpdate = AccountUpdate.fundNewAccount(sender);
    senderUpdate.send({ to: zkappAddress, amount: initialBalance });
    zkApp.deploy({ zkappKey });
    zkApp.owner.set(sender);
    zkApp.nullifierRoot.set(NULLIFIER_TREE.getRoot());
  });
  await tx.prove();
  await tx.sign([senderKey]).send();

  console.log(`zkapp balance: ${zkApp.account.balance.get().div(1e9)} MINA`);
  console.log('DEFAULT_NULLIFIER', DEFAULT_NULLIFIER.toString());
  console.log('-----check states after deployment-----');

  let owner: PublicKey = await zkApp.owner.getAndAssertEquals();
  console.log(`owner: ${owner.toBase58()}`);
  owner.assertEquals(sender);

  let nullifierRoot: Field = await zkApp.nullifierRoot.getAndAssertEquals();
  console.log(`nullifierRoot: ${nullifierRoot.toString()}`);
  nullifierRoot.assertEquals(NULLIFIER_TREE.getRoot());

  let committedGuardians: Field =
    await zkApp.committedGuardians.getAndAssertEquals();
  console.log(`committedGuardians: ${committedGuardians.toString()}`);
  committedGuardians.assertEquals(Field(0));

  let approvedGuardians: Field =
    await zkApp.approvedGuardians.getAndAssertEquals();
  console.log(`approvedGuardians: ${approvedGuardians.toString()}`);
  approvedGuardians.assertEquals(Field(0));

  let counters: UInt32[] = await zkApp.getCounters();
  console.log(`counters: ${counters.toString()}`);
  counters[0].assertEquals(UInt32.from(0));
  counters[1].assertEquals(UInt32.from(0));

  console.log('-----#registerGuardian-----');
  const guardian = Guardian.from(guardianAccount, DEFAULT_NULLIFIER);

  GUARDIAN_TREE.setLeaf(counters[0].toBigint(), guardian.hash());

  console.log('add a guardian');

  const txn = await Mina.transaction(guardianAccount, () => {
    zkApp.registerGuardian(guardian.hash(), GUARDIAN_TREE.getRoot());
  });
  await txn.prove();
  await txn.sign([guardianKey]).send();

  console.log('-----check committedGuardians-----');
  committedGuardians = await zkApp.committedGuardians.getAndAssertEquals();
  console.log(`committedGuardians: ${committedGuardians.toString()}`);
  committedGuardians.assertEquals(GUARDIAN_TREE.getRoot());

  counters = await zkApp.getCounters();
  console.log(`counters: ${counters.toString()}`);
  counters[0].assertEquals(UInt32.from(1));

  console.log('add second guardian');
  const guardian2 = Guardian.from(guardian2Account, DEFAULT_NULLIFIER);
  GUARDIAN_TREE.setLeaf(counters[0].toBigint(), guardian2.hash());
  const txn2 = await Mina.transaction(guardian2Account, () => {
    zkApp.registerGuardian(guardian2.hash(), GUARDIAN_TREE.getRoot());
  });
  await txn2.prove();
  await txn2.sign([guardian2Key]).send();

  console.log('-----check committedGuardians-----');
  committedGuardians = await zkApp.committedGuardians.getAndAssertEquals();
  console.log(`committedGuardians: ${committedGuardians.toString()}`);
  committedGuardians.assertEquals(GUARDIAN_TREE.getRoot());

  counters = await zkApp.getCounters();
  console.log(`counters: ${counters.toString()}`);
  counters[0].assertEquals(UInt32.from(2));
  counters[1].assertEquals(UInt32.from(0));

  console.log('-----#approveGuardian-----');
  console.log('approve first guardian');
  APPROVED_GUARDIAN_TREE.setLeaf(counters[1].toBigint(), guardian.hash());
  const txn3 = await Mina.transaction(sender, () => {
    zkApp.approveGuardian(
      senderKey,
      guardian.hash(),
      APPROVED_GUARDIAN_TREE.getRoot()
    );
  });
  await txn3.prove();
  await txn3.sign([senderKey]).send();

  console.log('-----check approvedGuardians-----');
  approvedGuardians = await zkApp.approvedGuardians.getAndAssertEquals();
  console.log(`approvedGuardians: ${approvedGuardians.toString()}`);
  approvedGuardians.assertEquals(APPROVED_GUARDIAN_TREE.getRoot());

  counters = await zkApp.getCounters();
  counters[1].assertEquals(UInt32.from(1));

  console.log('approve second guardian');
  APPROVED_GUARDIAN_TREE.setLeaf(counters[1].toBigint(), guardian2.hash());
  const txn4 = await Mina.transaction(sender, () => {
    zkApp.approveGuardian(
      senderKey,
      guardian2.hash(),
      APPROVED_GUARDIAN_TREE.getRoot()
    );
  });
  await txn4.prove();
  await txn4.sign([senderKey]).send();

  console.log('-----check approvedGuardians-----');
  approvedGuardians = await zkApp.approvedGuardians.getAndAssertEquals();
  console.log(`approvedGuardians: ${approvedGuardians.toString()}`);
  approvedGuardians.assertEquals(APPROVED_GUARDIAN_TREE.getRoot());

  counters = await zkApp.getCounters();
  counters[1].assertEquals(UInt32.from(2));

  console.log('-----#transfer-----');
  const balanceBefore: UInt64 = zkApp.account.balance.get();
  console.log('balance before transfer: ', balanceBefore.toString());
  if (balanceBefore > UInt64.from(0)) {
    console.log('sending balance to sender');
    const tx5 = await Mina.transaction(sender, () => {
      zkApp.transfer(senderKey, sender, balanceBefore);
    });
    await tx5.prove();
    await tx5.sign([senderKey]).send();

    const balanceAfter: UInt64 = zkApp.account.balance.get();
    console.log('balance after transfer: ', balanceAfter.toString());
  }

  console.log('------END TESTING GuardianZkApp------');
}
// check command line arg
let args = process.argv[2];
if (!args) {
  await main();
}
