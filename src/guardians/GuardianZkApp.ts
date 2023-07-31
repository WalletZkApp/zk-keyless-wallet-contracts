import {
  Bool,
  Field,
  MerkleWitness,
  SmartContract,
  state,
  State,
  method,
  Provable,
  Permissions,
  provablePure,
  DeployArgs,
  PublicKey,
  ProvablePure,
  VerificationKey,
} from 'snarkyjs';

import { Guardian } from './Guardian.js';
export { GuardianZkApp, IGuardianZkApp, GuardianZkAppUpdate, GuardianWitness };

type IGuardianZkApp = {
  verifyGuardian(guardian: Guardian, path: GuardianWitness): Bool;
  addGuardian(sender: PublicKey, guardian: Guardian, guardianRoot: Field): Bool; // emits "GuardianAdded" event
  editGuardian(
    sender: PublicKey,
    guardian: Guardian,
    newNullifierMessage: Field,
    path: GuardianWitness
  ): Bool; // emits "GuardianChanged" event
  transferOwnership(sender: PublicKey, newOwner: PublicKey): Bool; // emits "OwnershipTransferred" event
  // events
  events: {
    GuardianAdded: ProvablePure<{
      commitment: Field;
    }>;
    GuardianChanged: ProvablePure<{
      commitment: Field;
    }>;
    OwnershipTransferred: ProvablePure<{
      previousOwner: PublicKey;
      newOwner: PublicKey;
    }>;
  };
};

class GuardianWitness extends MerkleWitness(8) {
  static empty(): GuardianWitness {
    throw new Error('Method not implemented.');
  }
}

class GuardianZkApp extends SmartContract implements IGuardianZkApp {
  @state(PublicKey) owner = State<PublicKey>();
  @state(Field) committedGuardians = State<Field>();
  @state(Field) counter = State<Field>();

  events = {
    GuardianAdded: provablePure({
      commitment: Field,
    }),
    GuardianChanged: provablePure({
      commitment: Field,
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
    });
    this.committedGuardians.set(Field(0));
    this.counter.set(Field(0));
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
   * @notice Verify the guardian
   * @param guardian a guardian object
   * @param path a guardian witness
   * @returns Bool true if the guardian is verified successfully
   */
  @method
  public verifyGuardian(guardian: Guardian, path: GuardianWitness): Bool {
    const commitment = this.committedGuardians.getAndAssertEquals();
    commitment.assertEquals(path.calculateRoot(guardian.hash()));

    return Bool(true);
  }

  /**
   * @notice: Add a guardian to the Merkle Tree
   * @param sender a sender account
   * @param guardian a guardian object
   * @param guardianRoot a Merkle root of the guardian
   * @returns Bool true if the guardian is added successfully
   */
  @method
  public addGuardian(
    sender: PublicKey,
    guardian: Guardian,
    guardianRoot: Field
  ): Bool {
    this.sender.assertEquals(sender);

    this.onlyOwner(sender);
    this.committedGuardians.getAndAssertEquals();

    this.committedGuardians.set(guardianRoot);
    this.setCounter();

    this.emitEvent('GuardianAdded', {
      commitment: guardian.hash(),
    });
    return Bool(true);
  }

  /**
   * @notice: Edit a guardian in the Merkle Tree
   * @param sender a sender account
   * @param guardian a guardian object
   * @param newNullifierMessage a new nullifier message
   * @param path GuardianWitness, a guardian witness
   * @returns Bool true if the guardian is edited successfully
   */
  @method
  public editGuardian(
    sender: PublicKey,
    guardian: Guardian,
    newNullifierMessage: Field,
    path: GuardianWitness
  ): Bool {
    this.sender.assertEquals(sender);
    this.onlyOwner(sender);
    const commitment = this.committedGuardians.getAndAssertEquals();
    commitment.assertEquals(path.calculateRoot(guardian.hash()));

    const newGuardian = guardian.setNullifierMessage(newNullifierMessage);
    const newCommittedGuardians = path.calculateRoot(newGuardian.hash());
    this.committedGuardians.set(newCommittedGuardians);

    this.emitEvent('GuardianChanged', {
      commitment: newCommittedGuardians,
    });
    return Bool(true);
  }

  @method
  public resetCounter(sender: PublicKey): Bool {
    this.sender.assertEquals(sender);
    this.onlyOwner(sender);

    this.counter.set(Field(0));
    return Bool(true);
  }

  /**
   * @notice Transfer ownership of the contract to a new account (`newOwner`).
   * @dev can be called after recovery wallet  is finished
   * @param newOwner
   * @returns
   */
  @method
  public transferOwnership(sender: PublicKey, newOwner: PublicKey): Bool {
    const previousOwner = this.owner.getAndAssertEquals();
    previousOwner.assertEquals(sender);

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

  /**
   * @notice: private function Increment the counter
   * @returns void
   */
  private setCounter() {
    const currentState = this.counter.getAndAssertEquals();
    const newState = currentState.add(1);
    this.counter.set(newState);
  }
}

/**
 * @notice: This is a dummy contract to update the GuardianZkApp contract
 */
class GuardianZkAppUpdate extends SmartContract {
  deploy(args: DeployArgs) {
    super.deploy(args);
  }

  @method call() {
    Provable.log('GuardiansUpdate');
  }
}
