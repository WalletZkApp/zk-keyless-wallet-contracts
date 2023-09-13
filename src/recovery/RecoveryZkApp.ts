import {
  DeployArgs,
  Field,
  PublicKey,
  Permissions,
  SmartContract,
  State,
  state,
  method,
  PrivateKey,
  ProvablePure,
  Bool,
  provablePure,
  VerificationKey,
  UInt32,
} from 'o1js';

import { Guardian } from '../guardians/Guardian.js';
import { RECOVERY_STATUS } from '../constant.js';
import { WalletZkApp } from '../wallet/WalletZkApp.js';
import { Nominee } from '../nominees/Nominee.js';
import { MerkleWitness8 } from '../storage/offchain-storage.js';

export { IRecoveryZkApp, RecoveryZkApp };

type IRecoveryZkApp = {
  onlyOwner(sender: PublicKey): void;
  start(sender: PublicKey, candidatesTreeRoot: Field): Bool;
  startAndVote(
    walletZkAppInput: PublicKey,
    guardianKey: PrivateKey,
    guardian: Guardian,
    path: MerkleWitness8,
    nominee: PublicKey
  ): Bool;
  vote(
    walletZkAppInput: PublicKey,
    guardianKey: PrivateKey,
    guardian: Guardian,
    voterPath: MerkleWitness8
  ): Bool;
  tally(walletZkAppInput: PublicKey): Bool;
  end(sender: PublicKey): Bool;
  transferOwnership(sender: PublicKey, newOwner: PublicKey): Bool;
  replaceVerificationKey(
    sender: PublicKey,
    verificationKey: VerificationKey
  ): void;
  // events
  events: {
    RecoveryStarted: ProvablePure<{
      status: Field;
    }>;
    Voted: ProvablePure<{
      commitment: Field;
    }>;
    Tallied: ProvablePure<{
      status: Field;
    }>;
    Ended: ProvablePure<{
      status: Field;
    }>;
    OwnershipTransferred: ProvablePure<{
      previousOwner: PublicKey;
      newOwner: PublicKey;
    }>;
    VerificationKeyReplaced: ProvablePure<{
      previousVerificationKey: VerificationKey;
      verificationKey: VerificationKey;
    }>;
  };
};

class RecoveryZkApp extends SmartContract implements IRecoveryZkApp {
  @state(PublicKey) owner = State<PublicKey>();
  @state(Field) status = State<Field>(); // status of the recovery. 0: not started, 1: started, 2: completed
  @state(UInt32) voteCount = State<UInt32>();

  events = {
    RecoveryStarted: provablePure({
      status: Field,
    }),
    Voted: provablePure({
      commitment: Field,
    }),
    Tallied: provablePure({
      status: Field,
    }),
    Ended: provablePure({
      status: Field,
    }),
    OwnershipTransferred: provablePure({
      previousOwner: PublicKey,
      newOwner: PublicKey,
    }),
    VerificationKeyReplaced: provablePure({
      previousVerificationKey: VerificationKey,
      verificationKey: VerificationKey,
    }),
  };

  init() {
    super.init();
    this.account.permissions.set({
      ...Permissions.allImpossible(),
      access: Permissions.proof(),
      editActionState: Permissions.proofOrSignature(),
      editState: Permissions.proofOrSignature(),
      setVerificationKey: Permissions.proofOrSignature(),
    });

    this.status.set(Field(RECOVERY_STATUS.DEPLOYED));
  }

  // deploy smart contract, initialize the state
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
   * @notice: Start the recovery with props. Can be called only once
   * @param votersTreeRoot: merkle root of the voters tree
   * @returns Bool: true if the function is called successfully
   */
  @method
  public start(sender: PublicKey): Bool {
    this.sender.assertEquals(sender);
    this.onlyOwner(sender);

    const status = this.status.getAndAssertEquals();
    status.assertEquals(Field(RECOVERY_STATUS.DEPLOYED));

    this.status.set(Field(RECOVERY_STATUS.STARTED));
    this.emitEvent('RecoveryStarted', {
      status: Field(RECOVERY_STATUS.STARTED),
    });

    return Bool(true);
  }

  /**
   * @notice Start the recovery by guardian. Can be called only once
   * @param guardianKey
   * @param guardian
   * @param path
   * @returns
   */
  @method
  public startAndVote(
    walletZkAppInput: PublicKey,
    guardianKey: PrivateKey,
    guardian: Guardian,
    path: MerkleWitness8,
    nominee: PublicKey
  ): Bool {
    const status = this.status.getAndAssertEquals();
    status.assertEquals(Field(RECOVERY_STATUS.DEPLOYED));

    const walletZkApp = new WalletZkApp(walletZkAppInput);

    // check guardian key
    const checkGuardian = Guardian.from(
      guardianKey.toPublicKey(),
      guardian.nullifierMessage
    );

    walletZkApp.verifyGuardian(checkGuardian, path);

    this.status.getAndAssertEquals();
    this.status.set(Field(RECOVERY_STATUS.STARTED));
    this.emitEvent('RecoveryStarted', {
      status: Field(RECOVERY_STATUS.STARTED),
    });

    // Set merkle tree is_voted: true
    const newVoter = checkGuardian.vote(); // is_voted is updated
    const newVotersTree = path.calculateRoot(newVoter.hash()); // Recalculate the merkle tree with updated Guardian as voter
    const voteCount = this.voteCount.getAndAssertEquals();

    walletZkApp.updatecommittedGuardians(newVotersTree);
    const newState = voteCount.add(1);

    this.voteCount.set(newState);

    walletZkApp.transferOwnership(this.address, nominee);

    this.emitEvent('Voted', {
      commitment: newVoter.hash(),
    });

    return Bool(true);
  }

  /**
   * @notice: Vote for the election. Can be called only once for each voter. Single voting (one voter -> one candidate)
   * @param key: key of the guardian to generate public key
   * @param guardian
   * @param voterPath: path of the guardian in the merkle tree
   */
  @method
  public vote(
    walletZkAppInput: PublicKey,
    guardianKey: PrivateKey,
    guardian: Guardian,
    voterPath: MerkleWitness8
  ): Bool {
    const status = this.status.getAndAssertEquals();
    status.assertEquals(Field(RECOVERY_STATUS.STARTED));

    const walletZkApp = new WalletZkApp(walletZkAppInput);

    // check guardian key
    const checkGuardian = Guardian.from(
      guardianKey.toPublicKey(),
      guardian.nullifierMessage
    );

    walletZkApp.verifyGuardian(checkGuardian, voterPath);

    // Set merkle tree is_voted: true
    const newVoter = checkGuardian.vote(); // is_voted is updated
    const newVotersTree = voterPath.calculateRoot(newVoter.hash()); // Recalculate the merkle tree with updated Guardian as voter
    const voteCount = this.voteCount.getAndAssertEquals();
    const guardianCounter = walletZkApp.guardianCounter.getAndAssertEquals();
    guardianCounter.assertGreaterThanOrEqual(voteCount);

    walletZkApp.updatecommittedGuardians(newVotersTree);
    const newState = voteCount.add(1);

    this.voteCount.set(newState);
    this.emitEvent('Voted', {
      commitment: newVoter.hash(),
    });
    return Bool(true);
  }

  @method
  public tally(walletZkAppInput: PublicKey): Bool {
    const status = this.status.getAndAssertEquals();
    status.assertEquals(Field(RECOVERY_STATUS.STARTED));

    const walletZkApp = new WalletZkApp(walletZkAppInput);
    const voteCount = this.voteCount.getAndAssertEquals();
    const guardianCounter = walletZkApp.guardianCounter.getAndAssertEquals();
    const minVotes = guardianCounter.div(UInt32.from(2)).add(UInt32.from(1));
    voteCount.assertGreaterThanOrEqual(minVotes);

    this.status.getAndAssertEquals();
    this.status.set(Field(RECOVERY_STATUS.FINISHED));

    this.emitEvent('Tallied', {
      status: Field(RECOVERY_STATUS.FINISHED),
    });
    return Bool(true);
  }

  @method
  public end(sender: PublicKey): Bool {
    const status = this.status.getAndAssertEquals();
    status.equals(Field(RECOVERY_STATUS.FINISHED));

    this.sender.assertEquals(sender);
    this.onlyOwner(sender);

    this.status.set(Field(RECOVERY_STATUS.DEPLOYED));

    this.emitEvent('Ended', {
      status: Field(RECOVERY_STATUS.DEPLOYED),
    });
    return Bool(true);
  }

  /**
   * @notice Transfer ownership of the contract to a new account (`newOwner`).
   * @dev can be called after recovery wallet  is finished
   * @param sender the sender of the transaction
   * @param newOwner
   * @returns
   */
  @method
  public transferOwnership(sender: PublicKey, newOwner: PublicKey): Bool {
    this.sender.assertEquals(sender);
    const owner = this.owner.getAndAssertEquals();
    owner.assertEquals(sender);
    this.owner.set(newOwner);
    this.emitEvent('OwnershipTransferred', {
      previousOwner: owner,
      newOwner: newOwner,
    });
    return Bool(true);
  }

  /**
   * @notice: Set the verification key
   * @param sender the sender of the transaction
   * @param verificationKey the updated verification key
   */
  @method
  public replaceVerificationKey(
    sender: PublicKey,
    verificationKey: VerificationKey
  ) {
    this.sender.assertEquals(sender);
    this.onlyOwner(sender);

    const currentVerificationKey = this.account.verificationKey;
    this.account.verificationKey.set(verificationKey);

    this.emitEvent('VerificationKeyReplaced', {
      previousVerificationKey: currentVerificationKey,
      verificationKey: verificationKey,
    });
  }
}
