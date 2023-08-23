import {
  Bool,
  DeployArgs,
  Field,
  method,
  PublicKey,
  Permissions,
  ProvablePure,
  PrivateKey,
  provablePure,
  SmartContract,
  State,
  state,
  UInt32,
  UInt64,
} from 'snarkyjs';
// import { WALLET_STATUS } from '../constant';
import { WalletStateZkApp } from './states/index.js';
import { Guardian, GuardianZkApp } from '../guardians/index.js';
import { MerkleWitnessClass } from '../general.js';
import { Password } from '../passwords/index.js';
import { PackedLimits } from './states/WalletStateZkApp.js';
import { RecoveryZkApp } from '../recovery/index.js';
import { Otp } from '../otps/index.js';
import { RECOVERY_STATUS } from '../constant.js';
import { MerkleWitness8 } from '../storage/offchain-storage.js';

export { WalletZkApp, IWalletZkApp };

type IWalletZkApp = {
  onlyOwner(sender: PublicKey): void;
  getNetworkTimestamp(): UInt64;
  verifyOtp(otp: Otp, path: MerkleWitnessClass): Bool;
  verifyPassword(password: Password, path: MerkleWitnessClass): Bool;
  addGuardian(
    guardianZkAppAddress: PublicKey,
    otp: Otp,
    guardian: Guardian,
    path: MerkleWitnessClass,
    guardianPath: MerkleWitness8
  ): Bool; // emits "GuardianAdded" event
  addGuardians(
    otp: Otp,
    committedGuardians: Field,
    path: MerkleWitnessClass,
    guardianCounter: UInt32
  ): Bool;
  transfer(
    walletStatesZkAppAddress: PublicKey,
    otp: Otp,
    path: MerkleWitnessClass,
    to: PublicKey,
    amount: UInt64
  ): Bool; // emits "Withdraw" event
  setTransactionLimit(
    walletStatesZkAppAddress: PublicKey,
    otp: Otp,
    path: MerkleWitnessClass,
    newTransactionLimit: UInt32
  ): Bool;
  setDailyLimit(
    walletStatesZkAppAddress: PublicKey,
    otp: Otp,
    path: MerkleWitnessClass,
    newDailyLimit: UInt32
  ): Bool;
  pause(
    walletStatesZkAppAddress: PublicKey,
    otp: Otp,
    path: MerkleWitnessClass
  ): Bool;
  unpause(
    walletStatesZkAppAddress: PublicKey,
    otp: Otp,
    path: MerkleWitnessClass
  ): Bool;
  changeOtpByPassword(
    password: Password,
    path: MerkleWitnessClass,
    newOtpRoot: Field
  ): Bool;
  startRecoveryUsingPassword(
    recoveryZkAppAddress: PublicKey,
    password: Password,
    path: MerkleWitnessClass
  ): Bool;
  transferOwnership(sender: PublicKey, newOwner: PublicKey): Bool;

  // events
  events: {
    GuardianAdded: ProvablePure<{
      commitment: Field;
    }>;
    GuardiansAdded: ProvablePure<{
      previousCommitment: Field;
      commitment: Field;
    }>;
    NomineesAdded: ProvablePure<{
      commitment: Field;
    }>;
    Transfer: ProvablePure<{
      from: PublicKey;
      to: PublicKey;
      amount: UInt64;
    }>;
    OtpChanged: ProvablePure<{
      previousOtpRoot: Field;
      newOtpRoot: Field;
    }>;
    Recovered: ProvablePure<{
      previousCommittedGuardians: Field;
      committedGuardians: Field;
      previousCommittedOtpst: Field;
      committedOtps: Field;
    }>;
    OwnershipTransferred: ProvablePure<{
      previousOwner: PublicKey;
      newOwner: PublicKey;
    }>;
  };
};

class WalletZkApp extends SmartContract implements IWalletZkApp {
  @state(PublicKey) owner = State<PublicKey>();
  @state(Field) committedPasswords = State<Field>(); // Merkle root of the password tree
  @state(Field) committedGuardians = State<Field>(); // Committed guardians
  @state(Field) committedNominees = State<Field>(); // Committed nominees
  @state(Field) committedOtps = State<Field>(); // Committed one time passwords
  @state(UInt32) guardianCounter = State<UInt32>();

  events = {
    GuardianAdded: provablePure({
      commitment: Field,
    }),
    GuardiansAdded: provablePure({
      previousCommitment: Field,
      commitment: Field,
    }),
    NomineesAdded: provablePure({
      commitment: Field,
    }),
    Transfer: provablePure({
      from: PublicKey,
      to: PublicKey,
      amount: UInt64,
    }),
    OtpChanged: provablePure({
      previousOtpRoot: Field,
      newOtpRoot: Field,
    }),
    Recovered: provablePure({
      previousCommittedGuardians: Field,
      committedGuardians: Field,
      previousCommittedOtpst: Field,
      committedOtps: Field,
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
      access: Permissions.none(),
      editActionState: Permissions.proofOrSignature(),
      editState: Permissions.proofOrSignature(),
      send: Permissions.proofOrSignature(),
      receive: Permissions.none(),
    });
    this.committedPasswords.set(Field(0));
    this.committedGuardians.set(Field(0));
    this.committedNominees.set(Field(0));
    this.committedOtps.set(Field(0));
    this.guardianCounter.set(UInt32.from(0));
  }

  deploy(args: DeployArgs) {
    super.deploy(args);
  }

  @method
  onlyOwner(sender: PublicKey) {
    const owner = this.owner.getAndAssertEquals();
    owner.assertEquals(sender);
  }

  /**
   * @notice: get the network timestamp
   * @returns networkTimestamp UInt64 the network timestamp
   */
  @method
  getNetworkTimestamp(): UInt64 {
    const networkTimestamp = this.network.timestamp.getAndAssertEquals();
    return networkTimestamp;
  }

  /**
   * @notice: verify the otp
   * @param otp: private input otp
   * @param path: a merkle witness of the otp
   * @returns Bool: true if the otp is verified successfully
   */
  @method
  public verifyOtp(otp: Otp, path: MerkleWitnessClass): Bool {
    const otpRoot = this.committedOtps.getAndAssertEquals();

    otpRoot.assertEquals(path.calculateRoot(otp.hash()));

    otp.time.assertLessThanOrEqual(this.getNetworkTimestamp());

    return Bool(true);
  }

  /**
   * @notice: verify the password
   * @param password: private input password
   * @param path: a merkle witness of the password
   * @returns Bool: true if the password is verified successfully
   */
  @method
  public verifyPassword(password: Password, path: MerkleWitnessClass): Bool {
    const passwordRoot = this.committedPasswords.getAndAssertEquals();
    passwordRoot.assertGreaterThan(Field(0));

    passwordRoot.assertEquals(path.calculateRoot(password.hash()));

    return Bool(true);
  }

  @method
  public verifyGuardian(guardian: Guardian, path: MerkleWitness8): Bool {
    const commitment = this.committedGuardians.getAndAssertEquals();
    commitment.assertEquals(path.calculateRoot(guardian.hash()));

    return Bool(true);
  }

  /**
   * @notice: add a new guardian
   * @param password password of user
   * @param guardian guardian to be added
   * @param path Merkle witness of the password
   * @param guardianPath Merkle witness of the guardian
   * @returns true if the guardian is added successfully
   */
  @method addGuardian(
    guardianZkAppAddress: PublicKey,
    otp: Otp,
    guardian: Guardian,
    path: MerkleWitnessClass,
    guardianPath: MerkleWitness8
  ): Bool {
    this.verifyOtp(otp, path);
    // we want to verify if the guardian is registered in the guardian zkapp
    // const guardianZkApp = new GuardianZkApp(guardianZkAppAddress);
    // guardianZkApp.verifyGuardian(guardian.publicKey, guardian.nullifierMessage, guardianPath);

    this.committedGuardians.getAndAssertEquals();

    this.committedGuardians.set(guardianPath.calculateRoot(guardian.hash()));

    this.setGuardianCounter();

    this.emitEvent('GuardianAdded', {
      commitment: guardian.hash(),
    });
    return Bool(true);
  }

  @method
  public addGuardians(
    otp: Otp,
    committedGuardiansInput: Field,
    path: MerkleWitnessClass,
    guardianCounter: UInt32
  ): Bool {
    this.verifyOtp(otp, path);

    const committedGuardians = this.committedGuardians.getAndAssertEquals();
    committedGuardians.assertNotEquals(committedGuardiansInput);

    this.guardianCounter.getAndAssertEquals();

    this.committedGuardians.set(committedGuardiansInput);
    this.guardianCounter.set(guardianCounter);

    this.emitEvent('GuardiansAdded', {
      previousCommitment: committedGuardians,
      commitment: committedGuardiansInput,
    });
    return Bool(true);
  }

  @method
  updatecommittedGuardians(committedGuardiansInput: Field): Bool {
    const committedGuardians = this.committedGuardians.getAndAssertEquals();
    committedGuardians.assertNotEquals(committedGuardiansInput);

    this.committedGuardians.set(committedGuardiansInput);
    return Bool(true);
  }

  @method
  public transfer(
    walletStatesZkAppAddress: PublicKey,
    otp: Otp,
    path: MerkleWitnessClass,
    to: PublicKey,
    amount: UInt64
  ): Bool {
    this.verifyOtp(otp, path);

    const balance = this.account.balance.getAndAssertEquals();
    // Should have enough balance
    balance.assertGreaterThanOrEqual(amount);

    const walletStateZkApp = new WalletStateZkApp(walletStatesZkAppAddress);

    //walletStateZkApp.updatePeriod(this.address);

    // Should met requirements, whenNotPaused, transactionLimit, dailyLimit
    // === BEGIN VALIDATION ===
    walletStateZkApp.paused.getAndAssertEquals();
    walletStateZkApp.paused.get().assertFalse();

    const packedLimits: PackedLimits =
      walletStateZkApp.packedLimits.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));

    const transactionLimit: UInt32 = unpacked[1];
    // for now we round up amount without decimals
    const amountWithDecimal: UInt32 = amount
      .div(UInt64.from(1000000000))
      .toUInt32();
    amountWithDecimal.assertLessThanOrEqual(transactionLimit);

    // const currentPeriodAmount: UInt64 = unpacked[3]
    //   .mul(UInt32.from(1000000000))
    //   .toUInt64();
    // const totalAmount: UInt64 = currentPeriodAmount.add(amount);
    // totalAmount.assertGreaterThanOrEqual(currentPeriodAmount);

    // const dailyLimit: UInt32 = unpacked[2];
    // amountWithDecimal.assertLessThanOrEqual(dailyLimit);
    // === END VALIDATION ===

    // Update the current period
    // const now = this.getNetworkTimestamp();
    // const period: UInt64 = unpacked[0].toUInt64();

    // const currentPeriodEnd: UInt64 =
    //   walletStateZkApp.currentPeriodEnd.getAndAssertEquals();

    // Update the current period amount without decimals
    // unpacked[3] = totalAmount.div(UInt64.from(1000000000)).toUInt32();
    // let newPackedLimits: PackedLimits = PackedLimits.fromAuxiliary(unpacked);
    // walletStateZkApp.updatePackedLimits(this.address, newPackedLimits);

    this.send({ to: to, amount: amount });

    this.emitEvent('Transfer', {
      from: this.address,
      to: to,
      amount: amount,
    });

    return Bool(true);
  }

  @method
  public setTransactionLimit(
    walletStatesZkAppAddress: PublicKey,
    otp: Otp,
    path: MerkleWitnessClass,
    newTransactionLimit: UInt32
  ): Bool {
    this.verifyOtp(otp, path);
    const walletStateZkApp = new WalletStateZkApp(walletStatesZkAppAddress);
    return walletStateZkApp.setTransactionLimit(
      this.address,
      newTransactionLimit
    );
  }

  // @method
  public setDailyLimit(
    walletStatesZkAppAddress: PublicKey,
    otp: Otp,
    path: MerkleWitnessClass,
    newDailyLimit: UInt32
  ): Bool {
    this.verifyOtp(otp, path);

    const walletStateZkApp = new WalletStateZkApp(walletStatesZkAppAddress);
    return walletStateZkApp.setDailyLimit(this.address, newDailyLimit);
  }

  @method
  public pause(
    walletStatesZkAppAddress: PublicKey,
    otp: Otp,
    path: MerkleWitnessClass
  ): Bool {
    this.verifyOtp(otp, path);

    const walletStateZkApp = new WalletStateZkApp(walletStatesZkAppAddress);
    return walletStateZkApp.pause(this.address);
  }

  @method
  public unpause(
    walletStatesZkAppAddress: PublicKey,
    otp: Otp,
    path: MerkleWitnessClass
  ): Bool {
    this.verifyOtp(otp, path);

    const walletStateZkApp = new WalletStateZkApp(walletStatesZkAppAddress);

    return walletStateZkApp.unpause(this.address);
  }

  /**
   * @notice: change the otp by password
   * @param password current password
   * @param path merkle witness of the password
   * @param newOtpRoot new otp root
   * @returns Bool true if the otp is changed successfully
   */
  @method
  changeOtpByPassword(
    password: Password,
    path: MerkleWitnessClass,
    newOtpRoot: Field
  ): Bool {
    this.verifyPassword(password, path);

    const committedOtps = this.committedOtps.getAndAssertEquals();
    this.committedOtps.set(newOtpRoot);

    this.emitEvent('OtpChanged', {
      previousOtpRoot: committedOtps,
      newOtpRoot: newOtpRoot,
    });

    return Bool(true);
  }

  /**
   * @notice: start recovery using password
   * @param password
   * @param path
   * @param recoveryZkAppInput
   * @param votersTreeRoot
   * @param candidatesTreeRoot
   * @returns
   */
  @method
  public startRecoveryUsingPassword(
    recoveryZkAppAddress: PublicKey,
    password: Password,
    path: MerkleWitnessClass
  ): Bool {
    this.verifyPassword(password, path);

    const recoveryContract = new RecoveryZkApp(recoveryZkAppAddress);
    return recoveryContract.start(this.address);
  }

  @method
  public recover(
    sender: PublicKey,
    recoveryZkAppInput: PublicKey,
    newOtpRoot: Field,
    committedGuardiansInput: Field
  ): Bool {
    this.sender.assertEquals(sender);
    this.onlyOwner(sender);

    const recoveryZkApp = new RecoveryZkApp(recoveryZkAppInput);
    const status = recoveryZkApp.status.getAndAssertEquals();
    status.assertEquals(Field(RECOVERY_STATUS.FINISHED));

    const committedOtps = this.committedOtps.getAndAssertEquals();
    const committedGuardians = this.committedGuardians.getAndAssertEquals();

    this.committedGuardians.set(committedGuardiansInput);
    this.committedOtps.set(newOtpRoot);

    this.emitEvent('Recovered', {
      previousCommittedGuardians: committedGuardians,
      committedGuardians: committedGuardiansInput,
      previousCommittedOtpst: committedOtps,
      committedOtps: newOtpRoot,
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
    //this.sender.assertEquals(sender);
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
   * @notice: private function Increment the guardianCounter
   * @returns void
   */
  private setGuardianCounter() {
    const currentState = this.guardianCounter.getAndAssertEquals();
    const newState = currentState.add(1);
    this.guardianCounter.set(newState);
  }
}
