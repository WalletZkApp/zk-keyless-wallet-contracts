import {
  Bool,
  PublicKey,
  Permissions,
  SmartContract,
  State,
  method,
  state,
  DeployArgs,
  UInt64,
  VerificationKey,
  ProvablePure,
  provablePure,
  UInt32,
} from 'snarkyjs';
import { PackedUInt32Factory } from 'snarkyjs-pack';
import {
  DEFAULT_TRANSACTION_LIMIT,
  DEFAULT_DAILY_LIMIT,
  DEFAULT_PERIOD,
} from '../../constant.js';
export { WalletStateZkApp, IWalletStateZkApp, PackedLimits };

type IWalletStateZkApp = {
  onlyOwner(sender: PublicKey): void;
  whenNotPaused(): void;
  whenPaused(): void;
  getPeriod(): UInt32;
  getTransactionLimit(): UInt32;
  getDailyLimit(): UInt32;
  getCurrentPeriodAmount(): UInt32;
  pause(sender: PublicKey): Bool;
  unpause(sender: PublicKey): Bool;
  setTransactionLimit(sender: PublicKey, newTransactionLimit: UInt32): Bool;
  setDailyLimit(sender: PublicKey, newDailyLimit: UInt32): Bool;
  setCurrentPeriodAmount(
    sender: PublicKey,
    newCurrentPeriodAmount: UInt32
  ): Bool;
  updatePackedLimits(sender: PublicKey, newPackedLimits: PackedLimits): Bool;
  //updatePeriod(sender: PublicKey): void;
  transferOwnership(sender: PublicKey, newOwner: PublicKey): Bool;
  replaceVerificationKey(
    sender: PublicKey,
    verificationKey: VerificationKey
  ): void;
  // events
  events: {
    TransactionLimitChanged: ProvablePure<{
      previousLimit: UInt64;
      newLimit: UInt64;
    }>;
    DailyLimitChanged: ProvablePure<{
      previousLimit: UInt64;
      newLimit: UInt64;
    }>;
    /**
     * @notice Emitted when the pause is lifted by `account`.
     */
    Paused: ProvablePure<{
      account: PublicKey;
    }>;
    /**
     * @notice Emitted when the pause is lifted by `account`.
     */
    Unpaused: ProvablePure<{
      account: PublicKey;
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

class PackedLimits extends PackedUInt32Factory(4) {}

class WalletStateZkApp extends SmartContract implements IWalletStateZkApp {
  @state(PublicKey) owner = State<PublicKey>();
  @state(Bool) paused = State<Bool>();
  @state(UInt64) currentPeriodEnd = State<UInt64>();
  // period, transactionLimit, dailyLimit, currentPeriodAmount are packed into a single state variable
  // the limits are packed without decimals
  @state(PackedLimits) packedLimits = State<PackedLimits>();

  events = {
    TransactionLimitChanged: provablePure({
      previousLimit: UInt64,
      newLimit: UInt64,
    }),
    DailyLimitChanged: provablePure({
      previousLimit: UInt64,
      newLimit: UInt64,
    }),
    Paused: provablePure({
      account: PublicKey,
    }),
    Unpaused: provablePure({
      account: PublicKey,
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
      access: Permissions.proofOrSignature(),
      editActionState: Permissions.proofOrSignature(),
      editState: Permissions.proofOrSignature(),
      setVerificationKey: Permissions.proofOrSignature(),
    });
    this.paused.set(Bool(false));

    // period, transactionLimit, dailyLimit, currentPeriodAmount are packed into a single state variable
    this.packedLimits.set(
      PackedLimits.fromBigInts([
        BigInt(DEFAULT_PERIOD),
        BigInt(DEFAULT_TRANSACTION_LIMIT),
        BigInt(DEFAULT_DAILY_LIMIT),
        BigInt(0),
      ])
    );
  }

  deploy(args: DeployArgs) {
    super.deploy(args);
  }

  /**
   * @notice Throws if called by any account other than the owner.
   */
  @method
  onlyOwner(sender: PublicKey) {
    this.sender.assertEquals(sender);
    const owner = this.owner.getAndAssertEquals();
    owner.assertEquals(sender);
  }

  /**
   * @notice Modifier to make a function callable only when the contract is not paused.
   */
  @method
  whenNotPaused() {
    this.paused.getAndAssertEquals();
    this.paused.get().assertFalse();
  }

  /**
   * @notice Modifier to make a function callable only when the contract is paused.
   */
  @method
  whenPaused() {
    this.paused.getAndAssertEquals();
    this.paused.get().assertTrue();
  }

  @method
  public getPackedLimits(): UInt32[] {
    const packedLimits: PackedLimits = this.packedLimits.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    return unpacked;
  }

  /**
   * @returns the current period
   */
  @method
  public getPeriod(): UInt32 {
    return this.getPackedLimits()[0];
  }

  /**
   * @returns the transaction limit
   */
  @method
  getTransactionLimit(): UInt32 {
    return this.getPackedLimits()[1];
  }

  /**
   * @returns the daily limit
   */
  @method
  getDailyLimit(): UInt32 {
    return this.getPackedLimits()[2];
  }

  /**
   * @returns the current period amount without decimals
   */
  @method
  getCurrentPeriodAmount(): UInt32 {
    return this.getPackedLimits()[3];
  }

  /**
   * @notice Pause the contract
   * @param sender the sender of the transaction
   * @returns Bool(true) if the contract is paused, false otherwise
   */
  @method
  public pause(sender: PublicKey): Bool {
    this.onlyOwner(sender);

    this.paused.getAndAssertEquals();
    this.paused.set(Bool(true));
    this.emitEvent('Paused', {
      account: this.sender,
    });
    return Bool(true);
  }

  /**
   * @notice Unpause the contract
   * @param sender the sender of the transaction
   * @returns Bool(true) if the contract is unpaused, false otherwise
   */
  @method
  public unpause(sender: PublicKey): Bool {
    this.onlyOwner(sender);

    this.paused.getAndAssertEquals();
    this.paused.set(Bool(false));
    this.emitEvent('Unpaused', {
      account: this.sender,
    });
    return Bool(true);
  }

  /**
   * @notice Set the transaction limit
   * @param sender the sender of the transaction
   * @param newTransactionLimit the new transaction limit
   * @returns Bool(true) if the transaction limit was changed, false otherwise
   */
  @method
  public setTransactionLimit(
    sender: PublicKey,
    newTransactionLimit: UInt32
  ): Bool {
    this.onlyOwner(sender);

    const packedLimits: PackedLimits = this.packedLimits.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    const transactionLimit: UInt32 = unpacked[1];
    unpacked[1] = newTransactionLimit;

    const newPackedLimits: PackedLimits = PackedLimits.fromAuxiliary(unpacked);
    this.packedLimits.set(newPackedLimits);

    this.emitEvent('TransactionLimitChanged', {
      previousLimit: transactionLimit,
      newLimit: newTransactionLimit,
    });
    return Bool(true);
  }

  /**
   * @notice Set the daily limit
   * @param sender the sender of the transaction
   * @param newDailyLimit the new daily limit
   * @returns Bool(true) if the daily limit was changed, false otherwise
   */
  @method
  public setDailyLimit(sender: PublicKey, newDailyLimit: UInt32): Bool {
    this.onlyOwner(sender);

    const packedLimits: PackedLimits = this.packedLimits.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    const dailyLimit: UInt32 = unpacked[2];
    unpacked[2] = newDailyLimit;

    const newPackedLimits: PackedLimits = PackedLimits.fromAuxiliary(unpacked);
    this.packedLimits.set(newPackedLimits);

    this.emitEvent('DailyLimitChanged', {
      previousLimit: dailyLimit,
      newLimit: newDailyLimit,
    });
    return Bool(true);
  }

  /**
   * @notice Set the current period amount
   * @param sender the sender of the transaction
   * @param newCurrentPeriodAmount new current period amount
   * @returns Bool(true) if the current period amount was changed, false otherwise
   */
  @method
  public setCurrentPeriodAmount(
    sender: PublicKey,
    newCurrentPeriodAmount: UInt32
  ): Bool {
    this.onlyOwner(sender);

    const packedLimits: PackedLimits = this.packedLimits.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);
    packedLimits.packed.assertEquals(PackedLimits.pack(unpacked));
    unpacked[3] = newCurrentPeriodAmount;

    const newPackedLimits: PackedLimits = PackedLimits.fromAuxiliary(unpacked);
    this.packedLimits.set(newPackedLimits);

    return Bool(true);
  }

  @method
  updatePackedLimits(sender: PublicKey, newPackedLimits: PackedLimits): Bool {
    this.onlyOwner(sender);

    this.packedLimits.getAndAssertEquals();
    this.packedLimits.set(newPackedLimits);
    return Bool(true);
  }

  /**
   * @notice Update the current period
   * @param sender the sender of the transaction
   * @param timestamp current timestamp
   */
  @method
  updatePeriod(sender: PublicKey) {
    this.onlyOwner(sender);

    const now = this.network.timestamp.getAndAssertEquals();

    const currentPeriodEnd = this.currentPeriodEnd.getAndAssertEquals();
    currentPeriodEnd.assertLessThanOrEqual(now);
    const packedLimits: PackedLimits = this.packedLimits.getAndAssertEquals();
    const unpacked: UInt32[] = PackedLimits.unpack(packedLimits.packed);

    const period: UInt64 = unpacked[0].toUInt64();

    if (currentPeriodEnd < period) {
      //       // only update the period if the current period has ended
      // period.add(now).get().assertLessThanOrEqual(now);
      // this.currentPeriodEnd.set(period.add(now));
      // unpacked[3] = UInt32.from(0);
      // const newPackedLimits: PackedLimits = PackedLimits.fromAuxiliary(unpacked);
      // this.packedLimits.set(newPackedLimits);
    }
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
    this.onlyOwner(sender);

    this.owner.set(newOwner);
    this.emitEvent('OwnershipTransferred', {
      previousOwner: sender,
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
    this.onlyOwner(sender);

    const currentVerificationKey = this.account.verificationKey;
    this.account.verificationKey.set(verificationKey);

    this.emitEvent('VerificationKeyReplaced', {
      previousVerificationKey: currentVerificationKey,
      verificationKey: verificationKey,
    });
  }
}
