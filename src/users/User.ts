import { Field, PublicKey, Poseidon, Struct } from 'snarkyjs';

export class User extends Struct({
  userId: Field,
  nullifierMessage: Field,
}) {
  /**
   * @notice: Create a user with props
   * @param userId: id of the user
   * @param nullifierMessage: nullifier message of the user
   * @returns User, a user object
   */
  static from(userId: Field, nullifierMessage: Field) {
    return new User({
      userId,
      nullifierMessage,
    });
  }

  /**
   * @notice: Create an empty user
   * @returns User, an empty user object
   */
  static empty() {
    return User.from(Field(0), Field(0));
  }

  /**
   * @returns hash of the User
   */
  hash(): Field {
    return Poseidon.hash(
      this.userId.toFields().concat(this.nullifierMessage.toFields())
    );
  }

  /**
   * @notice: Set the nullifier message of the user
   * @param newNullifierMessage: Field, a new nullifier message of the guardian
   * @returns User, a user object with updated nullifier message
   */
  setNullifierMessage(newNullifierMessage: Field) {
    return new User({
      userId: this.userId,
      nullifierMessage: newNullifierMessage,
    });
  }
}
