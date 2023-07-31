import { Field, PublicKey, Poseidon, Struct } from 'snarkyjs';

export class Nominee extends Struct({
  publicKey: PublicKey,
  nullifierMessage: Field,
}) {
  /**
   * @notice Create a nominee with props
   * @param publicKey public key of the nominee
   * @param nullifierMessage nullifier message of the nominee
   * @returns Nominee a nominee object
   */
  static from(publicKey: PublicKey, nullifierMessage: Field) {
    return new Nominee({
      publicKey,
      nullifierMessage,
    });
  }

  /**
   * @notice Create an empty nominee
   * @returns Nominee, an empty nominee object
   */
  static empty() {
    return Nominee.from(PublicKey.empty(), Field(0));
  }

  /**
   * @returns hash of the Nominee
   */
  hash(): Field {
    return Poseidon.hash(
      this.publicKey.toFields().concat(this.nullifierMessage.toFields())
    );
  }

  /**
   * @notice Set the nullifier message of the nominee
   * @param newNullifierMessage: Field, a new nullifier message of the nominee
   * @returns NNomineeo, a nominee object with updated nullifier message
   */
  setNullifierMessage(newNullifierMessage: Field) {
    return new Nominee({
      publicKey: this.publicKey,
      nullifierMessage: newNullifierMessage,
    });
  }
}
