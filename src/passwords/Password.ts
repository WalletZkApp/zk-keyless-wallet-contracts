import { Field, Poseidon, Struct, UInt64 } from 'o1js';

export class Password extends Struct({
  accountId: Field,
  password: Field,
  nonce: UInt64,
  salt: Field,
}) {
  static from(accountId: Field, password: Field, nonce: UInt64, salt: Field) {
    return new Password({ accountId, password, nonce, salt });
  }

  static empty() {
    return Password.from(Field(0), Field(0), UInt64.from(0), Field(0));
  }

  hash(): Field {
    return Poseidon.hash(
      this.accountId
        .toFields()
        .concat(this.password.toFields())
        .concat(this.nonce.toFields())
        .concat(this.salt.toFields())
    );
  }

  changePassword(newPassword: Field) {
    return Password.from(this.accountId, newPassword, this.nonce, this.salt);
  }
}
