import { Field, Poseidon, Struct, UInt64 } from 'o1js';

export class Otp extends Struct({
  time: UInt64,
  token: Field,
}) {
  static from(time: UInt64, token: Field) {
    return new Otp({ time, token });
  }

  static empty() {
    return Otp.from(UInt64.from(0), Field(0));
  }

  hash(): Field {
    return Poseidon.hash(this.time.toFields().concat(this.token.toFields()));
  }
}
