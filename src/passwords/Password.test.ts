import { Field, Poseidon, UInt64 } from 'snarkyjs';
import { Password } from './Password.js';

const SALT = Math.floor(Math.random() * 999999);
const DEFAULT_PASSWORD = Field(123);

describe('Password', () => {
  describe('#Password().from', () => {
    it('should create a new password', async () => {
      const password = Password.from(
        Field(1),
        DEFAULT_PASSWORD,
        UInt64.from(1),
        Field(SALT)
      );
      expect(password.accountId).toEqual(Field(1));
      expect(password.password).toEqual(DEFAULT_PASSWORD);
      expect(password.nonce).toEqual(UInt64.from(1));
      expect(password.salt).toEqual(Field(SALT));
    });
  });
  describe('#empty().from', () => {
    it('should create an empty password', async () => {
      const password = Password.empty();
      expect(password.accountId).toEqual(Field(0));
      expect(password.password).toEqual(Field(0));
      expect(password.nonce).toEqual(UInt64.from(0));
      expect(password.salt).toEqual(Field(0));
    });
  });
  describe('#hash()', () => {
    it('should return hash of the password', async () => {
      const password = Password.from(
        Field(1),
        DEFAULT_PASSWORD,
        UInt64.from(1),
        Field(SALT)
      );
      const passwordHash = Poseidon.hash(
        password.accountId
          .toFields()
          .concat(password.password.toFields())
          .concat(password.nonce.toFields())
          .concat(password.salt.toFields())
      );
      expect(password.hash()).toEqual(passwordHash);
    });
  });
  describe('#changePassword', () => {
    it('should able to change password', async () => {
      const password = Password.from(
        Field(1),
        DEFAULT_PASSWORD,
        UInt64.from(1),
        Field(SALT)
      );
      const passwordHash = Poseidon.hash(
        password.accountId
          .toFields()
          .concat(password.password.toFields())
          .concat(password.nonce.toFields())
          .concat(password.salt.toFields())
      );
      expect(password.hash()).toEqual(passwordHash);

      const newPassword = Field(888);
      const newPasswordHash = Poseidon.hash(
        password.accountId
          .toFields()
          .concat(newPassword.toFields())
          .concat(password.nonce.toFields())
          .concat(password.salt.toFields())
      );
      const newCommitment = password.changePassword(newPassword);
      expect(newCommitment.hash()).toEqual(newPasswordHash);
    });
  });
});
