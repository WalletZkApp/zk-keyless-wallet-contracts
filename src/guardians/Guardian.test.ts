import { Bool, Field, Poseidon, PrivateKey, PublicKey } from 'snarkyjs';
import { Guardian } from './Guardian.js';
import { DEFAULT_NULLIFIER_MESSAGE } from '../constant.js';

describe('Guardian', () => {
  describe('#Guardian().from', () => {
    it('create a new guardian', async () => {
      const guardianAccount = PrivateKey.random().toPublicKey();
      const guardian = Guardian.from(
        guardianAccount,
        DEFAULT_NULLIFIER_MESSAGE
      );
      expect(guardian.publicKey).toEqual(guardianAccount);
      expect(guardian.nullifierMessage).toEqual(DEFAULT_NULLIFIER_MESSAGE);
    });
  });

  describe('#empty().from', () => {
    it('create a new guardian', async () => {
      const guardian = Guardian.empty();
      expect(guardian.publicKey).toEqual(PublicKey.empty());
      expect(guardian.nullifierMessage).toEqual(Field(0));
    });
  });

  describe('#hash()', () => {
    it('should return hash of the guardian', async () => {
      const guardianAccount = PrivateKey.random().toPublicKey();
      const guardianHash = Poseidon.hash(
        guardianAccount.toFields().concat(DEFAULT_NULLIFIER_MESSAGE)
      );
      const newGuardian = Guardian.from(
        guardianAccount,
        DEFAULT_NULLIFIER_MESSAGE
      );
      expect(newGuardian.hash()).toEqual(guardianHash);
    });
  });

  describe('#setNullifierMessage', () => {
    it('should return hash of the guardian', async () => {
      const guardianAccount = PrivateKey.random().toPublicKey();
      const guardianHash = Poseidon.hash(
        guardianAccount.toFields().concat(DEFAULT_NULLIFIER_MESSAGE)
      );
      const newGuardian = Guardian.from(
        guardianAccount,
        DEFAULT_NULLIFIER_MESSAGE
      );
      expect(newGuardian.hash()).toEqual(guardianHash);

      const newGuardianHash = Poseidon.hash(
        guardianAccount.toFields().concat(Field(888))
      );
      const newCommitment = newGuardian.setNullifierMessage(Field(888));
      expect(newCommitment.hash()).toEqual(newGuardianHash);
    });
  });
  describe('#vote', () => {
    it('should vote', async () => {
      const guardianAccount = PrivateKey.random().toPublicKey();
      const newGuardian = Guardian.from(
        guardianAccount,
        DEFAULT_NULLIFIER_MESSAGE
      );
      expect(newGuardian.isVoted).toEqual(Bool(false));

      const newCommitment = newGuardian.vote();
      expect(newCommitment.isVoted).toEqual(Bool(true));
    });
  });
});
