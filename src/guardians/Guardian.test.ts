import { Bool, Field, Poseidon, PrivateKey, PublicKey } from 'snarkyjs';
import { Guardian } from './Guardian.js';
import { DEFAULT_NULLIFIER } from '../constant.js';

describe('Guardian', () => {
  describe('#Guardian().from', () => {
    it('create a new guardian', async () => {
      const guardianAccount = PrivateKey.random().toPublicKey();
      const guardian = Guardian.from(guardianAccount, DEFAULT_NULLIFIER);
      expect(guardian.publicKey).toEqual(guardianAccount);
      expect(guardian.nullifierMessage).toEqual(DEFAULT_NULLIFIER);
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
        guardianAccount.toFields().concat(DEFAULT_NULLIFIER)
      );
      const newGuardian = Guardian.from(guardianAccount, DEFAULT_NULLIFIER);
      expect(newGuardian.hash()).toEqual(guardianHash);
    });
  });
  describe('#vote', () => {
    it('should vote', async () => {
      const guardianAccount = PrivateKey.random().toPublicKey();
      const newGuardian = Guardian.from(guardianAccount, DEFAULT_NULLIFIER);
      expect(newGuardian.isVoted).toEqual(Bool(false));

      const newCommitment = newGuardian.vote();
      expect(newCommitment.isVoted).toEqual(Bool(true));
    });
  });
});
