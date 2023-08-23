import { Field, Poseidon, PrivateKey, PublicKey } from 'snarkyjs';
import { DEFAULT_NULLIFIER } from '../constant.js';
import { Nominee } from './Nominee.js';

describe('Nominee', () => {
  describe('#Nominee().from', () => {
    it('create a new nominee', async () => {
      const nomineeAccount = PrivateKey.random().toPublicKey();
      const nominee = Nominee.from(nomineeAccount, DEFAULT_NULLIFIER);
      expect(nominee.publicKey).toEqual(nomineeAccount);
      expect(nominee.nullifierMessage).toEqual(DEFAULT_NULLIFIER);
    });
  });

  describe('#empty().from', () => {
    it('create a new nominee', async () => {
      const nominee = Nominee.empty();
      expect(nominee.publicKey).toEqual(PublicKey.empty());
      expect(nominee.nullifierMessage).toEqual(Field(0));
    });
  });

  describe('#hash()', () => {
    it('should return hash of the nominee', async () => {
      const nomineeAccount = PrivateKey.random().toPublicKey();
      const nomineeHash = Poseidon.hash(
        nomineeAccount.toFields().concat(Field(DEFAULT_NULLIFIER))
      );
      const newGuardian = Nominee.from(
        nomineeAccount,
        Field(DEFAULT_NULLIFIER)
      );
      expect(newGuardian.hash()).toEqual(nomineeHash);
    });
  });

  describe('#setNullifierMessage', () => {
    it('should return hash of the nominee', async () => {
      const nomineeAccount = PrivateKey.random().toPublicKey();
      const nomineeHash = Poseidon.hash(
        nomineeAccount.toFields().concat(Field(DEFAULT_NULLIFIER))
      );
      const newGuardian = Nominee.from(
        nomineeAccount,
        Field(DEFAULT_NULLIFIER)
      );
      expect(newGuardian.hash()).toEqual(nomineeHash);

      const newGuardianHash = Poseidon.hash(
        nomineeAccount.toFields().concat(Field(888))
      );
      const newCommitment = newGuardian.setNullifierMessage(Field(888));
      expect(newCommitment.hash()).toEqual(newGuardianHash);
    });
  });
});
