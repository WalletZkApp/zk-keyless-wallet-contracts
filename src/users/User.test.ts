import { Field, Poseidon, PrivateKey, PublicKey } from 'o1js';
import { User } from './User.js';

describe('User', () => {
  describe('#User().from', () => {
    it('create a new User', async () => {
      const user = User.from(Field(100), Field(1));
      expect(user.userId).toEqual(Field(100));
      expect(user.nullifierMessage).toEqual(Field(1));
    });
  });

  describe('#empty().from', () => {
    it('create a new User', async () => {
      const user = User.empty();
      expect(user.userId).toEqual(Field(0));
      expect(user.nullifierMessage).toEqual(Field(0));
    });
  });

  describe('#hash()', () => {
    it('should return hash of the User', async () => {
      const userHash = Poseidon.hash(Field(1).toFields().concat(Field(2)));
      const newUser = User.from(Field(1), Field(2));
      expect(newUser.hash()).toEqual(userHash);
    });
  });

  describe('#setNullifierMessage', () => {
    it('should return hash of the User', async () => {
      const userHash = Poseidon.hash(Field(1).toFields().concat(Field(2)));
      const newUser = User.from(Field(1), Field(2));
      expect(newUser.hash()).toEqual(userHash);

      const newUserHash = Poseidon.hash(Field(1).toFields().concat(Field(888)));
      const newCommitment = newUser.setNullifierMessage(Field(888));
      expect(newCommitment.hash()).toEqual(newUserHash);
    });
  });
});
