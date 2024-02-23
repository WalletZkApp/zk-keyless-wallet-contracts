import { Field, MerkleTree, PrivateKey } from 'o1js';
import { Guardian } from '../guardians/Guardian.js';
import { Candidate } from './Candidate.js';
import { DEFAULT_NULLIFIER, MAX_MERKLE_TREE_HEIGHT } from '../constant.js';
import { MerkleWitnessClass } from '../general.js';

describe('Candidate', () => {
  const candidatesTree = new MerkleTree(MAX_MERKLE_TREE_HEIGHT);
  describe('#Candidate', () => {
    it('create new candidates', async () => {
      for (let i = 0; i < 8; i++) {
        const guardianAccount = PrivateKey.random().toPublicKey();
        const guardian = Guardian.from(guardianAccount, DEFAULT_NULLIFIER);
        candidatesTree.setLeaf(BigInt(i), guardian.hash());
      }
      const candidates = Array.from({ length: 5 }, (_, i) =>
        Candidate.from(
          Field(i),
          Field(0),
          new MerkleWitnessClass(candidatesTree.getWitness(BigInt(i)))
        ).hash()
      );
      console.log(candidates);
    });
  });
  describe('#addVote', () => {
    it('add a vote to a candidate', async () => {
      const guardianAccount = PrivateKey.random().toPublicKey();
      const guardian = Guardian.from(guardianAccount, DEFAULT_NULLIFIER);
      candidatesTree.setLeaf(BigInt(0), guardian.hash());

      const candidate = Candidate.from(
        Field(1),
        Field(0),
        new MerkleWitnessClass(candidatesTree.getWitness(BigInt(0)))
      );
      const newCandidate = candidate.addVote();
      expect(newCandidate.voteCount).toEqual(Field(1));
    });
  });
});
