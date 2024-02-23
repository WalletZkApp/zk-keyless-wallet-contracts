import { Field, Poseidon, Struct, MerkleWitness } from 'o1js';
export { Candidate, CandidateWitness };

class CandidateWitness extends MerkleWitness(8) {}

class Candidate extends Struct({
  key: Field, // Tree index
  voteCount: Field,
  witness: CandidateWitness,
}) {
  /**
   * @notice: Create a candidate with props
   * @param key: key of the candidate
   * @param voteCount: vote count of the candidate
   * @param witness: witness of the candidate
   * @returns Candidate, a candidate object
   */
  static from(key: Field, voteCount: Field, witness: CandidateWitness) {
    return new Candidate({ key, voteCount, witness });
  }

  /**
   * @notice: Create an empty candidate
   * @returns Candidate, an empty candidate object
   */
  static empty() {
    return Candidate.from(Field(0), Field(0), CandidateWitness.empty());
  }

  /**
   * @returns hash of the Candidate
   */
  hash(): Field {
    return Poseidon.hash(this.key.toFields().concat(this.voteCount.toFields()));
  }

  /**
   * @notice: Add a vote to the candidate
   * @returns Candidate, a candidate object with updated vote count
   */
  addVote(): Candidate {
    return new Candidate({
      key: this.key,
      voteCount: this.voteCount.add(1),
      witness: this.witness,
    });
  }
}
