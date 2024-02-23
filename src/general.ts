import { MerkleWitness } from 'o1js';
import { MAX_MERKLE_TREE_HEIGHT } from './constant.js';

export class MerkleWitnessClass extends MerkleWitness(MAX_MERKLE_TREE_HEIGHT) {}
