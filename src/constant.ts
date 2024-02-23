import { Field, UInt64 } from 'o1js';

export const MAX_MERKLE_TREE_HEIGHT = 32;
export const DEFAULT_NULLIFIER = Field(777);
export const DEFAULT_NULLIFIER_MESSAGE = '777';
export const RECOVERY_STATUS = {
  DEPLOYED: 0, // Contract is deployed, guardian and candidates are not yet set.
  STARTED: 1, // Election is started, vote_count of every candidate is 0 and nullifier for all guardian is DEFAULT_NULLIFIER.
  FINISHED: 2, // Tally is called. Recovery process is now complete, count function can be called.
};

export const WALLET_STATUS = {
  DEPLOYED: 0, // Contract is deployed
  PAUZED: 1, // Contract is paused
  RECOVERY: 2, // Contract is in recovery mode
  RECOVERY_FINISHED: 3, // Recovery process is now complete
};

export const TEST_TOTP_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

export const DEFAULT_TRANSACTION_LIMIT = 2; // 2 MINA
export const DEFAULT_DAILY_LIMIT = 5; // 5 MINA
export const DEFAULT_PERIOD = 24 * 60 * 60 * 1000;
