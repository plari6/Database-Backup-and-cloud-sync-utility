// Library entry: use the engine from your own scripts (n8n Code node, custom schedulers, tests).
export { loadConfig, normalizeConfig, selectJobs, ConfigError } from './config.js';
export {
  createContext, backupJob, listBackups, resolveBackup, verifyBackup, restoreBackup,
  pruneJob, pruneDestination, jobStatus, checkStale, APP_VERSION,
} from './engine.js';
export {
  createKeyring, createEncryptStream, createDecryptStream, generateSymmetricKey,
  generateRecipientKeyPair, readFileHeader, DecryptError,
} from './crypto.js';
export { applyRetention } from './retention.js';
export { startDaemon } from './scheduler.js';
export { notify } from './notify.js';
export { createDriver, DRIVER_TYPES } from './drivers/index.js';
export { getDestination, objectKeys } from './destinations/index.js';
