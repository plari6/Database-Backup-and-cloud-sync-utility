import { postgresDriver } from './postgres.js';
import { mongodbDriver } from './mongodb.js';
import { mysqlDriver } from './mysql.js';
import { sqliteDriver } from './sqlite.js';
import { commandDriver } from './command.js';

export const DRIVER_TYPES = ['postgres', 'mongodb', 'mysql', 'sqlite', 'command'];

const FACTORIES = {
  postgres: postgresDriver,
  mongodb: mongodbDriver,
  mysql: mysqlDriver,
  sqlite: sqliteDriver,
  command: commandDriver,
};

export function createDriver(job) {
  const f = FACTORIES[job.type];
  if (!f) throw new Error(`Unknown job type "${job.type}"`);
  return f(job, { timeoutMs: (job.timeoutMinutes || 180) * 60_000 });
}
