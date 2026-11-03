import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadProjectConfig, envOr, envInt } from '@krusch/toolkit/config';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const defaults = {
    port: 3782,
    serviceName: 'krusch-grounded-harness',
    dbPath: './data/app.db',
    logDir: './logs'
};

const baseConfig = await loadProjectConfig(projectRoot, defaults);

export const config = Object.freeze({
    port: envInt('PORT', baseConfig.port, 3782),
    serviceName: envOr('SERVICE_NAME', baseConfig.serviceName, 'krusch-grounded-harness'),
    dbPath: envOr('DB_PATH', baseConfig.dbPath, './data/app.db'),
    logDir: envOr('LOG_DIR', baseConfig.logDir, './logs')
});
