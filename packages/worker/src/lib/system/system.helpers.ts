/* eslint-disable no-await-in-loop */
/* eslint-disable no-restricted-syntax */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { envMapToString, envStringToMap, execAsync, pathExists, settingsSchema } from '@runtipi/shared';
import { logger } from '../logger/logger';
import { getRepoHash } from '../../services/repo/repo.helpers';

type EnvKeys =
  | 'APPS_REPO_ID'
  | 'APPS_REPO_URL'
  | 'TZ'
  | 'INTERNAL_IP'
  | 'DNS_IP'
  | 'ARCHITECTURE'
  | 'TIPI_VERSION'
  | 'JWT_SECRET'
  | 'ROOT_FOLDER_HOST'
  | 'NGINX_PORT'
  | 'NGINX_PORT_SSL'
  | 'DOMAIN'
  | 'STORAGE_PATH'
  | 'POSTGRES_PORT'
  | 'POSTGRES_HOST'
  | 'POSTGRES_DBNAME'
  | 'POSTGRES_PASSWORD'
  | 'POSTGRES_USERNAME'
  | 'REDIS_HOST'
  | 'REDIS_PASSWORD'
  | 'LOCAL_DOMAIN'
  | 'DEMO_MODE'
  | 'GUEST_DASHBOARD'
  | 'TIPI_GID'
  | 'TIPI_UID'
  // eslint-disable-next-line @typescript-eslint/ban-types
  | (string & {});

const OLD_DEFAULT_REPO_URL = 'https://github.com/meienberger/runtipi-appstore';
const DEFAULT_REPO_URL = 'https://github.com/runtipi/runtipi-appstore';

/**
 * Reads and returns the generated seed
 */
const getSeed = async () => {
  const rootFolder = process.cwd();

  const seedFilePath = path.join(rootFolder, 'state', 'seed');

  if (!(await pathExists(seedFilePath))) {
    throw new Error('Seed file not found');
  }

  const seed = await fs.promises.readFile(seedFilePath, 'utf-8');

  return seed;
};

/**
 * Derives a new entropy value from the provided entropy and the seed
 * @param {string} entropy - The entropy value to derive from
 */
const deriveEntropy = async (entropy: string) => {
  const seed = await getSeed();
  const hmac = crypto.createHmac('sha256', seed);
  hmac.update(entropy);

  return hmac.digest('hex');
};

/**
 * Generates a random seed if it does not exist yet
 */
const generateSeed = async (rootFolder: string) => {
  if (!(await pathExists(path.join(rootFolder, 'state', 'seed')))) {
    const randomBytes = crypto.randomBytes(32);
    const seed = randomBytes.toString('hex');

    await fs.promises.writeFile(path.join(rootFolder, 'state', 'seed'), seed);
  }
};

/**
 * Will return the first internal IP address of the current system
 */
const getInternalIp = () => {
  const interfaces = os.networkInterfaces();

  for (let i = 0; i < Object.keys(interfaces).length; i += 1) {
    const devName = Object.keys(interfaces)[i];
    const iface = interfaces[devName || ''];

    const length = iface?.length || 0;
    for (let j = 0; j < length; j += 1) {
      const alias = iface?.[j];

      if (alias && alias.family === 'IPv4' && alias.address !== '127.0.0.1' && !alias.internal) return alias.address;
    }
  }

  return '0.0.0.0';
};

/**
 * Returns the architecture of the current system
 */
const getArchitecture = () => {
  const arch = os.arch();

  if (arch === 'arm64') return 'arm64';
  if (arch === 'x64') return 'amd64';

  throw new Error(`Unsupported architecture: ${arch}`);
};

/**
 * Generates a valid .env file from the settings.json file
 */
export const generateSystemEnvFile = async () => {
  const rootFolder = process.cwd();
  await fs.promises.mkdir(path.join(rootFolder, 'state'), { recursive: true });
  const settingsFilePath = path.join(rootFolder, 'state', 'settings.json');
  const envFilePath = path.join(rootFolder, '.env');

  if (!(await pathExists(envFilePath))) {
    await fs.promises.writeFile(envFilePath, '');
  }

  const envFile = await fs.promises.readFile(envFilePath, 'utf-8');
  const envMap: Map<EnvKeys, string> = envStringToMap(envFile);

  if (!(await pathExists(settingsFilePath))) {
    await fs.promises.writeFile(settingsFilePath, JSON.stringify({}));
  }

  const settingsFile = await fs.promises.readFile(settingsFilePath, 'utf-8');

  const settings = settingsSchema.safeParse(JSON.parse(settingsFile));

  if (!settings.success) {
    throw new Error(`Invalid settings.json file: ${settings.error.message}`);
  }

  await generateSeed(rootFolder);

  const { data } = settings;

  if (data.appsRepoUrl === OLD_DEFAULT_REPO_URL) {
    data.appsRepoUrl = DEFAULT_REPO_URL;
  }

  const jwtSecret = envMap.get('JWT_SECRET') || (await deriveEntropy('jwt_secret'));
  const repoId = getRepoHash(data.appsRepoUrl || DEFAULT_REPO_URL);
  const postgresPassword = envMap.get('POSTGRES_PASSWORD') || (await deriveEntropy('postgres_password'));
  const redisPassword = envMap.get('REDIS_PASSWORD') || (await deriveEntropy('redis_password'));

  const version = await fs.promises.readFile(path.join(rootFolder, 'VERSION'), 'utf-8');

  envMap.set('APPS_REPO_ID', repoId);
  envMap.set('APPS_REPO_URL', data.appsRepoUrl || DEFAULT_REPO_URL);
  envMap.set('TZ', Intl.DateTimeFormat().resolvedOptions().timeZone);
  envMap.set('INTERNAL_IP', data.listenIp || getInternalIp());
  envMap.set('DNS_IP', data.dnsIp || '9.9.9.9');
  envMap.set('ARCHITECTURE', getArchitecture());
  envMap.set('TIPI_VERSION', version);
  envMap.set('JWT_SECRET', jwtSecret);
  envMap.set('ROOT_FOLDER_HOST', rootFolder);
  envMap.set('NGINX_PORT', String(data.port || 80));
  envMap.set('NGINX_PORT_SSL', String(data.sslPort || 443));
  envMap.set('DOMAIN', data.domain || 'example.com');
  envMap.set('STORAGE_PATH', data.storagePath || rootFolder);
  envMap.set('POSTGRES_HOST', 'tipi-db');
  envMap.set('POSTGRES_DBNAME', 'tipi');
  envMap.set('POSTGRES_USERNAME', 'tipi');
  envMap.set('POSTGRES_PASSWORD', postgresPassword);
  envMap.set('POSTGRES_PORT', String(5432));
  envMap.set('REDIS_HOST', 'tipi-redis');
  envMap.set('REDIS_PASSWORD', redisPassword);
  envMap.set('DEMO_MODE', String(data.demoMode || 'false'));
  envMap.set('GUEST_DASHBOARD', String(data.guestDashboard || 'false'));
  envMap.set('LOCAL_DOMAIN', data.localDomain || 'tipi.lan');
  envMap.set('NODE_ENV', 'production');

  const currentUserGroup = process.getgid ? String(process.getgid()) : '1000';
  const currentUserId = process.getuid ? String(process.getuid()) : '1000';

  envMap.set('TIPI_GID', currentUserGroup);
  envMap.set('TIPI_UID', currentUserId);

  await fs.promises.writeFile(envFilePath, envMapToString(envMap));

  return envMap;
};

/**
 * Sets the value of an environment variable in the .env file
 *
 * @param {string} key - The key of the environment variable
 * @param {string} value - The value of the environment variable
 */
export const setEnvVariable = async (key: EnvKeys, value: string) => {
  const rootFolder = process.cwd();

  const envFilePath = path.join(rootFolder, '.env');

  if (!(await pathExists(envFilePath))) {
    await fs.promises.writeFile(envFilePath, '');
  }

  const envFile = await fs.promises.readFile(envFilePath, 'utf-8');
  const envMap: Map<EnvKeys, string> = envStringToMap(envFile);

  envMap.set(key, value);

  await fs.promises.writeFile(envFilePath, envMapToString(envMap));
};

/**
 * Copies the system files from the assets folder to the current working directory
 */
export const copySystemFiles = async () => {
  // Remove old unused files
  if (await pathExists(path.join(process.cwd(), 'scripts'))) {
    logger.info('Removing old scripts folder');
    await fs.promises.rmdir(path.join(process.cwd(), 'scripts'), { recursive: true });
  }

  const assetsFolder = path.join('/app', 'assets');

  // Copy docker-compose.yml file
  logger.info('Copying file docker-compose.yml');
  await fs.promises.copyFile(path.join(assetsFolder, 'docker-compose.yml'), path.join(process.cwd(), 'docker-compose.yml'));

  // Copy VERSION file
  logger.info('Copying file VERSION');
  await fs.promises.copyFile(path.join(assetsFolder, 'VERSION'), path.join(process.cwd(), 'VERSION'));

  // Copy traefik folder from assets
  logger.info('Creating traefik folders');
  await fs.promises.mkdir(path.join(process.cwd(), 'traefik', 'dynamic'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'traefik', 'shared'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'traefik', 'tls'), { recursive: true });

  logger.info('Copying traefik files');
  await fs.promises.copyFile(path.join(assetsFolder, 'traefik', 'traefik.yml'), path.join(process.cwd(), 'traefik', 'traefik.yml'));
  await fs.promises.copyFile(path.join(assetsFolder, 'traefik', 'dynamic', 'dynamic.yml'), path.join(process.cwd(), 'traefik', 'dynamic', 'dynamic.yml'));

  // Create base folders
  logger.info('Creating base folders');
  await fs.promises.mkdir(path.join(process.cwd(), 'apps'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'app-data'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'state'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'repos'), { recursive: true });

  // Create media folders
  logger.info('Creating media folders');
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'torrents', 'watch'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'torrents', 'complete'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'torrents', 'incomplete'), { recursive: true });

  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'usenet', 'watch'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'usenet', 'complete'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'usenet', 'incomplete'), { recursive: true });

  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'downloads', 'watch'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'downloads', 'complete'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'downloads', 'incomplete'), { recursive: true });

  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'data', 'books'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'data', 'comics'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'data', 'movies'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'data', 'music'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'data', 'tv'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'data', 'podcasts'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'data', 'images'), { recursive: true });
  await fs.promises.mkdir(path.join(process.cwd(), 'media', 'data', 'roms'), { recursive: true });
};

/**
 * Given a domain, generates the TLS certificates for it to be used with Traefik
 *
 * @param {string} data.domain The domain to generate the certificates for
 */
export const generateTlsCertificates = async (data: { domain?: string }) => {
  if (!data.domain) {
    return;
  }

  // If the certificate already exists, don't generate it again
  if (await pathExists(path.join(process.cwd(), 'traefik', 'tls', `${data.domain}.txt`))) {
    logger.info(`TLS certificate for ${data.domain} already exists`);
    return;
  }

  // Remove old certificates
  if (await pathExists(path.join(process.cwd(), 'traefik', 'tls', 'cert.pem'))) {
    logger.info('Removing old TLS certificate');
    await fs.promises.unlink(path.join(process.cwd(), 'traefik', 'tls', 'cert.pem'));
  }
  if (await pathExists(path.join(process.cwd(), 'traefik', 'tls', 'key.pem'))) {
    logger.info('Removing old TLS key');
    await fs.promises.unlink(path.join(process.cwd(), 'traefik', 'tls', 'key.pem'));
  }

  const subject = `/O=runtipi.io/OU=IT/CN=*.${data.domain}/emailAddress=webmaster@${data.domain}`;
  const subjectAltName = `DNS:*.${data.domain},DNS:${data.domain}`;

  try {
    logger.info(`Generating TLS certificate for ${data.domain}`);
    await execAsync(`openssl req -x509 -newkey rsa:4096 -keyout traefik/tls/key.pem -out traefik/tls/cert.pem -days 365 -subj "${subject}" -addext "subjectAltName = ${subjectAltName}" -nodes`);
    logger.info(`Writing txt file for ${data.domain}`);
    await fs.promises.writeFile(path.join(process.cwd(), 'traefik', 'tls', `${data.domain}.txt`), '');
  } catch (error) {
    logger.error(error);
  }
};

export const ensureFilePermissions = async (rootFolder: string) => {
  const filesAndFolders = [
    path.join(rootFolder, 'apps'),
    path.join(rootFolder, 'logs'),
    path.join(rootFolder, 'repos'),
    path.join(rootFolder, 'state'),
    path.join(rootFolder, 'traefik'),
    path.join(rootFolder, '.env'),
    path.join(rootFolder, 'VERSION'),
    path.join(rootFolder, 'docker-compose.yml'),
  ];

  const files600 = [path.join(rootFolder, 'traefik', 'shared', 'acme.json')];

  // Give permission to read and write to all files and folders for the current user
  for (const fileOrFolder of filesAndFolders) {
    if (await pathExists(fileOrFolder)) {
      await execAsync(`chmod -R a+rwx ${fileOrFolder}`).catch(() => {});
    }
  }

  for (const fileOrFolder of files600) {
    if (await pathExists(fileOrFolder)) {
      await execAsync(`chmod 600 ${fileOrFolder}`).catch(() => {});
    }
  }
};
