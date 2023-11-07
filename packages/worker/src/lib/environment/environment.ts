import { z } from 'zod';
import dotenv from 'dotenv';

if (process.env.NODE_ENV === 'development') {
  dotenv.config({ path: '.env.dev', override: true });
} else {
  dotenv.config({ override: true });
}

const environmentSchema = z
  .object({
    STORAGE_PATH: z.string(),
    ROOT_FOLDER_HOST: z.string(),
    APPS_REPO_ID: z.string(),
    ARCHITECTURE: z.enum(['arm64', 'amd64']),
    INTERNAL_IP: z.string().ip().or(z.literal('localhost')),
    TIPI_VERSION: z.string(),
    REDIS_PASSWORD: z.string(),
    REDIS_HOST: z.string(),
    POSTGRES_PORT: z.string(),
    POSTGRES_USERNAME: z.string(),
    POSTGRES_PASSWORD: z.string(),
    POSTGRES_DBNAME: z.string(),
    POSTGRES_HOST: z.string(),
  })
  .transform((env) => {
    const {
      STORAGE_PATH,
      ARCHITECTURE,
      ROOT_FOLDER_HOST,
      APPS_REPO_ID,
      INTERNAL_IP,
      TIPI_VERSION,
      REDIS_PASSWORD,
      REDIS_HOST,
      POSTGRES_DBNAME,
      POSTGRES_PASSWORD,
      POSTGRES_USERNAME,
      POSTGRES_PORT,
      POSTGRES_HOST,
      ...rest
    } = env;

    return {
      storagePath: STORAGE_PATH,
      rootFolderHost: ROOT_FOLDER_HOST,
      appsRepoId: APPS_REPO_ID,
      arch: ARCHITECTURE,
      tipiVersion: TIPI_VERSION,
      internalIp: INTERNAL_IP,
      redisPassword: REDIS_PASSWORD,
      redisHost: REDIS_HOST,
      postgresPort: POSTGRES_PORT,
      postgresUsername: POSTGRES_USERNAME,
      postgresPassword: POSTGRES_PASSWORD,
      postgresDatabase: POSTGRES_DBNAME,
      postgresHost: POSTGRES_HOST,
      ...rest,
    };
  });

export const getEnv = () => environmentSchema.parse(process.env);
