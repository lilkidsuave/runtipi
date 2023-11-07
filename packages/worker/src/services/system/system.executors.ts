import fs from 'fs';
import path from 'path';
import si from 'systeminformation';
import { execAsync, pathExists } from '@runtipi/shared';
import { AppExecutors } from '../app/app.executors';
import { logger } from '@/lib/logger';
import { getEnv } from '@/lib/environment';

export class SystemExecutors {
  private readonly rootFolder: string;

  private readonly logger;

  constructor() {
    this.rootFolder = process.cwd();
    this.logger = logger;
  }

  private handleSystemError = (err: unknown) => {
    if (err instanceof Error) {
      this.logger.error(`An error occurred: ${err.message}`);
      return { success: false, message: err.message };
    }
    this.logger.error(`An error occurred: ${err}`);

    return { success: false, message: `An error occurred: ${err}` };
  };

  private getSystemLoad = async () => {
    const { currentLoad } = await si.currentLoad();
    const mem = await si.mem();
    const [disk0] = await si.fsSize();

    return {
      cpu: { load: currentLoad },
      memory: { total: mem.total, used: mem.used, available: mem.available },
      disk: { total: disk0?.size, used: disk0?.used, available: disk0?.available },
    };
  };

  public cleanLogs = async () => {
    // TODO: Keep in CLI only
    try {
      await this.logger.flush();
      this.logger.info('Logs cleaned successfully');

      return { success: true, message: '' };
    } catch (e) {
      return this.handleSystemError(e);
    }
  };

  public systemInfo = async () => {
    try {
      const { rootFolderHost } = getEnv();
      const systemLoad = await this.getSystemLoad();

      await fs.promises.writeFile(path.join(rootFolderHost, 'state', 'system-info.json'), JSON.stringify(systemLoad, null, 2));
      await fs.promises.chmod(path.join(rootFolderHost, 'state', 'system-info.json'), 0o777);

      return { success: true, message: '' };
    } catch (e) {
      return this.handleSystemError(e);
    }
  };

  /**
   * This method will stop Tipi
   * It will stop all the apps and then stop the main containers.
   */
  public stop = async () => {
    // TODO: Keep in CLI only
    try {
      if (await pathExists(path.join(this.rootFolder, 'apps'))) {
        const apps = await fs.promises.readdir(path.join(this.rootFolder, 'apps'));
        const appExecutor = new AppExecutors();

        // eslint-disable-next-line no-restricted-syntax
        for (const app of apps) {
          // eslint-disable-next-line no-await-in-loop
          await appExecutor.stopApp(app, {}, true);
        }
      }

      this.logger.info('Stopping main containers...');
      await execAsync('docker compose down --remove-orphans --rmi local');

      return { success: true, message: 'Tipi stopped' };
    } catch (e) {
      return this.handleSystemError(e);
    }
  };

  /**
   * This method will stop and start Tipi.
   */
  public restart = async () => {
    // TODO: How to restart if itself is in the stack? Probably not relevant to keep
    try {
      await this.stop();
      return { success: true, message: '' };
    } catch (e) {
      return this.handleSystemError(e);
    }
  };

  /**
   * This method will create a password change request file in the state folder.
   */
  public resetPassword = async () => {
    // TODO: Keep in CLI only
    try {
      const { rootFolderHost } = getEnv();
      await fs.promises.writeFile(path.join(rootFolderHost, 'state', 'password-change-request'), '');
      return { success: true, message: '' };
    } catch (e) {
      return this.handleSystemError(e);
    }
  };
}
