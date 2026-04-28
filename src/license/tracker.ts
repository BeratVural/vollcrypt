import { LicenseConfig, LicenseStatus, LicenseTier } from './types';
import * as crypto from 'crypto';

const DEFAULT_SERVER = 'https://api.vollcrypt.com';

export class LicenseTracker {
  private config: LicenseConfig;
  private trackedUsers: Set<string> = new Set();
  private status: LicenseStatus | null = null;
  private reportTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: LicenseConfig = {}) {
    this.config = {
      serverUrl: DEFAULT_SERVER,
      reportIntervalMs: 3_600_000,
      offlineFallback: true,
      ...config,
    };
  }

  /**
   * Called when the library is initialized.
   * Connects to the license server and checks the status.
   */
  async initialize(): Promise<LicenseStatus> {
    try {
      const status = await this.validateLicense();
      this.status = status;
      this.startReportingCycle();
      return status;
    } catch (error) {
      if (this.config.offlineFallback) {
        // Assume free tier if server is unreachable
        // console.warn('[Vollcrypt] License server unreachable. Offline mode active.');
        this.status = {
          valid: true,
          tier: 'free',
          monthlyActiveUsers: 0,
          limit: 500,
          limitReached: false,
        };
        return this.status;
      }
      throw error;
    }
  }

  /**
   * Called when a user session starts.
   * Raw userId is never sent to the server — only the SHA-256 hash is sent.
   *
   * @param userId The application-side identifier for the user
   */
  trackUser(userId: string): void {
    const hashed = crypto
      .createHash('sha256')
      .update(`vollcrypt:${userId}`)
      .digest('hex');

    this.trackedUsers.add(hashed);

    // Limit check
    if (this.status && this.status.limit > 0) {
      if (this.trackedUsers.size > this.status.limit) {
        this.handleLimitExceeded();
      }
    }
  }

  /**
   * Returns the current MAU count.
   */
  getMonthlyActiveUsers(): number {
    return this.trackedUsers.size;
  }

  /**
   * Returns the current license status.
   */
  getStatus(): LicenseStatus | null {
    return this.status;
  }

  /**
   * Stops periodic reporting and clears resources.
   */
  destroy(): void {
    if (this.reportTimer) {
      clearInterval(this.reportTimer);
      this.reportTimer = null;
    }
  }

  // ─── Private ──────────────────────────────────────────────────────────────

  private async validateLicense(): Promise<LicenseStatus> {
    const response = await fetch(`${this.config.serverUrl}/v1/license/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        licenseKey: this.config.licenseKey ?? null,
        sdkVersion: '0.1.0', // can be dynamically changed during build
      }),
    });

    if (!response.ok) {
      throw new Error(`License validation failed: ${response.status}`);
    }

    return response.json() as Promise<LicenseStatus>;
  }

  private async reportUsage(): Promise<void> {
    if (!this.config.licenseKey) return; // Free, anonymous usage

    try {
      await fetch(`${this.config.serverUrl}/v1/license/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          licenseKey: this.config.licenseKey,
          monthlyActiveUsers: this.trackedUsers.size,
          reportedAt: Date.now(),
        }),
      });
    } catch {
      // Report could not be sent — fail silently
    }
  }

  private startReportingCycle(): void {
    this.reportTimer = setInterval(
      () => this.reportUsage(),
      this.config.reportIntervalMs!,
    );
  }

  private handleLimitExceeded(): void {
    const tier = this.status?.tier ?? 'free';
    const limit = this.status?.limit ?? 500;

    // console.warn(
    //   `[Vollcrypt] ⚠️  Monthly active user limit reached (${limit} MAU, tier: ${tier}). ` +
    //   `Library will continue to function. ` +
    //   `Upgrade your plan at: https://github.com/BeratVural/vollcrypt`
    // );
    // DOES NOT STOP EXECUTION — warning only
  }
}
