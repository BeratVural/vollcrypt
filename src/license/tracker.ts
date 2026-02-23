import { LicenseConfig, LicenseStatus, LicenseTier } from './types';
import * as crypto from 'crypto';

const DEFAULT_SERVER = 'https://api.vollsign.io';

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
   * Kütüphane başlatılırken çağrılır.
   * Lisans sunucusuna bağlanır, durumu kontrol eder.
   */
  async initialize(): Promise<LicenseStatus> {
    try {
      const status = await this.validateLicense();
      this.status = status;
      this.startReportingCycle();
      return status;
    } catch (error) {
      if (this.config.offlineFallback) {
        // Sunucuya ulaşılamazsa ücretsiz tier varsay
        console.warn('[Vollcrypt] Lisans sunucusuna ulaşılamadı. Offline mod aktif.');
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
   * Bir kullanıcı oturumu başladığında çağrılır.
   * Ham userId asla sunucuya gönderilmez — SHA-256 hash'i gönderilir.
   *
   * @param userId Kullanıcının uygulama tarafındaki tanımlayıcısı
   */
  trackUser(userId: string): void {
    const hashed = crypto
      .createHash('sha256')
      .update(`vollcrypt:${userId}`)
      .digest('hex');

    this.trackedUsers.add(hashed);

    // Limit kontrolü
    if (this.status && this.status.limit > 0) {
      if (this.trackedUsers.size > this.status.limit) {
        this.handleLimitExceeded();
      }
    }
  }

  /**
   * Anlık MAU sayısını döndürür.
   */
  getMonthlyActiveUsers(): number {
    return this.trackedUsers.size;
  }

  /**
   * Mevcut lisans durumunu döndürür.
   */
  getStatus(): LicenseStatus | null {
    return this.status;
  }

  /**
   * Periyodik raporlamayı durdurur ve kaynakları temizler.
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
        sdkVersion: '0.1.0', // build sırasında otomatik değişebilir
      }),
    });

    if (!response.ok) {
      throw new Error(`License validation failed: ${response.status}`);
    }

    return response.json() as Promise<LicenseStatus>;
  }

  private async reportUsage(): Promise<void> {
    if (!this.config.licenseKey) return; // Ücretsiz, anonim kullanım

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
      // Rapor gönderilemedi — sessizce devam et
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

    console.warn(
      `[Vollcrypt] ⚠️  Aylık aktif kullanıcı limitine ulaşıldı (${limit} MAU, tier: ${tier}). ` +
      `Kütüphane çalışmaya devam ediyor. ` +
      `Plan yükseltmek için: https://vollsign.io/pricing`
    );
    // ÇALIŞMAYI DURDURMAZ — yalnızca uyarı
  }
}
