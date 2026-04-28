export type LicenseTier = 'free' | 'starter' | 'pro' | 'enterprise';

export interface LicenseConfig {
  /** npm paketinden alınan lisans anahtarı. Ücretsiz kullanımda opsiyonel. */
  licenseKey?: string;
  /** License server URL. Default: https://api.vollcrypt.com */
  serverUrl?: string;
  /** MAU rapor aralığı (ms). Varsayılan: 3_600_000 (1 saat) */
  reportIntervalMs?: number;
  /** true: Lisans sunucusuna bağlanılamasa bile çalışmaya devam et */
  offlineFallback?: boolean;
}

export interface LicenseStatus {
  valid: boolean;
  tier: LicenseTier;
  monthlyActiveUsers: number;
  limit: number;           // -1 = sınırsız (enterprise)
  limitReached: boolean;
  gracePeriodDaysLeft?: number;
}

export interface LicenseLimits {
  free:       { mau: 500,    price: 0 };
  starter:    { mau: 5_000,  price: 5 };
  pro:        { mau: 50_000, price: 49 };
  enterprise: { mau: -1,     price: -1 };  // görüşme
}
