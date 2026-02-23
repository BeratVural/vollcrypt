-- Lisans anahtarları
CREATE TABLE licenses (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  license_key   VARCHAR(64) UNIQUE NOT NULL,
  tier          VARCHAR(20) NOT NULL DEFAULT 'free',
  -- 'free' | 'starter' | 'pro' | 'enterprise'
  owner_email   VARCHAR(255),
  stripe_customer_id    VARCHAR(255),
  stripe_subscription_id VARCHAR(255),
  mau_limit     INTEGER NOT NULL DEFAULT 500,  -- -1 = sınırsız
  is_active     BOOLEAN NOT NULL DEFAULT true,
  grace_period_until TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Aylık kullanım raporları
CREATE TABLE usage_reports (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id    UUID REFERENCES licenses(id),
  reported_mau  INTEGER NOT NULL,
  report_month  DATE NOT NULL,  -- Ayın ilk günü: 2024-02-01
  reported_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(license_id, report_month)
  -- ON CONFLICT: en yüksek değeri sakla
);

-- Aylık peak MAU indeksi
CREATE INDEX idx_usage_license_month ON usage_reports(license_id, report_month);
