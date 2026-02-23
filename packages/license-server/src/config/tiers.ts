import dotenv from 'dotenv';
dotenv.config();

export const TIERS = {
  free: {
    name: 'Free',
    mauLimit: 500,
    priceMonthly: 0,
    stripePriceId: null,
    features: [
      'Tüm kriptografik primitifler',
      'AES-256-GCM, Ed25519, X25519',
      'ML-KEM-768 (PQC)',
      'Topluluk desteği',
    ],
  },
  starter: {
    name: 'Starter',
    mauLimit: 5_000,
    priceMonthly: 5,
    stripePriceId: process.env.STRIPE_PRICE_STARTER,
    features: [
      'Free tier + her şey',
      '5.000 MAU',
      'Key Transparency',
      'Sealed Sender',
      'E-posta desteği',
    ],
  },
  pro: {
    name: 'Pro',
    mauLimit: 50_000,
    priceMonthly: 49,
    stripePriceId: process.env.STRIPE_PRICE_PRO,
    features: [
      'Starter + her şey',
      '50.000 MAU',
      'PCS Ratchet',
      'Öncelikli destek',
      'SLA garantisi',
    ],
  },
  enterprise: {
    name: 'Enterprise',
    mauLimit: -1,
    priceMonthly: -1,
    stripePriceId: null,
    features: [
      'Pro + her şey',
      'Sınırsız MAU',
      'Özel lisans (kaynak kodu açma yok)',
      'Dedicated destek',
      'On-premise kurulum',
    ],
  },
} as const;

export type TierKey = keyof typeof TIERS;
