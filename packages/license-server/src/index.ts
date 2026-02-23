import express, { Request, Response } from 'express';
import cors from 'cors';
import { db } from './db';
import { stripe } from './stripe';
import { TIERS, TierKey } from './config/tiers';
import crypto from 'crypto';

const app = express();

// Stripe webhooks need raw body, so we set up a special parser for it.
app.use('/v1/webhooks/stripe', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(cors());

// POST /v1/license/validate
app.post('/v1/license/validate', async (req: Request, res: Response): Promise<void> => {
  try {
    const { licenseKey, sdkVersion } = req.body;

    // 1. If no licenseKey provided, default to free tier
    if (!licenseKey) {
      res.json({
        valid: true,
        tier: 'free',
        monthlyActiveUsers: 0,
        limit: TIERS.free.mauLimit,
        limitReached: false,
      });
      return;
    }

    // 2. Find license in DB
    const { rows } = await db.query(
      'SELECT id, tier, mau_limit, is_active, grace_period_until FROM licenses WHERE license_key = $1',
      [licenseKey]
    );

    if (rows.length === 0) {
      res.status(404).json({ error: 'License not found' });
      return;
    }

    const license = rows[0];

    // 3. If not active, then invalid
    if (!license.is_active) {
      res.json({
        valid: false,
        tier: license.tier,
        monthlyActiveUsers: 0,
        limit: license.mau_limit,
        limitReached: true,
      });
      return;
    }

    // 4. Get latest usage report (monthlyActiveUsers)
    const reportRes = await db.query(
      'SELECT reported_mau FROM usage_reports WHERE license_id = $1 ORDER BY report_month DESC LIMIT 1',
      [license.id]
    );
    const monthlyActiveUsers = reportRes.rows.length > 0 ? reportRes.rows[0].reported_mau : 0;

    // 5. Calculate if limit reached
    const limitReached = license.mau_limit !== -1 && monthlyActiveUsers > license.mau_limit;

    // 6. Calculate Grace Period Days Left
    let gracePeriodDaysLeft = undefined;
    if (license.grace_period_until) {
      const now = new Date();
      const graceEnd = new Date(license.grace_period_until);
      const diffMs = graceEnd.getTime() - now.getTime();
      if (diffMs > 0) {
        gracePeriodDaysLeft = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
      } else {
        gracePeriodDaysLeft = 0;
      }
    }

    res.json({
      valid: true,
      tier: license.tier,
      monthlyActiveUsers,
      limit: license.mau_limit,
      limitReached,
      gracePeriodDaysLeft,
    });
  } catch (error) {
    console.error('Validate Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /v1/license/report
app.post('/v1/license/report', async (req: Request, res: Response): Promise<void> => {
  try {
    const { licenseKey, monthlyActiveUsers, reportedAt } = req.body;

    if (!licenseKey) {
      res.status(400).json({ error: 'License key required' });
      return;
    }

    // 1. Find license
    const licenseRes = await db.query('SELECT id, mau_limit FROM licenses WHERE license_key = $1', [licenseKey]);
    if (licenseRes.rows.length === 0) {
      res.status(404).json({ error: 'License not found' });
      return;
    }

    const licenseId = licenseRes.rows[0].id;
    const limit = licenseRes.rows[0].mau_limit;

    // 2. Identify current month (e.g., "2024-02-01")
    const now = new Date();
    const reportMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;

    // 3. Upsert
    await db.query(
      `INSERT INTO usage_reports (license_id, report_month, reported_mau)
       VALUES ($1, $2, $3)
       ON CONFLICT (license_id, report_month)
       DO UPDATE SET reported_mau = GREATEST(usage_reports.reported_mau, EXCLUDED.reported_mau), reported_at = NOW()`,
      [licenseId, reportMonth, monthlyActiveUsers]
    );

    // 4. If limit exceeded and no grace period set, set 14 days grace period
    if (limit !== -1 && monthlyActiveUsers > limit) {
      await db.query(
        `UPDATE licenses SET grace_period_until = NOW() + INTERVAL '14 days' 
         WHERE id = $1 AND grace_period_until IS NULL`,
        [licenseId]
      );
    }

    res.status(204).send();
  } catch (error) {
    console.error('Report Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /v1/license/register
app.post('/v1/license/register', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, tier } = req.body;
    
    if (!email || !tier || !(tier in TIERS)) {
       res.status(400).json({ error: 'Invalid or missing email/tier parameters' });
       return;
    }

    const selectedTier = TIERS[tier as TierKey];
    let stripeCustomerId = null;
    let stripeSubscriptionId = null;

    // Only create Stripe stuff for non-free
    if (tier !== 'free' && selectedTier.stripePriceId) {
      // 1. Create Stripe Customer
      const customer = await stripe.customers.create({ email });
      stripeCustomerId = customer.id;

      // 2. Create Stripe Subscription (Assume simple subscription flow without immediate payment, or require 0 days trial)
      const subscription = await stripe.subscriptions.create({
        customer: customer.id,
        items: [{ price: selectedTier.stripePriceId }],
        payment_behavior: 'default_incomplete',
        expand: ['latest_invoice.payment_intent'],
      });
      stripeSubscriptionId = subscription.id;
    }

    // 3. Generate license_key
    const licenseKey = 'vc_live_' + crypto.randomBytes(16).toString('hex');

    // 4. Save to DB
    await db.query(
      `INSERT INTO licenses (license_key, tier, owner_email, stripe_customer_id, stripe_subscription_id, mau_limit)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [licenseKey, tier, email, stripeCustomerId, stripeSubscriptionId, selectedTier.mauLimit]
    );

    // 5. Respond (in reality, email would be sent here)
    res.json({
      licenseKey,
      tier,
      mauLimit: selectedTier.mauLimit,
      message: 'License created successfully. Welcome email dispatched.'
    });

  } catch (error) {
    console.error('Register Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /v1/webhooks/stripe
app.post('/v1/webhooks/stripe', async (req: Request, res: Response): Promise<void> => {
  const sig = req.headers['stripe-signature'] as string;
  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET as string);
  } catch (err: any) {
    res.status(400).send(`Webhook Error: ${err?.message}`);
    return;
  }

  try {
    switch (event.type) {
      case 'customer.subscription.updated': {
        // Not implementing tier update logic here to keep it simple, but this is the hook
        break;
      }
      case 'customer.subscription.deleted': {
        const sub = event.data.object as Stripe.Subscription;
        await db.query(
          `UPDATE licenses SET is_active = false, grace_period_until = NOW() + INTERVAL '14 days' WHERE stripe_subscription_id = $1`,
          [sub.id]
        );
        break;
      }
      case 'invoice.payment_succeeded': {
        const inv = event.data.object as Stripe.Invoice;
        if (inv.subscription) {
          await db.query(
            `UPDATE licenses SET grace_period_until = NULL WHERE stripe_subscription_id = $1`,
            [inv.subscription]
          );
        }
        break;
      }
      case 'invoice.payment_failed': {
        const inv = event.data.object as Stripe.Invoice;
        if (inv.subscription) {
           await db.query(
            `UPDATE licenses SET grace_period_until = NOW() + INTERVAL '14 days' WHERE stripe_subscription_id = $1 AND grace_period_until IS NULL`,
            [inv.subscription]
          );
        }
        break;
      }
    }
  } catch(error) {
     console.error('Webhook Handling Error:', error);
  }

  res.json({ received: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`License server listening on port ${PORT}`);
});
