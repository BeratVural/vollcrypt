import Stripe from 'stripe';
import dotenv from 'dotenv';
dotenv.config();

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string, {
  apiVersion: '2024-04-10', // Or nearest supported specific to prompt
});
