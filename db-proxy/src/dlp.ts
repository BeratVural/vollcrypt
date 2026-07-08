import { maskValue } from '@vollcrypt/db-guard';

export function scanAndMaskCell(val: string): string {
  // Local match regex patterns to prevent overlapping mismatches and concurrency race conditions
  const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  const CREDIT_CARD_REGEX = /\b(?:\d[ -]*?){13,19}\b/g;
  const TC_NO_REGEX = /\b[1-9]\d{10}\b/g;
  const IBAN_REGEX = /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,26}\b/g;

  let masked = val;

  // Mask emails
  if (EMAIL_REGEX.test(masked)) {
    EMAIL_REGEX.lastIndex = 0;
    masked = masked.replace(EMAIL_REGEX, (match) => maskValue(match, 'email'));
  }

  // Mask credit cards
  if (CREDIT_CARD_REGEX.test(masked)) {
    CREDIT_CARD_REGEX.lastIndex = 0;
    masked = masked.replace(CREDIT_CARD_REGEX, (match) => maskValue(match, 'credit_card'));
  }

  // Mask TC Nos / National IDs
  if (TC_NO_REGEX.test(masked)) {
    TC_NO_REGEX.lastIndex = 0;
    masked = masked.replace(TC_NO_REGEX, (match) => maskValue(match, 'tc_no'));
  }

  // Mask IBANs
  if (IBAN_REGEX.test(masked)) {
    IBAN_REGEX.lastIndex = 0;
    masked = masked.replace(IBAN_REGEX, (match) => {
      const cleaned = match.replace(/\s+/g, '');
      if (cleaned.length >= 8) {
        return cleaned.slice(0, 4) + 'X'.repeat(cleaned.length - 8) + cleaned.slice(-4);
      }
      return 'XXXX-XXXX-XXXX-XXXX';
    });
  }

  return masked;
}
