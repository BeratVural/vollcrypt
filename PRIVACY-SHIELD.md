---
layout: default
title: Vollcrypt Shield Privacy Policy
---

# Vollcrypt Shield Privacy Policy

Effective date: August 15, 2026

Vollcrypt Shield Viewer is a local integrity-verification application. It does
not require a Vollcrypt account and does not collect advertising identifiers,
analytics, diagnostics telemetry, contact information, or payment information.

## Data processed

Viewer reads only folders, Shield state, signed baselines, audit records,
witness policies, and evidence packages selected or configured by the user. It
uses this data locally to verify signatures, calculate integrity status, and
display file changes. Viewer does not upload monitored files or their contents
to Vollcrypt.

The separate Shield agent can write local logs and can send notifications to a
webhook explicitly configured by the system administrator. The destination and
retention of administrator-configured notifications are controlled by that
administrator, not by Vollcrypt.

## Storage and deletion

Viewer settings and Shield evidence remain on the user's device or on storage
chosen by the user. Removing the application does not silently delete
administrator-managed baselines, recovery material, quarantine records, or
audit evidence. The system administrator controls their retention and removal.

## Network access

Viewer does not contact Vollcrypt servers. Network communication occurs only
when a user or administrator explicitly connects Shield to a configured local
agent, witness, webhook, SSH tunnel, or commercial control plane.

## Contact

Questions about this policy can be sent to
[berat.vural.tr@gmail.com](mailto:berat.vural.tr@gmail.com).
