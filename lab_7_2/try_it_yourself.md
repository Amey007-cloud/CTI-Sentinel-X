# Lab 7.2 — Try It Yourself

The TIY monitor combines two observations:

1. WiredTiger cache behavior from `db.serverStatus()`.
2. New annual security-report entries not already represented in the local MongoDB report set.

The default report source is the public `awesome-annual-security-reports` GitHub repository. The script is designed to continue reporting local cache metrics even if the external source is temporarily unavailable.
