# What only you can do (all from a phone)

In this order. Each step says where to tap.

1. **Revoke the old GitHub tokens** that were pasted into a chat. GitHub app or github.com:
   Settings, Developer settings, Personal access tokens, delete each one.
2. **Turn on two-step login** for GitHub, Railway, Google and Coinbase (Settings, Security in each).
3. **Install a password manager** (Bitwarden is free) and keep every password and secret there.
4. **Set CONTACT in Railway.** Railway, the agenttrust service, Variables, add `CONTACT` with
   your support email. It appears on the home, Terms and Privacy pages.
5. **Turn on the off-site backup.** On github.com, open the Agenttrust repo, Settings, Secrets and
   variables, Actions, and add two secrets:
   - `ADMIN_SECRET`: the same value as in Railway.
   - `BACKUP_PASSPHRASE`: a long random phrase from your password manager. Without it the
     backups cannot be opened, so keep it safe.
6. **Approve the changes** I prepared (merging the branch). The uptime check starts then, and
   GitHub emails you if the site goes down.
7. **Buy a domain** when you are ready (about $10-15 a year) and tell me which one.
8. **Send 10 outreach messages a week** from docs/launch/outreach.md.
