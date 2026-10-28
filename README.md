# zimbra_check_sender

Postfix milter for Zimbra/Carbonio that stops authenticated users from sending mail as somebody else.

It checks two things against LDAP:

- the envelope sender (`MAIL FROM`) of authenticated sessions must belong to the SASL login (`enforce_login`);
- the `From:` header must belong to the envelope sender, or to the SASL login when `enforce_login` is on.

Only addresses in `domains` are checked. Aliases, catch-all and canonical addresses are accepted through the LDAP attributes listed in `search_attrs`; `check_sendas_dist` additionally allows `sendAsDistList` on distribution lists. Anything unexpected (LDAP down, bad bind, login not found) is logged and the mail is let through, so the milter never silently loses mail by itself.

Original description: <https://iomarmochtar.wordpress.com/2017/09/13/zimbra-prevent-user-customizing-from-header/>

## Configuration

`etc/config.ini` is not tracked by git; copy it from `etc/config_dist.ini`. The path can be overridden with `ZMBR_CONFIG`.

| Option | Default | Meaning |
|---|---|---|
| `name` | `postfix/mail_from_check` | Logger name; this is what you grep in the mail log. |
| `listen_port` | `5000@127.0.0.1` | Milter socket, as `port@address`. Use `127.0.0.1`, never `0.0.0.0`. |
| `debug` | `false` | Verbose per-step logging. Turn off after deployment. |
| `domains` | – | `;`-separated, no spaces. Only `From:`/sender domains listed here are checked. |
| `exclude_re` | empty | Regex whitelist on the envelope sender. |
| `exclude_enve_re` | empty | Regex whitelist on the `From:` address. |
| `warn_msg` | `Client does not have permissions to send as this sender` | Text of the `550 5.7.1` reply. |
| `check_sendas_dist` | `false` | Also allow senders with `sendAsDistList` on a distribution list. Needs LDAP read rights for `zimbra_ldap_userdn`. |
| `only_authenticated` | `false` | Check only SASL-authenticated sessions (ignore inbound port 25). |
| `enforce_login` | `false` | Check the envelope sender against the SASL login as well as the `From:` header. |
| `ldap.url` | – | `ldap://host:389`. Use the host IP if LDAP does not listen on localhost. |
| `ldap.bind` | – | `uid=zimbra,cn=admins,cn=zimbra`. |
| `ldap.pwd` | – | Value of `zimbra_ldap_password`. |
| `ldap.base_search` | empty | Base DN of the domain tree, e.g. `ou=people,dc=example,dc=com`. One base per instance; multiple domains need a common parent. |
| `ldap.search_attrs` | `mail;zimbraMailCatchAllAddress;zimbraMailCanonicalAddress` | `;`-separated attributes that may hold an allowed address. |

The milter logs to syslog facility `mail`, which is `/var/log/zimbra.log` on Zimbra and journald on Carbonio.

## Deployment runbook (Carbonio)

RnD-only steps are marked. Replace `<domain>` with your domain (`megasyariah.co.id` for production, `taffeta.dev` for RnD). Commands run as root unless stated `zextras`.

### 0. Pre-deploy checks

Record the current state as `zextras`, and keep the output:

```sh
carbonio prov gs $(zmhostname) zimbraMtaSmtpdMilters
postconf smtpd_milters milter_default_action milter_mail_macros smtpd_sender_restrictions
/opt/zextras/common/sbin/postqueue -p | tail -1
```

- `zimbraMtaSmtpdMilters` is usually empty. If it is not, save the value for rollback.
- `smtpd_milters` should show only `inet:127.0.0.1:7026`.
- `milter_default_action = tempfail` means mail is deferred, not lost, if the milter is down. The milter must be running before you hook it in.
- `milter_mail_macros` must include `{auth_authen}`. Without it `only_authenticated` and `enforce_login` cannot work.
- Note the queue size for comparison afterwards.

Check services and ports as root:

```sh
systemctl list-units 'carbonio-*' | grep -iE 'mta|config'
systemctl status carbonio-configd carbonio-mta.target --no-pager
ss -ltnp | grep 5000
python3 --version
```

- `carbonio-configd` and the MTA target must be active. Unit names on older Carbonio may differ.
- Nothing should hold port 5000. If something does, pick another port and use it everywhere below.
- Python 3 must be present and reasonably current.

Check LDAP reachability as `zextras`:

```sh
/opt/zextras/bin/zmlocalconfig ldap_url zimbra_ldap_userdn
/opt/zextras/common/bin/ldapsearch -x -H <ldap_url from above> \
  -D "uid=zimbra,cn=admins,cn=zimbra" -W \
  -b "ou=people,<base DN of your domain>" "(mail=realuser@<domain>)" mail zimbraId
```

The search must return exactly one entry. For `megasyariah.co.id` the base DN is `ou=people,dc=megasyariah,dc=co,dc=id`.

Back up the generated Postfix config for reference:

```sh
mkdir -p /root/pre-milter
cp -a /opt/zextras/common/conf/main.cf /opt/zextras/common/conf/master.cf /root/pre-milter/
```

If a second MTA server exists, run the whole runbook on each. Finish and verify the first one before starting the second.

### 1. Install

```sh
apt update
apt install -y git python3-venv python3-dev build-essential libmilter-dev libldap2-dev libsasl2-dev
cd /opt
git clone <this repository> zmbr_check_sender
cd zmbr_check_sender
python3 -m venv venv
venv/bin/pip install pymilter python-ldap
useradd -r -s /usr/sbin/nologin zmbrmilter
```

The checkout must contain the ported version with `enforce_login`:

```sh
grep -c enforce_login /opt/zmbr_check_sender/check_sender_access.py
```

### 2. Configure

```sh
cd /opt/zmbr_check_sender/etc
cp config_dist.ini config.ini
```

Edit `config.ini`:

```ini
[main]
name = postfix/mail_from_check
listen_port = 5000@127.0.0.1
debug = true
domains = <domain>
exclude_re =
exclude_enve_re =
warn_msg = Client does not have permissions to send as this sender
check_sendas_dist = false
only_authenticated = true
enforce_login = true

[ldap]
url = ldap://<LDAP host IP>:389
bind = uid=zimbra,cn=admins,cn=zimbra
pwd = <zimbra_ldap_password>
base_search = ou=people,<base DN of your domain>
search_attrs = mail;zimbraMailCatchAllAddress;zimbraMailCanonicalAddress
```

Get the password as `zextras`:

```sh
/opt/zextras/bin/zmlocalconfig -s zimbra_ldap_password
```

Separate multiple domains with `;` and no spaces. A single `base_search` covers one domain tree. Then lock down the files:

```sh
chown -R zmbrmilter: /opt/zmbr_check_sender
chmod 600 /opt/zmbr_check_sender/etc/config.ini
```

### 3. Test the milter alone (before touching Postfix)

```sh
sudo -u zmbrmilter /opt/zmbr_check_sender/venv/bin/python /opt/zmbr_check_sender/check_sender_access.py
```

You should see `milter running on 5000@127.0.0.1`. In another terminal, `ss -ltnp | grep 5000` must show `127.0.0.1:5000`, not `0.0.0.0:5000`. Stop it with Ctrl+C.

### 4. Run it as a service

`/etc/systemd/system/zmbr-check-sender.service`:

```ini
[Unit]
Description=zmbr_check_sender milter
After=network.target

[Service]
User=zmbrmilter
WorkingDirectory=/opt/zmbr_check_sender
ExecStart=/opt/zmbr_check_sender/venv/bin/python /opt/zmbr_check_sender/check_sender_access.py
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now zmbr-check-sender
systemctl status zmbr-check-sender --no-pager
ss -ltnp | grep 5000
```

The service must be `active (running)` and listening on `127.0.0.1:5000` before the next step.

### 5. Hook it into Postfix

As `zextras`:

```sh
carbonio prov ms $(zmhostname) zimbraMtaSmtpdMilters inet:127.0.0.1:5000
```

Restart the MTA as root:

```sh
systemctl restart carbonio-mta.target
```

Then check as `zextras` (the config daemon may need a moment to rewrite the config):

```sh
postconf smtpd_milters
```

Expected: `inet:127.0.0.1:5000, inet:127.0.0.1:7026`. Carbonio adds 7026 itself; do not include it in the attribute. If only 7026 appears after a minute, restart `carbonio-configd` as root and check again. If it still does not change, roll back (section 9) and collect the output.

### 6. RnD server only

**Do not run this on production.** The lab version of Carbonio enforces `reject_sender_login_mismatch`, which was disabled to make the RnD box behave like production. The setting returns on every MTA restart or config regeneration, so reapply it after the restart in step 5 and after any later restart.

As `zextras`:

```sh
postconf -e "smtpd_sender_restrictions = check_sender_access regexp:/opt/zextras/common/conf/tag_as_originating.re, permit_mynetworks, permit_sasl_authenticated, permit_tls_clientcerts, check_sender_access regexp:/opt/zextras/common/conf/tag_as_foreign.re"
```

As root:

```sh
/opt/zextras/common/sbin/postfix reload
```

Verify as `zextras` that `reject_sender_login_mismatch` is gone:

```sh
postconf smtpd_sender_restrictions
```

### 7. Test

Run these from another machine (`apt install swaks`) using real mailbox logins. `A` and `B` are two real users in your domain.

| Test | Command options | Expected |
|---|---|---|
| Normal mail | `--auth-user A --from A --h-From A` | accepted |
| Own alias | `--auth-user A --from A --h-From <A's alias>` | accepted |
| Spoof `From:` header | `--auth-user A --from A --h-From B` | `550 5.7.1 Client does not have permissions to send as this sender` after the body |
| Spoof both | `--auth-user A --from B --h-From B` | `550 5.7.1 ...` at `MAIL FROM` |
| Unauthenticated | port 25, no login, any sender | not rejected by this milter |

Base command:

```sh
swaks --server <mta-host> --port 587 --tls --auth LOGIN \
  --auth-user A@<domain> --auth-password '...' \
  --from ... --h-From: "..." --to someone@<domain>
```

Check the log for each case:

```sh
journalctl --since "10 min ago" | grep mail_from_check
```

Look for `Violation found` on the rejected cases and for no `LDAP error` or `Invalid LDAP credential`. Also send from a real mail client (Thunderbird or Outlook) and receive one mail from outside.

### 8. After deployment

- Set `debug = false` in `config.ini`, then `systemctl restart zmbr-check-sender`.
- Watch for problems during the first days:

  ```sh
  journalctl --since "1 hour ago" | grep mail_from_check | grep -E "Violation|warning|LDAP error|Invalid"
  /opt/zextras/common/sbin/postqueue -p | tail -1
  ```

  Compare the queue size with the baseline and look for deferred mail mentioning the milter.
- Review every `Violation found` line. If a legitimate sender is blocked (shared mailbox, mailing list, scanner, web app), whitelist it with `exclude_re` (envelope sender) or `exclude_enve_re` (`From:` address), then restart the service.
- `login ... not found in ldap` warnings mean the login does not map to an LDAP entry. The mail is let through; find out why.
- After any Carbonio upgrade, confirm `postconf smtpd_milters` still contains port 5000.

### 9. Rollback

**Milter down and mail deferred** (4xx on submission, growing queue): bring the milter back first.

```sh
systemctl start zmbr-check-sender
journalctl -u zmbr-check-sender -n 50 --no-pager
```

Deferred mail is not lost; sending servers retry.

**Full rollback:**

1. As `zextras`, remove the milter from Postfix. If step 0 recorded a non-empty previous value, restore that instead of an empty string:

   ```sh
   carbonio prov ms $(zmhostname) zimbraMtaSmtpdMilters ''
   ```

2. As root, apply it:

   ```sh
   systemctl restart carbonio-configd
   ```

   Check as `zextras` that `postconf smtpd_milters` is back to `inet:127.0.0.1:7026`. If not, also run `systemctl restart carbonio-mta.target`.

3. Stop the service: `systemctl disable --now zmbr-check-sender`.
4. Flush deferred mail: `/opt/zextras/common/sbin/postqueue -f`.
5. Send a test mail and confirm normal delivery.

**RnD only:** the `postconf -e` change reverts itself on the next MTA restart or config regeneration. To undo it immediately, restart `carbonio-configd` and recheck `postconf smtpd_sender_restrictions`.

To remove everything:

```sh
rm /etc/systemd/system/zmbr-check-sender.service
systemctl daemon-reload
rm -rf /opt/zmbr_check_sender
userdel zmbrmilter
```

## Notes

- **Production is an older Carbonio.** Unit names, the config rule that builds `smtpd_milters`, and package availability may differ from the RnD box. The check that matters is step 5: `postconf smtpd_milters` must show port 5000. Test in a maintenance window with the rollback commands ready.
- **Fail-open behavior:** if LDAP is unreachable or the bind fails, the milter logs it and lets mail through, so a wrong LDAP password does not show up as rejected mail. Check the logs after setting `pwd`.
- **Scope:** only envelope senders and `From:` headers in your `domains` are checked. A logged-in user can still use an external address as the envelope sender.
- **Password in `config.ini`:** keep it `chmod 600` and never paste it into tickets or chats.
