#!/usr/bin/env python3
"""
check_sender_access.py - Python 3 port

Milter that prevents users from setting a From: header that does not belong
to them: the From: header address must match the envelope sender (MAIL FROM)
or be one of that account's allowed addresses in LDAP (alias, canonical,
catch-all, optionally send-as distribution list).

Original (Python 2): https://github.com/iomarmochtar/zmbr_check_sender

Changes from the original:
  * Python 3 (configparser, bytes -> str decoding of LDAP values)
  * LDAP filter values are escaped (original was open to LDAP injection)
  * LDAP connection is reused per SMTP connection and closed on close()
  * LDAP errors fail open with a log line instead of raising
  * referral entries from LDAP are ignored
  * log queue no longer blocks the milter when full
  * optional `only_authenticated` setting in [main] (default: false)
  * optional `enforce_login` setting in [main] (default: false): for SASL
    authenticated sessions, BOTH the envelope sender (MAIL FROM) and the From:
    header must be addresses allowed for the login name (from {auth_authen}).
    Needed when Postfix itself does not verify that the envelope sender belongs
    to the logged-in user (original script trusted the envelope sender).
  * optional ZMBR_CONFIG environment variable to point to another config file
"""

import os
import re
import sys
import time
import uuid
import logging
import queue as queue_mod
from configparser import ConfigParser
from email.utils import parseaddr
from logging.handlers import SysLogHandler
from multiprocessing import Process, Queue

import ldap
import ldap.filter
import Milter

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_CONF = os.environ.get('ZMBR_CONFIG', os.path.join(BASE_DIR, 'etc', 'config.ini'))

parser = ConfigParser(interpolation=None)
if not parser.read(MAIN_CONF):
    sys.exit('Cannot read configuration file: {0}'.format(MAIN_CONF))

S_MAIN = dict(parser.items('main'))


def _bool(value):
    return str(value).strip().lower() == 'true'


APP_NAME = S_MAIN.get('name', 'postfix/mail_from_check')
DEBUG = _bool(S_MAIN.get('debug', 'false'))
LISTEN = S_MAIN.get('listen_port', '5000@127.0.0.1').strip()
WARN_MSG = S_MAIN.get('warn_msg', 'Client does not have permissions to send as this sender')
CHECK_SENDAS_DIST = _bool(S_MAIN.get('check_sendas_dist', 'false'))
# when true, only SASL-authenticated sessions are checked (ignores inbound port 25 mail)
ONLY_AUTHENTICATED = _bool(S_MAIN.get('only_authenticated', 'false'))
# when true, authenticated sessions are checked against the SASL login name:
# envelope sender and From: header must both belong to that login
ENFORCE_LOGIN = _bool(S_MAIN.get('enforce_login', 'false'))

# Exceptions / whitelisting
_exc = S_MAIN.get('exclude_re', '').strip()
EXCEPTION_RE = re.compile(_exc) if _exc else None

_exc_enve = S_MAIN.get('exclude_enve_re', '').strip()
EXCEPTION_ENVE_RE = re.compile(_exc_enve) if _exc_enve else None

# domains (From: header) that will be filtered by this script
DOMAINS = [d.strip().lower() for d in S_MAIN.get('domains', '').split(';') if d.strip()]

LDAP_CONF = dict(parser.items('ldap'))
LDAP_CONF['search_attrs'] = [a.strip() for a in LDAP_CONF['search_attrs'].split(';') if a.strip()]
LDAP_CONF['ret_attrs'] = ['zimbraId'] + LDAP_CONF['search_attrs']
LDAP_CONF.setdefault('base_search', '')

escape = ldap.filter.escape_filter_chars

# queue for communicating with the logging process in background
logq = Queue(maxsize=1000)


# --------------------------------------------------------------------------
# Milter
# --------------------------------------------------------------------------
class CheckSenderAccess(Milter.Base):

    def __init__(self):
        self.id = Milter.uniqueID()
        self.start_time = time.time()
        self.check_id = uuid.uuid1().hex[:8]
        self.orig_from = None
        self.authenticated = False
        self.auth_user = None
        self.ldp = None
        self._accounts = {}
        self.logd('Sender access run')

    # -- logging -----------------------------------------------------------
    def log(self, msg):
        try:
            logq.put_nowait((self.check_id, msg))
        except queue_mod.Full:
            pass

    def logd(self, msg):
        """Log only if DEBUG is true"""
        if DEBUG:
            self.log(msg)

    def _done(self, ret_code):
        """Finish mail transaction"""
        self.log('execution time %.4f s' % (time.time() - self.start_time))
        return ret_code

    # -- ldap --------------------------------------------------------------
    def _init_ldap(self):
        """Initialize ldap connection, returns True on success"""
        ldap_url = LDAP_CONF['url']
        self.logd('Connect to ldap using url: {0}'.format(ldap_url))
        try:
            conn = ldap.initialize(ldap_url)
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
            conn.simple_bind_s(LDAP_CONF['bind'], LDAP_CONF['pwd'])
            self.ldp = conn
            return True
        except ldap.INVALID_CREDENTIALS:
            self.log('Invalid LDAP credential')
        except ldap.SERVER_DOWN:
            self.log('Cannot contact ldap server using url {0}'.format(ldap_url))
        except ldap.LDAPError as exc:
            self.log('LDAP error while connecting: {0}'.format(exc))
        self.ldp = None
        return False

    def gen_search_filter(self, email):
        """Generate ldap search filter"""
        return '(|{0})'.format(
            ''.join('({0}={1})'.format(attr, escape(email)) for attr in LDAP_CONF['search_attrs'])
        )

    def populate_emails(self, ldap_result):
        """
        Get zimbraId and all allowed emails from the ldap search result.
        python-ldap returns attribute values as bytes, decode them here.
        """
        result = [None, []]
        # entries with dn None are referrals, ignore them
        entries = [e for e in (ldap_result or []) if e[0] is not None]
        if not entries:
            return result

        # should not be more than 1 result
        if len(entries) > 1:
            self.log('warning: got more than one result from ldap search')
            return result

        for key, data in entries[0][1].items():
            values = [v.decode('utf-8', 'replace').strip() for v in data]
            if not values:
                continue
            if key.lower() == 'zimbraid':
                result[0] = values[0]
                continue
            result[1].extend(v.lower() for v in values)

        return result

    def _lookup_account(self, identity):
        """Return (zimbraId, [allowed addresses]) for identity, cached per connection"""
        if identity not in self._accounts:
            s_filter = self.gen_search_filter(identity)
            self.logd('Running ldap filter {0}'.format(s_filter))
            result = self.ldp.search_s(
                LDAP_CONF['base_search'], ldap.SCOPE_SUBTREE, s_filter, LDAP_CONF['ret_attrs'])
            self._accounts[identity] = self.populate_emails(result)
        return self._accounts[identity]

    def is_allowed(self, identity, addr):
        """
        True if `identity` (SASL login or envelope sender) may use `addr`,
        False if not, None when LDAP is unavailable (caller fails open).
        """
        if self.ldp is None and not self._init_ldap():
            return None

        try:
            zimbra_id, mails = self._lookup_account(identity)

            if identity == self.auth_user and zimbra_id is None and not mails:
                self.log('warning: login {0} not found in ldap (check search_attrs and '
                         'base_search), skipping check'.format(identity))
                return None

            # address is in the identity's own allowed list
            if addr in mails:
                return True

            if zimbra_id and CHECK_SENDAS_DIST:
                s_filter = (
                    '(&(mail={0})(objectClass=zimbraDistributionList)'
                    '(zimbraACE={1} usr sendAsDistList))'
                ).format(escape(addr), escape(zimbra_id))
                self.logd('Checking distribution list, running search filter {0}'.format(s_filter))
                result = self.ldp.search_s(
                    LDAP_CONF['base_search'], ldap.SCOPE_SUBTREE, s_filter, ['dn'])
                if [e for e in result if e[0] is not None]:
                    self.logd('{0} can send as distribution list {1}, allowing mail'.format(
                        identity, addr))
                    return True
        except ldap.LDAPError as exc:
            self.log('LDAP error while checking {0}: {1}'.format(addr, exc))
            self.ldp = None
            return None

        self.log("Violation found: {0} doesn't have any right sending email as {1}".format(
            identity, addr))
        return False

    # -- milter callbacks --------------------------------------------------
    def envfrom(self, mailfrom, *args):
        _, addr = parseaddr(mailfrom.lower())
        self.auth_user = (self.getsymval('{auth_authen}') or '').strip().lower() or None
        self.authenticated = bool(self.auth_user)
        if EXCEPTION_RE and EXCEPTION_RE.search(addr):
            self.logd('{0} matches EXCEPTION regex, ignoring'.format(addr))
            addr = None
        self.orig_from = addr

        # authenticated session: the envelope sender must belong to the login too
        if ENFORCE_LOGIN and self.auth_user and addr:
            parts = addr.split('@')
            if len(parts) == 2 and parts[1] in DOMAINS:
                self.logd('login {0} uses envelope sender {1}'.format(self.auth_user, addr))
                if self.is_allowed(self.auth_user, addr) is False:
                    self.setreply('550', '5.7.1', WARN_MSG)
                    return self._done(Milter.REJECT)
        return Milter.CONTINUE

    def header(self, name, val):
        if name.strip().lower() != 'from' or not self.orig_from:
            return Milter.CONTINUE

        if ONLY_AUTHENTICATED and not self.authenticated:
            self.logd('Session is not authenticated, skipping check')
            return Milter.CONTINUE

        _, from_addr = parseaddr(val.lower())

        # if no email then ignore it
        if not from_addr:
            return Milter.CONTINUE
        # if same as MAIL FROM then ignore it (with enforce_login the envelope
        # sender was already validated against the login in envfrom)
        if self.orig_from == from_addr:
            return Milter.CONTINUE

        # check if the From: domain is in the checked domain list
        parts = from_addr.split('@')
        if len(parts) != 2:
            return Milter.CONTINUE
        if parts[1] not in DOMAINS:
            return Milter.CONTINUE

        self.logd('{0} is in domain list ({1})'.format(from_addr, DOMAINS))

        if EXCEPTION_ENVE_RE and EXCEPTION_ENVE_RE.search(from_addr):
            self.logd('{0} matches EXCEPTION envelope FROM regex, continue'.format(from_addr))
            return self._done(Milter.CONTINUE)

        identity = self.auth_user if (ENFORCE_LOGIN and self.auth_user) else self.orig_from
        allowed = self.is_allowed(identity, from_addr)

        if allowed is None:  # LDAP trouble: fail open
            return self._done(Milter.CONTINUE)
        if not allowed:
            self.setreply('550', '5.7.1', WARN_MSG)
            return self._done(Milter.REJECT)
        return self._done(Milter.CONTINUE)

    def close(self):
        """Called when the SMTP connection to the milter closes"""
        if self.ldp is not None:
            try:
                self.ldp.unbind_s()
            except ldap.LDAPError:
                pass
            self.ldp = None
        return Milter.CONTINUE


# --------------------------------------------------------------------------
# Background logger / entry point
# --------------------------------------------------------------------------
def background_logger():
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG)
    handler = SysLogHandler(address='/dev/log', facility=SysLogHandler.LOG_MAIL)
    handler.setFormatter(logging.Formatter('%(name)s: %(message)s'))
    logger.addHandler(handler)

    while True:
        try:
            item = logq.get()
        except KeyboardInterrupt:
            break

        if not item:
            break
        check_id, msg = item
        logger.info('check_id=%s %s', check_id, msg)


def main():
    fmt = '%Y-%m-%d %H:%M:%S'
    print('{0} milter running on {1}'.format(time.strftime(fmt), LISTEN), flush=True)

    # handle log printing in the background
    bt = Process(target=background_logger, daemon=True)
    bt.start()

    socketname = 'inet:{0}'.format(LISTEN)
    timeout = 600
    # register to have the Milter factory create instances of the class
    Milter.factory = CheckSenderAccess
    Milter.runmilter('check_sender_access', socketname, timeout)

    # shutting down logging process
    logq.put(None)
    bt.join()
    print('{0} milter shutdown'.format(time.strftime(fmt)), flush=True)


if __name__ == '__main__':
    main()