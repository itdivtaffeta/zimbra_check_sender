#!/usr/bin/env python3
"""
Callback-level tests for check_sender_access.py.

The production module imports python-ldap and pymilter at module load and
binds its configuration at import time, so each test loads a fresh copy of
the module with fake `ldap`/`Milter` modules in sys.modules and a temporary
config file pointed to by ZMBR_CONFIG. No LDAP server or milter socket is
needed.
"""

import importlib.util
import os
import subprocess
import sys
import tempfile
import types
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_PATH = os.path.join(REPO_ROOT, 'check_sender_access.py')
CONFIG_DIST = os.path.join(REPO_ROOT, 'etc', 'config_dist.ini')
WARN_MSG = 'Client does not have permissions to send as this sender'

DIRECTORY = {
    'alice@example.test': [('uid=alice,ou=people,dc=example,dc=test', {
        'zimbraId': [b'ID-ALICE'],
        'mail': [b'alice@example.test', b'alias@example.test'],
    })],
    'bob@example.test': [('uid=bob,ou=people,dc=example,dc=test', {
        'zimbraId': [b'ID-BOB'],
        'mail': [b'bob@example.test'],
    })],
}

# Delegated send-as targets, keyed by (object class, right) as they appear in
# ACL search filters. info@ is a shared account; support@ has no grant for
# alice; lists@ is a distribution list with the DL right.
ACL_DIRECTORY = {
    ('zimbraAccount', 'ID-ALICE usr sendAs', 'mail=info@example.test'): [
        ('uid=info,ou=people,dc=example,dc=test', {
            'mail': [b'info@example.test'],
            'zimbraACE': [b'ID-ALICE usr sendAs'],
        })],
    ('zimbraDistributionList', 'ID-ALICE usr sendAsDistList',
     'mail=lists@example.test'): [
        ('cn=lists,ou=groups,dc=example,dc=test', {
            'mail': [b'lists@example.test'],
            'zimbraACE': [b'ID-ALICE usr sendAsDistList'],
        })],
}

CONFIG_TEMPLATE = """\
[main]
name = postfix/mail_from_check
listen_port = 5000@127.0.0.1
debug = false
domains = example.test
exclude_re = {exclude_re}
exclude_enve_re = {exclude_enve_re}
warn_msg = {warn_msg}
check_sendas_dist = {check_sendas_dist}
only_authenticated = {only_authenticated}
enforce_login = {enforce_login}

[ldap]
url = ldap://127.0.0.1:389
bind = uid=zimbra,cn=admins,cn=zimbra
pwd = secret
base_search = ou=people,dc=example,dc=test
search_attrs = mail;zimbraMailCatchAllAddress;zimbraMailCanonicalAddress
"""


def _escape_filter_chars(value):
    return (value.replace('\\', r'\5c').replace('*', r'\2a')
                 .replace('(', r'\28').replace(')', r'\29')
                 .replace('\x00', r'\00'))


def make_ldap_module(directory, fail=None):
    """Fake `ldap` module. fail: None | 'init' | 'bind' | 'search'."""
    mod = types.ModuleType('ldap')

    class LDAPError(Exception):
        pass

    class INVALID_CREDENTIALS(LDAPError):
        pass

    class SERVER_DOWN(LDAPError):
        pass

    class Conn:
        def set_option(self, *args):
            pass

        def simple_bind_s(self, bind, pwd):
            if fail == 'bind':
                raise INVALID_CREDENTIALS('invalid credentials')

        def search_s(self, base, scope, sfilter, attrs):
            if fail == 'search':
                raise LDAPError('search failed')
            # ACL search: match on the complete filter (object class, right,
            # and target address) so a query for the wrong right or object
            # class never passes accidentally.
            for (objclass, ace, mail), entry in ACL_DIRECTORY.items():
                if ('objectClass={0}'.format(objclass) in sfilter
                        and ace in sfilter and mail in sfilter):
                    return entry
            if 'objectClass=zimbraDistributionList' in sfilter or \
                    'objectClass=zimbraAccount' in sfilter:
                return []
            for key, entry in directory.items():
                if key in sfilter:
                    return entry
            return []

        def unbind_s(self):
            pass

    def initialize(url):
        if fail == 'init':
            raise SERVER_DOWN('cannot connect')
        return Conn()

    filt = types.ModuleType('ldap.filter')
    filt.escape_filter_chars = _escape_filter_chars
    mod.filter = filt
    mod.LDAPError = LDAPError
    mod.INVALID_CREDENTIALS = INVALID_CREDENTIALS
    mod.SERVER_DOWN = SERVER_DOWN
    mod.OPT_REFERRALS = 0
    mod.OPT_NETWORK_TIMEOUT = 1
    mod.SCOPE_SUBTREE = 2
    mod.initialize = initialize
    return mod


def make_milter_module():
    mod = types.ModuleType('Milter')
    mod.CONTINUE = 'CONTINUE'
    mod.REJECT = 'REJECT'
    mod.factory = None
    mod.runmilter = lambda *args, **kwargs: None
    counter = [0]

    def uniqueID():
        counter[0] += 1
        return counter[0]

    class Base:
        def getsymval(self, name):
            return self._symvals.get(name)

        def setreply(self, rcode, xcode, msg):
            self.reply = (rcode, xcode, msg)

    mod.uniqueID = uniqueID
    mod.Base = Base
    return mod


_load_counter = [0]


def load_milter(only_authenticated='true', enforce_login='true',
                exclude_re='', exclude_enve_re='', check_sendas_dist='false',
                fail=None):
    config_text = CONFIG_TEMPLATE.format(
        exclude_re=exclude_re, exclude_enve_re=exclude_enve_re,
        warn_msg=WARN_MSG, check_sendas_dist=check_sendas_dist,
        only_authenticated=only_authenticated,
        enforce_login=enforce_login)
    fd, cfg_path = tempfile.mkstemp(suffix='.ini')
    with os.fdopen(fd, 'w') as fh:
        fh.write(config_text)

    ldap_mod = make_ldap_module(DIRECTORY, fail=fail)
    sys.modules['ldap'] = ldap_mod
    sys.modules['ldap.filter'] = ldap_mod.filter
    sys.modules['Milter'] = make_milter_module()

    os.environ['ZMBR_CONFIG'] = cfg_path
    _load_counter[0] += 1
    name = 'check_sender_access_test_%d' % _load_counter[0]
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    finally:
        os.unlink(cfg_path)
    # convenience aliases for assertions (the module itself only
    # references Milter.CONTINUE / Milter.REJECT)
    mod.CONTINUE = sys.modules['Milter'].CONTINUE
    mod.REJECT = sys.modules['Milter'].REJECT
    return mod


def run_session(mod, auth_user, mail_from, from_header=None):
    """Drive one message through envfrom and (optionally) the From: header."""
    milter = mod.CheckSenderAccess()
    milter._symvals = {'{auth_authen}': auth_user} if auth_user else {}
    milter.reply = None
    envfrom_result = milter.envfrom(mail_from)
    header_result = (milter.header('From', from_header)
                     if from_header is not None else None)
    return milter, envfrom_result, header_result


class PolicyTest(unittest.TestCase):

    def test_authenticated_own_address_accepted(self):
        mod = load_milter()
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<alice@example.test>',
            'Alice <alice@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_authenticated_allowed_alias_accepted(self):
        mod = load_milter()
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<alice@example.test>',
            'Alias <alias@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_authenticated_header_spoof_rejected(self):
        mod = load_milter()
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<alice@example.test>',
            'Bob <bob@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.REJECT, r_hdr)
        self.assertEqual(('550', '5.7.1', WARN_MSG), milter.reply)

    def test_authenticated_envelope_spoof_rejected(self):
        mod = load_milter()
        milter, r_env, _ = run_session(
            mod, 'alice@example.test', '<bob@example.test>')
        self.assertEqual(mod.REJECT, r_env)
        self.assertEqual(('550', '5.7.1', WARN_MSG), milter.reply)

    def test_unauthenticated_skipped_when_only_authenticated(self):
        mod = load_milter(only_authenticated='true')
        milter, r_env, r_hdr = run_session(
            mod, None, '<bob@example.test>', 'Bob <bob@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_out_of_scope_domain_accepted(self):
        mod = load_milter()
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<alice@example.test>',
            'Carol <carol@other.test>')
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_ldap_down_fails_open_for_authenticated(self):
        # envelope is whitelisted so no LDAP happens in envfrom; the
        # From: check then hits an LDAP that is down -> mail passes
        mod = load_milter(exclude_re='^scanner@', fail='init')
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<scanner@example.test>',
            'Alias <alias@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_bad_ldap_bind_fails_open_for_authenticated(self):
        mod = load_milter(fail='bind')
        milter, r_env, _ = run_session(
            mod, 'alice@example.test', '<alice@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertIsNone(milter.reply)

    def test_ldap_down_fails_open_for_unauthenticated_inbound(self):
        mod = load_milter(only_authenticated='false', enforce_login='false',
                          fail='init')
        milter, r_env, r_hdr = run_session(
            mod, None, '<bob@example.test>', 'Alice <alice@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_login_not_found_in_ldap_fails_open(self):
        mod = load_milter()
        milter, r_env, r_hdr = run_session(
            mod, 'charlie@example.test', '<charlie@example.test>',
            'Charlie <charlie@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_exclude_re_does_not_bypass_from_ownership(self):
        mod = load_milter(exclude_re='^scanner@')
        # same address in envelope and header, but not owned by the login
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<scanner@example.test>',
            'Scanner <scanner@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.REJECT, r_hdr)
        self.assertEqual(('550', '5.7.1', WARN_MSG), milter.reply)

    def test_exclude_re_with_other_spoofed_from_rejected(self):
        mod = load_milter(exclude_re='^scanner@')
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<scanner@example.test>',
            'Bob <bob@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.REJECT, r_hdr)

    def test_exclude_re_with_owned_from_accepted(self):
        mod = load_milter(exclude_re='^scanner@')
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<scanner@example.test>',
            'Alias <alias@example.test>')
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_exclude_enve_re_still_whitelists_header(self):
        mod = load_milter(exclude_enve_re='^bob@')
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<alice@example.test>',
            'Bob <bob@example.test>')
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_duplicate_from_header_rejected(self):
        # first mailbox belongs to the login: parseaddr()-based checks
        # accepted this, hiding the second unchecked identity
        mod = load_milter()
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<alice@example.test>',
            'Alice <alice@example.test>, Bob <bob@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.REJECT, r_hdr)
        self.assertEqual(('550', '5.7.1', WARN_MSG), milter.reply)

    def test_malformed_from_headers_rejected(self):
        mod = load_milter()
        for bad in ('<<>>', 'undisclosed-recipients:;', 'not-an-address'):
            milter, r_env, r_hdr = run_session(
                mod, 'alice@example.test', '<alice@example.test>', bad)
            self.assertEqual(mod.REJECT, r_hdr, 'From: %r' % bad)
            self.assertEqual(('550', '5.7.1', WARN_MSG), milter.reply)

    def test_null_sender_checked_against_login(self):
        mod = load_milter()
        # bounce-style null envelope sender: owned From: passes
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<>', 'Alias <alias@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.CONTINUE, r_hdr)
        # spoofed From: rejected
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<>', 'Bob <bob@example.test>')
        self.assertEqual(mod.REJECT, r_hdr)
        self.assertEqual(('550', '5.7.1', WARN_MSG), milter.reply)

    def test_case_and_display_name_and_folding_accepted(self):
        mod = load_milter()
        milter, r_env, r_hdr = run_session(
            mod, 'ALICE@EXAMPLE.TEST', '<ALICE@EXAMPLE.TEST>',
            'Alice\r\n\t <Alice@Example.Test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)


class DelegatedSendAsTest(unittest.TestCase):
    """check_sendas_dist=true must accept account sendAs grants as well as
    distribution-list sendAsDistList grants, and reject targets that have
    neither. Delegated addresses live in ACL_DIRECTORY, keyed by the exact
    (object class, right, address) tuple the LDAP filter must contain."""

    def test_sendas_account_grant_accepted(self):
        # alice has 'ID-ALICE usr sendAs' on the info@ account
        mod = load_milter(check_sendas_dist='true')
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<alice@example.test>',
            'Info <info@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_sendas_account_grant_accepted_in_envelope(self):
        # envelope sender is the delegated address; exclude_re on the own
        # address so the envelope check runs against the login
        mod = load_milter(check_sendas_dist='true',
                          exclude_re='^alice@')
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<info@example.test>',
            'Info <info@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_sendas_account_without_grant_rejected(self):
        # support@ has no ACL entry at all
        mod = load_milter(check_sendas_dist='true')
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<alice@example.test>',
            'Support <support@example.test>')
        self.assertEqual(mod.REJECT, r_hdr)
        self.assertEqual(('550', '5.7.1', WARN_MSG), milter.reply)

    def test_sendas_grant_for_other_user_rejected(self):
        # bob has no grant on info@ (only ID-ALICE does)
        mod = load_milter(check_sendas_dist='true')
        milter, r_env, r_hdr = run_session(
            mod, 'bob@example.test', '<bob@example.test>',
            'Info <info@example.test>')
        self.assertEqual(mod.REJECT, r_hdr)
        self.assertEqual(('550', '5.7.1', WARN_MSG), milter.reply)

    def test_sendas_distlist_grant_accepted(self):
        # alice has 'ID-ALICE usr sendAsDistList' on lists@
        mod = load_milter(check_sendas_dist='true')
        milter, r_env, r_hdr = run_session(
            mod, 'alice@example.test', '<alice@example.test>',
            'Lists <lists@example.test>')
        self.assertEqual(mod.CONTINUE, r_env)
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)

    def test_sendas_grant_wrong_objectclass_rejected(self):
        # alice's account sendAs on info@ must not satisfy the DL filter;
        # alice's DL sendAsDistList on lists@ must not satisfy the account
        # filter. With check_sendas_dist off nothing is allowed either.
        mod = load_milter(check_sendas_dist='false')
        for addr, name in (('info@example.test', 'Info'),
                           ('lists@example.test', 'Lists')):
            milter, r_env, r_hdr = run_session(
                mod, 'alice@example.test', '<alice@example.test>',
                '{0} <{1}>'.format(name, addr))
            self.assertEqual(mod.REJECT, r_hdr, addr)
            self.assertEqual(('550', '5.7.1', WARN_MSG), milter.reply)

    def test_ldap_error_during_acl_search_fails_open(self):
        # own-address lookup succeeds... then fail: swap the connection for a
        # failing one right before the ACL search. The failing conn must come
        # from the same fake ldap module the milter imported, otherwise its
        # LDAPError class doesn't match the one is_allowed catches.
        mod = load_milter(check_sendas_dist='true')
        ldap_mod = mod.ldap
        milter = mod.CheckSenderAccess()
        milter._symvals = {'{auth_authen}': 'alice@example.test'}
        milter.reply = None
        self.assertEqual(mod.CONTINUE, milter.envfrom('<alice@example.test>'))

        class FailingConn:
            def search_s(self, *args):
                raise ldap_mod.LDAPError('search failed')

        milter.ldp = FailingConn()
        r_hdr = milter.header('From', 'Info <info@example.test>')
        self.assertEqual(mod.CONTINUE, r_hdr)
        self.assertIsNone(milter.reply)


class ListenerTest(unittest.TestCase):
    """Run the real entrypoint with stub deps; the shipped config_dist.ini
    must produce a localhost-only inet socket."""

    def test_entrypoint_binds_localhost_with_shipped_config(self):
        stub_dir = tempfile.mkdtemp(prefix='milter_stubs_')
        with open(os.path.join(stub_dir, 'Milter.py'), 'w') as fh:
            fh.write(
                "CONTINUE = 'CONTINUE'\n"
                "REJECT = 'REJECT'\n"
                "factory = None\n"
                "def uniqueID():\n"
                "    return 1\n"
                "class Base:\n"
                "    def getsymval(self, name):\n"
                "        return None\n"
                "    def setreply(self, *args):\n"
                "        pass\n"
                "def runmilter(name, socketname, timeout):\n"
                "    print('RUNMILTER_SOCKET={0}'.format(socketname), flush=True)\n"
            )
        os.mkdir(os.path.join(stub_dir, 'ldap'))
        with open(os.path.join(stub_dir, 'ldap', '__init__.py'), 'w') as fh:
            fh.write(
                "class LDAPError(Exception):\n"
                "    pass\n"
                "class INVALID_CREDENTIALS(LDAPError):\n"
                "    pass\n"
                "class SERVER_DOWN(LDAPError):\n"
                "    pass\n"
                "OPT_REFERRALS = 0\n"
                "OPT_NETWORK_TIMEOUT = 1\n"
                "SCOPE_SUBTREE = 2\n"
                "def initialize(url):\n"
                "    raise SERVER_DOWN('stub')\n"
            )
        with open(os.path.join(stub_dir, 'ldap', 'filter.py'), 'w') as fh:
            fh.write(
                "def escape_filter_chars(value):\n"
                "    return (value.replace('\\\\', r'\\5c').replace('*', r'\\2a')\n"
                "                 .replace('(', r'\\28').replace(')', r'\\29')\n"
                "                 .replace('\\x00', r'\\00'))\n"
            )

        env = dict(os.environ)
        env['PYTHONPATH'] = stub_dir + os.pathsep + env.get('PYTHONPATH', '')
        env['ZMBR_CONFIG'] = CONFIG_DIST
        # production runs on Linux where multiprocessing defaults to fork;
        # macOS defaults to spawn, under which the module-level log Queue is
        # re-created empty in the child and the shutdown sentinel is never
        # received. Force fork so the harness matches the deployment.
        wrapper = (
            'import multiprocessing, runpy, sys\n'
            'multiprocessing.set_start_method("fork")\n'
            'sys.argv = ["check_sender_access.py"]\n'
            'runpy.run_path({0!r}, run_name="__main__")\n'
        ).format(MODULE_PATH)
        proc = subprocess.run(
            [sys.executable, '-c', wrapper],
            capture_output=True, text=True, timeout=30, env=env,
            cwd=REPO_ROOT)
        self.assertEqual(0, proc.returncode,
                         'stdout=%r stderr=%r' % (proc.stdout, proc.stderr))
        self.assertIn('milter running on 5000@127.0.0.1', proc.stdout)
        self.assertIn('RUNMILTER_SOCKET=inet:5000@127.0.0.1', proc.stdout)
        self.assertNotIn('0.0.0.0', proc.stdout)


if __name__ == '__main__':
    unittest.main()
