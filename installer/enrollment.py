"""First-owner codes belong only in the trusted DSM administrator console."""
import time
from deployer import schema


def first_code(store):
    # One transaction: concurrent starts cannot mint a code after enrollment.
    import secrets
    with store.db() as db:
        if db.execute('SELECT 1 FROM credentials WHERE active=1').fetchone():
            return None
        token = secrets.token_urlsafe(32)
        db.execute('DELETE FROM bootstrap')
        db.execute('INSERT OR IGNORE INTO principals VALUES (?,?)', ('owner', 'admin'))
        db.execute('INSERT INTO bootstrap VALUES (?,?,?)', (schema.fingerprint(token), 'owner', int(time.time()) + 600))
        store.event(db, 'local-administrator', 'enrollment_opened', 'owner')
        return token


def console(store):
    deadline = 0
    print('Approval URL: ' + store.origin + '/', flush=True)
    while True:
        with store.db() as db:
            enrolled = db.execute('SELECT 1 FROM credentials WHERE active=1').fetchone()
        if enrolled:
            print('Passkey registered. First-install enrollment console disabled.', flush=True)
            return
        if time.monotonic() >= deadline:
            token = first_code(store)
            if token is None:
                return
            print('FIRST INSTALL: open ' + store.origin + '/enroll', flush=True)
            print('Single-use enrollment code (10 minutes; administrator only): ' + token, flush=True)
            deadline = time.monotonic() + 600
        time.sleep(5)
