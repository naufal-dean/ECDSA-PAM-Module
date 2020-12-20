import hashlib
import os
import psycopg2
import subprocess
import sys

try:
    sys.path.append('/media/sf_Kriptografi-Makalah-2')
    from ecdsa import SECP256K1, LoadKeyError, ECDSA, ValidationError
except Exception as e:
    print('[+] Error loading ecdsa module. Exiting...')
    print(e)
    exit(1)


DEFAULT_USER = 'nobody'
try:
    db = psycopg2.connect(dbname="pam", host="localhost", user="postgres", password="postgres")
except Exception as e:
    print('[+] Failed to establish db connection. Exiting...')
    exit(2)


class NoMatchedPubKeyError(Exception):
    pass


def get_private_keys_from_usb():
    # Use lsblk command to get USB (/media) path
    lsblk = filter(None, subprocess.check_output('lsblk').split('\n'))
    media_paths = [line.split()[-1] for line in lsblk
                   if line.split()[-1].startswith('/media')]
    # Get all private key from keys folder in each media
    keys = []
    for media_path in media_paths:
        for root, _, files in os.walk(os.path.join(media_path, 'keys')):
            keys.extend([os.path.join(root, file) for file in files
                         if file.endswith('.pri')])
    # Return
    return keys


def get_matched_public_key(id):
    cursor = db.cursor()
    cursor.execute('SELECT public_key, signature FROM validation_table WHERE id=%s', (id,))
    res = cursor.fetchone()
    if res is not None:
        public_key, signature = res
        return public_key
    else:
        raise NoMatchedPubKeyError()


def pam_sm_authenticate(pamh, flags, argv):
    # Setup user
    try:
        print('[+] Using PAM to authenticate...')
        user = pamh.get_user(None)
    except pamh.exception as e:
        print('[+] Error happened. Exiting...')
        return e.pam_result
    if user == None:
        pamh.user = DEFAULT_USER

    try:
        # Sign using all available private key in usb
        for key_path in get_private_keys_from_usb():
            try:
                print('[+] Trying key {0}:'.format(key_path)),

                # load curve from key
                curve = SECP256K1.load_key(key_path)
                ecdsa = ECDSA(curve)

                # Sign some random string
                chall = os.urandom(64)
                hs = hashlib.sha256(chall)
                chall_hash = int(hs.hexdigest(), 16)
                r, s = ecdsa.sign(chall_hash)

                # Get matched public key
                pubkey = get_matched_public_key(curve.id)

                # Verify signature
                ecdsa.curve = SECP256K1.parse_repr(pubkey)
                ecdsa.verify(chall_hash, r, s)
            except LoadKeyError as e:
                print('invalid key file')
            except NoMatchedPubKeyError as e:
                print('no matched pubkey')
            except ValidationError as e:
                print('validation error')
            except Exception as e:
                print(e)
            else:
                print('succeed')
                print('[+] Authenticated using PAM...')
                return pamh.PAM_SUCCESS
    except Exception as e:
        print(e)
        print('[+] PAM authentication error...')
        return pamh.PAM_AUTH_ERR

    # Matching private key not found in any usb
    print('[+] Matching private key not found...')
    return pamh.PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS
