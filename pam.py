import hashlib
import os
import sys

try:
    sys.path.append('/media/sf_Kriptografi-Makalah-2')
    from ecdsa import SECP256K1, ECDSA, ValidationError
except Exception as e:
    print('[+] Error loading ecdsa module. Exiting...')
    print(e)
    exit(1)


DEFAULT_USER = 'nobody'


def get_private_key_from_usb():
    # TODO: implement
    return ['dummy']


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
        # Create curve and ecdsa object
        # TODO: load curve from key in usb
        curve = SECP256K1()
        curve.generate_key()
        ecdsa = ECDSA(curve)

        # Sign some random string
        chall = os.urandom(64)
        hs = hashlib.sha256(chall)
        chall_hash = int(hs.hexdigest(), 16)
        r, s = ecdsa.sign(chall_hash)

        # Verify using all available private key in usb
        for key_path in get_private_key_from_usb():
            try:
                ecdsa.verify(chall_hash, r, s)
            except ValidationError as e:
                print('validation error')
            except Exception as e:
                print(e)
            else:
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
