import sys

try:
    sys.path.append('/media/sf_Kriptografi-Makalah-2')
    from ecdsa import SECP256K1, ECDSA
except Exception as e:
    print('[+] Error loading ecdsa module. Exiting...')
    print(e)
    exit(1)


DEFAULT_USER = 'nobody'


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

    # Init pam using simple sign verify
    curve = SECP256K1()
    curve.generate_key()

    ecdsa = ECDSA(curve)
    r, s = ecdsa.sign(12391023112093805123092410293810251203810238120938401293)

    if ecdsa.verify(12391023112093805123092410293810251203810238120938401293, r, s):
        print("Berhasil verifikasi")
        return pamh.PAM_SUCCESS
    else :
        print("Gagal verifikasi")
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
