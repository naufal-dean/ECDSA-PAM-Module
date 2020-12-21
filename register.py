import hashlib
import os
import psycopg2
import random

from ecdsa import SECP256K1, LoadKeyError, ECDSA, ValidationError


SYSTEM_PRIVATE_KEY_PATH = '/home/key.pri'


def get_unique_id():
    db = psycopg2.connect(dbname='pam', host='localhost', user='postgres', password='postgres')
    cursor = db.cursor()
    while True:  # randomize id until found unused id
        id = random.randint(1, 10 ** 9)
        cursor.execute('SELECT * FROM validation_table WHERE id=%s', (id,))
        if cursor.fetchone() is None:  # found unused id
            db.close()
            return id


def gen_key(id):
    curve = SECP256K1(id)
    curve.generate_key()
    return curve


def setup_usb(id, mpt, keyname=None):
    curve = gen_key(id)
    keyname = (keyname or 'key') + '.pri'
    with open(os.path.join(mpt, 'keys', keyname), 'wb') as f:
        f.write(curve.pri_key_repr())


def get_user_public_key_signature(user_public_key):
    curve = SECP256K1.load_key(SYSTEM_PRIVATE_KEY_PATH)
    print(curve)
    ecdsa = ECDSA(curve)
    hs = hashlib.sha256(user_public_key)
    pubkey_hash = int(hs.hexdigest(), 16)
    r, s = ecdsa.sign(pubkey_hash)
    return ','.join([str(r), str(s)])


def register_usb(mpt, keyname=None):
    try:
        keyname = (keyname or 'key') + '.pri'
        curve = SECP256K1.load_key(os.path.join(mpt, 'keys', keyname))
        signature = get_user_public_key_signature(curve.pub_key_repr())
        # save public key to host database
        db = psycopg2.connect(dbname='pam', host='localhost', user='postgres', password='postgres')
        cursor = db.cursor()
        cursor.execute('INSERT INTO validation_table(id, public_key, signature) VALUES(%s, %s, %s)',
                       (curve.id, curve.pub_key_repr(), signature))
        db.commit()
        db.close()
    except Exception as e:
        print(type(e))


if __name__ == '__main__':
    menu = ('Utils Menu:\n'
            '1. Generate new key and setup USB\n'
            '2. Register USB\n'
            '3. Exit')

    while True:
        try:
            print(menu)
            op = int(raw_input('>> '))
            if op == 1:
                id = get_unique_id()
                mountpoint = str(raw_input('Insert USB mountpoint: '))
                keyname = str(raw_input('Insert keyname (default "key"): '))
                setup_usb(id, mountpoint, keyname)
            elif op == 2:
                mountpoint = str(raw_input('Insert USB mountpoint: '))
                keyname = str(raw_input('Insert keyname (default "key"): '))
                register_usb(mountpoint, keyname)
            else:
                print('See you!')
                break
            print
        except Exception as e:
            print(e)
            print('Error happened')
            break
