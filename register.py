import os
import psycopg2

from ecdsa import SECP256K1, LoadKeyError, ECDSA, ValidationError


def gen_key(id):
    curve = SECP256K1(id)
    curve.generate_key()
    return curve


def setup_usb(id, mpt, keyname=None):
    curve = gen_key(id)
    keyname = (keyname or str(curve.id) or 'key') + '.pri'
    with open(os.path.join(mpt, 'keys', keyname), 'wb') as f:
        f.write(curve.pri_key_repr())


def register_usb(mpt, keyname=None):
    keyname = (keyname or 'key') + '.pri'
    curve = SECP256K1.load_key(os.path.join(mpt, 'keys', keyname))
    # save public key to host database
    db = psycopg2.connect(dbname='pam', host='localhost', user='postgres', password='postgres')
    cursor = db.cursor()
    cursor.execute('INSERT INTO validation_table(id, public_key, signature) VALUES(%s, %s, %s)',
                   (curve.id, curve.pub_key_repr(), 'sign_placeholder'))
    db.commit()


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
                id = int(raw_input('Insert your id: '))
                mountpoint = str(raw_input('Insert USB mountpoint: '))
                keyname = str(raw_input('Insert keyname (default "id"): '))
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
