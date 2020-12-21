from ecdsa import SECP256K1


if __name__ == '__main__':
    print('[Warning] This will overwrite current system key if exists...')
    confirm = str(raw_input('Are you sure? (y/n) '))

    if confirm.lower() != 'y':
        print('Generate system key aborted...')
        exit(0)

    curve = SECP256K1(0)
    curve.generate_key()
    curve.save_file('/home/key')
    
    print('System key generated...')
