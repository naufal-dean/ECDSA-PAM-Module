# ECDSA PAM Module

## Identitas
Naufal Dean Anugrah (13518123)

## Description
This repository contains code that is used in the [paper](http://informatika.stei.itb.ac.id/~rinaldi.munir/Kriptografi/2020-2021/Makalah-UAS/Makalah-UAS-Kripto-2020%20(54).pdf). And it is intended as a complement only. To use it in real environment, follow the steps in the paper.

## Python Version
`$ python --version`\
`Python 2.7.17`

## Environment Setup
1. Install dependencies\
`sudo apt-get update`\
`sudo apt-get install python`\
`sudo apt-get install libpam-python`

2. Install postgresql (script below is from [here](https://www.postgresql.org/download/linux/ubuntu/))
    ```
    sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
    sudo apt-get update
    sudo apt-get -y install postgresql
    ```

3. Allow password login on postgresql\
    - `sudo nano /etc/postgresql/13/main/pg_hba.conf`
    - change `local all postgres peer` to `local all postgres md5`
    - change `local all all peer` to `local all all md5`
    - save change
    - login as user postgres and set user postgres password using
        ```
        sudo -u postgres psql postgres
        \password postgres
        ```
    - input password
    - quit postgres using `\q`
    - restart postgresql using `sudo service postgresql restart`

4. Create **pam** database to store user public key
    - login as user postgres\
        `psql -U postgres -W`
    - create database
        ```
        CREATE DATABASE pam;
        ```
    - connect to database **pam**\
        `\c pam`
    - create **public_key** table
        ```
        CREATE TABLE validation_table (
            id int PRIMARY KEY,
            public_key varchar(500),
            signature varchar(300)
        );
        ```

4. Install python dependencies globally\
`sudo apt install python-pip`\
`sudo pip install psycopg2-binary`

5. Add this line to `/etc/pam.d/sudo`\
`auth sufficient  pam_python.so [<pam_py_path>]`
