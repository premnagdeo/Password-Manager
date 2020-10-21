from __future__ import print_function, unicode_literals
from PyInquirer import prompt, Separator
import sys, os
from cryptography.fernet import Fernet
import secrets
import string
import random
from passwordgenerator import pwgenerator
import re
import pyperclip
from hashlib import md5, sha256, sha512, pbkdf2_hmac
import binascii

# TODO save the master key
# TODO retrieve the master key
# TODO check master key
# TODO save passwords
# TODO retrieve passwords


def start_prompt():
    questions = [
        {
            'type': 'list',
            'name': 'start',
            'message': 'Do you have a master key?',
            'choices': [
                'Yes',
                'No, I would like to create one',
                Separator(),
                'No, Exit the program',
            ]
        }
    ]

    answers = prompt(questions)

    return answers['start']


def check_password_strength(password):
    '''

    :param password: string (master_key
    :return: Boolean indicating whether password is strong or weak (True=Strong, False=Weak)
    '''

    # calculating the length
    length_error = len(password) < 8

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~" + r'"]', password) is None

    # overall result
    password_ok = not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)

    return password_ok


def get_master_key(confirm=False):
    '''
    Gets master key input from user

    :return: master key string
    '''
    questions = [
        {
            'type': 'password',
            'name': 'master_key',
            'message': 'Enter the master key:',
        }
    ]

    if confirm:
        confirmation = [
            {
                'type': 'password',
                'name': 'master_key',
                'message': 'Confirm the master key:',
            }
        ]

    answers = prompt(questions)
    if confirm:
        confirmation_answer = prompt(confirmation)
        if answers == confirmation_answer:
            password_strength = check_password_strength(answers['master_key'])
            if password_strength:
                return answers['master_key']
            else:
                print("Weak Password, please enter a strong Password \nPassword must contain: \n1.Minimum 8 characters \n2.Lowercase and "
                      "Uppercase Characters \n3.At least 1 number or digit \n4.At least 1 special character")
                master_key = get_master_key(confirm=True)
                return master_key
        else:
            print('Passwords do not match, please enter the passwords again')
            master_key = get_master_key(confirm=True)
            return master_key
    else:
        return answers['master_key']


def generate_key():
    '''
    Generates a master key using the password generator package
    https://pypi.org/project/passwordgenerator/

    :return: randomly generated master_key as string
    '''

    return pwgenerator.generate()


hashing_algorithms = {
                        '$1': 'md5',
                        '$2': 'sha256',
                        '$3': 'sha512'
                    }

def save_master_key(master_key, algo='$3'):

    hashing_algo = hashing_algorithms[algo]

    salt = secrets.token_bytes(16)
    # password = salt + master_key

    # # Sample: hashed_password = sha512(password.encode()).hexdigest()
    # execute_hashing = hashing_algo + '("' + password + '".encode()).hexdigest()'
    # # Execute the hashing
    # hashed_password = eval(execute_hashing)
    #
    import time
    t1 = time.time()
    if algo == '$1':
        # MD5
        hashed_password = pbkdf2_hmac('md5', master_key.encode(), salt, 100000)
    elif algo == '$2':
        # SHA 256
        hashed_password = pbkdf2_hmac('sha256', master_key.encode(), salt, 100000)
    elif algo == '$3':
        # SHA 512
        hashed_password = pbkdf2_hmac('sha512', master_key.encode(), salt, 100000)
    else:
        print('Wrong algo parameter passed')
        quit()

    print(hashed_password)
    hashed_password = binascii.hexlify(hashed_password)
    salt = binascii.hexlify(salt)
    print(hashed_password)
    total = ':'.join((algo, salt.decode(), hashed_password.decode()))

    print("SHUTI THE TIME TAKEN FOR HASHING = ", time.time() - t1)


    print("Final (to be saved to file) =", total)
    # Save salt+hash


    # Retrieve salt+hash



    pass


def create_master_key():
    '''

    :return: master_key string to main program
    '''
    questions = [
        {
            'type': 'list',
            'name': 'choose_master_key',
            'message': 'How would you like to create the master key?',
            'choices': [
                'Manually enter my own key',
                'Create a random key for me'
            ]
        }
    ]

    answers = prompt(questions)

    if answers['choose_master_key'] == 'Manually enter my own key':
        master_key = get_master_key(confirm=True)

    else:
        master_key = generate_key()

    print("The master key is: \n{}".format(master_key))
    print(Separator())
    print("IMPORTANT: It is critical that you never forget this password")
    print(Separator())

    questions = ([
        {
            'type': 'confirm',
            'name': 'copy_to_clipboard',
            'message': 'Would you like to copy the Master Key to clipboard?',
            'default': True,
        },
    ])

    answer = prompt(questions)
    if answer['copy_to_clipboard']:
        pyperclip.copy(master_key)
        print("Master Key copied to clipboard")

    save_master_key(master_key)
    return master_key


def confirm_exit():
    questions = ([
        {
            'type': 'confirm',
            'name': 'exit',
            'message': 'Confirm Exit?',
            'default': True,
        },
    ])
    answer = prompt(questions)

    return answer['exit']


if __name__ == '__main__':

    exit_confirmation = False

    while not exit_confirmation:

        option = start_prompt()
        if option == 'Yes':
            master_key = get_master_key()

        elif option == 'No, I would like to create one':
            master_key = create_master_key()

        else:
            exit_confirmation = confirm_exit()
