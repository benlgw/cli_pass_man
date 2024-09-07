#from cryptography.fernet import Fernet

import webbrowser
import tabulate
import pyperclip
import string
import maskpass
import bcrypt
#import base64
import random
import sys, os

tabulate = tabulate.tabulate

def clear():
    os.system('clear')

def check_key():
    clear()
    files = os.listdir(os.path.abspath(os.getcwd()))
    if 'key.key' not in files:
        with open('key.key', 'w') as key:
            master = maskpass.askpass(prompt=f'Key File not detected! Please enter a new master password: ', mask='*')
            master = str(master)
            #master = str(input('Key File not detected! Please enter a new master password: '))
            master = master.encode('utf-8')
            master = bcrypt.hashpw(master, bcrypt.gensalt())
            master = str(master[2:-1])
            key.write(master)

def get_master():
    check_key()
    with open('key.key', 'r') as key:
        hash = key.read()
        hash = hash.encode('utf-8')
        hash = bytes(hash)
        
    while True:
        clear()
        master = maskpass.askpass(prompt=f'\nPlease input the password to unlock the vault: ', mask='*')
        master = str(master)
        #master = str(input('Please input the password to unlock the vault: '))
        master = master.encode('utf-8')
        if bcrypt.checkpw(master, hash):
            input('\n\033[32mPassword was successful! Press any key to continue...\033[0m')
            break
        else:
           input('\n\033[31mPassword is Incorrect!\033[0m\n')
    main(master)

def main(master):
    files = os.listdir(os.path.abspath(os.getcwd()))
    if 'vault.csv' not in files:
        with open('vault.csv', 'w') as vault:
            pass
    clear()
    with open('vault.csv', 'r') as vault:
        table: list = []
        for line_number, line in enumerate(vault):
            table.append(line.strip().split(','))
            table[-1].insert(0, line_number + 1)
            table[-1].append(f'[C{line_number + 1}]:Quick Copy Password | [D{line_number + 1}]:Quick Delete Entry')
        #print(table)
        for row_num, row in enumerate(table):
            #table[row_num][3] = decrypt(row[3], master)
            pass
        print(tabulate(table, headers=['', 'Website/App', 'Username', 'Password', 'Quick Options'], tablefmt='fancy_grid'))
    print('\n[C]Create New Entry | [S]Select an Entry | [D]Delete an Entry | [B]Back | [E]Exit')
    choice = input('\nWhat would you like to do?: ')
    if choice.upper() == 'C':
        create_entry(master)
        main(master)
    elif len(choice) > 1 and choice[0].upper() == 'C':
        quick_copy(table, choice)
        main(master)
    elif choice.upper() == 'S':
        select_entry(table)
        main(master)
    elif choice.upper() == 'D':
        delete_entry(table)
        main(master)
    elif len(choice) > 1 and choice[0].upper() == 'D':
        quick_delete(table, choice)
        main(master)
    elif choice.upper() == 'B':
        print('Nowhere to go back to')
    elif choice.upper() == 'E':
        sys.exit(clear())
    else:
        input('\n\033[31mInvalid Input!\033[0m')
        main(master)

def create_entry(master):
    while True:
        site = input('\nWhat is the name of the site?: ')
        if site != '':
            break
        else:
            input('\n\033[31mSite must not be blank!\033[0m')
    while True:
        choice = input('\nWould you like to [G]generate a username or [P]provide your own?: ')
        if choice.upper() == 'G':
            uname = generate_uname()
            break
        elif choice.upper() == 'P':
            uname = input(f'\nWhat is the username for {site}?: ')
            break
        else:
            input('\n\033[31mNot a valid option!\033[0m')
    while True:
        choice = input('\nWould you like to [G]generate a password or [P]provide your own?: ')
        if choice.upper() == 'G':
            password = generate_password()
            break
        elif choice.upper() == 'P':
            password = maskpass.askpass(prompt=f'\nWhat is the password for {site}?: ', mask='*')
            #password = input(f'\nWhat is the password for {site}?: ')
            break
        else:
            input('\n\033[31mNot a valid option!\033[0m')
            
    with open('vault.csv', 'a') as vault:
        vault.write(f'{site}, {uname}, {password}\n')

def generate_uname():
    characters_no_special = []
    characters_special = []
    for char in string.ascii_letters:
        characters_no_special.append(char)
        characters_special.append(char)
    for char in string.digits:
        characters_no_special.append(char)
        characters_special.append(char)
    for char in string.punctuation:
        characters_special.append(char)

    while True:
        length = input('\nHow many characters would you like your username to be?: ')
        if length.isdigit() == False:
            input('\n\033[31mNot a valid option!\033[0m')
        else:
            special = input('\nWould you like your username to contain special characters?[Y/N]: ')
            if special.upper()[0] == 'Y':
                special = True
            elif special.upper()[0] == 'N':
                special = False
            else:
                input('\n\033[31mNot a valid option!\033[0m')
        break

    if special == True:
        uname = ''
        rand = random.choices(characters_special, k=int(length))
        for char in rand:
            uname += char
        return uname
    elif special == False:
        uname = ''
        rand = random.choices(characters_no_special, k=int(length))
        for char in rand:
            uname += char
        return uname
    else:
        input('\n\033[31mSomething went wrong, press any key to return!\033[0m')
        main()

def generate_password():
    characters = []
    for char in string.ascii_letters and string.digits and string.punctuation:
        characters.append(char)

    while True:
        length = input('\nHow many characters would you like your username to be?: ')
        if length.isdigit() == False:
            input('\n\033[31mNot a valid option!\033[0m')
        break

    password = ''
    rand = random.choices(characters, k=int(length))
    for char in rand:
        password += char
    return password

def select_entry(table):
    while True:
        select = input('\nPlease enter the row number of the entry you would like to select: ')
        if int(select) > len(table):
            input('\n\033[31mRow does not exist!\033[0m')
        else:
            break
    while True:
        clear()
        print(tabulate([table[int(select) - 1]], headers=['', 'Website/App', 'Username', 'Password', 'Quick Options'], tablefmt='fancy_grid'))
        print('\nCopy [U]Username | Copy [P]Password | [O]Open Site | [E]Edit Entry | [D]Delete Entry | [B]Back')  
        choice = input('\nWhat would you like to do?: ')
        if choice.upper() == 'U':
            uname = str(table[int(select) - 1][2]).strip()
            pyperclip.copy(uname)
            while True:
                choice = input('\nWould you like to copy the password as well? [Y][N]: ')
                if choice.upper() == 'Y':
                    password = str(table[int(select) - 1][3]).strip()
                    pyperclip.copy(password)
                    break
                elif choice.upper() == 'N':
                    break
                else:
                    input('\n\033[31mNot a valid option!\033[0m')
        elif choice.upper() == 'P':
            password = str(table[int(select) - 1][3]).strip()
            pyperclip.copy(password)
        elif choice.upper() == 'O':
            webbrowser.open_new_tab(f'https://www.google.com/search?q={table[int(select) - 1][1]}')  #open site in new tab
        elif choice.upper() == 'E':
            edit_entry(table, select)
        elif choice.upper() == 'D':
            pass
        elif choice.upper() == 'B':
            break
        else:
            input('\n\033[31mNot a valid option!\033[0m')

def edit_entry(table, select):
    while True:
        print('\nEdit [W]Website/App | Edit [U]Username | Edit [P]Password | [B]Back')
        choice = input('\nWhat would you like to do?: ')
        if choice.upper() == 'W':
            new_web = input('\nWhat is the new site name?: ')
            table[int(select) - 1][1] = new_web
            break
        elif choice.upper() == 'U':
            new_user = input('\nWhat is the new username?: ')
            table[int(select) - 1][2] = new_user
            break
        elif choice.upper() == 'P':
            new_pass = input('\nWhat is the new password?: ')
            table[int(select) - 1][3] = new_pass
            break
        elif choice.upper() == 'B':
            break
        else:
            input('\n\033[31mNot a valid option!\033[0m')

def quick_copy(table, *row):
    row = ''.join(row)
    if int(row[1]) > len(table):
        input('\n\033[31mNot a valid option!\033[0m')
    else:
        password = (table[int(row[1:]) - 1][3]).strip()
        pyperclip.copy(password)

def quick_delete(table, *row):
    row = ''.join(row)
    if int(row[1]) > len(table):
        input('\n\033[31mNot a valid option!\033[0m')
    elif row[1].isdigit() == False:
        input('\n\033[31mNot a valid option!\033[0m')
    else:
        row = int(row[1])
        del table[row - 1]
        with open('vault.csv', 'w') as vault:
            print()
            for row in table:
                vault.write(f'{row[1]}, {row[2]}, {row[3]}\n')

def delete_entry(table):
    while True:
        delete = input('\nPlease enter the row number of the entry you would like to delete: ')
        if delete.upper() == 'B':
            break
        elif delete.isdigit() == False:
            input('\n\033[31mNot a valid option!\033[0m')
        else:
            delete = int(delete)
            del table[delete - 1]
            break
    with open('vault.csv', 'w') as vault:
        print()
        for row in table:
            vault.write(f'{row[1]}, {row[2]}, {row[3]}\n')

if __name__ == '__main__':
    get_master()