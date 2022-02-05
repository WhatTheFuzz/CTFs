import hashlib

### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################

flag_enc = open('level4.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level4.hash.bin', 'rb').read()


def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()


def level_4_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)
    
    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")



level_4_pw_check()



# The strings below are 100 possibilities for the correct password. 
#   (Only 1 is correct)
pos_pw_list = ["6b3e", "989c", "4b17", "d06f", "f495", "6ea1", "44e4", "1d45", "3e1a", "b0b4", "8c65", "3276", "c496", "9d3d", "2476", "6ef4", "6b7f", "c184", "c2a8", "9708", "7bea", "9a2d", "4a22", "93ae", "826b", "9a50", "8b39", "5410", "a86c", "3760", "6426", "ec8e", "c294", "a909", "cbc6", "2e75", "f137", "9cb3", "79e7", "469f", "a9f9", "3e37", "b33e", "3f31", "4b27", "2f06", "cc2f", "d9e4", "2de7", "7328", "b4d4", "8e74", "a677", "b139", "9c74", "8ea4", "36f6", "613b", "7a7a", "5710", "838c", "44d5", "7190", "99d9", "c0a6", "b218", "3223", "477e", "38e5", "19b4", "3267", "2287", "b947", "a8d0", "fd9c", "e99c", "d8b7", "4c82", "b289", "332b", "bba5", "716d", "653e", "eb5d", "ad77", "ad3a", "3922", "7565", "947d", "928c", "2937", "823f", "f362", "79cf", "4582", "c0d0", "ed20", "d89a", "129c", "4e81"]

