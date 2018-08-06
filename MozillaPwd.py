# -*- coding: utf-8 -*-

import base64
import configparser
import ctypes
import json
import os


SEC_SUCCESS = 0
SEC_FAILURE = -1


NssDll = None
ProfilePath = ''
JsonConfigPath = ''
OutputFilePath = ''

# 主密码
MasterPwd = ''

class SECItem(ctypes.Structure):
    _fields_ = [
    ('type', ctypes.c_int),
    ('data', ctypes.c_char_p),
    ('len', ctypes.c_uint),
    ]


def InitNssDll(masterPwd):
    path = ctypes.c_char_p()
    path.value = ProfilePath.encode('utf-8')
    mpwd = ctypes.c_char_p()
    mpwd.value = masterPwd.encode('utf-8')

    global NssDll
    NssDll = ctypes.CDLL(r"nss3.dll")

    if NssDll.NSS_Init(path) != SEC_SUCCESS:
        print('NSS_Init failed')
        return False

    keySlot = NssDll.PK11_GetInternalKeySlot()
    if keySlot == 0:
        print('PK11_GetInternalKeySlot failed')
        return False

    if NssDll.PK11_CheckUserPassword(ctypes.c_int(keySlot), mpwd) != SEC_SUCCESS:
        print('PK11_CheckUserPassword failed')
        return False

    if NssDll.PK11_Authenticate(keySlot, 1, 0) != SEC_SUCCESS:
        print('PK11_Authenticate failed')
        return False

    return True


def LoadJsonPwdData():
    entries = []
    with open(JsonConfigPath, "r") as o:
        js = json.load(o)
        for i in range(len(js['logins'])):
            entries.append({
            'username':js['logins'][i]['encryptedUsername'],
            'pwd':js['logins'][i]['encryptedPassword'],
            'url':js['logins'][i]['hostname']})
        return entries


def Decode(cipher):
    data = base64.b64decode(cipher)
    secItem = SECItem()

    cipherItem = SECItem()
    cipherItem.type = 0
    cipherItem.data = data
    cipherItem.len = len(data)
    if NssDll.PK11SDR_Decrypt(ctypes.byref(cipherItem), ctypes.byref(secItem), 0) != SEC_SUCCESS:
        print('PK11SDR_Decrypt failed')
        raise

    result = ctypes.string_at(secItem.data, secItem.len).decode('utf8')
    return result


def DocodeEntry(entry):
    try:
        entry['username'] = Decode(entry['username'])
        entry['pwd'] = Decode(entry['pwd'])
    except:
        print('Error when decode [ ' + entry['url'] + ' ]')
        entry['username'] = '<Error>'
        entry['pwd'] = '<Error>'


def DetermineProfileDirPath():
    iniPath = os.path.join(os.environ['APPDATA'], r'Mozilla\Firefox\profiles.ini')
    config = configparser.ConfigParser()
    config.read(iniPath)
    return os.path.join(os.environ['APPDATA'], r'Mozilla\Firefox', config['Profile0']['Path'])


def main():
    global ProfilePath
    global JsonConfigPath
    global OutputFilePath
    ProfilePath = DetermineProfileDirPath()
    JsonConfigPath = os.path.join(ProfilePath, r'logins.json')
    OutputFilePath = os.path.join(os.environ['USERPROFILE'], r'output.txt')

    # 切换工作目录
    os.chdir(os.path.join(os.environ['PROGRAMFILES(X86)'], r'Mozilla Firefox'))

    if not InitNssDll(MasterPwd):
        return

    entries = LoadJsonPwdData()
    for i in range(len(entries)):
        DocodeEntry(entries[i])
    with open(OutputFilePath, 'w') as o:
        json.dump(entries, o, indent=1)


if __name__ == "__main__":
    main()
