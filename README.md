# ctf
```
ctf stash ayaya
```
# To look for

```
Cryptography (encryption, decryption)
Forensic files
Steganography (may need repair binary)
Reverse engineering
Algorithm
```

# Encryptions

```
DES
TripleDES
AES
SHA1
SHA256

substitution, mix, shifting, round key, morse code, caesar cipher
```

# Ports
```
HTTP port 80 (use this no encryption. cache, hash(?))
HTTPS port 443
DNS port 53

search for open ports
```

# Tools
```
encase (for forensic analysis)
Metasploit
FTK
Wireshark
Audio mix software (steganography)
Decrypt tool (tool4noob)
forensicallybeta
steganography online
steganography encoder
Cryptii
Dcode
ezgif.com/split
https://gchq.github.io/CyberChef/
Doorbuster, Gobuster
Enum4Linux
Hydra
LinPEAS
JohnTheRipper
Ghidra, x64dbg, IDA Pro, related (Reverse Engineer)
```

# Tip

```
Find hidden word.
When accessing file, make a duplicate of the file. (l'important)
Exiftool (check image information, location, date)
maybe have sql injection?.

*everytime find smth, slam into .txt file*
*list down open ports* use subl (sublime texteditor)
*sublime use in linux: "subl <file>"*
```


# Sm command

```
man <cmd> (manual for help/reference)

nmap: nmap -sC -sV -oN nmap/initial xxx.xxx.xxx.xxx
netdiscover

tshark:
tshark -r <filename.pcapng> -T fields -e usb.capdata > flag

ssh: 
ssh <user>@<destination-ip>

gobuster (gobuster -w /opt/DirBuster-0.12/directory-list-2.3-medium.txt -u http://xxx.xxx.xxx.xxx/) (replace ip with destination.)

searchsploit	

hydra (bruteforce password) : 
hydra -l <user> -P /opt/rockyou.txt ssh://xxx.xxx.xxx.xxx (rockyou.txt may be other dict idk.)

enum4linux (enumeration for log(?)) : 
/opt/enum41inux/enum41inux.pl -a xxx.xxx.xxx.xxx | tee enum4linux.log (tee is for output to a file.)

linpeas: 
scp /opt/linPEAS/linpeas.sh <user>@<destination-address>:/dev/shm

johntheripper: 	
/opt/JohnTheRipper/run/ssh2john.py <file> > forjohn.txt(whatever)
/opt/JohnTheRipper/run/john forjohn.txt 
/opt/JohnTheRipper/run/john forjohn.txt --wordlist=/opt/rockyou.txt

netdiscover -i eth0 -r xxx.xxx.xxx.xxx/xx (network address)
nmap -T4 -n -Pn xxx.xxx.xxx.xxx (address to check)
nmap -A -sC -T4 -n -Pn -p <port num. eg, 22,80,111> xxx.xxx.xxx.xxx (address to check) -o <a folder. eg, CTF> 

-A (certain version, os, fingerprinting)
-sC (unsafe scripts)
-T4 (speed things idk)
-n (no dns)
-Pn (no ping)
-p (port)

if drupal /robots.txt (??idk)
searchsploit drupalgeddon | grep -v /dos/

cat, grep, mkdir, chmod, tee
ls /root/Documents/
cat /etc/shadow
chmod +wrx <filename>
chmod 600 <filename>
chmod u=rw,go=r <filename>
chmod a+x <filename>

netsh wlan show profile name="E" key=clear
```

```
Base64: end with== "==" || uppercasee, lowercase
Base32: ALL CAPITAL. || may have symbol or "====" ?
Brainfuck: ++++++++[>+>+++++<<<<]---
SMS Tapcode: eg. 77727772 = Saya
Other binary form: 2 char, convert either to 1 or 0. eg. z == 0, * == 1
hexadecimal : hexadecimal or base16? || 68 65 78 61 64 65 63 69 6d 61 6c 
vigenere cipher / ROT13 : Ebgngr zr 13 cynprf! || Rotate me 13 places!
ROT47 : *@F DA:? >6 C:89E C@F?5 323J C:89E C@F?5 Wcf E:>6DX
```
