import os # used to exit program
import socket # used to establish communication with server
import requests
import ssl # used to communicate with https protocol
import re # used for pattern matching and parsing scanner responses
import argparse # used for command line argument parsing
from colorama import Fore, Style, init # colorama to add color to text displayed using print() function
init(autoreset=True)# resets color of the print() text each time 

COMMON_SERVICES = {
    21: "ftp", # done
    22: "ssh", # done
    23: "telnet", # done
    25: "smtp", # done
    53: "dns",
    80: "http", # done
    110: "pop3", # done
    143: "imap",
    443: "https", # done
    445: "smb",
    3306: "mysql", # done
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
}    

def display_scan_output(scan_results): # display scan_result output from the dictionary
    print(
        f"{Style.BRIGHT}{Fore.YELLOW}{scan_results['port']:<10}"
        f"{Style.BRIGHT}{Fore.MAGENTA}{scan_results['state']:<10}"
        f"{Style.BRIGHT}{Fore.BLUE}{scan_results['service']:<12}"
        f"{Style.BRIGHT}{Fore.CYAN}{scan_results['version']}"
    )

def bannerGrab_immediateResponse(client):# port 21 23 ftp telnet banner grabbing
    version = client.recv(4096).decode(errors="ignore").strip()
    return version


def bannerGrab_ssh(client):# port 22 ssh banner grabbing
    response = client.recv(4096).decode(errors="ignore")
    version = re.sub(r"^\s+|\s$|SSH-2.0-?", "", response)
    return version


def bannerGrab_mysql(client):
    content = client.recv(4096)
    # +--------------------+
    # | Packet Length      | 3 bytes (0-2)
    # +--------------------+
    # | Sequence ID        | 1 byte (3)
    # +--------------------+
    # | Protocol Version   | 1 byte (4)
    # +--------------------+
    # | Server Version     | Variable length (5)
    # |                    | Ends with 0x00
    # +--------------------+
    # | Connection ID      | 4 bytes
    # +--------------------+
    # | Authentication...  |
    # | Capability Flags...|
    # | Character Set...   |
    # | Status Flags...    |
    # | ...                |
    # +--------------------+
    version = content[5:].split(b'\x00')[0].decode(errors="ignore") # content[5:] means store bytes from 5th index and split when null character(\x00) is seen and pick the first item from the list[0]
    return version             
 

def bannerGrab_smtp(client, TARGET):# port 25 smtp banner grabbing
    response = client.recv(4096).decode(errors="ignore").replace("\r\n","")
    version = re.sub(r"^\d{3}\s+|E?SMTP", "", response)
    return version


def bannerGrab_pop3(client):# port 110 pop3 banner grabbing
    response = client.recv(4096).decode(errors="ignore")
    version = re.sub(r"^\s+|\s+$|\+OK", "", response)
    return version


def bannerGrab_http(client, TARGET): # port 80 http banner grabbing
    # services like http wait for the client to send a message and then the server replies so 
    # the below request payload is created to send a message to the client
    request_payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"User-Agent: omniRecon\r\n"
        f"Accept: text/html\r\n\r\n"
    )
    client.sendall(request_payload.encode())# encoding to utf8 format
    response = client.recv(4096)
    if response:
        response = response.decode(errors="ignore").split("\r\n")
        for line in response:
            if line.startswith("Server:"):
                version = line.replace("Server:", "").strip() # replace extra spaces and replace Server header tag and only retrieve the version info
                return version


def bannerGrab_https(client, TARGET):# port 443 https banner grabbing
    # function to wrap the unencrypted tcp socket to encrypted ssl/tls socket
    # this creates a secured communication channel between server and client
    # so before sending raw data first to https we need to create a secured channel first and only then we can send data to the server
    context = ssl.create_default_context() # used to load ca certificates 
    secure_socket = context.wrap_socket(client, server_hostname=TARGET) # initiates tls handshake 
    return bannerGrab_http(secure_socket, TARGET)




def bannerGrab(client, TARGET, port): # banner grabbing
    #implement individual bannerGrab and parsing for each port service
    # services parsing and banner grabbing to be implemented => ftp, ssh, telnet, smtp, mysql
    if port in (21,23):
        return bannerGrab_immediateResponse(client)
    elif port == 22:
        return bannerGrab_ssh(client)
    elif port == 25:
        return bannerGrab_smtp(client, TARGET)
    elif port == 80:
        return bannerGrab_http(client, TARGET)
    elif port == 110:
        return bannerGrab_pop3(client)
    elif port == 443:
        return bannerGrab_https(client, TARGET)
    elif port == 3306:
        return bannerGrab_mysql(client)
    else:
        return bannerGrab_immediateResponse(client)



def fullTCPScan(TARGET, PORT):
    # the port_scanning should accept multiple ports
    # this can be implemented using nargs in argsparser
    print(f"{Style.BRIGHT}{Fore.GREEN}[*]Starting FullTCP Scan")
    print(f"{Fore.GREEN}omniRecon scan report for {TARGET}\n")
    print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<12}{'VERSION'}") # aligning to left 10 character width for port and state and 12 character left alignment for service. <(left alignment) and >(right alignment)
    for port in PORT:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:# creating a socket object # using the with keyword the socket object is closed automatically matter what
            port = int(port) # convert string to int (since PORT is taken in command line argument)
            try:
                scan_results = {"port":port, "state":"", "service":"", "version":""}
                try:
                    scan_results['service'] = socket.getservbyport(port, "tcp")
                except OSError as e:
                    scan_results['service'] = COMMON_SERVICES.get(port, 'unknown') # if common services list doesn't have that particular port service info then store unknown
                client.settimeout(10)
                client.connect((TARGET, port))
                scan_results['state'] = 'open'
                scan_results['version'] = bannerGrab(client, TARGET, port)
            except TimeoutError as t: # port might be open but firewall might filter that so it will drop packets (in that scenario we check so timeout) so that the socket doesn't wait indefinetly
                scan_results['state'] = 'filtered'
            except ConnectionRefusedError as c: # port might be closed so the server will send rst flag refusing connection (such scenario raises this exception)
                scan_results['state'] = 'closed'
            except OSError as e:
                print(f"{Fore.RED}Couldn't connect to target. Target Unreachable: {e}")
                os._exit(0)
            except KeyboardInterrupt:
                print(f"{Fore.RED}[x]closing omniRecon port scanning...")
            finally:
                display_scan_output(scan_results)



def directory_bruteforcing(TARGET, wordlist): # function to perform directory
    status_codes = [200, 201, 301, 302, 401, 403]
    print(f"{Style.BRIGHT}{Fore.GREEN}[*]Starting omniRecon Directory Bruteforce Attack\n")
    print(f"[+]Url/Domain] : {TARGET}")
    print(f"[+]Wordlist : {wordlist}")
    print("[+]Status codes : ",*status_codes, sep=", ")# *<list_variable> produces spaces between each list element and sep=", " separates each element by commas,
    print("============================================\n")
    print(f"\tomniRecon Directory Bruteforce Attack")
    print("============================================\n")
    try:
        with open(wordlist, "r") as file:
            words = file.read()
            for word in words:
                try:
                    response = requests.get(f"{TARGET}{word}")
                    if response.status_code in status_codes:
                        print(f"{Fore.CYAN}{word} ( Status: {response.status_code})")
                except KeyboardInterrupt:
                    print(f"{Style.RED}[x]Exiting omniRecon")
                    os._exit(0)
                except OSError as e:
                    print(f"{Style.RED}couldn't reach target server: {e}")
    except FileNotFoundError as f:
        print(f"{Fore.RED}{f}")    


def parseInput(TARGET): # remove http or https and 
    # r"" is used for raw string checking
    # ^ = starting $ = ending
    # \s+ one or multiple spaces and ^\s+ removes starting spaces and \s+$ removes ending spaces
    # https? means basically subtract https or http string the ? just after s makes s optional so regex will look for both patterns and :// will also get subtracted
    TARGET = re.sub(r"^\s+|\s+$|https?://", "", TARGET)
    return TARGET


def parseArgs():
    parser = argparse.ArgumentParser(description ="take omnirecon arguments") 
    parser.add_argument("-t", "--target", metavar="www.example.com", help="Provide domain name or IP address") # metavar = placeholder for the value which you need to give # help = description for the placeholder about what to input
    parser.add_argument("-p", "--port", nargs='*' ,metavar="80", help="Provide target port to connect with") # nargs allows multiple values for a single command line argument also nargs='*' allows 0 or more values to be given as command line value. nargs takes the values as list []
    parser.add_argument("-sT", "--fullTCP", action="store_true", help="Perform Full TCP Scan (3 way Handshake)")# argument to perform Full TCP 3 way Handshake Scan
    parser.add_argument("-w", "--wordlist", metavar="rockyou.txt", help="Provide wordlist")# provide wordlist absolute path
    return parser.parse_args()



def get_args():
    args = parseArgs() # (args) stores the arguments supplied
    if args.fullTCP and args.target and args.port:
        args.target = parseInput(args.target)
        fullTCPScan(args.target, args.port)
    elif args.target and args.wordlist:
        directory_bruteforcing(args.target, args.wordlist)
    else:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[x]missing or incorrect arguments")



def main():
    get_args()



if __name__ == "__main__": # if we import this script to somewhere else or file the code doesnt automatically gets executed so we can use the resuse this code without accidentally setting it off
    main()