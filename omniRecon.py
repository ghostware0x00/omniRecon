import socket
import argparse
from colorama import Fore, Style, init # colorama to add color to text displayed using print() function
init(autoreset=True)# resets color of the print() text each time 



def bannerGrab_ServerFirstArch(client): # services which do not require the client to send data first but server responds immediately upon connection
    service_info = client.recv(4096)
    if service_info:
        print(f"{Fore.CYAN}{service_info.decode()}")



def bannerGrab_HTTP(client, TARGET): # banner grabbing for http
    request_payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"User-Agent: omniRecon\r\n"
        f"Accept: text/html\r\n\r\n"
    )
    client.sendall(request_payload.encode())# encoding to utf8 format
    response = client.recv(4096)
    if response:
        print(f"{Fore.CYAN}{response.decode()}")



def port_scanning_and_service_enumeration(TARGET, PORT):
    # the port_scanning should accept multiple ports
    # this can be implemented using nargs in argsparser
    print(f"{Fore.GREEN}[*]Initiating OMNIRECON Port Scanning and Service Enumeration...")
    print(f"{Fore.GREEN}<---------------- SCAN RESULTS ---------------->")
    print(f"|PORTS\t|Connection\t|Service Version|------->")
    try:        
        for port in PORT:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:# creating a socket object # using the with keyword the socket object is closed automatically matter what
                port = int(port) # convert string to int (since PORT is taken in command line argument)
                try:
                    client.settimeout(30)
                    client.connect((TARGET, port))
                    print(f"")
                    if port == 80: #HTTP
                        bannerGrab_HTTP(client, TARGET) # function to handle http
                    elif port in (22, 21, 25, 3306): # SSH FTP SMTP MySQL
                        bannerGrab_ServerFirstArch(client) # handle server first architecture protocols
                    #elif port 
                except TimeoutError as t: # port might be open but firewall might filter that so it will drop packets (in that scenario we check so timeout) so that the socket doesn't wait indefinetly
                    print(f"{Fore.GREEN}{PORT}\tFiltered")
                except ConnectionRefusedError as c: # port might be closed so the server will send rst flag refusing connection (such scenario raises this exception)
                    print(f"{Fore.GREEN}{PORT}\tClosed")
                except OSError as e:
                    print(f"{Fore.RED}Couldn't connect to target. Target Unreachable: {e}")
    except KeyboardInterrupt:
        print(f"{Fore.RED}[x]closing omniRecon port scanning....")



def parseArgs():
    parser = argparse.ArgumentParser(description ="take omnirecon arguments") 
    parser.add_argument("-t", "--target", metavar="www.example.com", help="Provide domain name or IP address") # metavar = placeholder for the value which you need to give # help = description for the placeholder about what to input
    parser.add_argument("-p", "--port", nargs='*' ,metavar="80", help="Provide target port to connect with") # nargs allows multiple values for a single command line argument also nargs='*' allows 0 or more values to be given as command line value. nargs takes the values as list []
    return parser.parse_args()



def get_args():
    args = parseArgs() # (args) stores the arguments suppied
    if args.target and args.port:
        port_scanning_and_service_enumeration(args.target, args.port)
    else:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[x]missing or incorrect arguments")



def main():
    get_args()



if __name__ == "__main__": # if we import this script to somewhere else or file the code doesnt automatically gets executed so we can use the resuse this code without accidentally setting it off
    main()