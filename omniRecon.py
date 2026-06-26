import socket
import argparse
from colorama import Fore, Style, init # colorama to add color to text displayed using print() function
init(autoreset=True)# resets color of the print() text each time 

def port_scanning(TARGET, PORT):
    # the port_scanning should accept multiple ports
    # this can be implemented using nargs in argsparser
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:# creating a socket object
            # using the with keyword the socket object is closed automatically no matter what
            client.connect((TARGET, PORT))
            print(f"{Fore.GREEN}xxxxxxxxxxxxxxxxxxxxxxxxx SCAN RESULTS xxxxxxxxxxxxxxxxxxxxxxxxxxx")
            for port in PORT:
                if port != 80 or 443: # port 80 is http and 443 is https so we need the client to talk first before target sends message
                    service_info = client.recv(10000)
                    print(f"{service_info}")
    except KeyboardInterrupt:
        print(f"{Fore.CYAN}[x]closing connection")
    except OSError as e:
        print(f"{Fore.RED}Socket connection timed out : {e}")

def parseArgs():
    parser = argparse.ArgumentParser(description ="take omnirecon arguments") 
    parser.add_argument("-t", "--target", metavar="www.example.com", help="Provide domain name or IP address") # metavar = placeholder for the value which you need to give # help = description for the placeholder about what to input
    parser.add_argument("-p", "--port", nargs='*' ,metavar="80", help="Provide target port to connect with") # nargs allows multiple values for a single command line argument also nargs='*' allows 0 or more values to be given as command line value. nargs takes the values as list []
    return parser.parse_args()

def get_args():
    args = parseArgs() # (args) stores the arguments suppied
    if args.target and args.port:
        port_scanning(args.target, int(args.port))
    else:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[x]missing or incorrect arguments")

def main():
    get_args()


if __name__ == "__main__": # if we import this script to somewhere else or file the code doesnt automatically gets executed so we can use the resuse this code without accidentally setting it off
    main()