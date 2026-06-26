import socket
import argparse
from colorama import Fore, Style, init # colorama to add color to text displayed using print() function
init(autoreset=True)# resets color of the print() text each time 

def target_connect(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:# creating a socket object
            # using the with keyword the socket object is closed automatically no matter what
            client.connect((target, port))
            
    except KeyboardInterrupt: # when CTRL + C is pressed in keyboard (useful to exit the program)
        print(f"{Fore.BLUE}[x]closing connection")
    except OSError as e: # handles exception when we fail to connect to our target (such scenarios)
        print(f"{Fore.Red}[x]Could not connect to target. Target unreachable: {e}")



def parseArgs():
    parser = argparse.ArgumentParser(description ="take omnirecon arguments") 
    parser.add_argument("-t", "--target", metavar="www.examp.com", help="Provide domain name or IP address") # metavar = placeholder for the value which you need to give # help = description for the placeholder about what to input
    parser.add_argument("-p", "--port", metavar="80", help="Provide target port to connect with")
    # need to implement multiple values for port argument taking !!!! => [TO DO LIST]
    return parser.parse_args()

def get_args():
    args = parseArgs() # (args) stores the arguments suppied
    if args.target and args.port:
        target_connect(args.target, int(args.port))
    else:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[x]missing or incorrect arguments")

def main():
    get_args()


if __name__ == "__main__": # if we import this script to somewhere else or file the code doesnt automatically gets executed so we can use the resuse this code without accidentally setting it off
    main()