import socket
import argparse
from colorama import Fore, Style, init
init(autoreset=True)

def target_connect():
    pass



def parseArgs():
    parser = argparse.ArgumentParser(description ="take omnirecon arguments") 
    parser.add_argument("-t", "--target", metavar="www.examp.com", help="Provide domain name or IP address") # metavar = placeholder for the value which you need to give # help = description for the placeholder about what to input
    parser.add_argument("-p", "--port", metavar="80", help="Provide target port to connect with")
    # need to implement multiple values for port argument taking !!!! => [TO DO LIST]
    return parser.parse_args()

def get_args():
    args = parseArgs() # (args) stores the arguments suppied
    if args.target and args.port:
        print(f"[+]arguments provided")
    else:
        print(f"[x]no arguments provided")

def main():
    get_args()


if __name__ == "__main__": # if we import this script to somewhere else or file the code doesnt automatically gets executed so we can use the resuse this code without accidentally setting it off
    main()