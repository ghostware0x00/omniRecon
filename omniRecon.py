import socket
import argparse
from colorama import Fore, Style, init # colorama to add color to text displayed using print() function
init(autoreset=True)# resets color of the print() text each time 

COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
}    

def display_scan_output(scan_results): # display scan_result output from the dictionary
    print(f"------------------------------------------------------------------------------------")
    print(f"PORT: {Fore.GREEN}{scan_results['port']}")
    print(f"STATE: {Fore.GREEN}{scan_results['state']}")
    print(f"SERVICE: {Fore.GREEN}{scan_results['service']}")
    print(f"VERSION: {Fore.GREEN}{scan_results['version']}")
    


def bannerGrab_http(client, TARGET): # http banner grabbing
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



def bannerGrab(client, TARGET, port): # banner grabbing
    #implement individual bannerGrab and parsing for each port service
    # services parsing and banner grabbing to be implemented => ftp, ssh, telnet, smtp, mysql
    if port == 21:
        pass
    elif port == 22:
        pass
    elif port == 23:
        pass
    elif port == 25:
        pass
    elif port == 80:
        return bannerGrab_http(client, TARGET)
    elif port == 3306:
        pass

def fullTCPScan(TARGET, PORT):
    # the port_scanning should accept multiple ports
    # this can be implemented using nargs in argsparser
    print(f"{Style.BRIGHT}{Fore.GREEN}[*]Starting FullTCP Scan")
    print(f"{Fore.GREEN}omniRecon scan report for {TARGET}\n")
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
                scan_results['state'] = 'Open'
                scan_results['version'] = bannerGrab(client, TARGET, port)
            except TimeoutError as t: # port might be open but firewall might filter that so it will drop packets (in that scenario we check so timeout) so that the socket doesn't wait indefinetly
                scan_results['state'] = 'Filtered'
            except ConnectionRefusedError as c: # port might be closed so the server will send rst flag refusing connection (such scenario raises this exception)
                scan_results['state'] = 'Closed'
            except OSError as e:
                print(f"{Fore.RED}Couldn't connect to target. Target Unreachable: {e}")
                break
            except KeyboardInterrupt:
                print(f"{Fore.RED}[x]closing omniRecon port scanning...")
            finally:
                display_scan_output(scan_results)



def parseArgs():
    parser = argparse.ArgumentParser(description ="take omnirecon arguments") 
    parser.add_argument("-t", "--target", metavar="www.example.com", help="Provide domain name or IP address") # metavar = placeholder for the value which you need to give # help = description for the placeholder about what to input
    parser.add_argument("-p", "--port", nargs='*' ,metavar="80", help="Provide target port to connect with") # nargs allows multiple values for a single command line argument also nargs='*' allows 0 or more values to be given as command line value. nargs takes the values as list []
    parser.add_argument("-sT", "--fullTCP", action="store_true", help="Perform Full TCP Scan (3 way Handshake)")# argument to perform Full TCP 3 way Handshake Scan
    return parser.parse_args()



def get_args():
    args = parseArgs() # (args) stores the arguments supplied
    if args.fullTCP and args.target and args.port:
        fullTCPScan(args.target, args.port)
    else:
        print(f"{Style.BRIGHT}{Fore.YELLOW}[x]missing or incorrect arguments")



def main():
    get_args()



if __name__ == "__main__": # if we import this script to somewhere else or file the code doesnt automatically gets executed so we can use the resuse this code without accidentally setting it off
    main()