import argparse
from colorama import Fore, Style
from datetime import datetime
import jenkins
import re
import os

def format_string(color_obj,format_obj) -> str:
    return f"{color_obj}{format_obj}{Style.RESET_ALL}"

notify_negative = format_string(Fore.RED,'[!]')
notify_positive = format_string(Fore.GREEN,'[+]')
notify_info = format_string(Fore.BLUE,'[*]')

parser = argparse.ArgumentParser(description="Search the build console logs for a provided Jenkins instance")
parser.add_argument(
    "-f",
    "--file",
    dest="filename",
    type=str,
    help="Supply the name of a file which contains a list of <IP:Ports> you wish to search. If no port is supplied 8080 will be used by default"
)
parser.add_argument(
    "--host",
    dest="host",
    type=str,
    help="Supply the host <IP/Hostname:Ports> you wish to search. If no port is supplied 8080 will be used by default"
)
parser.add_argument(
    "-p"
    "--port",
    dest="port",
    type=str,
    help="Specify the port number the jenkins instance is running on"
)
parser.add_argument(
    "-u",
    "--username",
    dest="username",
    type=str,
    help="Specify the directory you wish to output the console logs to. This will set the directory to <DATE>-Jenkins-Logs by default"
)
parser.add_argument(
    "--password",
    dest="password",
    type=str,
    help="Specify the directory you wish to output the console logs to. This will set the directory to <DATE>-Jenkins-Logs by default"
)
parser.add_argument(
    "-d",
    "--directory",
    dest="directory",
    type=str,
    help="Specify the directory you wish to output the console logs to. This will set the directory to <DATE>-Jenkins-Logs by default"
)
parser.add_argument(
    "-s",
    "--search",
    dest="search",
    type=str,
    help="Specify the string/regex pattern you wish to search the console build logs for. This will search for 'sshpass' by default"
)
parser.add_argument(
    "--ssl",
    dest="ssl",
    action="store_true",
    help="Connect to the jenkins instance over SSL"
)
parser.add_argument(
    "-v",
    "--verbose",
    dest="verbose",
    action="store_true",
    help="Prints verbose match output to the console"
)
"""
Default argument settings
"""
parser.set_defaults(ssl=False)
parser.set_defaults(verbose=False)
parser.set_defaults(port=8080)
parser.set_defaults(search="sshpass")
parser.set_defaults(directory="{0}-Jenkins-Log".format(datetime.now().strftime("%m-%d-%Y-%H-%M-%S")))
args = parser.parse_args()

"""
Constants used throughout the program
"""
CONSOLE_LOG_DIRECTORY = f"{args.directory}/console_logs/"
MATCHED_LINES_DIRECTORY = f"{args.directory}/line_matches/"
SSHPASS_LOG_DIRECTORY = f"{args.directory}/sshpass_passwords/"
ERROR_LOG_DIRECTORY = f"{args.directory}/error_logs/"

"""
Log file handles to be initialized in the main routine
"""

def read_hosts_from_file(filename: str) -> list:
    with open(filename, 'r') as hostfile:
        return hostfile.readlines()

def is_integer(string: str) -> bool:
    """
    Boolean expression to check if the string passed the function is an iteger value - mainly used to process port values provided in the host file.
    """
    try: 
        int(string)
        return True
    except ValueError:
        return False
def process_sshpass_input(log_lines, sshpass_fh):
    for line in log_lines:
        words = line.split(" ")
        password = None
        host = None
        index = 0
        password_found = False
        for word in words:
            if word == "-p" or word == "-p,":
                prev_cmd = words[index-1]
                if "sshpass" in prev_cmd:                 
                    password = words[index+1]
                    password_found = True
                    if password[-1] == ',':
                        password = password[0:-1]
            if password_found:
                if "@" in word:
                    if re.search("([0-9]{1,3}\.){3}[0-9]{1,3}", word) or ".com" in word:
                        host = word.split(":")[0] # scp will include directory paths
                        if host[-1] == ",":
                            host = host[0:-1]
            index += 1
        if host and password != None:
            print(f"{notify_positive} HOST: {format_string(Fore.CYAN, host)} PASSWORD: {format_string(Fore.CYAN,password)}")
            sshpass_fh.write(f"{notify_positive} HOST: {format_string(Fore.CYAN, host)} PASSWORD: {format_string(Fore.CYAN,password)}\n")

def authenticate_to_jenkins(host: str, port: int) -> jenkins.Jenkins:
    """
    Returns an instance of Jenkins if the user is able to authenticate to the specified host.
    """
    protocol = "http"
    if len(host.split(":")) == 2 and is_integer(host.split(":")[1]):
        port = host.split(":")[1]
    if args.ssl:
        protocol = "https"
    if args.username != None and args.password != None:
        return jenkins.Jenkins(url=f"{protocol}://{host}:{port}",username=args.username, password=args.password)
    return jenkins.Jenkins(f"{protocol}://{host}:{port}")

def get_logname(directory: str, name: str) -> str:
    return "{}{}__{}.log".format(directory,name, datetime.now().strftime("%m-%d-%Y-%H-%M-%S"))

def main():

    hosts: list[str] = []
    if args.host == None and args.filename == None:
        print(f"{notify_negative} No host or filename was supplied.")
        return
    if args.filename != None:
        try:
            hosts = read_hosts_from_file(args.filename) #["9.30.110.26"] #["9.28.235.53"] #read_hosts_from_file(filename)
            if not hosts:
                raise Exception("No hosts found in file.")
        except Exception as e:
            print(f"{notify_negative} Unable to read hosts from {args.filename}")
            return
    if args.host != None:
        hosts.append(args.host)
    try:
        print(f"{notify_info} Creating directory structure...")
        print(args.directory)
        os.mkdir(args.directory)
        print(CONSOLE_LOG_DIRECTORY)
        os.mkdir(CONSOLE_LOG_DIRECTORY)
        print(MATCHED_LINES_DIRECTORY)
        os.mkdir(MATCHED_LINES_DIRECTORY)
        if args.search == "sshpass":
            print(SSHPASS_LOG_DIRECTORY)
            os.mkdir(SSHPASS_LOG_DIRECTORY)
        print(ERROR_LOG_DIRECTORY)
        os.mkdir(ERROR_LOG_DIRECTORY)
    except Exception as e:
        print(e)
        print(f"{notify_negative} Unable to create directory structure")
        return

    for host in hosts:
        
        port = args.port
        host = host.rstrip()
        ###
        consolelog_name = get_logname(CONSOLE_LOG_DIRECTORY, f"{host}-console")
        matchlog_name = get_logname(MATCHED_LINES_DIRECTORY, f"{host}-matches")
        sshpasslog_name = None
        if args.search == "sshpass":
            sshpasslog_name = get_logname(SSHPASS_LOG_DIRECTORY, f"{host}-sshpass")
        errorlog_name = get_logname(ERROR_LOG_DIRECTORY, f"{host}-error")
        print(f"{notify_info} Creating log files...")

        print(consolelog_name)
        console_log = open(consolelog_name, "w")
        print(matchlog_name)
        match_log = open(matchlog_name, "w")
        sshpass_log = None
        if sshpasslog_name != None:
            print(sshpasslog_name)
            sshpass_log = open(sshpasslog_name, "w")
        print(errorlog_name)
        error_log = open(errorlog_name, "w")
        ##
        try:
            server = authenticate_to_jenkins(host,port)
        except Exception as e:
            print(f"{notify_negative} Unable to authenticate to remote host: {host}:{port}")
            error_log.write(f"Unable to authenticate to remote host: {host}:{port}\n")
            return
        print(f"{notify_info} Enumerating Jenkins jobs on the remote server: {host}")
        for job in server.get_jobs():
            try:
                job_name = job["fullname"]
                info = server.get_job_info(job_name)
                builds = info["builds"]
                print(f"{notify_info} Enumerating builds for {job_name} job...")
                for build in builds:
                    build_number = build['number']
                    console_output = server.get_build_console_output(job_name, build_number)
                    console_log.write(console_output)
                    log_lines = console_output.split("\n")
                    if args.search == "sshpass":
                        process_sshpass_input(log_lines,sshpass_log)
                    for line in log_lines:
                        match = re.search(args.search, line)
                        if match:
                            if args.verbose:
                                print(f"{notify_positive} MATCH: {line}")
                            match_log.write(f"SERVER: {host} JOB_NAME: {job_name} BUILD_NUMBER: {build_number} LINE:{line}\n")
            except Exception as e:
                print(e)
                pass
        console_log.close()
        match_log.close()
        error_log.close()
        if sshpass_log != None:
            sshpass_log.close()

if __name__ == "__main__":
    main()