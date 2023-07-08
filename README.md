# JenkinsLogSearcher

JenkinsLogSearcher is a python script that can search all Jenkins console build logs for supplied strings or regular expressions. If no string or regular expression is supplied the default behavior is to identify any usage of SSHPass in the logs and parse credentials from them. The tool also saves Jenkins logs to disk so that more granular searches for secrets can be performed.

## Installation
```bash
git clone https://github.com/sanitycheck/JenkinsLogSearcher.git
cd JenkinsLogSearcher/
pip install -r requirements.txt
```

## Usage

```bash
usage: JenkinsLogSearcher.py [-h] [-f FILENAME] [--host HOST] [-p--port PORT] [-u USERNAME] [--password PASSWORD] [-d DIRECTORY] [-s SEARCH] [--ssl] [-v]

Search the build console logs for a provided Jenkins instance

options:
  -h, --help            show this help message and exit
  -f FILENAME, --file FILENAME
                        Supply the name of a file which contains a list of <IP:Ports> you wish to search. If no port is supplied 8080 will be used by default
  --host HOST           Supply the host <IP/Hostname:Ports> you wish to search. If no port is supplied 8080 will be used by default
  -p--port PORT         Specify the port number the jenkins instance is running on
  -u USERNAME, --username USERNAME
                        Specify the directory you wish to output the console logs to. This will set the directory to <DATE>-Jenkins-Logs by default
  --password PASSWORD   Specify the directory you wish to output the console logs to. This will set the directory to <DATE>-Jenkins-Logs by default
  -d DIRECTORY, --directory DIRECTORY
                        Specify the directory you wish to output the console logs to. This will set the directory to <DATE>-Jenkins-Logs by default
  -s SEARCH, --search SEARCH
                        Specify the string/regex pattern you wish to search the console build logs for. This will search for 'sshpass' by default
  --ssl                 Connect to the jenkins instance over SSL
  -v, --verbose         Prints verbose match output to the console
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)
