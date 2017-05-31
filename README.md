This script tests how much access a set of credentials give via SSH on a network. It is designed to work with systems that require multi-factor authentication to gain access. The module pexpect is used to control the ssh client.

For each host, you can provide a private key, a password, and a google authenticator seed (or any combination of those). The script output will explain which credentials were needed to access each host, or on what step of the login process the attempt failed.

#### Install Dependencies:

    sudo pip install pyotp


#### Help

    usage: ssh-credscan.py [-h] [-n] [-t] [-l] [-b] [-vl] [-v] path [path ...]

    positional arguments:
      path                 Configuration file. One host per line format: 'ip:port:username:password:key_path:gauth_secret'
                       
                           Examples:
                       
                           10.1.1.10:22:bob:password:/home/bob/.ssh/id_rsa:
                           10.1.1.11:22:alice::/home/alice/.ssh/id_dsa:
                           10.1.1.200:7000:jim::/home/jim/.ssh/id_rsa:3BQYORLS735ILSJC
                           10.1.1.100:4000:bob:password::

    optional arguments:
      -h, --help           show this help message and exit
      -n , --threads       Number of threads
      -t , --timeout       Seconds to wait after sending one of the credentials
      -l , --logdir        Log Directory, 'None' to disable. default: ./
      -b, --blank          If prompted for password and none is provided in config, attempt to use a blank password
      -vl, --verbose-logs  Log ssh process output in logfile
      -v, --verbose        Display ssh process output

#### Example Output:

    bob@dev ~/Documents/ssh-credscan $ ./ssh-credscan.py ./ssh_scan_config
    ------------
    Target Hosts
    ------------
    ['192.168.56.103', '22', 'bob', 'testpassword123', '/home/bob/.ssh/id_rsa_dev', '']
    ['192.168.56.104', '22', 'bob', 'testpassword123', '/home/bob/.ssh/id_rsa_dev', '']
    ['192.168.56.105', '22', 'bob', 'testpassword123', '/home/bob/.ssh/id_rsa_dev', 'MTCGUMMBV28WHXPR']
    ['192.168.56.105', '22', 'bob', 'testpassword123', '/home/bob/.ssh/id_rsa_dev', '']
    ['192.168.56.105', '22', 'bob', '', '/home/bob/.ssh/id_rsa_dev', '']
    ['192.168.56.104', '22', 'bob', '', '', '']
    Threads: 1
    Timeout: 10
    Log File: ./log_ssh_scan_75844.txt
    Scan with this configuration? (yes/no) yes
    Starting Scan...

    ['SUCCESS (valid_creds: key, password)', '192.168.56.103', '22', 'bob', 'testpassword123', '/home/bob/.ssh/id_rsa_dev', '']
    ['SUCCESS (valid_creds: key)', '192.168.56.104', '22', 'bob', 'testpassword123', '/home/bob/.ssh/id_rsa_dev', '']
    ['SUCCESS (valid_creds: key, password, gauth)', '192.168.56.105', '22', 'bob', 'testpassword123', '/home/bob/.ssh/id_rsa_dev', 'MTCGUMMBV28WHXPR']
    ['FAILURE (reason: gauth prompt, no gauth_secret in config) (valid_creds: key, password)', '192.168.56.105', '22', 'bob', 'testpassword123', '/home/bob/.ssh/id_rsa_dev', '']
    ['FAILURE (reason: password prompt, no password in config) (valid_creds: key)', '192.168.56.105', '22', 'bob', '', '/home/bob/.ssh/id_rsa_dev', '']
    ['SUCCESS (valid_creds: blank password)', '192.168.56.104', '22', 'bob', '', '', '']

    SCAN COMPLETE!
    File logged to ./log_ssh_scan_75844.txt

#### pexpect logic

* call ssh with command echo echval (unique random int), pass private key as parameter (if provided)
  * server returns echval (SUCCESS)
  * timeout or EOF (FAILURE)
  * server prompts for password
    * password not provided in config file (FAILURE)
    * password provided in config file, send it
      * server returns echval (SUCCESS)
      * timeout or EOF (FAILURE)
      * server prompts for verification code
        * gauth_secret not provided (FAILURE)
        * gauth_secret provided in config file, send gauth_secret
          * server returns echval (SUCCESS)
          * timeout or EOF (FAILURE)
  * server prompts for verification code
    * gauth_secret not provided in config (FAILURE)
    * gauth_secret provided in config file, send gauth_secret
      * server returns echval (SUCCESS)
      * timeout or EOF (FAILURE)
