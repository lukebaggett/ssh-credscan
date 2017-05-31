#!/usr/bin/python
import argparse
import sys
import random
import Queue
import threading
import pexpect
import pyotp

def check_target_pexpect(targets, results, t, blank):
    while not targets.empty():
        target, port, username, password, key_path, gauth_secret = targets.get()
        result = "FAILURE"
        valid_creds = []
        reason = ""
        beforelog = ""
        echval = str(random.randint(10000,99999))
        child = pexpect.spawn('ssh -v -o StrictHostKeychecking=no -p %s -i %s %s@%s "echo %s"' %
            (port, key_path, username, target, echval))
        s0 = child.expect([echval, 'assword:', 'code:', pexpect.EOF, pexpect.TIMEOUT], timeout=t)
        before = child.before
        beforelog += before
        if s0 == 0:
            if 'server accepts key' in before.lower():
                valid_creds.append("key")
            else:
                valid_creds.append("blank password")
            result = "SUCCESS"
        elif s0 == 1:
            if 'server accepts key' in before.lower():
                valid_creds.append("key")
            if ((not blank) and (password == "" or password == None)):
                reason = "password prompt, no password in config"
                result = "FAILURE"
            else:
                child.sendline(password)
                s1 = child.expect([echval, 'code:', pexpect.EOF, pexpect.TIMEOUT], timeout=t)
                before = child.before
                beforelog += before
                if s1 == 0:
                    valid_creds.append("password")
                    result = "SUCCESS"
                elif s1 == 1:
                    valid_creds.append("password")
                    if gauth_secret == "":
                        reason = "gauth prompt, no gauth_secret in config"
                        result = "FAILURE"
                    else:
                        totp = pyotp.TOTP(gauth_secret)
                        child.sendline(totp.now())
                        s2 = child.expect([echval, pexpect.EOF, pexpect.TIMEOUT], timeout=t)
                        before = child.before
                        beforelog += before
                        if s2 == 0:
                            valid_creds.append("gauth")
                            result = "SUCCESS"
                        elif s2 == 1:
                            reason = "EOF on gauth attempt"
                            result = "FAILURE"
                        elif s2 == 2:
                            reason = "timeout on gauth attempt"
                            result = "FAILURE"
                elif s1 == 2:
                    reason = "EOF on password attempt"
                    result = "FAILURE"
                elif s1 == 3:
                    reason = "timeout on password attempt"
                    result = "FAILURE"
        elif s0 == 2:
            if 'server accepts key' in before.lower():
                valid_creds.append("key")
            if gauth_secret == "":
                reason = "gauth prompt, no gauth_secret in config"
                result = "FAILURE"
            else:
                totp = pyotp.TOTP(gauth_secret)
                child.sendline(totp.now())
                s1 = child.expect([echval, pexpect.EOF, pexpect.TIMEOUT], timeout=t)
                before = child.before
                beforelog += before
                if s1 == 0:
                    valid_creds.append("gauth")
                    result = "SUCCESS"
                elif s1 == 1:
                    reason = "EOF on gauth attempt"
                    result = "FAILURE"
                elif s1 == 2:
                    reason = "timeout on gauth attempt"
                    result = "FAILURE"
        elif s0 == 3:
            reason = "EOF on initial attempt"
            result = "FAILURE"
        elif s0 == 4:
            reason = "timeout on initial attempt"
            result = "FAILURE"
        child.close()
        
        resultstr = (result + " (valid_creds: " + ", ".join(valid_creds) + ")")
        if reason != "":
            resultstr = (result + " (reason: " + reason + ") (valid_creds: " + ", ".join(valid_creds) + ")")
        results.put([resultstr, target, port, username, password, key_path, gauth_secret, beforelog])
        targets.task_done()

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('config', metavar='path', nargs='+', help=("""Configuration file. One host per line format: 'ip:port:username:password:key_path'

Examples:

10.1.1.10:22:bob:password:/home/bob/.ssh/id_rsa:
10.1.1.11:22:alice::/home/alice/.ssh/id_dsa:
10.1.1.200:7000:jim::/home/jim/.ssh/id_rsa:3BQYORLS735ILSJC
10.1.1.100:4000:bob:password::"""))
    parser.add_argument('-n', '--threads', default=1, type=int, metavar='', help="Number of threads")
    parser.add_argument('-t', '--timeout', default=10, type=int, metavar='', help="Seconds to wait after sending one of the credentials")
    parser.add_argument('-l', '--logdir', default='./', metavar='', help="Log Directory, 'None' to disable. default: ./")
    parser.add_argument('-b', '--blank', default=False, action='store_true', help="If prompted for password and none is provided in config, attempt to use a blank password")
    parser.add_argument('-vl', '--verbose-logs', default=False, action='store_true', help="Log ssh process output in logfile")
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help="Display ssh process output")
    if len(sys.argv) < 2:
        parser.print_help()
        exit()
    args = parser.parse_args()

    exitthread = threading.Event()
    exitthread.clear()

    configlines = []
    try:
        configlines = open(args.config[0] ,'r').read().splitlines()
    except:
        print "Failed to read config"
        exit()

    if configlines == []:
        print "Failed to read config"
        exit()

    badconfig = False
    for i in range(len(configlines)):
        if len(filter(lambda a: a != '', configlines[i].split(":"))) < 3:
            print ("INVALID CONFIG FILE LINE " + str(i) + "\n" + configlines[i])
            badconfig = True

    if badconfig:
        exit()

    print "------------\nTarget Hosts\n------------"
    targets = Queue.Queue()
    for i in configlines:
        targets.put(i.split(":"))
        print i.split(":")
    print ("Threads: " + str(args.threads))
    print ("Timeout: " + str(args.timeout))
    logfilename = (args.logdir + 'log_ssh_scan_' + str(random.randint(11111,99999)) + '.txt')
    if args.logdir == 'None':
        logfilename = 'None'
    print ("Log File: " + logfilename)

    while True:
        resp = raw_input("Scan with this configuration? (yes/no) ").lower()
        if resp == "yes":
            break
        elif resp == "no":
            exit() 

    print "Starting Scan...\n"
    results = Queue.Queue()
    for i in range(args.threads):
        worker = threading.Thread(target=check_target_pexpect, args=(targets, results, args.timeout, args.blank))
        worker.setDaemon(True)
        worker.start()

    resultsls = []
    if logfilename != 'None':
        fp = open(logfilename, 'wb')
    for i in range(len(configlines)):
        r = results.get()
        if args.verbose:
            print r[:-1]
            print r[7]
        else:
            print r[:-1]
        if logfilename != 'None':
            fp.write("%s, %s, %s, %s, %s, %s\n" % (r[0], r[1], r[2], r[3], r[4], r[5]))
            if args.verbose_logs:
                fp.write("%s\n\n" % r[7])
            fp.flush()

    print "\nSCAN COMPLETE!"
    if logfilename != 'None':
        fp.close()
        print ("File logged to " + logfilename)

if __name__ == "__main__":
    main()


