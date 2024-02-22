import os
import sys
from colorama import Fore, Style


def getScriptRoot():
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


class SimpleTerminalView:
    def __init__(self, *a, **kw):
        self.log_messages = []
        self.cryptomg = None
        self.super_simple = False
        self.quick_check = kw.get("quick_check", False)

    def msgprint(self, msg, time=None, severity="normal"):
        if self.super_simple == False:
            if severity == "normal":
                msg_color = Fore.YELLOW

            elif severity == "error":
                msg_color = Fore.RED

            elif severity == "success":
                msg_color = Fore.GREEN

            elif severity == "debug":
                if not self.cryptomg.debug:
                    return

                msg_color = Fore.MAGENTA

            print(f"{msg_color}{Style.BRIGHT}{msg}{Style.RESET_ALL}")
        else:
            if severity == "success":
                print(msg)

            elif severity == "error":
                print(msg, file=sys.stderr)

    @staticmethod
    def make_readable(char):
        if char < 33 or char > 126:
            return "[" + str(hex(char)).split("x")[1].upper() + "]"
        else:
            return chr(char)

    def handle_resize(self, x, y):
        pass

    def cleanup(self):
        raise Exception

    def clear(self):
        pass

    def sigwinch_handler(self):
        pass

    def config_draw(self):
        self.msgprint("CONFIGURATION:")

        if self.quick_check:
            self.msgprint("Running in Quick Check mode. Key will not be solved.", severity="error")

        if self.super_simple:
            self.msgprint("Running in SUPER SIMPLE mode (minimal output)", severity="success")
        else:
            self.msgprint("Running in SIMPLE mode (less output)", severity="success")
        self.msgprint(f"URL: {self.cryptomg.url}")
        if self.cryptomg.handler == "DH":
            handlerText = "Telerik.Web.UI.DialogHandler.aspx"
        elif self.cryptomg.handler == "SP":
            handlerText = "Telerik.Web.UI.SpellCheckHandler.axd"

        self.msgprint(f"Handler: {handlerText}")

        if self.cryptomg.cookie:
            cookieText = self.cryptomg.cookie
        else:
            cookieText = "None"

        self.msgprint(f"Cookies added to request: {cookieText}")
        if self.cryptomg.debug:
            debugText = "ENABLED"
        else:
            debugText = "DISABLED"
        self.msgprint(f"Debug Mode: {debugText}")

        if self.cryptomg.proxy:
            proxyText = self.cryptomg.proxy["http"]
        else:
            proxyText = "DISABLED"
        self.msgprint(f"Proxy: {proxyText}")

    def status_draw(self):
        solved_key_text = b"".join(self.cryptomg.solved_blocks).hex()
        if len(solved_key_text) > 0:
            self.msgprint("STATUS:")
            solved_key_text += " (" + b"".join(self.cryptomg.solved_blocks).decode() + ")"
            self.msgprint(solved_key_text)

            current_block_text = str(len(self.cryptomg.solved_blocks) + 1)

            self.msgprint(f"Current Block: {current_block_text}")
            self.msgprint(f"Current Position: {str(self.cryptomg.current_pos)}")
            self.msgprint(f"Possible Values")

    def possible_values_draw(self):
        self.msgprint(" ".join([self.make_readable(x) for x in self.cryptomg.possible_values]))

    def log_messages_draw(self):
        while len(self.log_messages) > 0:
            log, severity, time = self.log_messages.pop(0)
            self.msgprint(log, time=time, severity=severity)

    def detector_byte_draw(self):
        self.msgprint(f"Detector Bytes: {self.cryptomg.detector_byte}", severity="debug")

    def last_request_draw(self):
        pass

    def progress_bar_draw(self):
        pass

    def exploit_url_draw(self):
        if (self.cryptomg.handler == "SP" and self.cryptomg.findKeyComplete == True) or (
            self.cryptomg.handler == "DH" and self.cryptomg.exploit_url != ""
        ):
            output_message = ""

            host = self.cryptomg.url.split("/")[2]
            filename_key = f"{getScriptRoot()}/cryptomg_key_{host}.out"

            try:
                f = open(filename_key, "w")
                f.write(self.cryptomg.finalkey.hex())
                f.close()
                output_message += f"Key saved to {filename_key}"
            except Exception as e:
                output_message += f"Failed to save key! ({Fore.red}{e}{Style.RESET_ALL})"

            if self.cryptomg.handler == "SP":
                self.msgprint("SpellCheckHandler Endpoint can only be used to retrieve key", severity="error")

            elif self.cryptomg.handler == "DH":
                self.msgprint(f"Exploit URL: {self.cryptomg.exploit_url}")
                filename_exploit = f"{getScriptRoot()}/cryptomg_exploiturl_{host}.out"
                try:
                    f = open(filename_exploit, "w")
                    f.write(self.cryptomg.exploit_url)
                    f.close()
                    self.msgprint(f"Exploit URL saved to: {filename_exploit}", severity="success")

                except Exception as e:
                    output_message += f"Failed to save exploit URL! ({Fore.red}{e}{Style.RESET_ALL})"

                self.msgprint(output_message, severity="success")

            self.msgprint(f"Total Request Count: {str(self.cryptomg.request_count)}", severity="success")

    def footer_draw(self):
        pass

    def initial_draw(self):
        self.clear()
        self.msgprint(
            "dp_cryptOMG.py 0.1.3 - Telerik DialogHandler Weak Crypto Exploit (CVE-2017-9248) - @paulmmueller",
            severity="success",
        )

        self.config_draw()
        self.status_draw()
        self.log_messages_draw()
        self.detector_byte_draw()
