from blessed import Terminal

try:
    import cursor
except ModuleNotFoundError:
    cursor = None
import signal
import os


def getScriptRoot():
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


class TerminalView:
    @staticmethod
    def make_readable(char):
        if char < 33 or char > 126:
            return "[" + str(hex(char)).split("x")[1].upper() + "]"
        else:
            return chr(char)

    def handle_resize(self, x, y):
        self.initial_draw()

    def __init__(self, *a, **kw):
        self.init_window()

        self.logs_wrap_count = 0
        self.pv_wrap_count = 0
        self.possible_values_size = 14
        self.log_messages = []
        self.cryptomg = None

        try:
            signal.signal(signal.SIGWINCH, self.handle_resize)
        except AttributeError:
            pass

    def init_window(self):
        self.t = Terminal()
        print(self.t.civis)
        if cursor:
            cursor.hide()

    def cleanup(self):
        print(self.t.cnorm)
        if cursor:
            cursor.show()

    def clear(self):
        print(self.t.clear)

    def sigwinch_handler(self):
        self.clear()
        self.do_render()

    def config_draw(self):

        # configuration
        print(self.t.move(2, 4) + self.t.white_on_black(self.t.bold("CONFIGURATION:")))
        print(
            self.t.move(3, 4)
            + self.t.white_on_black(self.t.bold("URL: "))
            + self.t.slategray3(self.t.bold(self.cryptomg.url))
        )
        if self.cryptomg.handler == "DH":
            handlerText = "Telerik.Web.UI.DialogHandler.aspx"
        elif self.cryptomg.handler == "SP":
            handlerText = "Telerik.Web.UI.SpellCheckHandler.axd"

        print(
            self.t.move(4, 4)
            + self.t.white_on_black(self.t.bold("Handler: "))
            + self.t.slategray3(self.t.bold(handlerText))
        )

        if self.cryptomg.cookie:
            cookieText = self.cryptomg.cookie
        else:
            cookieText = "None"

        print(
            self.t.move(5, 4)
            + self.t.white_on_black(self.t.bold("Cookies: "))
            + self.t.slategray3(self.t.bold(cookieText))
        )

        if self.cryptomg.debug:
            debugText = "ENABLED"
        else:
            debugText = "DISABLED"
        print(
            self.t.move(6, 4)
            + self.t.white_on_black(self.t.bold("Debug: "))
            + self.t.slategray3(self.t.bold(debugText))
        )

        if self.cryptomg.proxy:
            proxyText = self.cryptomg.proxy["http"]
        else:
            proxyText = "DISABLED"
        print(
            self.t.move(7, 4)
            + self.t.white_on_black(self.t.bold("Proxy: "))
            + self.t.slategray3(self.t.bold(proxyText))
        )

    def status_draw(self):

        # status
        print(self.t.move(9, 4) + self.t.white_on_black(self.t.bold("STATUS:")))

        sk_width = int(self.t.width / 2) - 12
        solved_key_text = b"".join(self.cryptomg.solved_blocks).hex()
        if len(solved_key_text) > 0:
            solved_key_text += " (" + b"".join(self.cryptomg.solved_blocks).decode() + ")"
        solved_key_text_wrapped = self.t.wrap(solved_key_text, width=sk_width)

        line_count = 0
        for line in solved_key_text_wrapped:
            if line_count == 0:
                print(
                    self.t.move(10 + line_count, 4)
                    + self.t.white_on_black(self.t.bold("Solved Key: "))
                    + self.t.green(self.t.bold(line))
                )
            else:
                print(self.t.move(10 + line_count, 4) + self.t.green(self.t.bold(line)))

            line_count += 1
        current_block_text = str(len(self.cryptomg.solved_blocks) + 1)

        print(
            self.t.move(13, 4)
            + self.t.white_on_black(self.t.bold("Current Block: "))
            + self.t.slategray3(self.t.bold(current_block_text))
        )
        print(
            self.t.move(14, 4)
            + self.t.white_on_black(self.t.bold("Current Position: "))
            + self.t.slategray3(self.t.bold(str(self.cryptomg.current_pos)))
        )
        print(self.t.move(16, 4) + self.t.white_on_black(self.t.bold("Possible Values")))

    def possible_values_draw(self):

        pv_width = int(self.t.width / 2) - 5

        for n in range(0, 10):
            print(self.t.move(18 + n, 5) + (self.t.black("█") * pv_width))

        self.pv_wrap_count = 0
        for w in self.t.wrap(" ".join([self.make_readable(x) for x in self.cryptomg.possible_values]), width=pv_width):
            print(self.t.move(18 + self.pv_wrap_count, 5) + self.t.yellow_on_black(w))
            self.pv_wrap_count += 1

    def log_messages_draw(self):
        limit = 30
        log_width = int(self.t.width / 2) - 16
        processed_logs = []
        if len(self.log_messages) > 0:

            for i in reversed(self.log_messages):
                render = None
                log, severity, time = i

                if severity == "normal":
                    render = self.t.white_on_black(time) + " " + self.t.yellow_on_black(self.t.bold(log))
                    wrapped = self.t.wrap(render, log_width)

                elif severity == "error":
                    render = self.t.white_on_black(time) + " " + self.t.red_on_black(self.t.bold(log))
                    wrapped = self.t.wrap(render, log_width)

                elif severity == "success":
                    render = self.t.white_on_black(time) + " " + self.t.green_on_black(self.t.bold(log))
                    wrapped = self.t.wrap(render, log_width)

                elif severity == "debug":
                    if self.cryptomg.debug:
                        render = self.t.white_on_black(time) + " " + self.t.darkviolet_on_black(self.t.bold(log))
                        wrapped = self.t.wrap(render, log_width)

                if render:
                    # If the length of the wrapped log is less than the available log space
                    if len(wrapped) <= (limit - len(processed_logs)):
                        for x in reversed(wrapped):
                            processed_logs.append(x)
                    else:
                        break
        line_count = 0
        for w in reversed(processed_logs):
            # clear the line before writing to it

            print(self.t.move(4 + line_count, (int(self.t.width / 2) + 6)) + (self.t.black(("█")) * log_width))
            print(self.t.move(4 + line_count, (int(self.t.width / 2) + 6)) + w)
            line_count += 1

    def detector_byte_draw(self):
        print(
            self.t.move(23 + self.possible_values_size, 4)
            + self.t.white_on_black(self.t.bold("Detector Bytes: "))
            + self.t.slategray3(self.t.bold(self.cryptomg.detector_byte))
        )

    def last_request_draw(self):
        print(
            self.t.move(24 + self.possible_values_size, 4)
            + self.t.white_on_black(self.t.bold("Last Request: "))
            + self.t.slategray3(self.t.bold(self.cryptomg.last_request))
        )

    def progress_bar_draw(self):
        print(self.t.move(26 + self.possible_values_size, 4) + self.t.white_on_black(self.t.bold("Progress")))
        print(self.t.move(21 + self.possible_values_size + 6, 4) + self.t.white(("█" * (int(self.t.width / 2) - 3))))
        print(self.t.move(21 + self.possible_values_size + 8, 4) + self.t.white(("█" * (int(self.t.width / 2) - 3))))

        key_length = self.cryptomg.length

        completed = int(len(self.cryptomg.solved_blocks) * 4)
        completed_percent = float(completed) / float(key_length)
        progress_bar_length = int(self.t.width / 2) - 5

        solved_section = int(progress_bar_length * completed_percent)
        unsolved_section = progress_bar_length - solved_section

        progress_bar = (self.t.blue3(("█")) * solved_section) + (self.t.cornflowerblue(("█")) * unsolved_section)
        print(
            self.t.move(21 + self.possible_values_size + 7, 4)
            + self.t.white(("█"))
            + progress_bar
            + self.t.white(("█"))
        )

    def exploit_url_draw(self):

        if (self.cryptomg.handler == "SP" and self.cryptomg.findKeyComplete == True) or (
            self.cryptomg.handler == "DH" and self.cryptomg.exploit_url != ""
        ):
            eu_width = int(self.t.width / 2) - 12
            output_message = ""

            print(self.t.move(39, int(self.t.width / 2) + 5) + self.t.white_on_black(self.t.bold("Exploit URL:")))
            host = self.cryptomg.url.split("/")[2]
            filename_key = f"{getScriptRoot()}/cryptomg_key_{host}.out"

            try:
                f = open(filename_key, "w")
                f.write(self.cryptomg.finalkey.hex())
                f.close()
                output_message += "\n" + self.t.white("Key saved to ") + self.t.yellow(filename_key)
            except Exception as e:
                output_message += self.t.red(f"Failed to save key! ({e})")

            if self.cryptomg.handler == "SP":

                print(
                    self.t.move(39, int(self.t.width / 2) + 5)
                    + self.t.white_on_black(self.t.bold("Exploit URL:"))
                    + self.t.red_on_black(self.t.bold(" SpellCheckHandler Endpoint can only be used to retrieve key"))
                )

            elif self.cryptomg.handler == "DH":

                print(self.t.move(39, int(self.t.width / 2) + 5) + self.t.white_on_black(self.t.bold("Exploit URL:")))

                filename_exploit = f"{getScriptRoot()}/cryptomg_exploiturl_{host}.out"
                try:
                    f = open(filename_exploit, "w")
                    f.write(self.cryptomg.exploit_url)
                    f.close()
                    output_message += self.t.white("\nExploit URL saved to ") + self.t.yellow(filename_exploit)

                except Exception as e:
                    output_message += self.t.red(f"Failed to save exploit URL! ({e})")

            wrapped_output_message = self.t.wrap(output_message, width=eu_width)
            line_count = 0
            for line in wrapped_output_message:

                print(self.t.move(40 + line_count, int(self.t.width / 2) + 5) + self.t.white(self.t.bold(line)))
                line_count += 1

    def footer_draw(self):
        # footer
        lf = self.t.white_on_green(self.t.bold("    Press 'q' to exit "))
        rf = self.t.white_on_green(self.t.bold(f"Total Request Count: {str(self.cryptomg.request_count)}    "))
        pad = self.t.white_on_green(" ")
        llen = len(self.t.strip_seqs(lf))
        rlen = len(self.t.strip_seqs(rf))

        footer = lf + ((self.t.width - llen - rlen) * pad) + rf
        print(self.t.move(self.t.height - 2, 0) + footer)

    def initial_draw(self):
        self.clear()

        # header
        print(
            self.t.move(0, 0)
            + self.t.white_on_green(
                self.t.center(
                    self.t.bold(
                        "dp_cryptOMG.py 0.1.3 - Telerik DialogHandler Weak Crypto Exploit (CVE-2017-9248) - @paulmmueller @BlackLanternLLC"
                    )
                )
            )
        )

        self.config_draw()
        self.status_draw()
        self.possible_values_draw()
        self.log_messages_draw()
        self.progress_bar_draw()

        # possible values box
        print(self.t.move(17, 4) + self.t.white(("█" * (int(self.t.width / 2) - 3))))

        for i in range(18, (19 + self.possible_values_size)):
            print(self.t.move(i, 4) + self.t.white(("█")))

        # right side
        for i in range(18, (19 + self.possible_values_size)):
            print(self.t.move(i, int(self.t.width / 2)) + self.t.white(("█")))

        print(self.t.move(18 + self.possible_values_size, 4) + self.t.white(("█" * (int(self.t.width / 2) - 3))))

        # log box
        print(self.t.move(2, int(self.t.width / 2) + 5) + self.t.white_on_black(self.t.bold("LOGS")))

        # top
        print(self.t.move(3, int(self.t.width / 2) + 5) + self.t.white(("█" * (int(self.t.width / 2) - 14))))

        log_box_size = 32

        # left side
        for i in range(4, (4 + log_box_size)):
            print(self.t.move(i, int(self.t.width / 2) + 5) + self.t.white(("█")))

        # right side
        for i in range(4, (4 + log_box_size)):
            print(self.t.move(i, (int(self.t.width / 2) + 4) + (int(self.t.width / 2) - 14)) + self.t.white(("█")))

        # bottom
        print(
            self.t.move(4 + log_box_size, int(self.t.width / 2) + 5)
            + self.t.white(("█" * (int(self.t.width / 2) - 14)))
        )

        self.detector_byte_draw()
        self.last_request_draw()

        # exploit URL area
        self.exploit_url_draw()
        self.footer_draw()
