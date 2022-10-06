# dp_cryptomg

Another tool for exploiting CVE-2017-9248, a cryptographic weakness in Telerik UI for ASP.NET AJAX dialog handler. Exploitation leads to access to a file manager utility capable up uploading arbitrary files, usually leading to remote code execution.

The vulnerability is caused by an information leak via error messages during decryption of the Telerik "DialogParameters", which are a series of encrypted configuration values. These values are provided to the user, and then echoed back to the server as user-input. The leaked info about the decryption process allow for systemtic discovery of the `Telerik.Web.UI.DialogParametersEncryptionKey`. For a deep-dive into the vulnerability and how the tool works, visit our blog post at: LINK HERE.

![dp_cryptomg_Trim](https://user-images.githubusercontent.com/24899338/193930865-20e6ac1e-fdeb-4435-8415-fda74e2ade05.gif)

# Acknowledgements

* The original tool for exploiting CVE-2017-9248 [dp_crypto](https://github.com/bao7uo/dp_crypto) was invaluable for building this one. Not to mention, it's netted us plenty of RCEs over the years :)

* Research by SR Labs in their blog post [Achieving Telerik Remote Code Execution 100 Time Faster](https://www.srlabs.de/bites/telerik-100-times-faster) was the basis for the technique used in this tool and inspired us to create it

# Usage

Example (Basic usage):


```
python3 dp_crypto.py http://example.com/Telerik.Web.UI.DialogHandler.aspx
```
Example (Setting custom key length and using a proxy)

```
python3 dp_crypto.py -l 40 -p http://127.0.0.1:8080  http://example.com/Telerik.Web.UI.DialogHandler.aspx
```

usage: dp_cryptomg.py [-h] [-d] [-c COOKIE] [-k KNOWN_KEY] [-v VERSION] [-l LENGTH] [-p PROXY] [-s] [-S] url

```
positional arguments:
  url                   The target URL

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Enable debugging mode
  -c COOKIE, --cookie COOKIE
                        Add optional cookie header to every request
  -k KNOWN_KEY, --known-key KNOWN_KEY
                        The partial or complete known key, in HEX format
  -v VERSION, --version VERSION
                        Specify the Telerik version, if known
  -l LENGTH, --length LENGTH
                        The length of the key, if known
  -p PROXY, --proxy PROXY
                        Optionally set an HTTP proxy
  -s, --simple          Turn on off the fancy interface
  -S, --super-simple    Turn on off the fancy interface and show minimal output
```

# Features
- Increased speed over previous tools
- Capable of recovering key from both the `Telerik.Web.UI.DialogHandler.aspx` and the `Telerik.Web.UI.SpellCheckHandler.axd` endpoints
- Built in HTTP proxy support
- Capable of adding a custom cookie header to each request

# Important Notes
- If they key length is not the default length of 48, you must manually specify the length with the -l parameter
- If you experience issues with the "fancy" interface, you can disable it with the -s or -S options. This will also slightly increase the speed of the exploitation process.

# References

- CVE-2017-9248 - [https://nvd.nist.gov/vuln/detail/CVE-2017-9248](https://nvd.nist.gov/vuln/detail/CVE-2017-9248)
- Telerik Knowledge Base Cryptographic Weakness - [https://docs.telerik.com/devtools/aspnet-ajax/knowledge-base/common-cryptographic-weakness](https://docs.telerik.com/devtools/aspnet-ajax/knowledge-base/common-cryptographic-weakness)
- dp_crypto - [https://github.com/bao7uo/dp_crypto](https://github.com/bao7uo/dp_crypto)
- Telerik 100 Times Faster - [https://www.srlabs.de/bites/telerik-100-times-faster](https://www.srlabs.de/bites/telerik-100-times-faster)
- Pwning Web Applications via Telerik Web UI - [https://captmeelo.com/pentest/2018/08/03/pwning-with-telerik.html](Pwning Web Applications via Telerik Web UI)
