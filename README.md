# dp_cryptomg

Another tool for exploiting CVE-2017-9248, a cryptographic weakness in Telerik UI for ASP.NET AJAX dialog handler. Exploitation leads to access to a file manager utility capable up uploading arbitrary files, usually leading to remote code execution.

# Acknowledgements

* The original tool for exploiting CVE-2017-9248 [dp_crypto](https://github.com/bao7uo/dp_crypto) was invaluable for building this one, and has netted us plenty of RCEs over the years.

* Research by SR Labs in their blog post [Achieving Telerik Remote Code Execution 100 Time Faster](https://www.srlabs.de/bites/telerik-100-times-faster) was the basis for the technique used in this tool and inspired us to create it.

![dp_cryptomg_Trim](https://user-images.githubusercontent.com/24899338/193930865-20e6ac1e-fdeb-4435-8415-fda74e2ade05.gif)
