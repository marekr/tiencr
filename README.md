tiencr
======
This program will allow decrypting TI's .encr, .chem and possibly .senc file formats. 

They are all files from TI's battery management IC line of softwares like the bq20zXXXX and bq34zXXXX to name a few. 
The files are used for configuration of the chips. There may be other files used by their software using the same encryption scheme this may work on.

This tool is a completely "third party" tool and is definitely not supported in any way by TI. The software creator has no relation to TI or their employees.
This tool is USE AT YOUR OWN RISK and provided AS IS per the MIT LICENSE as described in the LICENSE file. 


compile
-----
The repo comes with a Visual C++ 2013 project.
This code should compile on any relatively recent version of MSVC++ or even gcc (excluding the ported getopt files of course on Linux). 

usage
-----

Decode a file "input.encr" and output a file "input.encr.decrypted" automatically
```
tiencr -i input.encr
```

Decode a file "input.encr" to a output file of any name of your choosing like "output.txt"
```
tiencr -i input.encr -o output.txt
```
