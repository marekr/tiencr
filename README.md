tiencr
======
This program will allow decrypting TI's .encr, .chem and possibly .senc file formats. 

They are all files from TI's battery management IC line of softwares like the bq20zXXXX and bq34zXXXX to name a few. 
The files are used for configuration of the chips. There may be other files used by their software using the same encryption scheme this may work on.

This tool is explicitly for educational purposes. It is also USE AT YOUR OWN RISK per the license.

compile
-----
The repo comes with a Visual C++ 2013 project.
This code should compile on relatively recent version of MSVC++ or even gcc (excluding the ported getopt files of course). 

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
