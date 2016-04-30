# Openssl tools

A small collection of tools that work with openssl.



Very very rough, but works.

Built this in visual studio with python plugin, as I look at this same code in pycharm some issues still to fix.




## csr_generator
Pulls from a spreadsheet, fqdn/url, and builds a key/csr, folders are built to deposit the files into for later use.

```
  Usage:
  python csr_generator.py  -f <file name>
  python csr_generator.py  -n node
```




### pfxbuilder
Scrapes a folder, pulls key/cer and with a pass phrase builds a pfx for use on a windows box.
```
  Usage:
  python pfxbuilder.py  -p <pass phrase>

```



## Acknowledgment
Initial x509 idea came from  Courtney Cotton's  [python-csr](https://github.com/cjcotton/python-csr) in the use
of the x509 openssl/crypt lib

