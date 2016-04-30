# Openssl tools

A small collection of tools that work with openssl.


Very very rough, but works.

Using python 3.5.
Built this in visual studio with the python plugin, as I look at this same code in pycharm some issues still to fix.
There are some string differences between 2.x and 3.x that are worth watching out for, such as the code snipet below.



## csr_generator
Pulls from a spreadsheet, fqdn/url, and builds a key/csr, folders are built to deposit the files into for later use.



```
<language python>
    if sans:
        sans = sans.split(",")

        altname = b'subjectAltName'
        dns = b'DNS:'

        for node in sans:
            node = node.strip()
            dns_name = dns + node.encode()
            extentions.append(crypto.X509Extension(altname, False, dns_name))

    req.add_extensions(extentions)
```


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

