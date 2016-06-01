#!/usr/bin/env python


'''\n  pfx generator
  Builds  directories containing  a cert, key and ".pfx" for each fqdn processed

  The list should be fqdn/url or box name.


  Usage:
  python pfxbuilder.py  -p <pass phrase>

  Arguments:

    -p      pass phrase (this is required to build a cert container)


  Flags:
    -h      help


  ############################################################
    If there is an output of  "key/cert do not match for <some fqdn>"

    use:
      openssl x509 -noout -modulus -in certificate.crt | openssl md5
      openssl rsa -noout -modulus -in privateKey.key | openssl md5
      openssl req -noout -modulus -in CSR.csr | openssl md5

    All 3 files should have the same md5 hash

  ############################################################


    Version: 003

'''

# Libraries/Modules
from OpenSSL import crypto, SSL
import sys
import os
import getopt
import re
import shutil


def usage():
    print(__doc__)


def pars_cmd(argv):
    file_name = None
    data_flag = 0
    pass_phrase = None

    if (len(sys.argv[1:]) != 0):

        try:
            opts, args = getopt.getopt(sys.argv[1:], "p:h")
        except getopt.GetoptError as err:
            # print help information and exit:
            print(err)  # will print something like "option -a not recognized"
            usage()
            sys.exit(2)

        # checks to see if opts(list) is empty

        if not opts:
            print("There were no options given use -h to see help\n")

        # parses opts and arguments
        for o, a in opts:

            if o in ("-h"):
                # help
                usage()
                exit()
            elif o in ("-p"):
                # pass phrase
                pass_phrase = a

            else:
                assert False, "parse - unhandled option"
                # ...
                # change options check as needed.

    return (pass_phrase)


def pfx_generator(d_path, pass_phrase, node_name):
    certfile = os.path.join(d_path, node_name + '.cer').replace("\\", "/")
    keyfile = os.path.join(d_path, node_name + '.key').replace("\\", "/")

    try:
        st_cert = open(certfile, 'rt').read()
    except:
        print("Check to see if " + node_name + '.cer' + " exists in keys directory")
        exit()

    try:
        st_key = open(keyfile, 'rt').read()
    except:
        print("Check to see if " + node_name + '.key' + " exists in keys directory")
        exit()

    pfx_file = node_name + '.pfx'

    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)
    except crypto.Error:
        print(" No " + node_name + ".cer for processing")

    try:
        privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, st_key)
    except crypto.Error:
        print(" No " + node_name + ".key for processing")

    # Check if key/cert are a matched pair if
    # not kick out of functon with return of 1

    context = SSL.Context(SSL.TLSv1_METHOD)
    context.use_privatekey(privkey)
    context.use_certificate(cert)

    try:
        context.check_privatekey()
    except:
        print("-- key/cert do not match for " + node_name)
        return 1

    pfx = crypto.PKCS12()
    pfx.set_certificate(cert)
    pfx.set_privatekey(privkey)

    try:
        pfxdata = pfx.export(pass_phrase)

        with open(os.path.join(d_path, pfx_file), 'wb') as pfxfile:
            pfxfile.write(pfxdata)
    except:
        print("--- " + node_name + " not processed ---")

    return 0


def list_builder(data_flag, file_name):
    # takes file name determins if it is a file or string
    # if it is a file, then builds from the file a many element dictionary
    #
    # if a string, dictionary will contain single entry.
    name_list = {}

    if data_flag == 1:
        try:
            with open(file_name) as file:
                for line_data in file:
                    name = line_data.strip()
                    if len(line_data) > 1:
                        # a "1" is putin for key values
                        # as a placeholder for future use
                        name_list[name] = 1
        except IOError as e:
            print(" Unable to open file" + e)
    elif data_flag == 2:
        name = file_name.strip()
        name_list[name] = 1
    else:
        assert False, "file - unhandled option"

    return name_list


def dir_scanning(dir_to_scan):
    '''
    : scan selected directory
    : return list of filenames
    '''

    file_list = []

    if not os.path.exists(dir_to_scan):
        print("\n" + dir_to_scan + " directory does not exist\n ")

    for file_object in os.scandir(dir_to_scan):
        file_list.append(file_object.name)

    return file_list


def node_build(f_list, file_extention):
    '''
    : builds list of nodes from file list
    '''

    node_list = []

    for file in f_list:
        file = file.lower()
        # regex to search file list for particular file extention
        # and then build variable with name minus extention

        if re.search(file_extention, file):
            dir_name = file[:-4]
            node_list.append(dir_name)

    return node_list


def dir_path_build(destination_dir, f_list):
    '''
    : builds destination path to node
    '''
    dir_path = []

    for file in f_list:
        dir_path.append(os.path.join(destination_dir, file).replace("\\", "/"))

    return dir_path


def dir_creation(node_list, file_extention, destination_dir):
    '''
    : if directory is not in place for file name
    :    a new one is created
    : if a directory exists it is shifted, checked
    :    for files and then deleted
    : returning a list of dir names created so we dont have to do this
    : again as we move files about?
    '''

    # for file in f_list:
    for node in node_list:

        dir_path = os.path.join(destination_dir, node).replace("\\", "/")

        # checking to see if dir exists
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)


def move_files(d_primary, node_list, ext_list, destination_dir):
    '''
    : d_primary = directory pulling from
    : f_list = to build directory push path
    : file_extention = used build list ?
    '''
    for file in node_list:
        # print(file)
        # print(d_primary)
        dir_path = os.path.join(destination_dir, file).replace("\\", "/")

        for file_ending in ext_list:
            full_file_name = file.strip() + file_ending

            source = os.path.join(d_primary, full_file_name).replace("\\", "/")
            destination = os.path.join(dir_path, full_file_name).replace("\\", "/")

            try:
                shutil.move(source, destination)
                # shutil.copy(source, destination)
            except:
                print(source + " file not found")


def reg_search(r_key):
    '''
    : builds complied search requriment
    : r_key = search criteria
    : re.M = mult-line
    : re.I = ignore case
    : before -> re.search(r'.cer', file, re.M|re.I)
    : after  -> re.search(file_extention, file)
    '''

    return re.compile(r_key, re.M | re.I)


def process_complete(node_list):
    '''
    : general output for user to know when process is complete
    : and a list of nodes processed.
    '''

    print("\n  Processing is complete\n    \" .pfx's \"  will be in subdirectory named after nodes ")
    print("\n  Completed Nodes are:")

    # printing out completed nodes
    for c_node in node_list:
        print("    " + c_node)


def main():
    '''
    : some built in  assumptions
    : there is a keys directory
    : there is a cer and there is an associated key for the cer
    : and both cer/key are in the keys directory

    '''

    # Pass Phrase must exist for pfx builder to work
    pass_phrase = pars_cmd(sys.argv)

    if pass_phrase == None:
        usage()
        exit()

    # list of extenions for file move
    ext_list = ['.key', '.pfx', '.cer']
    # extension to search for
    s_exten = reg_search('.cer')
    p_exten = reg_search('.pfx')

    # check to see if dir is in place this will not work
    # future source directory?
    primary_directory = 'keys'

    # destination directory
    # future dest var?
    destination_dir = 'keys/PROCESSED'

    if not os.path.exists(primary_directory):
        print("\nkeys directory does not exist\n ")

    # check to see if destination directory exists?
    # future destination directory?

    destination_directory = 'blah'

    # primary - processing file moving
    f_list = dir_scanning(primary_directory)
    nodes = node_build(f_list, s_exten)

    # directory_names = dir_creation(f_list, s_exten)
    dir_creation(nodes, s_exten, destination_dir)

    nodes_completed = []

    # process list of nodes
    # list of names is from a dictionary key/value
    # d_nodename is the key from the dictionary

    for d_nodename in nodes:
        d_nodename = d_nodename.rstrip()
        pfx_status = 0

        if len(d_nodename) > 0:
            # set consistency of nodename to lower case
            d_nodename = d_nodename.lower()

            pfx_status = pfx_generator(primary_directory, pass_phrase, d_nodename)
            if pfx_status == 0:
                nodes_completed.append(d_nodename)

    # after all pfx's are built, move key/cer/pfx to node named folder
    p_list = dir_scanning(primary_directory)
    p_nodes = node_build(p_list, p_exten)
    move_files(primary_directory, p_nodes, ext_list, destination_dir)

    # once everything is done ...
    process_complete(nodes_completed)


if __name__ == "__main__":
    main()
