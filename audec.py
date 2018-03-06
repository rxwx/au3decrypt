from __future__ import print_function

import re
import hashlib
from Crypto.Cipher import ARC2

import os
import re
import sys
import rarfile
import argparse
import yara
from StringIO import StringIO

"""
pre-reqs:

sudo apt install unar
sudo apt install yara
pip install yara
pip install pycrypto
"""

INF_FILE_REGEX = r'[0-9a-fA-F]{32}\s=\s"([a-zA-z0-9]+.[a-zA-z0-9]+)"'

SFX_RAR_HEADER = '\x52\x61\x72\x21\x1A\x07\x00'

SFX_YARA = r"""
rule SFX_Autoit_Crypter {
   meta:
      description = "SFX with AutoIt RC2 encrypted file"
      hash = "e490ec4ec7446e1bed7471a1a1d1c8447744aa4e868827a9a373c6cd809ab222"
   strings:
      $s1 = "d:\\Projects\\WinRAR\\SFX\\build\\sfxrar32\\Release\\sfxrar.pdb" ascii nocase
      $s2 = /[a-z]{3}.pdf/ ascii wide
      $s3 = /[a-z]{3}.docx/ ascii wide
      $s4 = /[a-z]{3}.icm/ ascii wide
      $s5 = /[a-z]{3}.ico/ ascii wide
      $s6 = /[a-z]{3}.mp3/ ascii wide
      $s7 = /[a-z]{3}.mp4/ ascii wide
      $s8 = /[a-z]{3}.txt/ ascii wide
      $s9 = /[a-z]{3}.jpg/ ascii wide
   condition:
        uint16(0) == 0x5a4d and filesize > 1000KB and all of them
}"""

INF_YARA = r"""
rule autoit_crypter_inf {
   meta:
    description = "AutoIt crypter INF file containing key & data"
   strings:
      $ini_setting = "[Setting]" ascii
      $keys_setting = "Keys=" ascii
      $key_setting = "Key=" ascii
      $auex_setting = "AuEx=" ascii
      $exec_setting = "ExEc=" ascii
      $startups_setting = "StartUps=" ascii
      $data_setting = "[Data]" ascii
      $edata_setting = "[eData]" ascii
   condition:
      all of them
 }"""


def match_yara(inbuf, rule):
    rules = yara.compile(source=rule)
    return rules.match(data=inbuf)


def unpack_sfx(inbuf):
    sfx_hash = hashlib.sha256(inbuf).hexdigest()
    output_file    = "{0}_unpacked".format(sfx_hash)
    try:
        st = inbuf.index(SFX_RAR_HEADER)
    except ValueError:
        print("[!] SFX header not found!")
        sys.exit(1)

    with rarfile.RarFile(StringIO(inbuf[st:])) as rf:
        for x in rf.namelist():
            if '=' in x:
                break
        if '=' not in x:
            print("[!] Couldn't find INF file")
            sys.exit(1)

        with rf.open(x) as inf:
            infstr = inf.read()    
            m = re.search(INF_FILE_REGEX, infstr)
            inf_file = m.group(1)
        
        with rf.open(inf_file) as inf_buf, open(output_file, 'wb') as of:
            of.write(inf_buf.read())
            inf_buf.seek(0)
            outbuf = inf_buf.read()

    print("[+] Unpacked INF written to: {}".format(output_file))
    return outbuf


def decrypt(inbuf):
    """
    Decrypts sample using RC2
    """
    # file hash
    sfx_hash = hashlib.sha256(inbuf).hexdigest()
    print("[-] INF Hash: {}".format(sfx_hash))
    output_file    = "{0}_decrypted".format(sfx_hash)

    # find key
    m = re.search(r'Keys=([a-zA-Z]+)', inbuf)
    key = m.group(1)
    md = hashlib.md5(key)
    pbekey = md.digest()
    print("[+] Found key: {}".format(key))
    #print("[*] PBE key: {}".format(md.hexdigest().upper()))

    # find encrypted data
    m=re.search(r'\[Data\]0x([0-9a-fA-F]+)\[eData\]', inbuf)
    data = m.group(1).decode('hex')
    #print("[*] Encrypted header: {}".format(data[0:16].encode('hex').upper()))

    #create decryptor
    iv = '\x00' * ARC2.block_size # null iv
    decrypted = ARC2.new(pbekey, ARC2.MODE_CBC, iv, effective_keylen=128).decrypt(data)
    #print("[+] Decrypted header: {}".format(decrypted[0:16].encode('hex').upper()))
    #assert '\x4D\x5A\x90\x00' == decrypted[0:4] # MZ header

    with open(output_file, 'wb') as f:
        f.write(decrypted)

    print('[+] Decrypted payload written to: {}'.format(output_file))
    return decrypted


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Decryption / static analysis tool for Win32_Injector.Autoit samples")
    parser.add_argument("-i", "--input", help="Input file (sample). This can either be the raw SFX packed binary, or the extracted INF file.", required=True)
    parser.add_argument('-d', "--decode", help="Decode RAT config", action='store_const', const='decode', default=False)

    args = parser.parse_args()

    with open(args.input, 'rb') as f:
        inbuf = f.read()

    if match_yara(inbuf, INF_YARA):
        print("[*] Processing INF file.")
        decrypted = decrypt(inbuf)
    elif match_yara(inbuf, SFX_YARA):
        print("[*] Processing SFX file.")
        unpacked = unpack_sfx(inbuf)
        decrypted = decrypt(unpacked)
    else:
        print("[!] File does not appear to be encrypted with Win32_Injector.Autoit")
        sys.exit(1)

    if args.decode:
        open(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'RATDecoders', '__init__.py'), 'a').close()
        from RATDecoders import ratdecoder
        sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'RATDecoders'))
        ratdecoder.rule_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'RATDecoders', 'yaraRules', 'yaraRules.yar')
        config_data = ratdecoder.run(decrypted)
        try:
            ratdecoder.print_output(config_data, False)
        except AttributeError:
            print("[!] Unable to extract config")
