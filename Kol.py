# -*- coding:utf-8 -*-
"""
@Author: Andyjajang
@File: loginFb.py
@Time: 2021-11-29 21:24
@Desc: It's all about getting better.
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode, b64encode
from jsbeautifier import beautify
from jsmin import jsmin
from os import listdir, urandom, makedirs
from os.path import isfile, isdir, join as pjoin, split as psplit, exists, abspath
from loguru import logger as log
from masar import extract_asar, pack_asar
from shutil import rmtree
from argparse import ArgumentParser
import struct
import sys

# DEBUG
DEBUG = False

log.remove()
if DEBUG:
    log.add(sys.stderr, level="DEBUG")
else:
    log.add(sys.stderr, level="INFO")

AES_KEY = struct.pack("<4Q", *[0x4B029A9482B3E14E, 0xF157FEB4B4522F80, 0xE25692105308F4BE, 0x6DD58DDDA3EC0DC2])


def _mkDir(_path):
    if not exists(_path):
        makedirs(_path)
    else:
        if _path == psplit(__file__)[0]:
            log.warning("plz try not to use the root dir.")
        else:
            log.warning(f"May FolderExists: {_path}")


def decScript(b64: bytes, prettify: bool):
    lCode = b64decode(b64)
    # iv: the first 16 bytes of the file
    aesIv = lCode[0:16]
    # cipher text
    cipherText = lCode[16:]
    # AES 256 CBC
    ins = AES.new(key=AES_KEY, iv=aesIv, mode=AES.MODE_CBC)
    code = unpad(ins.decrypt(cipherText), 16, 'pkcs7')
    if prettify:
        code = beautify(code.decode()).encode()
    return code


def extractWdec(asarPath, path, prettify):
    """
    :param prettify: bool
    :param asarPath: asar out dir
    :param path: out dir
    :return: None
    """
    # try to create empty dir to save extract files
    path = pjoin(path, "typoraCrackerTemp")

    if exists(path):
        rmtree(path)
    _mkDir(path)

    log.info(f"extract asar file: {asarPath}")
    # extract app.asar to {path}/*
    extract_asar(asarPath, path)
    log.success(f"extract ended.")

    log.info(f"read Directory: {path}")
    # construct the save directory {pathRoot}/dec_app
    outPath = pjoin(psplit(path)[0], "dec_app")
    # try to create empty dir to save decryption files
    if exists(outPath):
        rmtree(outPath)
    _mkDir(outPath)

    log.info(f"set Directory: {outPath}")
    # enumerate extract files
    fileArr = listdir(path)
    for name in fileArr:
        # read files content
        fpath = pjoin(path, name)
        scode = open(fpath, "rb").read()
        log.info(f"open file: {name}")
        # if file suffix is *.js then decryption file
        if isfile(fpath) and name.endswith(".js"):
            scode = decScript(scode, prettify)
        else:
            log.debug(f"skip file: {name}")
        # save content {outPath}/{name}
        open(pjoin(outPath, name), "wb").write(scode)
        log.success(f"decrypt and save file: {name}")

    rmtree(path)
    log.debug("remove temp dir")


def encScript(_code: bytes, compress):
    if compress:
        _code = jsmin(_code.decode(), quote_chars="'\"`").encode()
    aesIv = urandom(16)
    cipherText = _code
    ins = AES.new(key=AES_KEY, iv=aesIv, mode=AES.MODE_CBC)
    enc = aesIv + ins.encrypt(pad(cipherText, 16, 'pkcs7'))
    lCode = b64encode(enc)
    return lCode


def packWenc(path, outPath, compress):
    """
    :param path: out dir
    :param outPath: pack path app.asar
    :param compress: Bool
    :return: None
    """
    # check out path
    if isfile(outPath):
        log.error("plz input Directory for app.asar")
        raise NotADirectoryError

    _mkDir(outPath)

    encFilePath = pjoin(psplit(outPath)[0], "typoraCrackerTemp")
    if exists(encFilePath):
        rmtree(encFilePath)
    _mkDir(encFilePath)

    outFilePath = pjoin(outPath, "app.asar")
    log.info(f"set outFilePath: {outFilePath}")
    fileArr = listdir(path)

    for name in fileArr:
        fpath = pjoin(path, name)
        if isdir(fpath):
            log.error("TODO: found folder")
            raise IsADirectoryError

        scode = open(fpath, "rb").read()
        log.info(f"open file: {name}")
        if isfile(fpath) and name.endswith(".js"):
            scode = encScript(scode, compress)

        open(pjoin(encFilePath, name), "wb").write(scode)
        log.success(f"encrypt and save file: {name}")

    log.info("ready to pack")
    pack_asar(encFilePath, outFilePath)
    log.success("pack done")

    rmtree(encFilePath)
    log.debug("remove temp dir")


def main():
    argParser = ArgumentParser(
        description="[extract and decryption / pack and encryption] app.asar file from [Typora].",
        epilog="If you have any questions, please contact [ MasonShi@88.com ]")
    argParser.add_argument("asarPath", type=str, help="app.asar file path/dir [input/ouput]")
    argParser.add_argument("dirPath", type=str, help="as tmp and out directory.")

    argParser.add_argument('-u', dest='mode', action='store_const',
                           const=packWenc, default=extractWdec,
                           help='pack & encryption (default: extract & decryption)')
    argParser.add_argument('-f', dest='format', action='store_const',
                           const=True, default=False,
                           help='enabled prettify/compress (default: disabled)')
    args = argParser.parse_args()

    args.mode(args.asarPath, args.dirPath, args.format)
    log.success("Done!")
# -*- coding:utf-8 -*-
"""
@Author: Andyjajang
@File: crack-FB-Andyjajang.py
@Time: 2021-11-29 22:34
@Desc: It's all about getting better.
"""
import os
import errno
import io
import struct
import shutil
import fileinput
import json


def round_up(i, m):
    return (i + m - 1) & ~(m - 1)


class Asar:
    def __init__(self, path, fp, header, base_offset):
        self.path = path
        self.fp = fp
        self.header = header
        self.base_offset = base_offset

    @classmethod
    def open(cls, path):
        fp = open(path, 'rb')
        data_size, header_size, header_object_size, header_string_size = struct.unpack('<4I', fp.read(16))
        header_json = fp.read(header_string_size).decode('utf-8')
        return cls(
            path=path,
            fp=fp,
            header=json.loads(header_json),
            base_offset=round_up(16 + header_string_size, 4)
        )

    @classmethod
    def compress(cls, path):
        offset = 0
        paths = []

        def _path_to_dict(path):
            nonlocal offset, paths
            result = {'files': {}}
            for f in os.scandir(path):
                if os.path.isdir(f.path):
                    result['files'][f.name] = _path_to_dict(f.path)
                elif f.is_symlink():
                    result['files'][f.name] = {
                        'link': os.path.realpath(f.name)
                    }
                # modify
                elif f.name == "main.node":
                    size = f.stat().st_size
                    result['files'][f.name] = {
                        'size': size,
                        "unpacked": True
                    }
                else:
                    paths.append(f.path)
                    size = f.stat().st_size
                    result['files'][f.name] = {
                        'size': size,
                        'offset': str(offset)
                    }
                    offset += size
            return result

        def _paths_to_bytes(paths):
            _bytes = io.BytesIO()
            with fileinput.FileInput(files=paths, mode="rb") as f:
                for i in f:
                    _bytes.write(i)
            return _bytes.getvalue()

        header = _path_to_dict(path)
        header_json = json.dumps(header, sort_keys=True, separators=(',', ':')).encode('utf-8')
        header_string_size = len(header_json)
        data_size = 4
        aligned_size = round_up(header_string_size, data_size)
        header_size = aligned_size + 8
        header_object_size = aligned_size + data_size
        diff = aligned_size - header_string_size
        header_json = header_json + b'\0' * diff if diff else header_json
        fp = io.BytesIO()
        fp.write(struct.pack('<4I', data_size, header_size, header_object_size, header_string_size))
        fp.write(header_json)
        fp.write(_paths_to_bytes(paths))

        return cls(
            path=path,
            fp=fp,
            header=header,
            base_offset=round_up(16 + header_string_size, 4))

    def _copy_unpacked_file(self, source, destination):
        unpacked_dir = self.path + '.unpacked'
        if not os.path.isdir(unpacked_dir):
            print("Couldn't copy file {}, no extracted directory".format(source))
            return

        src = os.path.join(unpacked_dir, source)
        if not os.path.exists(src):
            print("Couldn't copy file {}, doesn't exist".format(src))
            return

        dest = os.path.join(destination, source)
        shutil.copyfile(src, dest)

    def _extract_file(self, source, info, destination):
        if 'offset' not in info:
            self._copy_unpacked_file(source, destination)
            return

        self.fp.seek(self.base_offset + int(info['offset']))
        r = self.fp.read(int(info['size']))

        dest = os.path.join(destination, source)
        with open(dest, 'wb') as f:
            f.write(r)

    def _extract_link(self, source, link, destination):
        dest_filename = os.path.normpath(os.path.join(destination, source))
        link_src_path = os.path.dirname(os.path.join(destination, link))
        link_to = os.path.join(link_src_path, os.path.basename(link))

        try:
            os.symlink(link_to, dest_filename)
        except OSError as e:
            if e.errno == errno.EXIST:
                os.unlink(dest_filename)
                os.symlink(link_to, dest_filename)
            else:
                raise e

    def _extract_directory(self, source, files, destination):
        dest = os.path.normpath(os.path.join(destination, source))

        if not os.path.exists(dest):
            os.makedirs(dest)

        for name, info in files.items():
            item_path = os.path.join(source, name)

            if 'files' in info:
                self._extract_directory(item_path, info['files'], destination)
            elif 'link' in info:
                self._extract_link(item_path, info['link'], destination)
            else:
                self._extract_file(item_path, info, destination)

    def extract(self, path):
        if not os.path.isdir(path):
            raise NotADirectoryError()
        self._extract_directory('.', self.header['files'], path)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.fp.close()


def pack_asar(source, dest):
    with Asar.compress(source) as a:
        with open(dest, 'wb') as fp:
            a.fp.seek(0)
            fp.write(a.fp.read())


def extract_asar(source, dest):
    with Asar.open(source) as a:
        a.extract(dest)


if __name__ == '__main__':
    main()
