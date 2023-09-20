#!/usr/bin/env python

from __future__ import with_statement

import os
import sys
import errno
import argparse
import getpass
from pathlib import Path
import atexit
import signal
import stat

from fuse import FUSE, FuseOSError, Operations, fuse_get_context
from vol_multiple import get_data
from vol_multiple import get_file
from vol_multiple import get_file_old
from vol_multiple import borrar_contenido_carpeta
from vol_multiple import obtain_file_paths
from vol_multiple import remove_files_container
from vol_multiple import get_fuse
from vol_multiple import set_fuse
from vol_multiple import get_path_files
from vol_multiple import gen_attr_data
from vol_multiple import get_file_open
from vol_multiple import remove_file_container_filename
from vol_multiple import open_empty_file
from vol_multiple import createfile

ROOT = ""
CONTAINER = ""
KEY = ""
MOUNTPOINT = ""

class Passthrough(Operations):
    def __init__(self, root, password, container_file, mount_point):
        self.root = root
        self.password = password
        self.container_file = container_file
        self.mount_point = mount_point
        self.files = []
        # Datos del 
        # get_fuse(self.container_file, self.password, self.root + "/")


    # Helpers
    # =======

    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        full_path = self._full_path(path)
        print("access")
        # if not os.access(full_path, mode):
        #     raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        print("chmod")
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        print("chown")
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        print("getattr")
        print(full_path)
        print(path)
        if (path == "/"):
            st = os.lstat(full_path)
            data = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime', 'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
        else:
            entries, types, lengths = get_path_files(self.container_file, self.password, self.mount_point)
            data = gen_attr_data()
            try:
                print("path-1: "+ str(path[1:]))
                index = entries.index(path[1:])
            
                # print(lengths)
                # print(lengths[index])
                data["st_nlink"] = 1
                data["st_mode"] = 33188
                data["st_size"] = lengths[index]
                # data["st_mode"] = stat.S_IFDIR
            except:
                data["st_nlink"] = 1
                data["st_mode"] = 33188
                data["st_size"] = 10000
                print("Se esta creando el fichero")
        # print(data)
        return data

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        print("readdir")
        print(full_path.replace(self.root, ""))
        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        entries, types, lengths = get_path_files(self.container_file, self.password, self.mount_point)
        print(entries)
        entries_new = []
        if (full_path.replace(self.root, "") == "/"):
            for entry, type_entry in zip(entries,types):
                print(entry + type_entry)
                if("/" not in entry):
                    entries_new.append(entry)
                else:
                    entry = entry.split("/")[0]
                    if (entry not in entries_new):
                        entries_new.append(entry.split("/")[0])
        else:
            for entry in entries:
                if (path.replace("/", "") in entry):
                    print(entry)
                    entries_new.append(entry.replace(path.replace("/", ""),"").replace("/",""))
        print(entries_new)
        dirents.extend(entries_new)
        self.files = dirents
        for r in dirents:
            yield r

    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        print("readlink")
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def rmdir(self, path):
        full_path = self._full_path(path)
        print("rmdir")
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        print("mkdir")
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        print("statfs")
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def unlink(self, path):
        print("unlink")
        print(path)
        open_empty_file(self.container_file, self.password, self.root + path)
        file_removed = remove_file_container_filename(self.container_file, self.password, path[1:])
        print("Removed: " + str(file_removed))
        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        print("symlink")  
        return os.symlink(target, self._full_path(name))

    def rename(self, old, new):
        print("rename")
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        print("link")
        return os.link(self._full_path(name), self._full_path(target))

    def utimens(self, path, times=None):
        print("utimens")
        return os.utime(self._full_path(path), times)



    def open(self, path, flags):
        print("open")
        print(path)
        full_path = self._full_path(path)
        open_empty_file(self.container_file, self.password, self.root + path)
        try:
            outhpath = get_file_open(self.container_file, self.password, path, self.root)
            print("Outhpath: " + str(outhpath))
        except:
            print("No outhpath")
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        print("create")
        print(mode)
        print(path)
        # open_empty_file(self.container_file, self.password, path[1:])
        uid, gid, pid = fuse_get_context()
        full_path = self._full_path(path)
        print(full_path)
        fd = os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
        os.chown(full_path,uid,gid) #chown to context uid & gid
        return fd

    def read(self, path, length, offset, fh):
        print("read")
        os.lseek(fh, offset, os.SEEK_SET)
        # return b'hahahaha'
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        print("write")
        # print(path)
        # print(buf)
        # print(offset)
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        print("truncate")
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        print("flush")        

    def release(self, path, fh):
        print("release")
        print(path)
        print(fh)
        # Rutina para guardar el cambio en el fichero y borrarlo del sistema de archivos
        file_removed = remove_file_container_filename(self.container_file, self.password, path[1:])
        print(path[1:])
        archivos_encontrados = obtain_file_paths(self.root)
        print(archivos_encontrados)
        print(path)
        for ruta_archivo in archivos_encontrados:
            set_fuse(self.container_file, self.password, ruta_archivo, self.root)
        borrar_contenido_carpeta(self.root)
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        print("fsync")
        return self.flush(path, fh)


def create_fuse_filesystem(mountpoint, root, password, container_file):
    fuse = FUSE(Passthrough(root, password=password, container_file=container_file, mount_point=mountpoint), mountpoint, nothreads=True, foreground=True, allow_other=False)

def cleanup():
    # Lógica para realizar tareas de limpieza al terminar la ejecución
    

    ####### Crear una rutina para borrar los datos del fichero contenedor
    remove_files_container(CONTAINER, KEY)
    ####### Crear rutina para guardar los datos en fichero contenedor
    archivos_encontrados = obtain_file_paths(ROOT)
    for ruta_archivo in archivos_encontrados:
        set_fuse(CONTAINER, KEY, ruta_archivo, ROOT)
    ####### Crear rutina para borrar el directorio root 
    borrar_contenido_carpeta(ROOT)
    print("Programa finalizado")
    
def signal_handler(signal, frame):
    # Lógica para manejar la señal de interrupción (Ctrl + C)
    cleanup()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='Tool for encrypt one or more messages in a file with plausible deniability')
    parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')
    parser.add_argument('-s', '--size', help='Size of the random data to introduce in the file in Bytes')
    parser.add_argument('-o', '--outfile', help='Path of the output file (with name of the file)')
    parser.add_argument('-i', '--inputfile', help='Path of the input file (with name of the file)')
    
    subparsers = parser.add_subparsers(dest='command')
    
    create_parser = subparsers.add_parser('init', help='Create a file with the salt, nonce and random data')
    create_parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')
    
    # set_parser = subparsers.add_parser('set', help='Set a encrypt message with a key')
    # set_parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')

    # get_parser = subparsers.add_parser('get', help='Get a encrypt message with a key')
    # get_parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')

    random_parser = subparsers.add_parser('random', help='Insert random data in the file')
    random_parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')
    random_parser.add_argument('-s', '--size', help='Size of the random data to introduce in the file in Bytes')

    getfile_parser = subparsers.add_parser('getfile', help='Get a encrypt file with a key')
    getfile_parser.add_argument('-f', '--file', help='Path of the file container (with name of the file)')
    getfile_parser.add_argument('-o', '--outfile', help='Path of the output file (with name of the file)')

    setfile_parser = subparsers.add_parser('setfile', help='Set a encrypt file with a key')
    setfile_parser.add_argument('-f', '--file', help='Path of the file container (with name of the file)')
    setfile_parser.add_argument('-i', '--inputfile', help='Path of the input file (with name of the file)')

    # umount_parser = subparsers.add_parser('umount', help='Umount the volumme')
    # umount_parser.add_argument('-m', '--mountpoint', help='Path of the mount point')
    # umount_parser.add_argument('-f', '--file', help='Path of the file container (with name of the file)')
    # umount_parser.add_argument('-i', '--inputfile', help='Path of the output file (with name of the file)')

    fuse_parser = subparsers.add_parser('fuse', help='Mount the FUSE')
    fuse_parser.add_argument('-m', '--mountpoint', help='Path of the mount point')
    fuse_parser.add_argument('-r', '--root', help='Path of the root directory')
    fuse_parser.add_argument('-f', '--file', help='Path of the file container (with name of the file)')
    



    args = parser.parse_args()

    if args.command == 'init':
        
        if not args.file:
            print("Use the option -f or --file to indicate the path of the file to be saved")
            sys.exit()
        
        createfile(args.file)
    elif args.command == 'set':
        
        if not args.file:
            print("Use the option -f or --file to indicate the path of the file to be saved")
            sys.exit()

        key = getpass.getpass("Secret key: ")
        key_confirmed = getpass.getpass("Confirm secret key: ")
        if key.strip() != key_confirmed.strip():
            print("The entered values must match")
            sys.exit()
        
        message = input("Message: ")
        if message.strip() == "":
            print("No empty message allowed")
            sys.exit()
        
        set_data(args.file, key.encode("utf-8"), message.encode("utf-8"))
    
    elif args.command == 'setfile':
        
        if not args.file:
            print("Use the option -f or --file to indicate the path of the container file")
            sys.exit()

        key = getpass.getpass("Secret key: ")
        key_confirmed = getpass.getpass("Confirm secret key: ")
        if key.strip() != key_confirmed.strip():
            print("The entered values must match")
            sys.exit()

        if not args.inputfile:
            print("Use the option -i or --inputfile to indicate the path of the file to be saved in the container file")
            sys.exit()
    
        set_file(args.file, key.encode("utf-8"), args.inputfile)

    elif args.command == 'get':
        
        if not args.file:
            print("Use the option -f or --file to indicate the path of the container file")
            sys.exit()
        
        key = getpass.getpass("Secret key: ")

        get_data(args.file, key.encode("utf-8"))

    elif args.command == 'getfile':
        
        if not args.file:
            print("Use the option -f or --file to indicate the path of the container file")
            sys.exit()
        if not args.outfile:
            print("Use the option -o or --outfile to indicate the path of the output file you want to recover")
            sys.exit()
        
        key = getpass.getpass("Secret key: ")
        

        get_file(args.file, key.encode("utf-8"), args.outfile)

    elif args.command == 'umount':
        
        if not args.mountpoint:
            print("Use the option -m or --mountpoint to indicate the path of the mount point")
            sys.exit()
        if not args.inputfile:
            print("Use the option -i or --inputfile to indicate the path of the file to be saved in the container file)")
            sys.exit()
        if not args.file:
            print("Use the option -f or --file to indicate the path of the container file")
            sys.exit()
            
        key = getpass.getpass("Secret key: ")

        indexes = search(args.file, key.encode("utf-8"))
        remove_bytes_from_file(args.file, indexes)
        umount(args.mountpoint)
        set_file(args.file, key.encode("utf-8"), args.inputfile)


    elif args.command == 'fuse':
        
        if not args.root:
            print("Use the option -r or --root to indicate the path of the root directory")
            sys.exit()
        if not args.file:
            print("Use the option -f or --file to indicate the path of the file to be saved")
            sys.exit()
        if not args.mountpoint:
            print("Use the option -m or --mountpoint to indicate the path of the mount point")
            sys.exit()
        key = getpass.getpass("Secret key: ")
        key = key.encode("utf8")
        
        # Variables necesarias para la iniciación del fuse
        container_file = args.file
        global ROOT
        ROOT = args.root.strip()
        global CONTAINER
        CONTAINER = container_file.strip()
        global KEY
        KEY = key
        global MOUNTPOINT
        MOUNTPOINT = args.mountpoint.strip()

        print("Mountpoint: " + MOUNTPOINT)
        print("Root: " + ROOT)
        print("Key: " + KEY.decode("utf8"))
        print("Container :" + CONTAINER)
        create_fuse_filesystem(MOUNTPOINT, ROOT, KEY, CONTAINER)

        
        

    elif args.command == 'random':
        
        if not args.file:
            print("Use the option -f or --file to indicate the path of the container file")
            sys.exit()
        if not args.size:
            print("Use the option -s or --size to indicate the size of the random data in Bytes to introduce")
            sys.exit()
        
        try:
            size = int(args.size)
        except ValueError:
            print('Please enter an integer')
            sys.exit()


def pruebas():
    KEY = b"pruebas2"
    CONTAINER = "./new.bin"
    create_fuse_filesystem("/tmp/fuse", "/home/jorge/tf/fuse", KEY, CONTAINER)


if __name__ == '__main__':

    # Registrar la función de limpieza para que se llame al finalizar
    # atexit.register(cleanup)

    # Registrar el manejador de señal para la interrupción (Ctrl + C)
    # signal.signal(signal.SIGINT, signal_handler)
    # Inicio del programa
    main()

    # pruebas()
