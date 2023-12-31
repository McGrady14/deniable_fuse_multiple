import sys
import os
from random import randint
import hashlib
import argparse
import getpass
import shutil
import stat

from chacha20 import decrypt_message
from chacha20 import encrypt_message_salt_nonce
from crc32 import calculate_crc32
from crc32 import is_crc32_valid
# from mount_volume import mount
# from umount_volume import umount


FIRST_INDEX = 0
# Clave hasheada con SHA-256 de 32B
KEY_HASH_SIZE = 32
# Tamaño de la data en cada bloque 
DATA_SIZE = 16384
# Cada fichero creado tiene su propia salt y su propio nonce de 16B
SALT_SIZE = 16
NONCE_SIZE = 16
# Metadata 3B para el num de bloque de la entrada y 3B para los Bytes que son data real en los 120B del DATA_SIZE
N_BLOCK_SIZE = 5
N_LENGTH_SIZE = 5
# Tamaño nombre
FILENAME_SIZE = 64
# Checksum CRC32 de 16B
CHECKSUM_SIZE = 16
# Tamaño de bloque completo con hash, metadata, data y checksum
BLOCK_SIZE = KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + FILENAME_SIZE + DATA_SIZE + CHECKSUM_SIZE
# Tamaño random data
MIN_RANDOM_DATA = 1024
MAX_RANDOM_DATA = 8192
MID_RANDOM_DATA = 2048

# tamaño maximo data_size 4294967296B 4GB
    

# Tamaño tipo de entrada directorio o fichero 1B
TYPE_SIZE = 1
# Tamaño del bloque que indica el tamaño de la data max 4GB por lo que al guardarlo como STR necesitamos 10B
N_LENGTH_SIZE = 10
# Tamaño entrada 64B --> 64 caracteres es lo mismo que el tamaño del nombre
FILENAME_SIZE = 64
# Tamaño data --> no se puede especificar, se calcula de cada fichero, solo una entrada por fichero, no hay tamaño de bloque fijo 
DATA_SIZE_ = 0
# Checksum CRC32 de 16B
CHECKSUM_SIZE = 16
# Block size
BLOCK_SIZE = TYPE_SIZE + FILENAME_SIZE + N_LENGTH_SIZE + DATA_SIZE + CHECKSUM_SIZE
# Para crear la tabla de metadata de cada clave
def set_fuse(file_path, key, infile, root_directorie):
    salt, nonce = get_salt_nonce(file_path)
    
    # Lectura del fichero a introducir
    with open(infile,"r+b") as f:
        complete_file = f.read()
        message = complete_file

        # Se cifra la data del fichero
        ciphertext = encrypt_message_salt_nonce(message, key, salt, nonce)

        # Lectura del fichero contenedor
        with open(file_path, "ab") as file:
            # Se hashea la clave, se va a guardar hasheada
            key_hashed = hashlib.sha256(key) 
            
            # Revison del tipo: si es directorio o fichero si tiene una "/" es un directorio ## no es relevante se podria quitar
            if (str(infile).find("/") == -1):
                type_file = "F"
            else:
                type_file = "D"
            
            if (".swap" not in str(infile)):
                # Num orden de bloque
                type_data = str(type_file).zfill(TYPE_SIZE).encode("utf-8")
                type_data_ = encrypt_message_salt_nonce(type_data, key, salt, nonce) 
                
                # Longitud del mensaje en el bloque
                length = str(len(ciphertext)).zfill(N_LENGTH_SIZE).encode("utf-8")
                length_ = encrypt_message_salt_nonce(length, key, salt, nonce)

                # Calculo del checksum de la data del bloque 
                checksum = calculate_crc32(ciphertext) 
                checksum = encrypt_message_salt_nonce(checksum.to_bytes(CHECKSUM_SIZE, 'big'), key, salt, nonce)
                
                # Nombre fichero
                # filename = str(infile).split("/")[-1]
                infile = infile.replace(root_directorie, "")[1:]
                filename = infile.ljust(FILENAME_SIZE).encode("utf-8")
                filename_ = encrypt_message_salt_nonce(filename, key, salt, nonce) 

                # Bloque completo 
                block_complete = key_hashed.digest() + type_data_ + length_ + filename_ + ciphertext + checksum
                # Introducimos los datos al final del fichero 
                file.close()
                append_data(block_complete, file_path)
                # Introducimos data random al fichero
                rand_data = randint(MIN_RANDOM_DATA, MID_RANDOM_DATA)
                dunce_data(path, rand_data)

        f.close()

def set_fuse_ant(file_path, key, infile, root_directorie):
    salt, nonce = get_salt_nonce(file_path)
    
    # Lectura del fichero a introducir
    with open(infile,"r+b") as f:
        complete_file = f.read()
        message = complete_file

        # Se cifra la data del fichero
        ciphertext = encrypt_message_salt_nonce(message, key, salt, nonce)

        # Lectura del fichero contenedor
        with open(file_path, "ab") as file:
            # Se hashea la clave, se va a guardar hasheada
            key_hashed = hashlib.sha256(key) 
            
            # Revison del tipo: si es directorio o fichero si tiene una "/" es un directorio ## no es relevante se podria quitar
            if (str(infile).find("/") == -1):
                type_file = "F"
            else:
                type_file = "D"
            
            # Num orden de bloque
            type_data = str(type_file).zfill(TYPE_SIZE).encode("utf-8")
            type_data_ = encrypt_message_salt_nonce(type_data, key, salt, nonce) 
            
            # Longitud del mensaje en el bloque
            length = str(len(ciphertext)).zfill(N_LENGTH_SIZE).encode("utf-8")
            length_ = encrypt_message_salt_nonce(length, key, salt, nonce)

            # Calculo del checksum de la data del bloque 
            checksum = calculate_crc32(ciphertext) 
            checksum = encrypt_message_salt_nonce(checksum.to_bytes(CHECKSUM_SIZE, 'big'), key, salt, nonce)
            
            # Nombre fichero
            # filename = str(infile).split("/")[-1]
            infile = infile.replace(root_directorie, "")[1:]
            filename = infile.ljust(FILENAME_SIZE).encode("utf-8")
            filename_ = encrypt_message_salt_nonce(filename, key, salt, nonce) 

            # Bloque completo 
            block_complete = key_hashed.digest() + type_data_ + length_ + filename_ + ciphertext + checksum
            # Introducimos los datos al final del fichero 
            file.close()
            append_data(block_complete, file_path)
            # Introducimos data random al fichero
            rand_data = randint(MIN_RANDOM_DATA, MID_RANDOM_DATA)
            dunce_data(path, rand_data)

        f.close()
def open_empty_file(path, key, outpath):
    # Seleccionar la salt y el nonce del fichero
    if (".swp" not in outpath):
        plaintext = b" "
        create_file(plaintext, outpath)

def get_fuse(path, key, outpath):
    # Seleccionar la salt y el nonce del fichero
    salt, nonce = get_salt_nonce(path)
    with open(path, "r+b") as file:
        # Se buscan las posiciones donde hay bloques 
        indexes = search(path, key)
        # Contenedor de todos los mensajes de los bloques con la clave indicada
        total_files = []

        for index in indexes:
            # Cursor en el inicio del bloque
            file.seek(index)
            # Lectura del bloque de la metadata del fichero
            metadata_block_size = KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE
            metadata_block = file.read(metadata_block_size)
            # Extraer los bytes de la clave hasheada
            key_hash_file = metadata_block[FIRST_INDEX : KEY_HASH_SIZE]
            key_hash = hashlib.sha256(key)  # Calculo del hash de la clave provista para comparar con la leída del bloque
            # Extraer la metadata del numero de bloque
            type_data_cipher = metadata_block[KEY_HASH_SIZE : KEY_HASH_SIZE + TYPE_SIZE]
            type_data_plaintext = decrypt_message(salt, nonce, type_data_cipher, key)
            type_data_plaintext = (type_data_plaintext.decode("utf-8"))
            # Extraer la metadata de la longitud de la data del mensaje en el bloque
            length_cipher = metadata_block[KEY_HASH_SIZE + TYPE_SIZE : KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE]
            length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
            length_plaintext = int(length_plaintext.decode("utf-8"))
            # Extraer el nombre del fichero
            filename_cipher = metadata_block[KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE : KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE]
            filename_plaintext = decrypt_message(salt, nonce, filename_cipher, key)
            filename_plaintext = str(filename_plaintext.decode("utf-8")).strip()

            # Se mueve el puntero en el fichero 
            new_index = index + KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE
            file.seek(new_index)
            # Lectura del bloque de datos mas el bloque del checksum
            block_size = length_plaintext + CHECKSUM_SIZE
            block = file.read(block_size)
            # Extraer la data del mensaje 
            message = block[FIRST_INDEX : length_plaintext]
            # Extraer el checksum de la data del bloque
            crc = block[length_plaintext : length_plaintext + CHECKSUM_SIZE]
            crc_plaintext = decrypt_message(salt, nonce, crc, key)
            crc_plaintext = int.from_bytes(crc_plaintext, byteorder='big')
            
            if key_hash.digest() == key_hash_file:
                if (is_crc32_valid(message, crc_plaintext)):
                    total_files.append(filename_plaintext)
                    if (type_data_plaintext == "F"):
                        plaintext = decrypt_message(salt, nonce, message, key)
                        create_file(plaintext, outpath + str(filename_plaintext))
                    else:
                        directories = filename_plaintext.split("/")
                        # filename_plaintext = directories[-1]
                        directories.pop(-1)
                        total = outpath
                        for directorie in directories:
                            total = total + directorie + "/"
                        if not os.path.exists(total):
                            print(f"La carpeta '{total}' no existe.")
                            os.makedirs(total)
                        
                        plaintext = decrypt_message(salt, nonce, message, key)
                        create_file(plaintext, outpath + str(filename_plaintext))

                else:
                    print("CRC No Válido")
    
    
    
    return total_files
    # mount(outpath, "/mnt/ext4")


# Funcion para crear los ficheros guardados
def create_file(data, outpath):
    # Para crear el fichero
    with open(outpath, "w+b") as file:
        file.write(data)
        file.close()

def borrar_contenido_carpeta(carpeta):
    # Verificar si la carpeta existe
    if not os.path.exists(carpeta):
        print(f"La carpeta '{carpeta}' no existe.")
        return

    try:
        # Recorrer los elementos de la carpeta
        for nombre_archivo in os.listdir(carpeta):
            ruta_archivo = os.path.join(carpeta, nombre_archivo)

            if os.path.isfile(ruta_archivo):
                # Borrar archivo
                os.remove(ruta_archivo)
            elif os.path.isdir(ruta_archivo):
                # Borrar directorio recursivamente
                shutil.rmtree(ruta_archivo)

        print(f"El contenido de la carpeta '{carpeta}' ha sido borrado exitosamente.")

    except Exception as e:
        print(f"Se produjo un error al borrar el contenido de la carpeta '{carpeta}': {str(e)}")


def obtain_file_paths(directorio):
    rutas_archivos = []

    for directorio_actual, _, archivos in os.walk(directorio):
        for archivo in archivos:
            ruta_completa = os.path.join(directorio_actual, archivo)
            rutas_archivos.append(ruta_completa)

    return rutas_archivos

def remove_files_container(container_file, key):
    salt, nonce = get_salt_nonce(container_file)
    indexes = search(container_file, key)
    borrar_bytes_archivo(container_file, indexes, key)

def remove_file_container_filename(container_file, key, filename):
    salt, nonce = get_salt_nonce(container_file)
    indexes = search_index_filename(container_file, key, filename)
    if not indexes:
        return False
    else: 
        borrar_bytes_archivo(container_file, indexes, key)
        return True


### Búsqueda de key hasheadas con sha256 
def search_index_filename(path, key, filename):
    salt, nonce = get_salt_nonce(path)
    with open(path, "rb") as file:
        # Fichero completo 
        data = file.read()
        key_hashed = hashlib.sha256(key) # Clave hasheada con sha256
        index = 0 # Primer byte
        indexes = [] 
        while True:
            # Mover el cursor al indice siguiente
            file.seek(index)
            data = file.read(KEY_HASH_SIZE) # Se leen 32B para compararlos con la clave hasheada

            if not data:  # Fin del archivo
                break
            if key_hashed.digest() == data:
                print(filename)
                # Cursor en el inicio del bloque
                file.seek(index)
                # Lectura del bloque de la metadata del fichero
                metadata_block_size = KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE
                metadata_block = file.read(metadata_block_size)
                # Extraer los bytes de la clave hasheada
                key_hash_file = metadata_block[FIRST_INDEX : KEY_HASH_SIZE]
                key_hash = hashlib.sha256(key)  # Calculo del hash de la clave provista para comparar con la leída del bloque
                # Extraer la metadata del numero de bloque
                type_data_cipher = metadata_block[KEY_HASH_SIZE : KEY_HASH_SIZE + TYPE_SIZE]
                type_data_plaintext = decrypt_message(salt, nonce, type_data_cipher, key)
                type_data_plaintext = (type_data_plaintext.decode("utf-8"))
                # Extraer la metadata de la longitud de la data del mensaje en el bloque
                length_cipher = metadata_block[KEY_HASH_SIZE + TYPE_SIZE : KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE]
                length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
                length_plaintext = int(length_plaintext.decode("utf-8"))
                # Extraer el nombre del fichero
                filename_cipher = metadata_block[KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE : KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE]
                filename_plaintext = decrypt_message(salt, nonce, filename_cipher, key)
                filename_plaintext = str(filename_plaintext.decode("utf-8")).strip() 
                                
                print(filename_plaintext)
                if filename_plaintext == filename:
                    indexes.append(index + data.index(key_hashed.digest())) # Índice de inicio de la secuencia
                    break

            index += 1 # Busqueda byte a byte, no es eficiente en ficheros grandes, hay que mejorar la búsqueda
            
    return indexes

def get_end_index(container_file, index, key):
    salt, nonce = get_salt_nonce(container_file)
    with open(container_file, "r+b") as file:
        # Cursor en el inicio del bloque
        file.seek(index)
        # Lectura del bloque de la metadata del fichero
        metadata_block_size = KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE
        metadata_block = file.read(metadata_block_size)

        # Extraer la metadata de la longitud de la data del mensaje en el bloque
        length_cipher = metadata_block[KEY_HASH_SIZE + TYPE_SIZE : KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE]
        length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
        length_plaintext = int(length_plaintext.decode("utf-8"))

        block_size = length_plaintext + CHECKSUM_SIZE
        end_index = index + metadata_block_size + block_size
        file.close()

    return end_index

def borrar_bytes_archivo(container_file, indexes, key):
    indexes.sort(reverse=True)
    for index in indexes:
        with open(container_file, 'r+b') as file:
            end_index = get_end_index(container_file, index, key)
            # Leer el contenido completo del container_file
            contenido = bytearray(file.read())

            # Eliminar el rango de bytes del contenido
            del contenido[index:end_index]

            # Volver al inicio del container_file y escribir el contenido modificado
            file.seek(0)
            file.write(contenido)

            # Truncar el archivo a la nueva longitud
            file.truncate(len(contenido))

# Borrar bytes del fichero contenedor
def remove_bytes_from_file(file_path, indexes):
    indexes.sort(reverse=True)
    for index in indexes:
        end_index = int(index) + BLOCK_SIZE
        with open(file_path, 'rb') as file:
            file_content = bytearray(file.read())

        del file_content[index:end_index]

        with open(file_path, 'wb') as file:
            file.write(file_content)

# Dividir el mensaje en bloques de mensaje de maximo DATA_SIZE
def split_bytes_into_segments(byte_string, segment_size):
    segments = []
    index = 0
    while index < len(byte_string):
        segment = byte_string[index:index+segment_size]
        segments.append(segment)
        index += segment_size
    return segments

# Sacar bytes aleatorios 
def random_data(size):
    return os.urandom(size)

# Para crear una salt y un nonce para el fichero contenedor
def get_salt_nonce(path):
    with open(path, "r+b") as file:
        file.seek(FIRST_INDEX)
        nonce = file.read(NONCE_SIZE)
        file.seek(NONCE_SIZE)
        salt = file.read(SALT_SIZE)

        return salt, nonce

# Introducir data al final del fichero
def append_data(data, path):
    with open(path, "ab") as file:
        file.write(data)
        file.close()


def dunce_data(path, size):
    data = random_data(size)
    append_data(data, path)

# Crear fichero con nonce y salt del fichero 
def createfile(path):
    print("Creating file ...")
    with open(path, "w+b") as file:
        # Generamos la salt y el nonce
        salt = random_data(SALT_SIZE)
        nonce = random_data(NONCE_SIZE)
        # Se crea el fichero, al inicio en nonce y la salt 
        file.write(nonce)
        file.write(salt)
        # Se generan entre 1k y 8k de data aleatoria 
        rand_data = randint(MIN_RANDOM_DATA, MAX_RANDOM_DATA)
        file.write(random_data(rand_data))

    print("File created in ", str(path))


### Búsqueda de key hasheadas con sha256 
def search(path, key):
    with open(path, "rb") as file:
        # Fichero completo 
        data = file.read()
        key_hashed = hashlib.sha256(key) # Clave hasheada con sha256
        index = 0 # Primer byte
        indexes = [] # Guardar los indices donde se encuentran los hashes
        while True:
            # Mover el cursor al indice siguiente
            file.seek(index)
            data = file.read(KEY_HASH_SIZE) # Se leen 32B para compararlos con la clave hasheada
            if not data:  # Fin del archivo
                break
            if key_hashed.digest() in data:
                indexes.append(index + data.index(key_hashed.digest())) # Índice de inicio de la secuencia
            index += 1 # Busqueda byte a byte, no es eficiente en ficheros grandes, hay que mejorar la búsqueda
            
    return indexes

# Metodo para insertar un fichero dentro del fichero contenedor con una clave
def set_file(path, key, infile):
    with open(infile,"r+b") as f:
        complete_file = f.read()
        # set_data(path, key, complete_file)
        message = complete_file
    salt, nonce = get_salt_nonce(path)
    with open(path, "ab") as file:
        key_hashed = hashlib.sha256(key) 

        # El texto a guardar se divide en  funcion del tamaño del dato 
        plaintexts = split_bytes_into_segments(message, DATA_SIZE)
        # Las partes del mensaje cifrado 
        ciphertexts = []
        for plaintext in plaintexts:
            ciphertext = encrypt_message_salt_nonce(plaintext, key, salt, nonce)
            ciphertexts.append(ciphertext)

        n_block = 1 # El inicio de los bloques siempre es 1 ## TODO hay utilizarlo para el seteo aleatorio y para la acumulación de mensajes, actualmente si se actualiza un mensaje, se empiza con el n_block = 1  y es un error
        for cipher in ciphertexts:

            if(len(cipher) < DATA_SIZE):
                
                # Longitud del mensaje en el bloque
                length = str(len(cipher)).zfill(N_LENGTH_SIZE).encode("utf-8")
                length_ = encrypt_message_salt_nonce(length, key, salt, nonce) 
                # Mensaje cifrado
                cipher = cipher + os.urandom(DATA_SIZE - len(cipher))
                # Calculo del checksum de la data del bloque 
                checksum = calculate_crc32(cipher) 
                checksum = encrypt_message_salt_nonce(checksum.to_bytes(CHECKSUM_SIZE, 'big'), key, salt, nonce)
                # Num orden de bloque
                blocks = str(n_block).zfill(N_BLOCK_SIZE).encode("utf-8")
                blocks_ = encrypt_message_salt_nonce(blocks, key, salt, nonce) 
                # Nombre fichero
                filename = str(infile).split("/")[-1]
                filename = filename.ljust(FILENAME_SIZE).encode("utf-8")
                filename_ = encrypt_message_salt_nonce(filename, key, salt, nonce) 
                # Bloque completo 
                block_complete = key_hashed.digest() + blocks_ + length_ + filename_ + cipher + checksum
                # Introducimos los datos al final del fichero 
                file.close()
                append_data(block_complete, path)
                # Introducimos data random al fichero
                rand_data = randint(MIN_RANDOM_DATA, MID_RANDOM_DATA)
                dunce_data(path, rand_data)


            else:
                # Longitud del mensaje en el bloque
                length = str(len(cipher)).zfill(N_LENGTH_SIZE).encode("utf-8")
                length_ = encrypt_message_salt_nonce(length, key, salt, nonce)
                # Calculo del checksum de la data del bloque 
                checksum = calculate_crc32(cipher)
                checksum = encrypt_message_salt_nonce(checksum.to_bytes(CHECKSUM_SIZE, 'big'), key, salt, nonce)
                # Num orden de bloque
                blocks = str(n_block).zfill(N_BLOCK_SIZE).encode("utf-8")
                blocks_ = encrypt_message_salt_nonce(blocks, key, salt, nonce)
                # Nombre fichero
                filename = str(infile).split("/")[-1]
                filename = filename.ljust(FILENAME_SIZE).encode("utf-8")
                filename_ = encrypt_message_salt_nonce(filename, key, salt, nonce) 
                # Bloque completo 
                block_complete = key_hashed.digest() + blocks_ + length_ + filename_ + cipher + checksum
                # Introducimos los datos al final del fichero 
                file.close()
                append_data(block_complete, path)
                # Introducimos data random al fichero
                rand_data = randint(MIN_RANDOM_DATA, MID_RANDOM_DATA)
                dunce_data(path, rand_data)

            n_block+=1 # Aumento del número de bloque 


# Metodo para introducir data en el fichero
def set_data(path, key, message):
    salt, nonce = get_salt_nonce(path)
    with open(path, "ab") as file:
        key_hashed = hashlib.sha256(key) 

        # El texto a guardar se divide en  funcion del tamaño del dato 
        plaintexts = split_bytes_into_segments(message, DATA_SIZE)
        # Las partes del mensaje cifrado 
        ciphertexts = []
        for plaintext in plaintexts:
            ciphertext = encrypt_message_salt_nonce(plaintext, key, salt, nonce)
            ciphertexts.append(ciphertext)

        n_block = 1 # El inicio de los bloques siempre es 1 ## TODO hay utilizarlo para el seteo aleatorio y para la acumulación de mensajes, actualmente si se actualiza un mensaje, se empiza con el n_block = 1  y es un error
        for cipher in ciphertexts:

            if(len(cipher) < DATA_SIZE):
                
                # Longitud del mensaje en el bloque
                length = str(len(cipher)).zfill(N_LENGTH_SIZE).encode("utf-8")
                length_ = encrypt_message_salt_nonce(length, key, salt, nonce) 
                # Mensaje cifrado
                cipher = cipher + os.urandom(DATA_SIZE - len(cipher))
                # Calculo del checksum de la data del bloque 
                checksum = calculate_crc32(cipher) 
                checksum = encrypt_message_salt_nonce(checksum.to_bytes(CHECKSUM_SIZE, 'big'), key, salt, nonce)
                # Num orden de bloque
                blocks = str(n_block).zfill(N_BLOCK_SIZE).encode("utf-8")
                blocks_ = encrypt_message_salt_nonce(blocks, key, salt, nonce) 
                # Bloque completo 
                block_complete = key_hashed.digest() + blocks_ + length_ + cipher + checksum 
                # Introducimos los datos al final del fichero 
                file.close()
                append_data(block_complete, path)
                # Introducimos data random al fichero
                rand_data = randint(MIN_RANDOM_DATA, MID_RANDOM_DATA)
                dunce_data(path, rand_data)


            else:
                # Longitud del mensaje en el bloque
                length = str(len(cipher)).zfill(N_LENGTH_SIZE).encode("utf-8")
                length_ = encrypt_message_salt_nonce(length, key, salt, nonce)
                # Calculo del checksum de la data del bloque 
                checksum = calculate_crc32(cipher)
                checksum = encrypt_message_salt_nonce(checksum.to_bytes(CHECKSUM_SIZE, 'big'), key, salt, nonce)
                # Num orden de bloque
                blocks = str(n_block).zfill(N_BLOCK_SIZE).encode("utf-8")
                blocks_ = encrypt_message_salt_nonce(blocks, key, salt, nonce)
                # Bloque completo 
                block_complete = key_hashed.digest() + blocks_ + length_ + cipher + checksum
                # Introducimos los datos al final del fichero 
                file.close()
                append_data(block_complete, path)
                # Introducimos data random al fichero
                rand_data = randint(MIN_RANDOM_DATA, MID_RANDOM_DATA)
                dunce_data(path, rand_data)

            n_block+=1 # Aumento del número de bloque 
        

def get_data(path, key):
    # Seleccionar la salt y el nonce del fichero
    salt, nonce = get_salt_nonce(path)
    with open(path, "r+b") as file:
        # Se buscan las posiciones donde hay bloques 
        indexes = search(path, key)
        # Contenedor de todos los mensajes de los bloques con la clave indicada
        total_planintext = ""

        for index in indexes:
            # Cursor en el inicio del bloque
            file.seek(index)
            # Lectura del bloque completo
            block = file.read(BLOCK_SIZE)
            # Extraer los bytes de la clave hasheada
            key_hash_file = block[FIRST_INDEX : KEY_HASH_SIZE]
            key_hash = hashlib.sha256(key)  # Calculo del hash de la clave provista para comparar con la leída del bloque
            # Extraer la metadata del numero de bloque
            n_block_cipher = block[KEY_HASH_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE]
            n_block_plaintext = decrypt_message(salt, nonce, n_block_cipher, key)
            n_block_plaintext = int(n_block_plaintext.decode("utf-8"))
            # Extraer la metadata de la longitud de la data del mensaje en el bloque
            length_cipher = block[KEY_HASH_SIZE + N_BLOCK_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE]
            length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
            length_plaintext = int(length_plaintext.decode("utf-8"))
            # Extraer la data del mensaje 
            message = block[KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + DATA_SIZE]
            # Extraer el checksum de la data del bloque
            crc = block[KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + DATA_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + DATA_SIZE + CHECKSUM_SIZE]
            crc_plaintext = decrypt_message(salt, nonce, crc, key)
            crc_plaintext = int.from_bytes(crc_plaintext, byteorder='big')
            
            if key_hash.digest() == key_hash_file:
                if (is_crc32_valid(message, crc_plaintext)):
                    if (length_plaintext == DATA_SIZE):
                        plaintext = decrypt_message(salt, nonce, message, key)
                        total_planintext = total_planintext + plaintext.decode("utf-8")
                    else:
                        data_ = message[:length_plaintext]
                        plaintext = decrypt_message(salt, nonce, data_, key)
                        total_planintext = total_planintext + plaintext.decode("utf-8")
                else:
                    print("CRC No Válido")
        
        return(total_planintext)


def get_file(path, key, outpath):
    # Seleccionar la salt y el nonce del fichero
    salt, nonce = get_salt_nonce(path)
    with open(path, "r+b") as file:
        # Se buscan las posiciones donde hay bloques 
        indexes = search(path, key)
        # Contenedor de todos los mensajes de los bloques con la clave indicada
        total_files = []

        for index in indexes:
            # Cursor en el inicio del bloque
            file.seek(index)
            # Lectura del bloque completo
            block = file.read(BLOCK_SIZE)
            # Extraer los bytes de la clave hasheada
            key_hash_file = block[FIRST_INDEX : KEY_HASH_SIZE]
            key_hash = hashlib.sha256(key)  # Calculo del hash de la clave provista para comparar con la leída del bloque
            # Extraer la metadata del numero de bloque
            n_block_cipher = block[KEY_HASH_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE]
            n_block_plaintext = decrypt_message(salt, nonce, n_block_cipher, key)
            n_block_plaintext = int(n_block_plaintext.decode("utf-8"))
            # Extraer la metadata de la longitud de la data del mensaje en el bloque
            length_cipher = block[KEY_HASH_SIZE + N_BLOCK_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE]
            length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
            length_plaintext = int(length_plaintext.decode("utf-8"))
            # Extraer el nombre del fichero
            filename_cipher = block[KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + FILENAME_SIZE]
            filename_plaintext = decrypt_message(salt, nonce, filename_cipher, key)
            filename_plaintext = str(filename_plaintext.decode("utf-8")).strip()
            # Extraer la data del mensaje 
            message = block[KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + FILENAME_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + FILENAME_SIZE + DATA_SIZE]
            # Extraer el checksum de la data del bloque
            crc = block[KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + FILENAME_SIZE + DATA_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + FILENAME_SIZE + DATA_SIZE + CHECKSUM_SIZE]
            crc_plaintext = decrypt_message(salt, nonce, crc, key)
            crc_plaintext = int.from_bytes(crc_plaintext, byteorder='big')
            
            if key_hash.digest() == key_hash_file:
                if (is_crc32_valid(message, crc_plaintext)):
                    total_files.append(filename_plaintext)
                else:
                    print("CRC No Válido")
    
    # Para crear el fichero
    # with open(outpath, "w+b") as file:
    #     file.write(total_planintext)
    
    return total_files
    # mount(outpath, "/mnt/ext4")

def get_path_files(path, key, outpath):
    # Seleccionar la salt y el nonce del fichero
    salt, nonce = get_salt_nonce(path)
    with open(path, "r+b") as file:
        # Se buscan las posiciones donde hay bloques 
        indexes = search(path, key)
        # Array con los nombres de todos los ficheros
        total_files = []
        total_types = []
        lengths = []

        for index in indexes:
            # Cursor en el inicio del bloque
            file.seek(index)
            # Lectura del bloque de la metadata del fichero
            metadata_block_size = KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE
            metadata_block = file.read(metadata_block_size)
            # Extraer los bytes de la clave hasheada
            key_hash_file = metadata_block[FIRST_INDEX : KEY_HASH_SIZE]
            key_hash = hashlib.sha256(key)  # Calculo del hash de la clave provista para comparar con la leída del bloque
            # Extraer la metadata del numero de bloque
            type_data_cipher = metadata_block[KEY_HASH_SIZE : KEY_HASH_SIZE + TYPE_SIZE]
            type_data_plaintext = decrypt_message(salt, nonce, type_data_cipher, key)
            type_data_plaintext = (type_data_plaintext.decode("utf-8"))
            # Extraer la metadata de la longitud de la data del mensaje en el bloque
            length_cipher = metadata_block[KEY_HASH_SIZE + TYPE_SIZE : KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE]
            length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
            length_plaintext = int(length_plaintext.decode("utf-8"))
            # Extraer el nombre del fichero
            filename_cipher = metadata_block[KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE : KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE]
            filename_plaintext = decrypt_message(salt, nonce, filename_cipher, key)
            filename_plaintext = str(filename_plaintext.decode("utf-8")).strip()

            # Se mueve el puntero en el fichero 
            new_index = index + KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE
            file.seek(new_index)
            # Lectura del bloque de datos mas el bloque del checksum
            block_size = length_plaintext + CHECKSUM_SIZE
            block = file.read(block_size)
            # Extraer la data del mensaje 
            message = block[FIRST_INDEX : length_plaintext]
            # Extraer el checksum de la data del bloque
            crc = block[length_plaintext : length_plaintext + CHECKSUM_SIZE]
            crc_plaintext = decrypt_message(salt, nonce, crc, key)
            crc_plaintext = int.from_bytes(crc_plaintext, byteorder='big')
            
            if key_hash.digest() == key_hash_file:
                if (is_crc32_valid(message, crc_plaintext)):
                    total_files.append(filename_plaintext)
                    total_types.append(type_data_plaintext)
                    lengths.append(length_plaintext)
                else:
                    print("CRC No Válido")
    
    
    
    return total_files, total_types, lengths
    # mount(outpath, "/mnt/ext4")



def get_file_old(path, key, outpath):
    # Seleccionar la salt y el nonce del fichero
    salt, nonce = get_salt_nonce(path)
    with open(path, "r+b") as file:
        # Se buscan las posiciones donde hay bloques 
        indexes = search(path, key)
        # Contenedor de todos los mensajes de los bloques con la clave indicada
        total_planintext = b''

        for index in indexes:
            # Cursor en el inicio del bloque
            file.seek(index)
            # Lectura del bloque completo
            block = file.read(BLOCK_SIZE)
            # Extraer los bytes de la clave hasheada
            key_hash_file = block[FIRST_INDEX : KEY_HASH_SIZE]
            key_hash = hashlib.sha256(key)  # Calculo del hash de la clave provista para comparar con la leída del bloque
            # Extraer la metadata del numero de bloque
            n_block_cipher = block[KEY_HASH_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE]
            n_block_plaintext = decrypt_message(salt, nonce, n_block_cipher, key)
            n_block_plaintext = int(n_block_plaintext.decode("utf-8"))
            # Extraer la metadata de la longitud de la data del mensaje en el bloque
            length_cipher = block[KEY_HASH_SIZE + N_BLOCK_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE]
            length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
            length_plaintext = int(length_plaintext.decode("utf-8"))
            # Extraer el nombre del fichero
            filename_cipher = block[KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + FILENAME_SIZE]
            filename_plaintext = decrypt_message(salt, nonce, filename_cipher, key)
            filename_plaintext = str(filename_plaintext.decode("utf-8")).strip()
            # Extraer la data del mensaje 
            message = block[KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + FILENAME_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + FILENAME_SIZE + DATA_SIZE]
            # Extraer el checksum de la data del bloque
            crc = block[KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + FILENAME_SIZE + DATA_SIZE : KEY_HASH_SIZE + N_BLOCK_SIZE + N_LENGTH_SIZE + FILENAME_SIZE + DATA_SIZE + CHECKSUM_SIZE]
            crc_plaintext = decrypt_message(salt, nonce, crc, key)
            crc_plaintext = int.from_bytes(crc_plaintext, byteorder='big')
            
            if key_hash.digest() == key_hash_file:
                if (is_crc32_valid(message, crc_plaintext)):
                    if (length_plaintext == DATA_SIZE):
                        plaintext = decrypt_message(salt, nonce, message, key)
                        total_planintext = total_planintext + plaintext
                    else:
                        data_ = message[:length_plaintext]
                        plaintext = decrypt_message(salt, nonce, data_, key)
                        total_planintext = total_planintext + plaintext
                else:
                    print("CRC No Válido")
    
    # Para crear el fichero
    with open(outpath, "w+b") as file:
        file.write(total_planintext)
    
    return filename_plaintext
    # mount(outpath, "/mnt/ext4")
def get_file_open(path, key, outpath, root_dir):
    # Seleccionar la salt y el nonce del fichero
    salt, nonce = get_salt_nonce(path)
    with open(path, "r+b") as file:
        # Se buscan las posiciones donde hay bloques 
        indexes = search(path, key)
        # Contenedor de todos los mensajes de los bloques con la clave indicada
        total_files = []

        for index in indexes:
            # Cursor en el inicio del bloque
            file.seek(index)
            # Lectura del bloque de la metadata del fichero
            metadata_block_size = KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE
            metadata_block = file.read(metadata_block_size)
            # Extraer los bytes de la clave hasheada
            key_hash_file = metadata_block[FIRST_INDEX : KEY_HASH_SIZE]
            key_hash = hashlib.sha256(key)  # Calculo del hash de la clave provista para comparar con la leída del bloque
            # Extraer la metadata del numero de bloque
            type_data_cipher = metadata_block[KEY_HASH_SIZE : KEY_HASH_SIZE + TYPE_SIZE]
            type_data_plaintext = decrypt_message(salt, nonce, type_data_cipher, key)
            type_data_plaintext = (type_data_plaintext.decode("utf-8"))
            # Extraer la metadata de la longitud de la data del mensaje en el bloque
            length_cipher = metadata_block[KEY_HASH_SIZE + TYPE_SIZE : KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE]
            length_plaintext = decrypt_message(salt, nonce, length_cipher, key)
            length_plaintext = int(length_plaintext.decode("utf-8"))
            # Extraer el nombre del fichero
            filename_cipher = metadata_block[KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE : KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE]
            filename_plaintext = decrypt_message(salt, nonce, filename_cipher, key)
            filename_plaintext = str(filename_plaintext.decode("utf-8")).strip()

            # Se mueve el puntero en el fichero 
            new_index = index + KEY_HASH_SIZE + TYPE_SIZE + N_LENGTH_SIZE + FILENAME_SIZE
            file.seek(new_index)
            # Lectura del bloque de datos mas el bloque del checksum
            block_size = length_plaintext + CHECKSUM_SIZE
            block = file.read(block_size)
            # Extraer la data del mensaje 
            message = block[FIRST_INDEX : length_plaintext]
            # Extraer el checksum de la data del bloque
            crc = block[length_plaintext : length_plaintext + CHECKSUM_SIZE]
            crc_plaintext = decrypt_message(salt, nonce, crc, key)
            crc_plaintext = int.from_bytes(crc_plaintext, byteorder='big')
            
            if key_hash.digest() == key_hash_file:
                if (is_crc32_valid(message, crc_plaintext)):
                    # if(outpath[1:] == "." + filename_plaintext + ".swp"):
                    #     total_files.append(filename_plaintext)
                    #     plaintext = decrypt_message(salt, nonce, message, key)
                    #     create_file(plaintext, root_dir + outpath)
                    #     break
                    if(outpath[1:] == filename_plaintext):
                        total_files.append(filename_plaintext)
                        plaintext = decrypt_message(salt, nonce, message, key)
                        create_file(plaintext, root_dir + outpath)
                        break

                else:
                    print("CRC No Válido")
    
    
    
    return filename_plaintext
    # mount(outpath, "/mnt/ext4")
def gen_attr_data():
    data = {
        'st_atime': 0,
        'st_ctime': 0,
        'st_gid': 1000,
        'st_mode': 0,
        'st_mtime': 0,
        'st_nlink': 0,
        'st_size': 100,
        'st_uid': 0
    }
    return data


def main():
    
    parser = argparse.ArgumentParser(description='Tool to create a fuse filesystem with plausible deniability')
    parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')
    parser.add_argument('-s', '--size', help='Size of the random data to introduce in the file in Bytes')
    parser.add_argument('-o', '--outfile', help='Path of the output file (with name of the file)')
    parser.add_argument('-i', '--inputfile', help='Path of the input file (with name of the file)')
    
    subparsers = parser.add_subparsers(dest='command')
    
    create_parser = subparsers.add_parser('create', help='Create a file with the salt, nonce and random data')
    create_parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')
    
    set_parser = subparsers.add_parser('set', help='Set a encrypt message with a key')
    set_parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')

    get_parser = subparsers.add_parser('get', help='Get a encrypt message with a key')
    get_parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')

    random_parser = subparsers.add_parser('random', help='Insert random data in the file')
    random_parser.add_argument('-f', '--file', help='Path of the file (with name of the file)')
    random_parser.add_argument('-s', '--size', help='Size of the random data to introduce in the file in Bytes')

    getfile_parser = subparsers.add_parser('getfile', help='Get a encrypt file with a key')
    getfile_parser.add_argument('-f', '--file', help='Path of the file container (with name of the file)')
    getfile_parser.add_argument('-o', '--outfile', help='Path of the output file (with name of the file)')

    setfile_parser = subparsers.add_parser('setfile', help='Set a encrypt file with a key')
    setfile_parser.add_argument('-f', '--file', help='Path of the file container (with name of the file)')
    setfile_parser.add_argument('-i', '--inputfile', help='Path of the input file (with name of the file)')

    umount_parser = subparsers.add_parser('umount', help='Umount the volumme')
    umount_parser.add_argument('-m', '--mountpoint', help='Path of the mount point')
    umount_parser.add_argument('-f', '--file', help='Path of the file container (with name of the file)')
    umount_parser.add_argument('-i', '--inputfile', help='Path of the output file (with name of the file)')


    args = parser.parse_args()

    if args.command == 'create':
        
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
        

        dunce_data(args.file, size)


def pruebas():
    key = b'pruebas1'
    path = "./new.bin"
    read = "./data"
    # with open(read,"r+b") as f:
    #     total = f.read()
    #     print(len(total))
    #     print(type(total))
        # set_data(path, key, total)
    # indexes = search(read, key)
    # for index in indexes:
    #     print(index)
    #     end_index = int(index) + BLOCK_SIZE
        # print(end_index)
        # print("remove")
    # remove_bytes_from_file(read, indexes)
    # path = "./fuse"
    mountpoint = "/tmp/fuse"
    # create_fuse_filesystem(path, mountpoint, key)
    # createfile(path)
    files = []
    files.append("./prueba/hola/pruebas.py")
    files.append("./ger/magic.py")
    files.append("./ale/file.py")
    files.append("./fichero.py")
    for file in files:
        print(file)
        set_fuse(path, key, file, "")
    # outfiles = get_metadata(path, key, "./ejemplos/")

    # for file in outfiles:
        # print(file)

    # borrar_contenido_carpeta("/home/jorge/tf/fuse")
if __name__ == "__main__":
    # main()
    # pruebas()
    print("NADA")