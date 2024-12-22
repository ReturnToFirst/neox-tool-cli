import os
import struct
import tempfile
import argparse
import zipfile
import logging
import tqdm
import glob
import io

from decompress import zflag_decompress, special_decompress
from decrypt import file_decrypt, XORDecryptor
from utils import readuint16, readuint32, readuint64, readuint8, get_decompression_algorithm_name, get_decryption_algorithm_name
from parse import parse_compression_type, parse_extension, get_info_size

# reads an entry of the NPK index, if its 28 the file sign is 32 bits and if its 32 its 64 bits (NeoX 1.2 / 2 shienanigans)
def read_index(f, info_size, x, nxfn_files, index_offset):
    if info_size == 28:
        file_sign = [readuint32(f), f.tell() + index_offset]
    elif info_size == 32:
        file_sign = [readuint64(f), f.tell() + index_offset]
    file_offset = readuint32(f)
    file_length = readuint32(f)
    file_original_length = readuint32(f)
    zcrc = readuint32(f)                #compressed crc
    crc = readuint32(f)                 #decompressed crc
    zip_flag = readuint16(f)
    file_flag = readuint16(f)
    file_structure = nxfn_files[x] if nxfn_files else None
    return (
        file_sign,
        file_offset, 
        file_length,
        file_original_length,
        zcrc,
        crc,
        file_structure,
        zip_flag,
        file_flag,
        )

# main code
def unpack(args):
    allfiles = []
    try:
        # if input path is not provided, scan current directory
        if args.input == None:
            allfiles = glob.glob("*.npk")
        elif os.path.isdir(args.input):
            allfiles = [args.input + "/" + x for x in os.listdir(args.input) if x.endswith(".npk")]
        else:
            allfiles.append(args.input)
    except TypeError as e:
        logging.exception("NPK files not found")
    if not allfiles:
        logging.exception("No NPK files found in that folder")
        
    #sets the decryption keys for the custom XOR cypher
    xor_decryptor = XORDecryptor(args.xor_key_file)

    #goes through every file
    for output in allfiles:
        
        #sets the final destination output
        logging.info("UNPACKING: {}".format(output))
        folder_output = output[:-4]
        
        #makes the folder where the files will be dumped
        if not os.path.exists(folder_output):
            os.mkdir(folder_output)
            
        #opens the file
        with open(output, 'rb') as f:
            
            #this is the only thing that the force command does, doesnt read the bytes corresponding the NXPK / EXPK header
            if not args.force:
                data = f.read(4)
                pkg_type = None
                if data == b'NXPK':
                    pkg_type = 0
                elif data == b'EXPK':
                    pkg_type = 1
                else:
                    raise Exception('NOT NXPK/EXPK FILE')
                logging.info("FILE TYPE: %s", data.decode())
            
            # amount of files
            files = readuint32(f)
            logging.info("FILES: %s", files)
            
            #var1, its always set to 0
            var1 = readuint32(f)
            logging.debug("UNKNOWN: %s", var1)
            
            #determines what i call "encryption mode", its 256 when theres NXFN file data at the end
            encryption_mode = readuint32(f)
            logging.debug("ENCRYPTMODE: %s", encryption_mode)
            
            #determines what i call "hash mode", it can be 0, 1, 2, and 3, 0 and 1 are fine, 3 is not supported (i think) and 2 is unknown
            hash_mode = readuint32(f)
            logging.info("HASHMODE: %s", hash_mode)
            
            #offset where the index starts
            index_offset = readuint32(f)
            logging.info("INDEXOFFSET: %s", index_offset)

            #determines the "log_level_size" aka the size of each file offset data, it can be 28 or 32 bytes
            info_size = get_info_size(f, hash_mode, encryption_mode, index_offset, files)
            logging.info("INDEXSIZE: %s", info_size)

            index_table = []
            nxfn_files = []
            
            #checks for the "hash mode"
            if hash_mode == 2:
                logging.warning("HASHING MODE 2 DETECTED, MAY NOT WORKS!!")
            elif hash_mode == 3:
                raise Exception("HASHING MODE 3 IS CURRENTLY NOT SUPPORTED")
                
            #checks for the encryption mode and does the NXFN shienanigans
            if encryption_mode == 256 and args.nxfn_file:
                with open(folder_output+"/NXFN_result.txt", "w") as nxfn:
                    #data reader goes to where the NXFN file starts, it starts with b"NXFN" + 12 bytes (unknown for now)
                    f.seek(index_offset + (files * info_size) + 16)
                    
                    #nxfn file entries are plaintext bytes, separated by an empty byte
                    nxfn_files = [x for x in (f.read()).split(b'\x00') if x != b'']
                    
                    #dumps this file into a file called NXFN_result.txt
                    for nxfnline in nxfn_files:
                        nxfn.write(nxfnline.decode() + "\n")
            
            #does the same thing above, but doesnt write the file
            elif encryption_mode == 256:
                f.seek(index_offset + (files * info_size) + 16)
                nxfn_files = [x for x in (f.read()).split(b'\x00') if x != b'']

            #goes back to the index offset (or remains in the same place)
            f.seek(index_offset)

            #opens a temporary file
            with tempfile.TemporaryFile() as tmp:
                
                #reads the whole of the index file
                data = f.read(files * info_size)

                #if its an EXPK file, it decodes it with the custom XOR key
                if pkg_type:
                    data = xor_decryptor.decrypt(data)
                    
                #writes the data
                tmp.write(data)
                
                #goes to the start of the file
                tmp.seek(0)
                
                #checks if its only supposed to read one file, then it reads the data and adds it to a list as touples with the log_level itself
                if args.test:
                    index_table.append(read_index(tmp, info_size, 0, nxfn_files, index_offset))
                else:
                    for x in range(files):
                        index_table.append(read_index(tmp, info_size, x, nxfn_files, index_offset))
                        
            #calculates how many files it should analyse before reporting progress in the console (and adds 1 to not divide by 0)
            step = len(index_table) // 50 + 1

            #goes through every index in the index table
            for i, item in enumerate(tqdm.tqdm(index_table)):
                ext = None
                data2 = None
                
                #checks if it should print the progression text
                    
                #unpacks the index
                file_sign, file_offset, file_length, file_original_length, zcrc, crc, file_structure, zflag, file_flag = item
                
                #prints the index data
                logging.debug("FILESIGN: %s", hex(file_sign[0]))
                logging.debug("FILEOFFSET: %s", file_offset)
                logging.debug("FILELENGTH: %s", file_length)
                logging.debug("FILEORIGLENGTH: %s", file_original_length)
                logging.debug("ZIPCRCFLAG: %s", zcrc)
                logging.debug("CRCFLAG: %s", crc)
                logging.debug("ZFLAG: %s", zflag)
                logging.debug("FILEFLAG: %s")
                
                #goes to the offset where the file is indicated by the index
                f.seek(file_offset)
                
                #checks if its empty, and if include_empty is false, skips it
                if file_original_length == 0 and not args.include_empty:
                    continue
                
                #reads the amount of bytes corresponding to that file
                data = f.read(file_length)
                
                #defines the method for the file structure (if it has NXFN structure, if not its 00000000.extension)
                def check_file_structure():
                    if file_structure and not args.no_nxfn:
                        file_output = folder_output + "/" + file_structure.decode().replace("\\", "/")
                        os.makedirs(os.path.dirname(file_output), exist_ok=True)
                        ext = file_output.split(".")[-1]
                    else:
                        file_output = folder_output + '/{:08}.'.format(i)
                    return file_output

                #gets the file structure
                file_output = check_file_structure()

                #if its an EXPK file,it decrypts the data
                if pkg_type:
                    data = xor_decryptor.decrypt(data)
                    
                #prints out the decryption algorithm type
                logging.debug("DECRYPTION: %s", get_decryption_algorithm_name(file_flag))

                #does the decryption
                data = file_decrypt(file_flag, data, args.key, crc, file_length, file_original_length)

                #prints out the compression type
                logging.debug("COMPRESSION: %s", get_decompression_algorithm_name(zflag))

                #does the decompression
                data = zflag_decompress(zflag, data, file_original_length)
                    
                #gets the compression type and prints it
                compression = parse_compression_type(data)
                logging.debug("COMPRESSION1: %s", compression.upper() if compression != None else "None")

                #does the special decompresison type (NXS and ROTOR)
                data = special_decompress(compression, data)

                #special code for zip files
                if compression == 'zip':
                    
                    #checks the file structure for zip files
                    file_output = check_file_structure() + "zip"
                    logging.info("FILENAME_ZIP: %s", file_output)
                    
                    #writes the zip file data
                    with open(file_output, 'wb') as dat:
                        dat.write(data)
                        
                    #extracts the zip file
                    with zipfile.ZipFile(file_output, 'r') as zip:
                        zip.extractall(file_output[0:-4])
                        
                    #deletes the zip file 
                    if args.delete_compressed:
                        os.remove(file_output)
                        
                    #skips the rest of the code and goes on with the next index
                    continue

                #tries to guess the extension of the file

                if not file_structure:
                    ext = parse_extension(data)
                    file_output += ext
                
                logging.info("FILENAME: %s", file_output)
                
                #writes the data
                with open(file_output, 'wb') as dat:
                    dat.write(data)
        
        #prints the end time
        logging.info("FINISHED - DECOMPRESSED %d FILES", files)


# defines the parser arguments
def get_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input', help="Specify the input of the file or directory, if not specified will do all the files in the current directory", type=str)
    parser.add_argument('-o', '--output', help="Specify the output of the file or directory, if not specified will do all the files in the current directory", type=str)
    parser.add_argument('-x', '--xor-key-file', help="key file for xor decryption", default='neox_xor.key', type=str)
    parser.add_argument('-k', '--key', help="Select the key to use in the CRC128 hash algorithm (check the keys.txt for information)",type=int)

    parser.add_argument('-c', '--delete-compressed', action="store_true",help="Delete compressed files (such as ZStandard or ZIP files) after decompression")
    parser.add_argument('-m', '--merge-folder', help="Merge dumped files to output folder")
    parser.add_argument('--nxfn-file', action="store_true",help="Writes a text file with the NXFN dump output (if applicable)")

    parser.add_argument('-f', '--force', help="Forces the NPK file to be extracted by ignoring the header",action="store_true")
    parser.add_argument('--no-nxfn',action="store_true", help="Disables NXFN file structure")

    parser.add_argument('-v', '--log-level', help="Print information about the npk file(s) 1 to 5 for least to most info", default=3, type=int)
    parser.add_argument('-l', '--log-file', help="Path to log file", default="export.log", type=str)
    parser.add_argument('-t', '--test', help='Export only one file from .npk file(s) for test', action='store_true')  
    parser.add_argument('-a', '--analyse', help='Analyse .npk file(s) struct and save to file.', action="store_true")

    return parser.parse_args()

if __name__ == '__main__':
    args = get_parser()
    logging.basicConfig(format="%(asctime)s %(levelname)s (%(funcName)s) : %(message)s",
                        level=(5-args.log_level)*10,
                        handlers=[
                            logging.FileHandler(filename=args.log_file, mode="w"),
                            logging.StreamHandler()
                        ]
    )
    unpack(args)
