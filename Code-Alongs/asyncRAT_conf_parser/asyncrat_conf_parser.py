#! /usr/bin/env python3

# good library - https://github.com/malwarefrank/dnfile

import argparse as ar
import logging as log
import re

# set up a separate logger for this script
logger = log.getLogger(__name__)


class AsyncRATParser():
    
    PATTERN_FOR_CONFIG = b'(\x72.{9}){9}'
    PATTERN_PARSED_RVA = b'\x72(.{4})\x80(.{4})'
    OPCODE_RET = b'\x2a'

    class AsyncRATParserError(Exception):
        pass



    def __init__(self,file_path):
        self.file_path = file_path
        self.data = self.get_file_data()
        '''
        # Find start of the configuration section and retreive
        the virtual addresses of the config keys and their encrypted values
        
        # Map adresses from the configuration to their
        # Recreate the AES decryption algorithm used by the RAT
        # Decrypt encrypted config value using offsets and map them to their keys
        # Present decrypted config to the user
        '''
        self.config_adress_map = self.get_config_address_map()
    
    def get_file_data(self):
        #Open the file path and read in the binary data
        #Log an exception if something goes wrong opening the file
        logger.debug(f'Reading contents from: {self.file_path}')
        try:
            with open(self.file_path,'rb') as file:
                data =  file.read()
        except Exception:
            raise self.AsyncRATParserError(
                f'Error reading from path: {self.file_path}') from Exception
        logger.debug(f'Successfully read data')
        return data

    
    def get_config_address_map(self):
        # Create a regex pattern to find config section
        # Parse out each virtual address of:
        # 1. encrypted value of the config key 
        # 2. the of the config key i.e Port
        # convert the virtual address from little endian to hex.
        logger.debug(f'Extracting the config address map')
        config_mappings = []
        hit = re.search(self.PATTERN_FOR_CONFIG, self.data, re.DOTALL)
        if hit is None:
            raise self.AsyncRATParserError('Could not find the start of the config')
        config_start = hit.start()
        parsed_conf = self.get_string_from_offset(config_start,self.OPCODE_RET)  
        parsed_rvas = re.findall(self.PATTERN_PARSED_RVA,parsed_conf,re.DOTALL)
        
        # little endian to int
        for (us_rva,string_rva) in parsed_rvas:
            config_value_rva = self.bytes_to_int(us_rva, 'little')
            config_name_rva = self.bytes_to_int(string_rva, 'little')
            config_mappings.append((config_value_rva,config_name_rva))

    def bytes_to_int(self, bytes, order):
        try:
            res = int.from_bytes(bytes,byteorder=order)
        except Exception as e:
            raise self.AsyncRATParserError(f"Error parsing integer from value: {bytes}") from e
        return res

    def get_string_from_offset(self,str_offset,delimiter = b'\0'):
        try:
            result = self.data[str_offset:].partition(delimiter)[0]
        except Exception as e:
            raise self.AsyncRATParserError(
                f'Couldn\'t extract the string value from offset {hex(str_offset)} with chosen delimiter {delimiter}')
        return result

    def report():
        pass

if __name__ == '__main__':
    ap = ar.ArgumentParser()
    ap.add_argument('file_paths',
                    nargs = '+',
                    help = 'One or more AsyncRat payload file paths')
    ap.add_argument('-d','--debug',
                    action = 'store_true',
                    help = 'Enable debug logging')
    args = ap.parse_args()
    if args.debug:
        # if a debug argument is set, then setup the log to default
        log.basicConfig(level=log.DEBUG)
    else:
        log.basicConfig(level=log.WARNING)
    
    for fp in args.file_paths:
        try:
            print(AsyncRATParser(fp).report())
        except:
            logger.exception(f'Exception occured for {fp}, exec_info=True')
            continue
        