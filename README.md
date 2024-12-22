# NeoX NPK Extractor

File extractor for NeoX Engine .npk files.

## Setup
```bash
pip install -r requirements.txt
```

## Usage

```bash
> python main.py
usage: main.py [-h] [-i INPUT] [-o OUTPUT] [-d] [-v VERBOSE] [-x XOR_KEY_FILE] [-k KEY] [-f] [-s] [--nxfn-file] [--no-nxfn] [--convert-images] [--include-empty] [-t]

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Specify the output of the file or directory, if not specified will do all the files in the current directory
  -o OUTPUT, --output OUTPUT
                        Specify the output of the file or directory, if not specified will do all the files in the current directory
  -d, --delete-compressed
                        Delete compressed files (such as ZStandard or ZIP files) after decompression
  -v VERBOSE, --verbose VERBOSE
                        Print verbosermation about the npk file(s) 1 to 5 for least to most verbose
  -x XOR_KEY_FILE, --xor-key-file XOR_KEY_FILE
                        key file for xor decryption
  -k KEY, --key KEY     Select the key to use in the CRC128 hash algorithm (check the keys.txt for verbosermation)
  -f, --force           Forces the NPK file to be extracted by ignoring the header
  -s, --selected-file   Decompress Only file selected
  --nxfn-file           Writes a text file with the NXFN dump output (if applicable)
  --no-nxfn             Disables NXFN file structure
  --convert-images      Automatically converts KTX, PVR and ASTC to PNG files (WARNING, SUPER SLOW)
  --include-empty       Prints empty files
  -t, --test            Export only one file from .npk file(s) for test
```

# Disclaimer
This project is intended solely for research and educational purposes. It is a reverse engineering framework designed to explore and understand software systems. The use of this framework for any illegal or unauthorized activity, including but not limited to the unauthorized access, alteration, or distribution of software or data, is strictly prohibited.

By using this framework, you acknowledge that you are fully responsible for ensuring that your actions comply with all relevant legal, ethical, and regulatory requirements, including international laws if applicable, within the laws of your region.


# Credits
* [zhouhang95](https://github.com/zhouhang95/neox_tools) - Original script
* [hax0r313373](https://github.com/hax0r31337/denpk2) - Code for RSA/NXS3 decryption
* [xforce](https://github.com/xforce/neox-tools) - Research on NPK files and how they work
* [yuanbi](https://github.com/yuanbi/NeteaseUnpackTools) - Rotor encryption and marshalling for PYC
* [MarcosVLl2](https://github.com/MarcosVLl2/neox_tools) - Maintainer of Neoxtools

