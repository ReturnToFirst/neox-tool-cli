# NeoX NPK Extractor

File extractor for NeoX Engine .npk files.

# Setup
```bash
pip install -r requirements.txt
```

# Instructions to extract
## Basic examples

To check your current version, use the '-v' or '--version' argument<br>
```bash
python extractor.py --version
```

No arguments will go through all the files and folders and find all NPK files<br>
```bash
python extractor.py
```

With the '-h' argument, you can see all the help options<br>
```bash
python extractor.py -h
```

With the '-p' argument, you can specify a file or a folder which to analyse<br>
```bash
python extractor.py -p script.npk
```

With the '-d' argument, if there are any ZIP or ZStandard files in the NPK, these will get deleted after extraction<br>
```bash
python extractor.py -p script.npk -d
```

With the '-i' argument, you can see data on the NPK file being extracted (from 1 to 5 for verbosity)<br>
```bash
python extractor.py -p res.npk -i (1 to 5)
```

With the '--nxfn-file' argument, there will be a "NXFN_result.txt" file that has the NXFN file structuring from inside the NPK (if applicable)<br>
```bash
python extractor.py -p res2.npk --nxfn-file
```

With the '--no-nxfn' argument, you can disable the NXFN file structuring (useful if it's failing, you should not be using this unless there is a bug that stops you from extracting, which should be reported)<br>
```bash
> python extractor.py -p res4.npk --no-nxfn
``` 

With the '--do-one' argument, the program will only do one file from inside the NPK (useful for testing purposes)<br>
```bash
> python extractor.py -p script.npk --do-one
```

I am trying to add compability to every type of NPK file, it is really appreciated to join the official [Discord](https://discord.gg/eedXVqzmfn) for more information <br>

# Disclaimer
I am not the creator (please check the original fork), I will be offering support only for the scripts that are found in this GitHub branch, I can fix issues with the "mesh viewer" / "mesh converter" if possible but you are better off referring those issues to zhouhang95.<br>

# Credits::

Thank you to::
* [zhouhang95](https://github.com/zhouhang95/neox_tools) - Original script
* [hax0r313373](https://github.com/hax0r31337/denpk2) - Code for RSA/NXS3 decryption
* [xforce](https://github.com/xforce/neox-tools) - Research on NPK files and how they work
* [yuanbi](https://github.com/yuanbi/NeteaseUnpackTools) - Rotor encryption and marshalling for PYC
* [MarcosVLl2](https://github.com/MarcosVLl2/neox_tools) - Maintainer of Neoxtools

