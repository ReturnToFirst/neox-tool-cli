import io
import struct
from dataclasses import dataclass
from pathlib import Path

@dataclass
class NPKIndex:
    file_name: str
    file_offset: int
    file_length: int
    file_original_length: int
    crc_compressed: int
    crc_original: int
    compression_flag: int
    encryption_flag: int

    def __post_init__(self, f:io.BufferedReader, info_size:int, index_offset:int):
        if info_size == 28:
            sign_format = '<I'
        elif info_size == 32:
            sign_format = '<Q'

        data_format = f'{sign_format}IIIIHH'
        data_size = struct.calcsize(data_format)
        data = f.read(data_size)

        unpacked = struct.unpack(data_format, data)

        self.file_offset = unpacked[1]
        self.file_length = unpacked[2]
        self.file_original_length = unpacked[3]
        self.crc_compressed = unpacked[4]
        self.crc_original = unpacked[5]
        self.compression_flag = unpacked[6]
        self.encryption_flag = unpacked[7]

@dataclass
class NPKFile:
    path: Path
    reader: io.BufferedReader
    type: str
    file_count: int
    encryption_flag: int
    use_nxfn: bool
    hashing_mode: int
    index_start_offset: int
    index: list[NPKIndex]

    def __post_init__(self, file_path: Path):
        self.reader = open(file_path, "rb")

        self.reader.seek(0)
        header_data = self.reader.read(24)

        unpacked = struct.unpack('<4sIHHI', header_data)

        self.type = unpacked[0]
        self.file_count = unpacked[1]
        self.encryption_flag = unpacked[2]
        self.hashing_mode = unpacked[3]
        self.index_start_offset = unpacked[4]
        
        self.type = self.type.decode('utf-8')[::-1]  # Reverse and decode type string
        self.use_nxfn = self.encryption_flag == 256
        
    def get_info_size(self) -> int:
        if self.encryption_flag == 256 or self.hashing_mode == 2:
            return 0x1C
        current_pos = self.reader.tell()
        self.reader.seek(self.index_start_offset)
        # Read the first 4 bytes to determine buffer size per file
        buf = self.reader.read(4 * self.file_count)
        self.reader.seek(current_pos)
        return len(buf) // self.file_count

# Return name of compression type based on file"s header
def parse_compression_type(data: bytes) -> str:
    if not data:
        return None

    # Define possible compression signatures and their types
    signatures = {
        b"\x1d\x04": "rot",
        b"\x15\x23": "rot",
        b"\x50\x4b\x03\x04": "zip",
        b"\x50\x4b\x05\x06": "zip",
        b"NXS3\x03\x00\x00\x01": "nxs3",
    }

    # Check for each signature prefix match
    for signature, compression_type in signatures.items():
        if data.startswith(signature):
            return compression_type

    return None

# Get file extension based on file structure to get the file extension
def parse_extension(data):
    # If data is empty, return None
    if len(data) == 0:
        return None
    
    # Mapping of file signatures and their corresponding extensions
    signature_map = {
        b"PVR": "pvr",
        b"\x34\x80\xc8\xbb": "mesh",
        b"RIFF": "wem",  # Default to "wem", check "FEV" and "WAVE" later
        b"RAWANIMA": "rawanimation",
        b"NEOXBIN1": "uiprefab",
        b"SKELETON": "skeleton",
        b"\x01\x00\x05\x00\x00\x00": "foliage",
        b"NEOXMESH": "uimesh",
        b"NVidia(r) GameWorks Blast(tm) v.1": "blast",
        b"\xe3\x00\x00\x00": "pyc",
        b"CocosStudio-UI": "coc",
        b"\x13\xab\xa1\x5c": "astc",
        b"hit": "hit",
        b"PKM": "pkm",
        b"DDS": "dds",
        b"TRUEVISION-XFILE": "tga",
        b"NFXO": "nfx",
        b"\xc1\x59\x41\x0d": "unknown1",
        b"CompBlks": "cbk",
        b"BM": "bmp",
        b"from typing import ": "pyi",
        b"KTX": "ktx",
        b"blastmesh": "blastmesh",
        b"clothasset": "clothasset",
        b"PNG": "png",
        b"FSB5": "fsb",
        b"VANT": "vant",
        b"MDMP": "mdmp",
        b"RGIS": "gis",
        b"NTRK": "trk",
        b"OggS": "ogg",
        b"\xff\xd8": "jpg",
        b"BKHD": "bnk",
        b"-----BEING PUBLIC KEY-----": "pem",
        b"%": "tpl",
        b"TZif": "tzif",
        b"JFIF": "jfif",
        b"ftyp": "mp4",
        b"\xc5\x00\x00\x80\x3f": "slpb",
    }
    
    # Check for predefined signatures
    for signature, extension in signature_map.items():
        if data.startswith(signature):
            return extension
    
    # Handle special cases for "RIFF" with "FEV" and "WAVE"
    if data[:4] == b"RIFF":
        if b"FEV" in data:
            return "fev"
        elif b"WAVE" in data:
            return "wem"
        
    return _parse_neoxml_type(data)

def _parse_neoxml_type(data: bytes) -> str:
    neo_xml_map = {
        b"<Material": "mtl",
        b"<MaterialGroup": "mtg",
        b"<MetaInfo": "pvr.meta",
        b"SHEX": "binary",
        b"<Section": "sec",
        b"<SubMesh": "gim",
        b"<FxGroup": "sfx",
        b"<Track": "trackgroup",
        b"<Instances": "decal",
        b"<Physics": "col",
        b"<LODPolicy": "lod",
        b"Type=\"Animation\"": "animation",
        b"DisableBakeLightProbe=": "prefab",
        b"<Scene": "scn",
        b"\"ParticleSystemTemplate\"": "pse",
        b"<MainBody": "nxcompute",
        b"?xml": "xml",
        b"<MapSkeletonToMeshBone": "skeletonextra",
        b"<ShadingModel": "nxshader",
        b"<BlastDynamic": "blt",
        b"\"ParticleAudio\"": "psemusic",
        b"<BlendSpace": "blendspace1d",
        b"<AnimationConfig": "animconfig",
        b"<AnimationGraph": "animgraph",
        b"<Head Type=\"Timeline\"": "timeline",
        b"<Chain": "physicalbone",
        b"<BlendSpace" and b"is2D=\"true\"": "blendspace",
        b"<PostProcess": "postprocess",
        b"\"mesh_import_options\":{": "nxmeta",
        b"<SceneConfig": "scnex",
        b"<LocalPoints": "localweather",
        b"GeoBatchHint=\"0\"": "gimext",
        b"\"AssetType\":\"HapticsData\"": "haptic",
        b"<LocalFogParams": "localfogparams",
        b"<Audios": "prefabaudio",
        b"\"ReferenceSkeleton\"": "featureschema",
        b"<Relationships": "xml.rels",
        b"<Waterfall": "waterfall",
        b"\"ReferenceSkeletonPath\"": "mirrortable",
        b"<ClothAsset": "clt",
        b"<plist": "plist",
        b"<ShaderCompositor": "render",
        b"<SkeletonRig": "skeletonrig",
        b"format: ": "atlas",
        b"<ShaderCache": "cache",
        b"char" and b"width=": "fnt",
        b"<AllCaches": "info",
        b"<AllPreloadCaches": "list",
        b"<Remove_Files": "map",
        b"<HLSL File=\"": "md5",
        b"<EnvParticle": "envp",
        b"<TextureGroup": "txg",
        b"<cinematic": "xml",
        b"<NeoX": "unkown_neox",
        b"\"CCLayer\"": "cclayer",
        b"\"CCNode\"": "ccnode",
        b"2.1.0.0": "csb",
        b"#?RADIANCE": "hdr",
        b"<Macros": "xml.template",
        b"precision mediump": "ps",
        b"POSITION": "vs",
        b"technique": "nfx",
        b"package google.protobuf": "proto",
        b"#ifndef": "h",
        b"#include <google/protobuf": "cc",
        b"void": "shader",
        b"<script": "html",
        b"Javascript": "js",
        b"biped": "bip",
        b"div.document": "css",
        b"png" and b"tga" and b"1000": "spr",
        b"{": "json",
        b"SEBD": "col_android",
        b"IMG = {": "txt",
        b"\"md5\"": "file_signature",
        b"2048" and b"512": "spr",
    }

    for signature, extension in neo_xml_map.items():
        if signature in data:
            return extension
    
    return "dat"