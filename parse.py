import io

# Determines the info size by basic math (from the start of the index pointer // EOF or until NXFN data )
def get_info_size(f:io.BufferedReader, hash_mode: int, encrypt_mode:int , index_offset:int , files_count: int):
    if encrypt_mode == 256 or hash_mode == 2:
        return 0x1C
    indexbuf = f.tell()
    f.seek(index_offset)
    buf = f.read()
    f.seek(indexbuf)
    return len(buf) // files_count

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