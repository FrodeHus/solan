from os import path
import sys
from typing import List
import zlib
import struct
import exiftool

from solan import SIG_TYPES
from solan.rules import (
    BaseSignature,
    EndOfThreat,
    SignatureCleanScript,
    SignatureDefaults,
    SignatureExplicitResource,
    SignatureFilePath,
    SignatureFilename,
    SignatureHSTR,
    SignatureIP,
    SignatureLuaStandalone,
    SignatureStatic,
    Threat,
)


class Vdm:
    def __init__(self, vdm_path: str):
        self.vdm_path = vdm_path
        self.delta_path = None

        filename, version = self.get_file_info()
        if filename.startswith("mpav"):
            self.vdm_type = "anti-virus"
            self.delta_path = "mpavdlta.vdm"
        elif filename.startswith("mpas"):
            self.vdm_type = "anti-spyware"
            self.delta_path = "mpasdlta.vdm"

        self.version = version

        self.raw_data = self.extract_vdm(self.vdm_path)
        try:
            self.raw_data = self.apply_delta(self.delta_path, self.raw_data)
        except Exception as err:
            print(err)
            exit(1)

    def extract_vdm(self, vdm_path: str):
        # Get VDM data
        data = open(vdm_path, "rb").read()
        # Look for the resource signature
        base = data.index(b"RMDX")
        if not base:
            raise ValueError(f"Not a valid VDM file: {self.vdm_path}")

        # Extract relevant information
        offset, size = struct.unpack("II", data[base + 0x18 : base + 0x20])
        # Decompress the data
        decompressed_vdm = zlib.decompress(data[base + offset + 8 :], -15)
        # Ensure correctness
        assert len(decompressed_vdm) == size
        # Dumps the output

        return decompressed_vdm

    def apply_delta(self, delta_path: str, base_data: bytes):
        if not delta_path:
            return base_data

        delta_raw_data = self.extract_vdm(delta_path)
        offset = 0
        while offset < len(delta_raw_data):
            signature, offset = self.parse_signature(delta_raw_data, offset)
            if signature.type_name == "SIGNATURE_TYPE_DELTA_BLOB":
                break

        delta_blob = signature.value
        ptr = 0
        unknown1, unknown2 = struct.unpack("II", delta_blob[ptr : ptr + 8])
        ptr += 8
        results: List[bytes] = []

        from rich.progress import Progress

        with Progress() as progress:
            task = progress.add_task("Applying delta...", total=len(delta_blob))
            while ptr < len(delta_blob):
                info = struct.unpack("H", delta_blob[ptr : ptr + 2])[0]
                ptr += 2
                if info & 0x80 == 0x80:
                    # append from base
                    size = info & 0x7FFF
                    base_offset = struct.unpack(">I", delta_blob[ptr : ptr + 4])[0]
                    ptr += 4
                    # size = (info & 0x7FFF) + 6
                    results.append(base_data[base_offset : base_offset + size])
                else:
                    # append from delta
                    results.append(delta_blob[ptr : ptr + info])
                    ptr += info

                progress.update(task, completed=ptr)
        return b"".join(results)

    def get_file_info(self):
        try:
            with exiftool.ExifToolHelper() as ef:
                metadata = ef.get_tags(self.vdm_path, tags=None)[0]
                return metadata["EXE:OriginalFileName"], metadata["EXE:ProductVersion"]
        except:
            filename = path.basename(self.vdm_path)
            return filename, ""

    def parse_signature(self, db: bytes, offset: int):
        sig_type = db[offset]
        size_low = db[offset + 1]
        size_high = struct.unpack("<H", db[offset + 2 : offset + 4])[0]

        offset += 4
        size = size_low | size_high << 8
        if size == 0xFFFFFF:
            raise ValueError("bleh")

        value = db[offset : offset + size]
        offset += size

        signature = SIG_TYPES[sig_type] if sig_type in SIG_TYPES else None
        if not signature:
            return None, offset
        if signature == "SIGNATURE_TYPE_THREAT_BEGIN":
            return Threat(sig_type, signature, value), offset
        if signature == "SIGNATURE_TYPE_THREAT_END":
            return EndOfThreat(sig_type, signature, value), offset
        if signature.find("HSTR") > -1:
            return SignatureHSTR(value, sig_type, signature), offset
        if signature == "SIGNATURE_TYPE_FILEPATH":
            return SignatureFilePath(signature, value), offset
        if signature == "SIGNATURE_TYPE_FILENAME":
            return SignatureFilename(signature, value), offset
        if signature == "SIGNATURE_TYPE_STATIC":
            return SignatureStatic(sig_type, signature, value), offset
        if signature == "SIGNATURE_TYPE_DEFAULTS":
            return SignatureDefaults(sig_type, signature, value), offset
        if signature == "SIGNATURE_TYPE_CLEANSCRIPT":
            return SignatureCleanScript(sig_type, signature, value), offset
        if signature == "SIGNATURE_TYPE_LUASTANDALONE":
            return SignatureLuaStandalone(sig_type, signature, value), offset
        if signature == "SIGNATURE_TYPE_NID":
            return SignatureIP(sig_type, signature, value), offset
        if signature == "SIGNATURE_TYPE_EXPLICITRESOURCE":
            return SignatureExplicitResource(sig_type, signature, value), offset
        return BaseSignature(sig_type, signature, value), offset
