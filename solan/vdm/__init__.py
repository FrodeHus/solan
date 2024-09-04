import sys
import zlib
import struct
import tempfile

def extract_vdm(vdm_path : str):
    # Get VDM data
    data = open(vdm_path, "rb").read()
    # Look for the resource signature
    base = data.index(b"RMDX")
    # Extract relevant information
    offset, size = struct.unpack("II", data[base + 0x18: base + 0x20])
    # Decompress the data
    x = zlib.decompress(data[base + offset + 8:], -15)
    # Ensure correctness
    assert len(x) == size
    # Dumps the output
    
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(x)
    
    return tmp