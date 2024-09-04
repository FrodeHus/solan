
import os
import sys

from solan.rules import FilePath_Rule, Filename_Rule, HSTR_Rule, Threat, parse_signature
from solan.vdm import extract_vdm


def main():
    extracted = extract_vdm(sys.argv[1])
    with extracted as f:
        db_size = f.seek(0, os.SEEK_END)
        f.seek(0)
        threat : Threat = None
        while(f.tell() < db_size):
            signature = parse_signature(f)
            if type(signature) is Threat:
                threat = signature
                print(threat)
            elif type(signature) is HSTR_Rule:
                threat.hstr_rules = signature.rules
                print(threat.hstr_rules)
            elif type(signature) is FilePath_Rule:
                threat.filepaths.append(signature)
            elif type(signature) is Filename_Rule:
                threat.filenames.append(signature) 
                
if __name__ == "__main__":
    main()