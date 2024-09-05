import os
import sys
import pprint
from solan.rules import FilePath_Rule, Filename_Rule, HSTR_Rule, Threat, parse_signature
from solan.vdm import extract_vdm


def main():
    f = extract_vdm(sys.argv[1])
    try:
        db_size = f.seek(0, os.SEEK_END)
        f.seek(0)
        threat : Threat = None
        while(f.tell() < db_size):
            signature = parse_signature(f, threat)
            if type(signature) is Threat:
                threat = signature
                # print(threat)
            elif type(signature) is HSTR_Rule:
                threat.hstr_rules = signature
                if signature.rule_type == "SIGNATURE_TYPE_CMDHSTR_EXT":
                    print(threat)
                    pprint.pprint(threat.hstr_rules)
                    print("-------------------------------------------------------")
            elif type(signature) is FilePath_Rule:
                threat.filepaths.append(signature)
            elif type(signature) is Filename_Rule:
                threat.filenames.append(signature) 
    except Exception as err:
        pprint.pprint(err)
    finally:
        f.close()
        os.unlink(f.name)

if __name__ == "__main__":
    main()
