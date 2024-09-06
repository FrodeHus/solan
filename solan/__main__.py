import os
import sys
import pprint
from solan.rules import (
    Threat,
    parse_signature,
)
from solan.vdm import extract_vdm

threats: list[Threat] = []

def main():
    f = extract_vdm(sys.argv[1])
    try:
        db_size = f.seek(0, os.SEEK_END)
        f.seek(0)
        threat : Threat = None
        while(f.tell() < db_size):
            signature = parse_signature(f)
            if type(signature) is Threat:
                threat = signature
                # print(threat)
                threats.append(threat)

            elif threat and signature:
                threat.signatures.append(signature)

    except Exception as err:
        pprint.pprint(err)
    finally:
        f.close()
        os.unlink(f.name)

    signature_count = sum([len(s.signatures) for s in threats])
    print(f"Loaded {len(threats)} threats with {signature_count} signatures.")
    eicar = [
        threat
        for threat in threats
        if threat.threat_name.lower().find("amsibypass") > -1
    ]

    for threat in eicar:
        pprint.pprint(threat)
        pprint.pprint(threat.signatures)

if __name__ == "__main__":
    main()
