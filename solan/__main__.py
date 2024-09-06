import os
import sys
import pprint
from solan.rules import (
    EndOfThreat,
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
        threat: Threat = None
        while f.tell() < db_size:
            signature = parse_signature(f)
            if type(signature) is Threat:
                threat = signature
                threats.append(threat)
            elif type(signature) is EndOfThreat:
                if signature.threat_id != threat.threat_id:
                    print(
                        f"End of threat definition detected, but didnt match active threat: {threat.threat_id} != {signature.threat_id}"
                    )
                    exit(1)
            elif threat and signature:
                threat.signatures.append(signature)

    except Exception as err:
        pprint.pprint(err)
    finally:
        f.close()
        os.unlink(f.name)

    signature_count = sum([len(s.signatures) for s in threats])
    print(f"Loaded {len(threats)} threats with {signature_count} signatures.")
    test_threats = [
        threat for threat in threats if threat.threat_name.find("AmsiBypass") > -1
    ]

    for threat in test_threats:
        pprint.pprint(threat)
        pprint.pprint(threat.signatures)


if __name__ == "__main__":
    main()
