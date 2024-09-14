import os
import sys
import pprint
from solan.rules import (
    EndOfThreat,
    Threat,
    parse_signature,
)
from solan.ui import renderThreats
from solan.vdm import extract_vdm
from rich.progress import Progress

threats: list[Threat] = []


def main():
    f = extract_vdm(sys.argv[1])
    try:
        db_size = f.seek(0, os.SEEK_END)
        f.seek(0)
        threat: Threat = None
        with Progress() as progress:
            task = progress.add_task("Loading signatures...", total=db_size)
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

                progress.update(task, completed=f.tell())

    except Exception as err:
        pprint.pprint(err)
    finally:
        f.close()
        os.unlink(f.name)

    signature_count = sum([len(s.signatures) for s in threats])
    print(f"Loaded {len(threats)} threats with {signature_count} signatures.")

    cmd = None
    while cmd != "q":
        cmd = input("> ")
        cmd_params = cmd.split(" ")
        if cmd == "categories":
            pprint.pprint({t.category for t in threats})
        elif cmd_params[0] == "list":
            what = cmd_params[1]
            if what == "all":
                for threat in threats:
                    pprint.pprint(threat)
            else:
                renderThreats([t for t in threats if t.category == what])
        elif cmd_params[0] == "get":
            id = int(cmd_params[1])
            for threat in threats:
                if threat.threat_id == id:
                    pprint.pprint(threat)
                    pprint.pprint(threat.signatures)
                    break
        elif cmd_params[0] == "find":
            results = [
                threat
                for threat in threats
                if threat.threat_name.lower().find(cmd_params[1].lower()) > -1
            ]
            for threat in results:
                pprint.pprint(threat)

if __name__ == "__main__":
    main()
