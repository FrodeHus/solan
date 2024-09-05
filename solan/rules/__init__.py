from io import BufferedReader
import string
from enum import Enum

import chardet

from solan import SIG_TYPES


class WildcardType(Enum):
    MatchExactByteCount = 1
    MatchUpToByteCount = 2
    MatchEitherByteCount = 3
    RegexMatchExactCount = 4
    RegexMatchUpToCount = 5


class Threat:

    def __init__(self, header: bytes) -> None:
        self.threat_id, self.threat_name = self._parse_threat_header(header)
        self.threat_name = self.threat_name.decode("unicode_escape")
        self.hstr_rules = None
        self.filenames = []
        self.filepaths = []

    def __str__(self) -> str:
        return f"{self.threat_id} - {self.threat_name}"

    def _parse_threat_header(self, data: bytes):
        signature_id = int.from_bytes(data[0:3], "little")
        unknown = data[4:9]
        threat_name_size = data[10]
        unknown2 = data[11:12]
        threat_name = data[13 : 13 + threat_name_size]
        return signature_id, threat_name


class FilePath_Rule:

    def __init__(self, rule_type: str, rule_data: bytes) -> None:
        self.rule_type = rule_type
        # self.path = rule_data.decode("utf-8")

    def __str__(self) -> str:
        return self.path


class Filename_Rule:

    def __init__(self, rule_type: str, rule_data: bytes) -> None:
        self.rule_type = rule_type
        # self.filename = rule_data.decode("utf-8")

    def __str__(self) -> str:
        return self.filename


class RuleSegment:
    def __init__(
        self,
        segment_index: int = None,
        segment_length: int = None,
        detection_bytes: bytes = None,
        regex: str = None,
        byte_count1: int = None,
        byte_count2: int = None,
        wildcard_type: WildcardType = None,
    ) -> None:
        self.detection_bytes: bytes = detection_bytes
        self.regex: str = regex.decode("utf-8") if regex else None
        self.byte_count1: int = byte_count1
        self.byte_count2: int = byte_count2
        self.wildcard_type: WildcardType = wildcard_type
        self.segment_index: int = segment_index
        self.segment_length: int = (
            len(detection_bytes) if detection_bytes else segment_length
        )

    def __str__(self) -> str:
        if self.wildcard_type == WildcardType.MatchExactByteCount:
            return f"([\w]{{{self.byte_count1}}})"
        if self.wildcard_type == WildcardType.MatchUpToByteCount:
            return f"([\w]{{0,{self.byte_count1}}})"
        if self.wildcard_type == WildcardType.RegexMatchExactCount:
            return f"([{self.regex}]{{{self.byte_count1}}})"
        if self.wildcard_type == WildcardType.RegexMatchUpToCount:
            return f"([{self.regex}]{{0,{self.byte_count1}}})"
        return "(TODO)"


class HSTR_Rule:

    def __init__(self, rule_type: str, rule_data: bytes, threat: Threat) -> None:
        self.rule_type = rule_type
        self.threat = threat
        self.detection_threshold, self.rules = self._parse_hstr_rule_ext(rule_data)

    def __str__(self) -> str:
        pretty = f"type: {self.rule_type} - detection_threshold: {self.detection_threshold} - rule_count: {len(self.rules)}\nrules:\n"
        for rule in self.rules:
            pretty += " " + rule.__str__() + "\n"
        return pretty

    def __repr__(self) -> str:
        return self.__str__()

    def _parse_hstr_rule_ext(self, data: bytes):
        """
        typedef struct _STRUCT_PEHSTR_HEADER {
          UINT16  ui16Unknown;
          UINT8   ui8ThresholdRequiredLow;
          UINT8   ui8ThresholdRequiredHigh;
          UINT8   ui8SubRulesNumberLow;
          UINT8   ui8SubRulesNumberHigh;
          BYTE    bEmpty;
          BYTE    pbRuleData[];
        } STRUCT_PEHSTR_HEADER, * PSTRUCT_PEHSTR_HEADER;
        """
        unknown_bytes = data[0:2]
        detection_threshold = data[2] | (data[3] << 8)
        sub_rules_count = data[4] | (data[5] << 8)
        empty = data[6]
        offset = 7
        rule_index = 0
        rules = []
        while rule_index < sub_rules_count:
            """
            typedef struct _STRUCT_RULE_PEHSTR_EXT {
                UINT8  ui8SubRuleWeightLow;
                UINT8  ui8SubRuleWeightHigh;
                UINT8  ui8SubRuleSize;
                UINT8  ui8CodeUnknown;
                BYTE   pbSubRuleBytesToMatch[];
            } STRUCT_RULE_PEHSTR_EXT, *PSTRUCT_RULE_PEHSTR_EXT;
            """
            try:
                rule_weight = data[offset] | (data[offset + 1] << 8)
                rule_size = data[offset + 2]
                rule_data = data[offset + 3 : offset + 4 + rule_size]
                offset += rule_size + 4
                rule_segments = self._get_rule_segments(rule_data)
                rule = Rule(rule_segments, rule_weight, rule_data)
                rules.append(rule)
            except Exception as err:
                # print(err)
                pass
            finally:
                rule_index += 1
        return detection_threshold, rules

    def _generate_yara_rule(self):
        pass

    def _parse_wildcard(self, rule_data: bytes, offset: int = 0):
        last_found = -1
        # match exactly X number of bytes
        wildcard_index = rule_data.find(b"\x90\x01", offset)
        if wildcard_index > -1:
            byte_match_count = rule_data[wildcard_index + 2]
            last_found = wildcard_index
            yield RuleSegment(
                segment_index=wildcard_index,
                segment_length=3,
                wildcard_type=WildcardType.MatchExactByteCount,
                byte_count1=byte_match_count,
            )

        # match up to X number of bytes
        wildcard_index = rule_data.find(b"\x90\x02", offset)
        if wildcard_index > -1:
            last_found = wildcard_index
            byte_match_count = rule_data[wildcard_index + 2]
            yield RuleSegment(
                segment_index=wildcard_index,
                segment_length=3,
                wildcard_type=WildcardType.MatchUpToByteCount,
                byte_count1=byte_match_count,
            )

        # match either X or Y number of bytes
        wildcard_index = rule_data.find(b"\x90\x03", offset)
        if wildcard_index > -1:
            last_found = wildcard_index
            byte_match_count = rule_data[wildcard_index + 2]
            byte_match_count2 = rule_data[wildcard_index + 3]
            yield RuleSegment(
                segment_index=wildcard_index,
                segment_length=4,
                wildcard_type=WildcardType.MatchEitherByteCount,
                byte_count1=byte_match_count,
                byte_count2=byte_match_count2,
            )

        # match exactly X number of bytes with Y length regex pattern following
        wildcard_index = rule_data.find(b"\x90\x04", offset)
        if wildcard_index > -1:
            last_found = wildcard_index
            byte_match_count = rule_data[wildcard_index + 2]
            regex_size = rule_data[wildcard_index + 3]
            regex = rule_data[wildcard_index + 4 : wildcard_index + 4 + regex_size]
            yield RuleSegment(
                segment_index=wildcard_index,
                segment_length=3 + regex_size,
                wildcard_type=WildcardType.RegexMatchExactCount,
                byte_count1=byte_match_count,
                regex=regex,
            )

            # match up to X number of bytes with Y length regex pattern follow
        wildcard_index = rule_data.find(b"\x90\x05", offset)
        if wildcard_index > -1:
            last_found = wildcard_index
            byte_match_count = rule_data[wildcard_index + 2]
            regex_size = rule_data[wildcard_index + 3]
            regex = rule_data[wildcard_index + 4 : wildcard_index + 4 + regex_size]
            yield RuleSegment(
                segment_index=wildcard_index,
                segment_length=3 + regex_size,
                wildcard_type=WildcardType.RegexMatchUpToCount,
                byte_count1=byte_match_count,
                regex=regex,
            )

        if last_found > -1:
            yield from self._parse_wildcard(rule_data, last_found + 1)

    def _get_rule_segments(self, rule_data: bytes):
        segments: list[RuleSegment] = []
        wildcards = list(self._parse_wildcard(rule_data))

        if wildcards:
            data = bytearray()
            offset = 0
            for wildcard in wildcards:
                segments.append(
                    RuleSegment(
                        segment_index=offset,
                        detection_bytes=rule_data[offset : wildcard.segment_index],
                    )
                )
                segments.append(wildcard)
                offset = wildcard.segment_index + wildcard.segment_length + 1
            segments.append(
                RuleSegment(
                    segment_index=offset,
                    detection_bytes=rule_data[offset:],
                )
            )
        else:
            segments.append(RuleSegment(segment_index=0, detection_bytes=rule_data))

        return segments


class Rule:
    def __init__(
        self, segments: list[RuleSegment], weight: int, raw_bytes: bytes
    ) -> None:
        self.segments = segments
        self.weight = weight
        self.raw_bytes = raw_bytes

    def __str__(self) -> str:
        return f"weight: {self.weight} rule: {_convert_to_printable(self.segments)}"

    def __repr__(self) -> str:
        return self.__str__()


def _convert_to_printable(segments: list[RuleSegment] = None):

    data = bytearray()
    for segment in segments:
        try:
            if segment.wildcard_type:
                data += segment.__str__().encode()
            else:
                data += segment.detection_bytes
        except:
            pass
    printables = string.ascii_letters + string.digits + string.punctuation + " "

    data = data.replace(b"\x00", b"")
    encoding = chardet.detect(data)
    encoding = encoding["encoding"] if encoding["encoding"] else "unicode_escape"
    return "".join(
        c if c in printables else r"\x{0:02x}".format(ord(c))
        for c in data.decode(encoding, "replace")
    )


def parse_signature(data_reader: BufferedReader, threat: Threat = None):
    sig_type = int.from_bytes(data_reader.read(1), "little")
    size_low = int.from_bytes(data_reader.read(1), "little")
    size_high = int.from_bytes(data_reader.read(2), "little")
    size = size_low | size_high << 8
    value = data_reader.read(size)

    signature = SIG_TYPES[sig_type] if sig_type in SIG_TYPES else None
    if not signature:
        return None
    if signature == "SIGNATURE_TYPE_THREAT_END":
        return None
    if signature.endswith("HSTR_EXT"):
        return HSTR_Rule(signature, value, threat)
    if signature == "SIGNATURE_TYPE_FILEPATH":
        return FilePath_Rule(signature, value)
    if signature == "SIGNATURE_TYPE_FILENAME":
        return Filename_Rule(signature, value)
    if signature == "SIGNATURE_TYPE_NSCRIPT_SP":
        # jscript
        pass
    if signature == "SIGNATURE_TYPE_FRIENDLYFILE_SHA256":
        print(str(value))
        pass
    if signature == "SIGNATURE_TYPE_DBVAR":
        print("MpEngine config")
        pass
    if signature == "SIGNATURE_TYPE_THREAT_BEGIN":
        return Threat(value)
