import binascii
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


class BaseSignature:
    def __init__(self, type_value: int, type_name: str, value: bytes) -> None:
        self.type_value = type_value
        self.type_name = type_name
        self.value = value

    def __str__(self) -> str:
        return f"0x{self.type_value:02x}: {self.type_name}"

    def __repr__(self) -> str:
        return self.__str__()


class Threat(BaseSignature):
    def __init__(self, type_value: int, type_name: str, value: bytes) -> None:
        super().__init__(type_value, type_name, value)
        self.threat_id, self.threat_name = self._parse_threat_header(value)
        self.threat_name = self.threat_name
        self.signatures: list[BaseSignature] = []
        self.category = (
            self.threat_name.split("/")[0] if "/" in self.threat_name else "Generic"
        )

    def __str__(self) -> str:
        return f"id: {self.threat_id} - name: {self.threat_name} - category: {self.category}"

    def __repr__(self) -> str:
        return self.__str__()

    def _parse_threat_header(self, data: bytes):
        """
        typedef struct _STRUCT_SIG_TYPE_THREAT_BEGIN {

            UINT32 ui32SignatureId;
            BYTE   unknownBytes1[6];
            UINT8  ui8SizeThreatName;
            BYTE   unknownBytes2[2];
            CHAR   lpszThreatName[ui8SizeThreatName];
            BYTE   unknownBytes3[9];
        } STRUCT_SIG_TYPE_THREAT_BEGIN,* PSTRUCT_SIG_TYPE_THREAT_BEGIN;
        """
        signature_id = int.from_bytes(data[0:4], "little")
        unknown = data[4:10]
        threat_name_size = data[10]
        unknown2 = data[11]
        if data[12] == 0xAF or data[12] == 0xAC or data[12] == 0x84:
            start = 13
        else:
            start = 12
        title_data = data[start : start + threat_name_size]
        threat_name = title_data.decode("utf-8", "ignore")
        return signature_id, threat_name


class EndOfThreat(BaseSignature):
    def __init__(self, type_value: int, type_name: str, value: bytes) -> None:
        super().__init__(type_value, type_name, value)
        self.threat_id = int.from_bytes(value, "little")


class SignatureStatic(BaseSignature):
    def __init__(self, type_value: int, type_name: str, value: bytes) -> None:
        super().__init__(type_value, type_name, value)

    def __str__(self) -> str:
        return (
            super().__str__()
            + "\ndetection bytes: "
            + binascii.hexlify(self.value, sep=" ").decode("utf-8")
        )


class SignatureFilePath(BaseSignature):

    def __init__(self, rule_type: str, rule_data: bytes) -> None:
        super().__init__(95, "SIGNATURE_TYPE_FILEPATH", rule_data)
        self.rule_type = rule_type
        self.path = _decode_str(rule_data)

    def __str__(self) -> str:
        return super().__str__() + "\nfilepath: " + self.path


class SignatureFilename(BaseSignature):

    def __init__(self, rule_type: str, rule_data: bytes) -> None:
        super().__init__(94, "SIGNATURE_TYPE_FILENAME", rule_data)
        self.rule_type = rule_type
        self.filename = _decode_str(rule_data)

    def __str__(self) -> str:
        return super().__str__() + "\nfilename: " + self.filename


class SignatureDefaults(BaseSignature):
    def __init__(self, type_value: int, type_name: str, value: bytes) -> None:
        super().__init__(type_value, type_name, value)

    def __str__(self) -> str:
        return super().__str__() + "\ndefaults: " + _decode_str(self.value)


class SignatureCleanScript(BaseSignature):
    def __init__(self, type_value: int, type_name: str, value: bytes) -> None:
        super().__init__(type_value, type_name, value)

    def __str__(self) -> str:
        return super().__str__() + "\nscript: " + _decode_str(self.value)


class SignatureHSTR(BaseSignature):

    def __init__(
        self,
        rule_data: bytes,
        signature_type: int,
        signature_name: str,
    ) -> None:
        super().__init__(signature_type, signature_name, rule_data)
        self.detection_threshold, self.rules = self._parse_hstr_rule_ext(rule_data)

    def __str__(self) -> str:
        pretty = super().__str__()
        pretty += f"\ndetection_threshold: {self.detection_threshold} - rule_count: {len(self.rules)}\nrules:\n"
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
            
            for PEHSTR, the rule structure is almost the same - except for ui8CodeUnknown            
            """
            try:
                rule_weight = data[offset] | (data[offset + 1] << 8)
                rule_size = data[offset + 2]
                unknown = data[offset + 3]
                padding = 0
                if unknown == 0x81:
                    padding = 1

                if self.type_name.endswith("_EXT"):
                    rule_data = data[
                        offset + 3 + padding : offset + 3 + padding + rule_size
                    ]
                    offset += len(rule_data) + 4 + padding
                else:
                    rule_data = data[offset + 2 : offset + 2 + rule_size]
                    offset += len(rule_data) + 3

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


def _decode_str(data: bytes) -> str:
    encoding = chardet.detect(data)
    encoding = encoding["encoding"] if encoding["encoding"] else "ascii"
    return data.decode(encoding, "replace")


def parse_signature(data_reader: BufferedReader):
    sig_type = int.from_bytes(data_reader.read(1), "little")
    size_low = int.from_bytes(data_reader.read(1), "little")
    size_high = int.from_bytes(data_reader.read(2), "little")
    size = size_low | size_high << 8
    value = data_reader.read(size)

    signature = SIG_TYPES[sig_type] if sig_type in SIG_TYPES else None
    if not signature:
        return None
    if signature == "SIGNATURE_TYPE_THREAT_BEGIN":
        return Threat(sig_type, signature, value)
    if signature == "SIGNATURE_TYPE_THREAT_END":
        return EndOfThreat(sig_type, signature, value)
    if signature.find("HSTR") > -1:
        return SignatureHSTR(value, sig_type, signature)
    if signature == "SIGNATURE_TYPE_FILEPATH":
        return SignatureFilePath(signature, value)
    if signature == "SIGNATURE_TYPE_FILENAME":
        return SignatureFilename(signature, value)
    if signature == "SIGNATURE_TYPE_STATIC":
        return SignatureStatic(sig_type, signature, value)
    if signature == "SIGNATURE_TYPE_DEFAULTS":
        return SignatureDefaults(sig_type, signature, value)
    if signature == "SIGNATURE_TYPE_CLEANSCRIPT":
        return SignatureCleanScript(sig_type, signature, value)
    return BaseSignature(sig_type, signature, value)
