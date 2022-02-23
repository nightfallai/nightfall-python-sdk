from typing import List, Optional, Any
from dataclasses import dataclass

from nightfall.detection_rules import Confidence


@dataclass
class Range:
    """An object representing where a finding was discovered in content.
    :param start: The start of the range.
    :type start: int
    :param end: The end of the range.
    :type end: int
    """
    start: int
    end: int


@dataclass
class Finding:
    """An object representing an occurrence of a configured detector (i.e. finding) in the provided data.
    Attributes:
        finding (str): The data that triggered a detector match.
        redacted_finding (str): The redacted finding if redaction was configured, None otherwise.
        before_context (str): The data that immediately preceded the finding if configured, None otherwise.
        after_context (str): The data that immediately succeeded the finding if configured, None otherwise.
        detector_name (str): The the name of the detector, if configured, None otherwise.
        detector_uuid (str): The ID that uniquely identifies this detector.
        confidence (Confidence): The confidence that the data contained in Finding is an instance of the matched
            detector.
        byte_range (Range): The byte range in which a finding was detected within the item.
        codepoint_range (Range): The codepoint range in which a finding was detected within the item. This differs
            from byte range since a codepoint may contain multiple bytes.
        row_range (Range): The row in which a finding was detected, if it was in a tabular document. Index starts at 1.
        column_range (Range): The column(s) in which a finding was detected, if it was in a tabular document. Index starts at 1.
        commit_hash (str): The hash of the commit in which the finding was detected, if known.
        matched_detection_rule_uuids (List[str]): The list of detection rule UUIDs that contained a detector that
            triggered a match.
        matched_detection_rules (List[str]): The list of inline detection rules that contained a detector that triggered
            a match.
    """
    finding: str
    redacted_finding: Optional[str]
    before_context: Optional[str]
    after_context: Optional[str]
    detector_name: Optional[str]
    detector_uuid: str
    confidence: Confidence
    byte_range: Range
    codepoint_range: Range
    row_range: Optional[Range]
    column_range: Optional[Range]
    commit_hash: str
    matched_detection_rule_uuids: List[str]
    matched_detection_rules: List[str]

    @classmethod
    def from_dict(cls, resp: dict) -> "Finding":
        return cls(
            resp["finding"],
            resp.get("redactedFinding"),
            resp.get("beforeContext"),
            resp.get("afterContext"),
            resp["detector"].get("name"),
            resp["detector"].get("uuid"),
            Confidence[resp["confidence"]],
            Range(resp["location"]["byteRange"]["start"], resp["location"]["byteRange"]["end"]),
            Range(resp["location"]["codepointRange"]["start"], resp["location"]["codepointRange"]["end"]),
            _range_or_none(resp["location"]["rowRange"]),
            _range_or_none(resp["location"]["columnRange"]),
            resp["location"].get("commitHash", ""),
            resp["matchedDetectionRuleUUIDs"],
            resp["matchedDetectionRules"]
        )

def _range_or_none(range_or_none: Any) -> Optional[Range]:
    """Some ranges are not always present, this function returns either None or a Range."""
    if range_or_none is None:
        return None
    start = range_or_none["start"]
    end = range_or_none["end"]
    return Range(start, end)

