from typing import List
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
        matched_detection_rule_uuids (List[str]): The list of detection rule UUIDs that contained a detector that
            triggered a match.
        matched_detection_rules (List[str]): The list of inline detection rules that contained a detector that triggered
            a match.
    """
    finding: str
    redacted_finding: str
    before_context: str
    after_context: str
    detector_name: str
    detector_uuid: str
    confidence: Confidence
    byte_range: Range
    codepoint_range: Range
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
            resp["matchedDetectionRuleUUIDs"],
            resp["matchedDetectionRules"]
        )
