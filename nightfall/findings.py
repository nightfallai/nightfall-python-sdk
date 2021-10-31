from nightfall.detection_rules import Confidence


class Range:
    """An object representing where a finding was discovered in content."""
    def __init__(self, start: int, end: int):
        """Instantiate a Range object.
        :param start: The start of the range.
        :type start: int
        :param end: The end of the range.
        :type end: int
        """
        self.start = start
        self.end = end


class Finding:
    """An object representing an occurrence of a configured detector (i.e. finding) in the provided data."""
    def __init__(self,
                 finding: str,
                 redacted_finding: str,
                 before_context: str,
                 after_context: str,
                 detector_name: str,
                 detector_uuid: str,
                 confidence: Confidence,
                 byte_range: Range,
                 codepoint_range: Range,
                 matched_detection_rule_uuids: list[str],
                 matched_detection_rules: list[str]):
        """Instantiate a Finding object.
        :param finding: The data that triggered a detector match.

        :type finding: str
        :param redacted_finding: The redacted finding if redaction was configured, None otherwise.
        :type redacted_finding: str
        :param before_context: The data that immediately preceded the finding if configured, None otherwise.
        :type before_context: str
        :param after_context: The data that immediately succeeded the finding if configured, None otherwise.
        :type after_context: str
        :param detector_name: The the name of the detector, if configured, None otherwise.
        :type detector_name: str
        :param detector_uuid: The ID that uniquely identifies this detector.
        :type detector_uuid: str
        :param confidence: The confidence that the data contained in Finding is an instance of the matched detector.
        :type confidence: Confidence
        :param byte_range: The byte range in which a finding was detected within the item.
        :type byte_range: Range
        :param codepoint_range: The codepoint range in which a finding was detected within the item. This differs
            from byte range since a codepoint may contain multiple bytes.
        :type codepoint_range: Range
        :param matched_detection_rule_uuids: The list of detection rule UUIDs that contained a detector that triggered a
            match.
        :type matched_detection_rule_uuids: list[str]
        :param matched_detection_rules: The list of inline detection rules that contained a detector that triggered a
            match.
        :type matched_detection_rules: list[str]
        """
        self.finding = finding
        self.redacted_finding = redacted_finding
        self.before_context = before_context
        self.after_context = after_context
        self.detector_name = detector_name
        self.detector_uuid = detector_uuid
        self.confidence = confidence
        self.byte_range = byte_range
        self.codepoint_range = codepoint_range
        self.matched_detection_rule_uuids = matched_detection_rule_uuids
        self.matched_detection_rules = matched_detection_rules

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
