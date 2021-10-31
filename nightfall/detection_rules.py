from nightfall.exceptions import NightfallUserError


class DetectionRule:
    def __init__(self, detectors: list, logical_op: str = "ANY"):
        self.detectors = detectors
        self.logical_op = logical_op

    def as_dict(self):
        return {"detectors": [d.as_dict() for d in self.detectors], "logicalOp": self.logical_op}


class Regex:
    def __init__(self, pattern: str, is_case_sensitive: bool):
        self.pattern = pattern
        self.is_case_sensitive = is_case_sensitive

    def as_dict(self):
        return {"pattern": self.pattern, "isCaseSensitive": self.is_case_sensitive}


class WordList:
    def __init__(self, word_list: list[str], is_case_sensitive: bool):
        self.word_list = word_list
        self.is_case_sensitive = is_case_sensitive

    def as_dict(self):
        return {"wordList": self.word_list, "isCaseSensitive": self.is_case_sensitive}


class ContextRule:
    def __init__(self, regex: Regex, window_before: int, window_after: int, fixed_confidence: str):
        self.regex = regex
        self.window_before = window_before
        self.window_after = window_after
        self.fixed_confidence = fixed_confidence

    def as_dict(self):
        return {
            "regex": self.regex,
            "proximity": {"windowBefore": self.window_before, "windowAfter": self.window_after},
            "confidenceAdjustment": {"fixedConfidence": self.fixed_confidence}
        }


class ExclusionRule:
    def __init__(self, match_type: str, regex: Regex = None, word_list: WordList = None):
        if (not regex and not word_list) or (regex and word_list):
            raise NightfallUserError("need either regex or word_list to build an ExclusionRule")
        self.match_type = match_type
        self.regex = regex
        self.word_list = word_list

    def as_dict(self):
        result = {"matchType": self.match_type}
        if self.regex:
            result["regex"] = self.regex.as_dict()
        if self.word_list:
            result["wordList"] = self.word_list.as_dict()
        return result


class MaskConfig:
    def __init__(self, masking_char: chr, num_chars_to_leave_unmasked: int = 0,
                 mask_right_to_left: bool = False, chars_to_ignore: list[chr] = []):
        self.masking_char = masking_char
        self.num_chars_to_leave_unmasked = num_chars_to_leave_unmasked
        self.mask_right_to_left = mask_right_to_left
        self.chars_to_ignore = chars_to_ignore

    def as_dict(self):
        return {
            "maskingChar": self.masking_char,
            "numCharsToLeaveUnmasked": self.num_chars_to_leave_unmasked,
            "maskRightToLeft": self.mask_right_to_left,
            "charsToIgnore": self.chars_to_ignore
        }


class RedactionConfig:
    def __init__(
            self,
            remove_finding: bool,
            mask_config: MaskConfig = None,
            substitution_phrase: str = None,
            public_key: str = None
    ):
        if [mask_config, substitution_phrase, public_key].count(None) != 2:
            raise NightfallUserError("need one of mask_config, substitution_phrase, or public_key")

        self.remove_finding = remove_finding
        self.mask_config = mask_config
        self.substitution_phrase = substitution_phrase
        self.public_key = public_key

    def as_dict(self):
        result = {"removeFinding": self.remove_finding}
        if self.mask_config:
            result["maskConfig"] = self.mask_config.as_dict()
        if self.substitution_phrase:
            result["substitutionConfig"] = {"substitutionPhrase": self.substitution_phrase}
        if self.public_key:
            result["cryptoConfig"] = {"publicKey": self.public_key}
        return result


class Detector:
    def __init__(
            self,
            min_confidence: str,
            min_num_findings: int,
            nightfall_detector: str = None,
            regex: Regex = None,
            word_list: WordList = None,
            uuid: str = None,
            display_name: str = None,
            context_rules: list[ContextRule] = None,
            redaction_config: RedactionConfig = None
    ):
        if [nightfall_detector, regex, word_list, uuid].count(None) != 3:
            raise NightfallUserError("need one of nightfall_detector, regex, word_list, or uuid")

        self.min_confidence = min_confidence
        self.min_num_findings = min_num_findings
        self.nightfall_detector = nightfall_detector
        self.regex = regex
        self.word_list = word_list
        self.uuid = uuid
        self.display_name = display_name
        self.context_rules = context_rules
        self.redaction_config = redaction_config

    def as_dict(self):
        result = {"minConfidence": self.min_confidence, "minNumFindings": self.min_num_findings}
        if self.nightfall_detector:
            result["nightfallDetector"] = self.nightfall_detector
            result["detectorType"] = "NIGHTFALL_DETECTOR"
        if self.regex:
            result["regex"] = self.regex.as_dict()
            result["detectorType"] = "REGEX"
        if self.word_list:
            result["wordList"] = self.word_list.as_dict()
            result["detectorType"] = "WORD_LIST"
        if self.uuid:
            result["uuid"] = self.uuid
        if self.display_name:
            result["displayName"] = self.display_name
        if self.context_rules:
            result["contextRules"] = [c.as_dict() for c in self.context_rules]
        if self.redaction_config:
            result["redactionConfig"] = self.redaction_config.as_dict()
        return result
