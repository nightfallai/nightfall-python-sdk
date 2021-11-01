from enum import Enum
from typing import List

from nightfall.exceptions import NightfallUserError


class Regex:
    """A RE2 regular expression and config for use with Nightfall"""
    def __init__(self, pattern: str, is_case_sensitive: bool):
        """Instantiate a Regex object
        :param pattern: The RE2 pattern to use.
        :type pattern: str
        :param is_case_sensitive: Whether to make matches have the same case as the expression given
        :type is_case_sensitive: bool
        """
        self.pattern = pattern
        self.is_case_sensitive = is_case_sensitive

    def as_dict(self):
        return {"pattern": self.pattern, "isCaseSensitive": self.is_case_sensitive}


class WordList:
    """A list of words that can be used to customize the behavior of a detector while Nightfall performs a scan."""
    def __init__(self, word_list: List[str], is_case_sensitive: bool):
        """Instantiate a WordList object
        :param word_list: The list of words to use.
        :type word_list: List[str]
        :param is_case_sensitive: Whether to make matches have the same case as each word given
        :type is_case_sensitive: bool
        """
        self.word_list = word_list
        self.is_case_sensitive = is_case_sensitive

    def as_dict(self):
        return {"wordList": self.word_list, "isCaseSensitive": self.is_case_sensitive}


class Confidence(Enum):
    """Confidence describes the certainty that a piece of content matches a detector."""
    VERY_UNLIKELY = "VERY_UNLIKELY"
    UNLIKELY = "UNLIKELY"
    POSSIBLE = "POSSIBLE"
    LIKELY = "LIKELY"
    VERY_LIKELY = "VERY_LIKELY"


class ContextRule:
    """An object that describes how a regular expression may be used to adjust the confidence of a candidate finding.
    This context rule will be applied within the provided byte proximity, and if the regular expression matches, then
    the confidence associated with the finding will be adjusted to the value prescribed.
    """
    def __init__(self, regex: Regex, window_before: int, window_after: int, fixed_confidence: Confidence):
        """Instantiate a ContextRule object
        :param regex: The regular expression configuration to run within the context of a candidate finding.
        :type regex: Regex
        :param window_before: The number of leading characters to consider as context.
        :type window_before: int
        :param window_after: The number of trailing characters to consider as context.
        :type window_after: int
        :param fixed_confidence: How to adjust the result of the match if the context rule matches.
        :type fixed_confidence: Confidence
        """
        self.regex = regex
        self.window_before = window_before
        self.window_after = window_after
        self.fixed_confidence = fixed_confidence

    def as_dict(self):
        return {
            "regex": self.regex,
            "proximity": {"windowBefore": self.window_before, "windowAfter": self.window_after},
            "confidenceAdjustment": {"fixedConfidence": self.fixed_confidence.value}
        }


class ExclusionRule:
    """An object that describes a regular expression or list of keywords that may be used to disqualify a
    candidate finding from triggering a detector match.
    """
    def __init__(self, match_type: str, regex: Regex = None, word_list: WordList = None):
        """Instantiate an ExclusionRule object.
        One of regex or word_list is required.

        :param match_type: the match type. One of "FULL" or "PARTIAL".
        :type match_type: str
        :param regex: The regular expression configuration to run on a candidate finding.
        :type regex: Regex or None
        :param word_list: The list of words to compare to a candidate finding.
        :type word_list: WordList or None
        """
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
    """An object that specifies how findings should be masked when returned by the API."""
    def __init__(self, masking_char: chr, num_chars_to_leave_unmasked: int = 0,
                 mask_right_to_left: bool = False, chars_to_ignore: List[chr] = []):
        """Instantiate a MaskConfig object
        :param masking_char: character that will be repeated to replace the finding.
            This character may be a multi-byte character, but it must be exactly one codepoint.
        :type masking_char: chr
        :param num_chars_to_leave_unmasked: the number of characters to leave unmasked at either the left or right of
            the finding when it is returned.
        :type num_chars_to_leave_unmasked int
        :param mask_right_to_left: True if num_chars_to_leave_unmasked should be on the right, False otherwise.
        :type mask_right_to_left: bool
        :param chars_to_ignore: the set of characters to leave unmasked when the finding is returned. These characters
            may be multi-byte characters, but each entry in the array must be exactly one codepoint.
        :type chars_to_ignore: List[chr]
        """
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
    """An object that configures how any detected findings should be redacted when returned to the client. When this
    configuration is provided as part of a request, exactly one of the four types of redaction should be set.

    Four types of redaction are supported:
    - Masking: replacing the characters of a finding with another character, such as '*' or '👀'
    - Info Type Substitution: replacing the finding with the name of the detector it matched, such
      as CREDIT_CARD_NUMBER
    - Substitution: replacing the finding with a custom string, such as "oh no!"
    - Encryption: encrypting the finding with an RSA public key
    """
    def __init__(
            self,
            remove_finding: bool,
            mask_config: MaskConfig = None,
            substitution_phrase: str = None,
            infotype_substitution: bool = False,
            public_key: str = None
    ):
        """Instantiate a RedactionConfig object.
        One of mask_config, substitution_phrase, infotype_substitution or public_key is required.

        :param remove_finding: Whether the original finding should be omitted in responses from the API.
        :type remove_finding: bool
        :param mask_config: Build a redaction config with masking.
        :type mask_config: MaskConfig or None
        :param substitution_phrase: Build a redaction config with info type substitution.
        :type substitution_phrase: str or None
        :param infotype_substitution: Build a redaction config with info type substitution.
        :type infotype_substitution: bool or None
        :param public_key: Build a redaction config with RSA encryption.
        :type public_key: str or None
        """
        config_counts = [mask_config, substitution_phrase, public_key].count(None)
        if (infotype_substitution and config_counts != 3) or (config_counts != 2 and not infotype_substitution):
            raise NightfallUserError("need one of mask_config, substitution_phrase, infotype_substitution,"
                                     " or public_key")

        self.remove_finding = remove_finding
        self.mask_config = mask_config
        self.substitution_phrase = substitution_phrase
        self.infotype_substitution = infotype_substitution
        self.public_key = public_key

    def as_dict(self):
        result = {"removeFinding": self.remove_finding}
        if self.mask_config:
            result["maskConfig"] = self.mask_config.as_dict()
        if self.substitution_phrase:
            result["substitutionConfig"] = {"substitutionPhrase": self.substitution_phrase}
        if self.infotype_substitution:
            result["infoTypeSubstitutionConfig"] = {}
        if self.public_key:
            result["cryptoConfig"] = {"publicKey": self.public_key}
        return result


class Detector:
    """An object that represents a data type or category of information. Detectors are used to scan content
    for findings.
    """
    def __init__(
            self,
            min_confidence: Confidence,
            min_num_findings: int,
            nightfall_detector: str = None,
            regex: Regex = None,
            word_list: WordList = None,
            uuid: str = None,
            display_name: str = None,
            context_rules: List[ContextRule] = None,
            exclusion_rules: List[ExclusionRule] = None,
            redaction_config: RedactionConfig = None
    ):
        """Instantiate a Detector object.
        One of nightfall_detector, regex, word_list or uuid required.

        :param min_confidence: The minimum confidence threshold for the detector trigger a finding.
        :type min_confidence: Confidence
        :param min_num_findings: The minimum number of occurrences of the detector required to trigger a finding.
        :type min_num_findings: int
        :param nightfall_detector: Create an instance of a detector based on a pre-built Nightfall detector.
        :type nightfall_detector: str or None
        :param regex: Create an instance of a detector based on a regular expression.
        :type regex: Regex or None
        :param word_list: Create an instance of a detector based on a word list.
        :type word_list: WordList or None
        :param uuid: Create an instance of a detector by using an existing detector's UUID.
        :type uuid: str or None
        :param display_name: A display name for this detector.
        :type display_name: str or None
        :param context_rules: The context rules to use to customize the behavior of this detector.
        :type context_rules: List[ContextRule] or None
        :param exclusion_rules: The exclusion rules to use to customize the behavior of this detector.
        :type exclusion_rules: List[ExclusionRule] or None
        :param redaction_config: Sets the redaction configuration to-be-applied to this detector. This configuration is
            currently only supported for scanning plaintext, not for file scanning.
        :type redaction_config: RedactionConfig or None
        """
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
        self.exclusion_rules = exclusion_rules
        self.redaction_config = redaction_config

    def as_dict(self):
        result = {"minConfidence": self.min_confidence.value, "minNumFindings": self.min_num_findings}
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
        if self.exclusion_rules:
            result["exclusionRules"] = [e.as_dict() for e in self.exclusion_rules]
        if self.redaction_config:
            result["redactionConfig"] = self.redaction_config.as_dict()
        return result


class LogicalOp(Enum):
    """ A modifier that is used to decide when a finding should be surfaced in the context of a detection rule.
    - When ALL is specified, all detectors in a detection rule must trigger a match in order for the finding to be
      reported. This is the equivalent of a logical "AND" operator.
    - When ANY is specified, only one of the detectors in a detection rule must trigger a match in order for the finding
      to be reported. This is the equivalent of a logical "OR" operator.
    """
    ANY = "ANY"
    ALL = "ALL"


class DetectionRule:
    """An object that contains a set of detectors to be used when scanning content."""
    def __init__(self, detectors: List[Detector], logical_op: LogicalOp = LogicalOp.ANY):
        """Instantiate a DetectionRule
        :param detectors: A list of Detectors to scan content with.
        :type detectors: List[Detector]
        :param logical_op: The method for combining the detectors. One of:
          - LogicalOp.ANY (logical or, i.e. a finding is emitted only if any of the provided detectors match)
          - LogicalOp.ALL (logical and, i.e. a finding is emitted only if all provided detectors match)
        :type logical_op: LogicalOp
        """
        self.detectors = detectors
        self.logical_op = logical_op

    def as_dict(self):
        return {"detectors": [d.as_dict() for d in self.detectors], "logicalOp": self.logical_op.value}

