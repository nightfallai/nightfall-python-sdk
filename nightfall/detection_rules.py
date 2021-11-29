from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from nightfall.exceptions import NightfallUserError


@dataclass
class Regex:
    """A RE2 regular expression and config for use with Nightfall
    Attributes:
        pattern (str): The RE2 pattern to use.
        is_case_sensitive (bool): Whether to make matches have the same case as the expression given
    """
    pattern: str
    is_case_sensitive: bool

    def as_dict(self):
        return {"pattern": self.pattern, "isCaseSensitive": self.is_case_sensitive}


@dataclass
class WordList:
    """A list of words that can be used to customize the behavior of a detector while Nightfall performs a scan.
    Attributes:
        word_list (List[str]): The list of words to use.
        is_case_sensitive (bool): Whether to make matches have the same case as each word given
    """
    word_list: List[str]
    is_case_sensitive: bool

    def as_dict(self):
        return {"values": self.word_list, "isCaseSensitive": self.is_case_sensitive}


class Confidence(Enum):
    """Confidence describes the certainty that a piece of content matches a detector."""
    VERY_UNLIKELY = "VERY_UNLIKELY"
    UNLIKELY = "UNLIKELY"
    POSSIBLE = "POSSIBLE"
    LIKELY = "LIKELY"
    VERY_LIKELY = "VERY_LIKELY"


@dataclass
class ContextRule:
    """An object that describes how a regular expression may be used to adjust the confidence of a candidate finding.
    This context rule will be applied within the provided byte proximity, and if the regular expression matches, then
    the confidence associated with the finding will be adjusted to the value prescribed.
    Attributes:
        regex (Regex): The regular expression configuration to run within the context of a candidate finding.
        window_before (int): The number of leading characters to consider as context.
        window_after (int): The number of trailing characters to consider as context.
        fixed_confidence (Confidence): How to adjust the result of the match if the context rule matches.
    """
    regex: Regex
    window_before: int
    window_after: int
    fixed_confidence: Confidence

    def as_dict(self):
        return {
            "regex": self.regex.as_dict(),
            "proximity": {"windowBefore": self.window_before, "windowAfter": self.window_after},
            "confidenceAdjustment": {"fixedConfidence": self.fixed_confidence.value}
        }


class MatchType(Enum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"


@dataclass
class ExclusionRule:
    """An object that describes a regular expression or list of keywords that may be used to disqualify a
    candidate finding from triggering a detector match. One of regex or word_list is required.
    Attributes:
        match_type (MatchType): the match type.
        regex (Regex or None): The regular expression configuration to run on a candidate finding.
        word_list (WordList or None): The list of words to compare to a candidate finding.
    """
    match_type: MatchType
    regex: Optional[Regex] = None
    word_list: Optional[WordList] = None

    def __post_init__(self):
        if (not self.regex and not self.word_list) or (self.regex and self.word_list):
            raise NightfallUserError("need either regex or word_list to build an ExclusionRule", 40001)

    def as_dict(self):
        result = {"matchType": self.match_type.value}
        if self.regex:
            result["regex"] = self.regex.as_dict()
            result["exclusionType"] = "REGEX"
        if self.word_list:
            result["wordList"] = self.word_list.as_dict()
            result["exclusionType"] = "WORD_LIST"
        return result


@dataclass
class MaskConfig:
    """An object that specifies how findings should be masked when returned by the API.
    Attributes:
        masking_char (chr): character that will be repeated to replace the finding.
            This character may be a multi-byte character, but it must be exactly one codepoint.
        num_chars_to_leave_unmasked (int): the number of characters to leave unmasked at either the left or right of
            the finding when it is returned.
        mask_right_to_left (bool): True if num_chars_to_leave_unmasked should be on the right, False otherwise.
        chars_to_ignore (List[chr]): the set of characters to leave unmasked when the finding is returned. These
            characters may be multi-byte characters, but each entry in the array must be exactly one codepoint.
        """
    masking_char: chr
    num_chars_to_leave_unmasked: int = 0
    mask_right_to_left: bool = False
    chars_to_ignore: List[chr] = field(default_factory=list)

    def as_dict(self):
        return {
            "maskingChar": self.masking_char,
            "numCharsToLeaveUnmasked": self.num_chars_to_leave_unmasked,
            "maskRightToLeft": self.mask_right_to_left,
            "charsToIgnore": self.chars_to_ignore
        }


@dataclass
class RedactionConfig:
    """An object that configures how any detected findings should be redacted when returned to the client. When this
    configuration is provided as part of a request, exactly one of the four types of redaction should be set.
    One of mask_config, substitution_phrase, infotype_substitution or public_key is required:
        - Masking: replacing the characters of a finding with another character, such as '*' or '👀'
        - Info Type Substitution: replacing the finding with the name of the detector it matched, such
            as CREDIT_CARD_NUMBER
        - Substitution: replacing the finding with a custom string, such as "oh no!"
        - Encryption: encrypting the finding with an RSA public key
    Attributes:
        remove_finding (bool): Whether the original finding should be omitted in responses from the API.
        mask_config (MaskConfig): Build a redaction config with masking.
        substitution_phrase (str or None): Build a redaction config with a substitution phrase.
        infotype_substitution (bool or None): Build a redaction config with info type substitution.
        public_key (str or None): Build a redaction config with RSA encryption.
    """
    remove_finding: bool
    mask_config: Optional[MaskConfig] = None
    substitution_phrase: Optional[str] = None
    infotype_substitution: bool = False
    public_key: Optional[str] = None

    def __post_init__(self):
        config_counts = [self.mask_config, self.substitution_phrase, self.public_key].count(None)
        if (self.infotype_substitution and config_counts != 3) or \
                (config_counts != 2 and not self.infotype_substitution):
            raise NightfallUserError("need one of mask_config, substitution_phrase, infotype_substitution,"
                                     " or public_key", 40001)

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


@dataclass
class Detector:
    """An object that represents a data type or category of information. Detectors are used to scan content
    for findings. One of nightfall_detector, regex, word_list or uuid required.
    Attributes:
        min_confidence (Confidence): The minimum confidence threshold for the detector trigger a finding.
        min_num_findings (int): The minimum number of occurrences of the detector required to trigger a finding.
        nightfall_detector (str or None): Create an instance of a detector based on a pre-built Nightfall detector.
        regex (Regex or None): Create an instance of a detector based on a regular expression.
        word_list (WordList or None): Create an instance of a detector based on a word list.
        uuid (str or None): Create an instance of a detector by using an existing detector's UUID.
        display_name (str or None): A display name for this detector.
        context_rules (List[ContextRule] or None): The context rules to use to customize the behavior of this detector.
        exclusion_rules (List[ExclusionRule] or None): The exclusion rules to use to customize the behavior of this
            detector.
        redaction_config (RedactionConfig or None): The redaction configuration to-be-applied to this detector.
            This configuration is currently only supported for scanning plaintext, not for file scanning.
    """
    min_confidence: Confidence
    min_num_findings: int = 1
    nightfall_detector: Optional[str] = None
    regex: Optional[Regex] = None
    word_list: Optional[WordList] = None
    uuid: Optional[str] = None
    display_name: Optional[str] = None
    context_rules: Optional[List[ContextRule]] = None
    exclusion_rules: Optional[List[ExclusionRule]] = None
    redaction_config: Optional[RedactionConfig] = None

    def __post_init__(self):
        if [self.nightfall_detector, self.regex, self.word_list, self.uuid].count(None) != 3:
            raise NightfallUserError("need one of nightfall_detector, regex, word_list, or uuid", 40001)

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


@dataclass
class DetectionRule:
    """An object that contains a set of detectors to be used when scanning content.
    Attributes:
        detectors (List[Detector]): A list of Detectors to scan content with.
        logical_op (LogicalOp): The method for combining the detectors. One of:
          - LogicalOp.ANY (logical or, i.e. a finding is emitted only if any of the provided detectors match)
          - LogicalOp.ALL (logical and, i.e. a finding is emitted only if all provided detectors match)
        name (str): The name of the detection rule.
    """
    detectors: List[Detector]
    logical_op: LogicalOp = LogicalOp.ANY
    name: Optional[str] = None

    def as_dict(self):
        result = {"detectors": [d.as_dict() for d in self.detectors], "logicalOp": self.logical_op.value}
        if self.name:
            result["name"] = self.name
        return result
