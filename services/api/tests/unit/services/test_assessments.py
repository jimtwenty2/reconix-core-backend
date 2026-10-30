from reconix_api.models.enums import SeverityStatus, ValidationStatus
from reconix_api.services.assessments import every, worst


def test_the_worst_severity_wins():
    assert worst({"LOW": 3, "HIGH": 1, "NONE": 5}) == SeverityStatus.HIGH
    assert worst({"UNKNOWN": 1, "LOW": 1}) == SeverityStatus.LOW
    assert worst({"NONE": 2, "UNKNOWN": 1}) == SeverityStatus.UNKNOWN


def test_no_findings_has_no_worst_severity():
    assert worst({}) is None
    assert worst({"HIGH": 0}) is None


def test_every_value_is_a_key_in_order():
    assert every(ValidationStatus, {"CONFIRMED": 2}) == {
        "CONFIRMED": 2,
        "UNCONFIRMED": 0,
        "INCONCLUSIVE": 0,
    }
