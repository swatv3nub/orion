from app.engine.assessment import reconcile_assessment
from app.llm.schemas import AnalystAssessment
from app.models import Classification, Evaluation, Hypothesis, HypothesisStatus, Severity


def setup_assessment(*, classification="confirmed", confidence=0.9, unresolved_questions=None):
    return AnalystAssessment(
        classification=classification,
        severity="informational",
        confidence=confidence,
        summary="TCP port 80 is open and returned an HTTP response.",
        summary_evidence_refs=["E-1", "E-2"],
        factual_claims=[{"text": "TCP port 80 is open", "evidence_refs": ["E-1"]},
                        {"text": "The endpoint returned an HTTP response", "evidence_refs": ["E-2"]}],
        hypotheses=[{
            "id": "H-001", "statement": "The observed service is supported by the evidence.",
            "evidence_refs": ["E-1", "E-2"], "confidence": confidence,
            "supporting_evidence": ["E-1", "E-2"], "status": "supported",
        }],
        supporting_evidence=["E-1", "E-2"],
        unresolved_questions=unresolved_questions or [],
        human_review_required=True,
        automated_action="none",
    )


def run(assessment, *, status=HypothesisStatus.supported, missing=None, confidence=0.04):
    evaluation = Evaluation(
        classification=Classification.needs_investigation,
        confidence=confidence,
        missing_evidence=missing or [],
        needs_investigation=True,
    )
    hypothesis = Hypothesis(
        id="H-001", title="Observed service", description="Observed service requires validation.",
        supporting_evidence=["E-1", "E-2"], missing_evidence=missing or [], confidence=0.8, status=status,
    )
    return reconcile_assessment(assessment, evaluation, Severity.informational, [hypothesis])


def test_confirmed_port_observation_does_not_confirm_security_condition():
    _, final, consistency = run(
        setup_assessment(),
        status=HypothesisStatus.plausible,
        missing=["Expected exposure status", "Service ownership", "Authentication and access-control configuration"],
    )
    assert final.classification == "needs_investigation"
    assert consistency.status == "reconciled"


def test_missing_security_context_reconciles_confirmed_to_investigation():
    llm = setup_assessment()
    deterministic, final, consistency = run(
        llm,
        status=HypothesisStatus.plausible,
        missing=["Expected exposure status", "Service ownership", "Authentication and access-control configuration"],
    )
    assert llm.classification == "confirmed"
    assert deterministic.classification == "needs_investigation"
    assert final.classification == "needs_investigation"
    assert final.source == "reconciled"
    assert "The LLM assessment identifies verified observations" in final.rationale
    assert "Missing evidence includes:" in final.rationale
    assert "Authentication and access-control configuration" in final.rationale
    assert "Service ownership" in final.rationale
    assert "The deterministic assessment does not contain a supported hypothesis meeting the confirmation threshold" in final.rationale
    assert "The LLM assessment confirms the observation" not in final.rationale
    assert "deterministic hypothesis is not supported" not in final.rationale
    assert consistency.status == "reconciled"


def test_sufficiently_supported_finding_remains_confirmed():
    # Supported deterministic hypothesis, adequate confidence, and no relevant gaps.
    _, final, consistency = run(setup_assessment(), confidence=0.9)
    assert final.classification == "confirmed"
    assert final.source == "reconciled"
    assert consistency.status == "reconciled"


def test_existing_benign_classification_remains_supported():
    _, final, consistency = run(setup_assessment(classification="benign"))
    assert final.classification == "benign"
    assert final.source == "reconciled"
    assert consistency.status == "reconciled"


def test_unrelated_unresolved_question_does_not_downgrade_confirmed():
    _, final, consistency = run(
        setup_assessment(unresolved_questions=["What was the historical login pattern?"]), confidence=0.9
    )
    assert final.classification == "confirmed"
    assert consistency.status == "reconciled"


def test_matching_needs_investigation_classification_is_consistent():
    _, final, consistency = run(setup_assessment(classification="needs_investigation"))
    assert final.classification == "needs_investigation"
    assert final.source == "llm"
    assert consistency.status == "consistent"


def test_llm_and_deterministic_assessments_are_both_available_on_reconciliation():
    deterministic, final, consistency = run(
        setup_assessment(), status=HypothesisStatus.plausible,
        missing=["Expected exposure status"],
    )
    assert deterministic.classification == "needs_investigation"
    assert final.classification == "needs_investigation"
    assert consistency.status == "reconciled"


def test_low_confidence_confirmed_result_fails_closed():
    _, final, consistency = run(setup_assessment(confidence=0.6))
    assert final.classification == "needs_investigation"
    assert consistency.status == "reconciled"
