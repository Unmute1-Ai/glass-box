from dataclasses import dataclass

@dataclass(frozen=True)
class SchoolAIRequest:
    data_subject: str  # student | educator
    use_for_model_training: bool
    persistent_tracking: bool
    high_impact_decision: bool
    human_oversight_present: bool
    social_companion_mode: bool
    transparency_notice_present: bool


def decide_school_ai_request(req: SchoolAIRequest):
    if req.data_subject not in {"student", "educator"}:
        return "DENY", "unsupported_school_data_subject"
    if req.use_for_model_training:
        return "DENY", "school_data_training_use_disallowed"
    if req.persistent_tracking:
        return "DENY", "student_or_educator_tracking_disallowed"
    if req.social_companion_mode:
        return "DENY", "social_companion_mode_disallowed"
    if req.high_impact_decision and not req.human_oversight_present:
        return "DENY", "human_oversight_required"
    if not req.transparency_notice_present:
        return "DENY", "plain_language_transparency_required"
    return "ALLOW", "school_ai_policy_satisfied"


def authority_delta_from_school_policy() -> int:
    return 0
