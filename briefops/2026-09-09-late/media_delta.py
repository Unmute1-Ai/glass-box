from dataclasses import dataclass
@dataclass(frozen=True)
class AccessibleMediaArtifact:
    artifact_id:str
    source_provenance_verified:bool
    generated_by_model:bool
    visual_description:str|None
    captions:str|None
    user_editable:bool
    contains_raw_biometric:bool=False
@dataclass(frozen=True)
class MediaDecision:
    decision:str
    reason:str
def admit_accessible_media(a):
    if not a.source_provenance_verified:return MediaDecision("DENY","unverified_media_provenance")
    if a.contains_raw_biometric:return MediaDecision("DENY","raw_biometric_media_retention_disallowed")
    if not a.visual_description:return MediaDecision("DENY","visual_description_required")
    if not a.user_editable:return MediaDecision("DENY","accessible_media_must_be_user_editable")
    return MediaDecision("ALLOW","accessible_media_admitted")