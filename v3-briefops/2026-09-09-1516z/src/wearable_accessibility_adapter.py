from dataclasses import dataclass

ACCESSIBLE_OUTPUTS = frozenset({"speech","caption","haptic","high_contrast_text"})
RAW_SENSOR_TYPES = frozenset({"camera_frame","microphone_pcm","imu_stream","eye_gaze_raw"})

@dataclass(frozen=True)
class WearableSkill:
    skill_id: str
    simulated_hardware: bool
    outputs: frozenset[str]
    retains_raw_sensor_data: bool = False
    authority_granted: bool = False

def admit_wearable_skill(skill: WearableSkill):
    if not skill.outputs.issubset(ACCESSIBLE_OUTPUTS):
        return "DENY", "unsupported_accessibility_output"
    if skill.retains_raw_sensor_data:
        return "DENY", "raw_sensor_retention_disallowed"
    if skill.authority_granted:
        return "DENY", "wearable_skill_cannot_grant_authority"
    return "ADMIT", "accessibility_skill_admitted"
