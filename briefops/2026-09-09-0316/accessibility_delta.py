from dataclasses import dataclass

ALLOWED_MODALITIES = {"asl","speech","aac","text","gesture","switch","caption","haptic","derived_wrist_signal"}

@dataclass(frozen=True)
class AccessibleIntent:
    modality: str
    normalized_intent: str
    raw_sensor_retained: bool = False

def normalize_accessible_intent(modality: str, normalized_intent: str) -> AccessibleIntent:
    if modality not in ALLOWED_MODALITIES:
        raise ValueError("unsupported_accessibility_modality")
    return AccessibleIntent(modality, normalized_intent, raw_sensor_retained=False)
