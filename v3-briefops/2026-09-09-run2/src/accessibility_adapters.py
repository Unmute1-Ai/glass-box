SUPPORTED_INPUTS = {"asl","speech","aac","text","gesture","switch","caption","haptic","derived_wrist_signal","visual_description"}

def normalize(modality: str, intent: str):
    if modality not in SUPPORTED_INPUTS:
        raise ValueError("unsupported_modality")
    return {
        "modality": modality,
        "normalized_intent": intent,
        "raw_sensor_retained": False,
        "authority_granted": False,
    }
