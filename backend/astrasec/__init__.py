"""
AstraSec — Artificial Immune System for Autonomous AI Threat Prediction,
Adaptive Defense and Self-Healing.

Department of Computer Science and Engineering
Sri Manakula Vinayagar Engineering College (Autonomous)

Team:
    HARSHITA U      - 23UCS062 (Team Leader)
    HARINI S        - 23UCS059
    MAHALAKSHMI S   - 23UCS095
Guide:
    Mr. B. THIYAGARAJAN, Assistant Professor

The package exposes five cooperating engines that mirror the vertebrate
immune system:

    Module 1  Behavior Learning Engine      -> innate immunity / self-model
    Module 2  AI Health & Risk Analyzer     -> homeostasis monitoring
    Module 3  Threat Prediction Engine      -> antigen recognition
    Module 4  Adaptive Defense Engine       -> effector response
    Module 5  Self-Healing & Immune Memory  -> adaptive immunity / memory cells
"""

__version__ = "1.0.0"
__project__ = "AstraSec"
__tagline__ = (
    "Artificial Immune System for Autonomous AI Threat Prediction, "
    "Adaptive Defense and Self-Healing"
)

THREAT_CLASSES = (
    "benign",
    "prompt_injection",
    "jailbreak",
    "adversarial_obfuscation",
    "data_exfiltration",
    "model_extraction",
)

__all__ = ["__version__", "__project__", "__tagline__", "THREAT_CLASSES"]
