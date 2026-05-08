"""Current model artifact names and paths."""

from backend.shared.paths import MODELS_DIR
from backend.shared.schema import PCAP_DOMAINS


ARINC_MODEL_PATH = MODELS_DIR / "isolation_forest_arinc.pkl"
PCAP_STATS_PATH = MODELS_DIR / "pcap_domain_stats.json"
ARINC_STATS_PATH = MODELS_DIR / "arinc_label_stats.json"

DOMAIN_TO_MODEL_NAME = {domain: domain for domain in PCAP_DOMAINS}


def pcap_model_path(domain: str):
    return MODELS_DIR / f"isolation_forest_pcap_{DOMAIN_TO_MODEL_NAME[domain]}.pkl"

