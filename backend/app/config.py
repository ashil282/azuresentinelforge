from pathlib import Path
import os
ROOT=Path(__file__).resolve().parents[2]
DATA=Path(os.getenv("ASF_DATA_DIR",ROOT/"data"))
DB=Path(os.getenv("ASF_DB_PATH",DATA/"asf.db"))
RULES=Path(os.getenv("ASF_RULES_DIR",ROOT/"backend"/"rules"))
