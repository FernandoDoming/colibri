import os
import shutil

def get_root_dir():
    return os.path.join(
        os.path.expanduser("~"), ".colibri"
    )

def get_sample_results_path(sha256: str):
    return os.path.join(
        get_root_dir(), "results", sha256
    )
