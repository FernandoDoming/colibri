import logging

LOG_FORMAT = "%(asctime)-15s [%(levelname)s] - %(message)s"
logging.basicConfig(format=LOG_FORMAT)
log = logging.getLogger("identikit.witness.malware_config")
log.setLevel(logging.INFO)

# -----------------------------------------------------------------
class dotdict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

# -----------------------------------------------------------------
class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


