"""Python bindings for the IDA SDK via idax."""

try:
    from idax._idax import *  # noqa: F401,F403
except ImportError:
    pass

BAD_ADDRESS: int = 0xFFFFFFFFFFFFFFFF
