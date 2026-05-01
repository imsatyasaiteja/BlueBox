"""BlueBox encrypted hash-chain logger layer."""

__all__ = ["HashChainLogger", "RawEvent"]


def __getattr__(name):
    if name in __all__:
        from logger_layer.hash_chain_logger import HashChainLogger, RawEvent

        return {"HashChainLogger": HashChainLogger, "RawEvent": RawEvent}[name]
    raise AttributeError(name)
