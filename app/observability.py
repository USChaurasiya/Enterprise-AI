"""Privacy-first Rius tracing. No telemetry is sent without RIUS_API_KEY."""
import os
import logging
import ssl
from functools import wraps

log = logging.getLogger(__name__)

def _configure_ca_bundle():
    if os.getenv("SSL_CERT_FILE") or os.getenv("SSL_CERT_DIR"):
        return

    paths = ssl.get_default_verify_paths()
    has_ca_file = paths.cafile and os.path.isfile(paths.cafile)
    has_ca_dir = paths.capath and os.path.isdir(paths.capath)
    if has_ca_file or has_ca_dir:
        return

    try:
        import certifi
    except ImportError:
        log.warning("No CA bundle found; install certifi or configure SSL_CERT_FILE")
        return

    os.environ["SSL_CERT_FILE"] = certifi.where()


def initialize():
    """Call once, before instrumented app modules are loaded."""
    from dotenv import load_dotenv
    load_dotenv()
    if not os.getenv("RIUS_API_KEY") or os.getenv("RIUS_DISABLED", "false").lower() in ("1", "true", "yes"):
        log.info("Rius observability disabled (no key or kill switch)")
        return
    try:
        _configure_ca_bundle()
        import rius
        rius.init(service_name=os.getenv("RIUS_SERVICE_NAME", "atlas-ai-fde"), capture_content=False)
        log.info("Rius observability enabled")
    except Exception:
        log.exception("Rius initialization failed; application will continue without telemetry")

def trace(name):
    """Decorate sync/async functions; never export arguments or return values."""
    def decorate(fn):
        try:
            import rius
            return rius.observe(name=name, capture_input=False, capture_output=False)(fn)
        except ImportError:
            return fn
    return decorate
