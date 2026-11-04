"""AFIT WATCH TOWER - the security-camera monitoring service package."""

# The one version string the product publishes. It is what the console reports on its Settings
# screen and what the monitoring host puts on its heartbeat to the cloud service, so it lives here
# rather than in the FastAPI constructor call, where only the API documentation could read it.
__version__ = "1.0.0"
