# AFIT WATCH TOWER

### AI-Powered Campus Security Surveillance, Early Warning & Incident Management

**Turning conventional surveillance into intelligent, proactive security.**

AFIT WATCH TOWER is an AI-powered security surveillance and incident management platform designed to help institutions improve security awareness, detect potentially important events, and respond more efficiently through automated video analysis, centralized monitoring, intelligent alerts, and organized evidence management.

The project is proposed for the Air Force Institute of Technology (AFIT), Kaduna, Nigeria, with the objective of making compatible existing security cameras more useful through an intelligent software layer.

Rather than depending entirely on personnel continuously watching every camera feed, AFIT WATCH TOWER is designed to analyse supported video streams, identify predefined event patterns, notify authorized security personnel, and provide tools for reviewing and investigating incidents.

> **Project status:** In development. Initial implementation begins with a simulated camera environment. Integration with physical cameras depends on verified, supported interfaces and institutional authorization.

## Overview

Traditional surveillance systems can record important events without ensuring that someone notices them as they occur. Reviewing footage after an incident can also require considerable time and manual effort.

AFIT WATCH TOWER addresses these challenges by introducing an intelligent monitoring layer between compatible cameras and security operations.

The platform is designed to connect camera management, AI-assisted video analytics, event notifications, incident workflows, evidence management, and operational reporting in one centralized application.

The system is intended to support security personnel—not replace human judgment or automatically determine guilt.

## Key Features

### Centralized Security Dashboard
- Unified overview of registered cameras and their operational status.
- Camera monitoring grid for supported live feeds.
- Prioritized event alerts and incident summaries.
- Real-time updates for relevant system activity.
- Search and filtering by location, camera, event category, and status.
- Clear separation between simulated feeds and verified live feeds.

### Camera and Location Management
- Register and organize cameras across campus locations.
- Associate cameras with buildings, zones, entrances, and restricted areas.
- Track integration status and supported capabilities.
- Monitor available connectivity and stream-health indicators.
- Provide an extensible architecture for multiple camera vendors.

### AI-Assisted Event Detection
The system is designed to evaluate selected visual events, including:

- Potential unauthorized entry into configured restricted areas.
- Movement patterns that may indicate physical altercations.
- Objects remaining unattended in monitored locations.
- Configurable unusual movement patterns.
- Additional validated safety-event categories as the project evolves.

Detection capabilities will depend on the selected models, available video quality, camera positioning, and measured evaluation results.

### Intelligent Alerts and Notifications
- Generate structured event alerts.
- Associate alerts with camera locations and timestamps.
- Include available snapshots or evidence references.
- Prioritize alerts using configurable rules.
- Notify authorized personnel through supported channels.
- Reduce duplicate alerts and track notification delivery attempts.

### Incident Management
- Review and classify AI-generated alerts.
- Create and assign incidents.
- Record investigation notes and actions taken.
- Track incident status and escalation.
- Maintain a timeline of relevant activity.
- Document resolution and closure.

### Evidence Management
- Organize authorized snapshots and video clips.
- Associate evidence with cameras, events, and incidents.
- Control access to sensitive recordings.
- Audit evidence viewing and export.
- Support integrity checks and documented evidence handling.
- Apply approved retention and preservation policies.

### Camera and Service Health
- Monitor camera connectivity where observable.
- Identify stream failures and integration errors.
- Track video-processing service health.
- Record relevant technical warnings.
- Support maintenance and troubleshooting workflows.

### Reporting and Analytics
- Camera availability and outage reporting.
- Event and incident summaries.
- Alert review and response-time measurements.
- AI evaluation metrics.
- Audit and evidence-access reports.
- Operational insights for authorized security management.

### Security and Administration
- Authentication and role-based access control.
- Restricted access to camera feeds and evidence.
- Audit logging for sensitive operations.
- Secure configuration and credential handling.
- Configurable retention and notification policies.
- Administrative oversight and operational controls.

## How It Works

AFIT WATCH TOWER follows a four-stage monitoring workflow.

**1. Capture**

Compatible cameras provide video through an authorized integration interface. During early development, simulated cameras and test footage are used.

**2. Analyse**

The video-processing service examines eligible frames or streams using configured computer-vision models and detection rules.

**3. Alert**

When a possible event is detected, the system creates a structured alert containing the event category, camera location, timestamp, and available supporting evidence.

**4. Review and Respond**

Authorized security personnel receive the alert, review the available information, and decide whether to dismiss it, investigate further, or create an incident.

This workflow allows the system to identify potential events without requiring an operator to be watching every individual camera feed continuously.

Automated monitoring still depends on camera availability, connectivity, processing resources, and detection accuracy. AI alerts are indications for human review, not definitive conclusions.

## System Architecture

The project is organized into modular services:

- **Web Application:** Security dashboard, camera management, event review, incident workflows, and administration.
- **Backend API:** Authentication, authorization, business logic, camera records, alerts, incidents, notifications, and audit operations.
- **Video and AI Processing Service:** Video ingestion, frame processing, model inference, and detection-event generation.
- **Camera Integration Layer:** Adapters for simulated cameras and officially supported physical-camera interfaces.
- **PostgreSQL Database:** Structured operational records, configuration metadata, event history, incidents, jobs, and audit logs.
- **Evidence Storage:** Approved storage for snapshots, clips, and associated evidence metadata.
- **Real-Time Communication:** Dashboard updates for alerts, incidents, and relevant health changes.

The architecture is designed to support independent development and future extension of individual modules.

## Camera Integration Strategy

The project begins with a simulator so that application development does not depend on immediate access to physical camera feeds.

Future integration will be investigated through documented and authorized interfaces, potentially including:

- Official vendor SDKs or APIs.
- Supported RTSP streams.
- ONVIF-compatible interfaces.
- Other approved vendor streaming or recording interfaces.

AFIT's existing cameras are reportedly managed through the UBox application. Direct integration with those devices has not yet been verified.

QR-based device registration may help associate a physical camera with its application record, but a QR code does not necessarily provide video access or authorize third-party integration.

Physical-camera support will be declared only after the relevant interface has been verified and successfully tested.

## Security and Privacy Principles

Security and responsible handling of surveillance information are core design requirements.

The project aims to implement:

- Least-privilege access controls.
- Server-side authorization.
- Secure credential management.
- Encrypted communication.
- Controlled evidence access and export.
- Audit trails for sensitive operations.
- Configurable evidence-retention policies.
- Human review of AI-generated alerts.
- Institutional approval for camera access and production deployment.

Facial identification and automated decisions about individual guilt are not part of the initial project scope.

## Development Principles

- **Modular:** Camera integrations, AI models, and application features can evolve independently.
- **Testable:** Development begins with simulated cameras and repeatable test scenarios.
- **Evidence-driven:** AI capabilities are evaluated using defined metrics and representative test data.
- **Secure by design:** Authorization, privacy, and auditing are considered throughout development.
- **Operationally realistic:** Unsupported camera capabilities are not assumed to exist.
- **Resource-conscious:** Processing and storage requirements are measured before scaling.
- **No Redis dependency:** PostgreSQL-backed jobs are used for appropriate discrete asynchronous tasks; continuous video processing bypasses the job queue.

## Current Development Roadmap

- [ ] Project foundation and repository structure.
- [ ] PostgreSQL schema and database migrations.
- [ ] Authentication and role-based permissions.
- [ ] Camera and location registry.
- [ ] Simulated camera adapter.
- [ ] Security dashboard.
- [ ] Event detection and alert pipeline.
- [ ] Incident management.
- [ ] Evidence management and access auditing.
- [ ] Notification and escalation workflows.
- [ ] AI detection prototype and evaluation.
- [ ] Camera integration feasibility assessment.
- [ ] Authorized physical-camera proof of concept.
- [ ] Controlled pilot and performance evaluation.
- [ ] Production hardening and documentation.

Roadmap items represent planned work and should not be interpreted as completed functionality unless explicitly documented.

## Project Goals

The long-term goals of AFIT WATCH TOWER are to:

1. Improve visibility across compatible campus surveillance cameras.
2. Reduce dependence on continuous manual observation.
3. Help security personnel identify relevant events sooner.
4. Make incident investigation and evidence retrieval more efficient.
5. Improve camera and service-health awareness.
6. Establish a scalable foundation for AI-assisted institutional security.

## Contributing

Development should follow the project's security, testing, documentation, and architecture guidelines.

Before contributing:
1. Review the project documentation.
2. Understand the module boundaries and API contracts.
3. Avoid committing credentials, private camera information, or real surveillance footage.
4. Add appropriate tests for new functionality.
5. Document integration assumptions and limitations.
6. Ensure camera-related changes use authorized, supported interfaces.

Contributions involving real camera access or sensitive surveillance data must follow applicable institutional authorization and privacy requirements.

## Disclaimer

AFIT WATCH TOWER is a proposed and developing project. It is not an official AFIT system unless formally adopted or authorized by the institution.

Camera compatibility, AI detection performance, and production deployment readiness must be established through technical testing and appropriate approvals.

The system is intended to assist authorized security personnel. AI-generated events may be incorrect or incomplete and must be evaluated by humans before operational decisions are made.

## License

The project license will be specified by the repository owner before public redistribution. Until a license is added, no additional rights to reuse, modify, or redistribute the project's code should be assumed.

---

**AFIT WATCH TOWER — From passive surveillance to intelligent security awareness.**
