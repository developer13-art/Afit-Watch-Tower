"""Personnel-mobile integration layer.

Shared by the local monitoring application and the cloud API: the schema in `models`, the
service-to-service signature scheme in `signing`, and the transactional outbox in `outbox`.
Import `watchtower.mobile.models` wherever the full database metadata is required.
"""
