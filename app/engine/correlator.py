from __future__ import annotations

from itertools import combinations
from typing import Any, Iterable
from urllib.parse import urlsplit

from app.engine.graph import EvidenceGraph
from app.models import CorrelationResult, Evidence, EvidenceRelation, InvestigationContext


class EvidenceCorrelator:
    """Build deterministic relationships from evidence metadata.

    Evidence is counted once per canonical representation. Correlation adds at
    most 0.15 confidence in the hypothesis engine; evidence volume alone does
    not make a finding more severe or certain.
    """

    def correlate(self, context: InvestigationContext, graph: EvidenceGraph) -> CorrelationResult:
        self._expand_scan_results(context, graph)
        evidence = context.evidence
        unique_ids: list[str] = []
        duplicate_ids: list[str] = []
        duplicate_of: dict[str, str] = {}
        seen: dict[tuple[Any, ...], str] = {}
        for item in evidence:
            key = self._identity(item, context)
            if key in seen:
                duplicate_ids.append(item.id)
                duplicate_of[item.id] = seen[key]
            else:
                seen[key] = item.id
                unique_ids.append(item.id)

        relationships: list[EvidenceRelation] = []
        for left, right in combinations(evidence, 2):
            for relation_type, confidence, rationale in self._relationships(left, right, context):
                relation = EvidenceRelation(
                    source_evidence_id=left.id,
                    target_evidence_id=right.id,
                    relationship_type=relation_type,
                    confidence=confidence,
                    rationale=rationale,
                )
                relationships.append(relation)
                graph.add_edge(left.id, right.id, relation_type)
        return CorrelationResult(
            relationships=relationships,
            unique_evidence_ids=unique_ids,
            duplicate_evidence_ids=duplicate_ids,
            duplicate_of=duplicate_of,
        )

    def _expand_scan_results(self, context: InvestigationContext, graph: EvidenceGraph) -> None:
        additions: list[Evidence] = []
        for source in list(context.evidence):
            if source.type != "scan_result":
                continue
            existing = {(item.type, repr(sorted(item.metadata.items(), key=lambda pair: pair[0]))) for item in context.evidence}
            for category, value in self._scan_observations(source.metadata):
                metadata = self._observation_metadata(source, value)
                signature = (f"reconix_{category}_observation", repr(sorted(metadata.items(), key=lambda pair: pair[0])))
                if signature in existing:
                    continue
                existing.add(signature)
                additions.append(Evidence(
                    id=f"{context.investigation_id}:E-{len(context.evidence) + len(additions) + 1:03d}",
                    source=source.source,
                    type=f"reconix_{category}_observation",
                    finding=f"{category} observation: {self._display(value)}",
                    confidence=source.confidence,
                    timestamp=source.timestamp,
                    raw_reference=source.raw_reference,
                    metadata=metadata,
                ))
        for item in additions:
            context.evidence.append(item)
            graph.add_node(item.id, "evidence", item.model_dump(mode="json"))

    def _scan_observations(self, metadata: dict[str, Any]) -> Iterable[tuple[str, Any]]:
        found: list[tuple[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        fields = {
            "port": "port", "ports": "port", "dns": "dns", "dns_records": "dns",
            "records": "dns", "subdomain": "subdomain", "subdomains": "subdomain",
            "ssl": "tls", "tls": "tls", "certificate": "tls", "certificates": "tls",
            "http": "http", "http_response": "http", "http_status": "http",
            "cloud": "cloud", "cloud_observations": "cloud", "cloud_provider": "cloud",
        }

        def add(category: str, value: Any) -> None:
            key = (category, repr(self._observation_key(category, value)))
            if key not in seen:
                seen.add(key)
                found.append((category, value))

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    name = key.lower()
                    if name in {"results", "observations", "findings"} and isinstance(item, list):
                        for entry in item:
                            category = self._category(Evidence(id="scan", source="scan", type="scan", finding="scan", confidence=1.0, raw_reference="scan", metadata=entry)) if isinstance(entry, dict) else "unknown"
                            if category != "unknown":
                                add(category, entry)
                        continue
                    category = fields.get(name)
                    if category:
                        values = item if isinstance(item, list) else [item]
                        for entry in values:
                            add(category, entry)
                        continue
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)

        visit(metadata)
        yield from found

    def _observation_key(self, category: str, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        keys = {
            "port": {"port", "service", "state"},
            "dns": {"name", "type", "value", "record", "records"},
            "tls": {"subject", "issuer", "serial", "certificate", "expires"},
            "http": {"url", "status", "status_code", "title"},
            "subdomain": {"hostname", "subdomain", "name"},
            "cloud": {"provider", "service", "account", "region"},
        }.get(category, set())
        return tuple(sorted((key, repr(item)) for key, item in value.items() if key in keys))

    def _observation_metadata(self, source: Evidence, value: Any) -> dict[str, Any]:
        scan_ids = self._scan_ids(source)
        metadata = {"scan_id": sorted(scan_ids)[0] if scan_ids else source.raw_reference}
        if isinstance(value, dict):
            metadata.update(value)
        else:
            metadata["value"] = value
        assets = self._asset_values(source, None)
        if assets:
            metadata["asset"] = sorted(assets)[0]
        return metadata

    def _relationships(self, left: Evidence, right: Evidence, context: InvestigationContext) -> list[tuple[str, float, str]]:
        relationships: list[tuple[str, float, str]] = []
        left_scan, right_scan = self._scan_ids(left), self._scan_ids(right)
        left_finding, right_finding = self._finding_ids(left), self._finding_ids(right)
        left_asset, right_asset = self._asset_values(left, context), self._asset_values(right, context)
        if left_scan & right_scan:
            relationships.append(("same_scan", 1.0, "Both evidence records reference the same scan_id."))
        if left_finding & right_finding:
            relationships.append(("same_finding", 1.0, "Both evidence records reference the same finding_id."))
        if left_asset & right_asset:
            relationships.append(("same_asset", 0.95, "Both evidence records resolve to the same asset."))

        categories = {self._category(left), self._category(right)}
        if categories == {"port"}:
            relationships.append(("related_service", 0.9, "Open-port observations describe services on the same asset or scan."))
        elif categories == {"dns", "http"}:
            relationships.append(("related_dns", 0.9, "DNS and HTTP observations connect name resolution to web service data."))
        elif categories == {"dns", "tls"}:
            relationships.append(("related_tls", 0.9, "DNS and TLS observations connect the asset name to certificate data."))
        elif "subdomain" in categories and "dns" in categories:
            relationships.append(("related_dns", 0.9, "The subdomain and DNS observations describe the same naming surface."))
        elif "port" in categories and "http" in categories:
            relationships.append(("related_http", 0.9, "The port and HTTP observations describe the same web-facing service."))
        if "cloud" in categories and (left_scan & right_scan or left_asset & right_asset):
            relationships.append(("related_cloud", 0.85, "Cloud observations share the scan or asset context."))
        return relationships

    def _identity(self, evidence: Evidence, context: InvestigationContext) -> tuple[Any, ...]:
        finding_ids = self._finding_ids(evidence)
        if finding_ids and evidence.type in {"finding_observation", "scan_result", "finding"}:
            return ("finding", sorted(finding_ids)[0])
        assets = tuple(sorted(self._asset_values(evidence, context)))
        return ("evidence", evidence.source, evidence.type, evidence.finding, evidence.raw_reference, assets)

    def _category(self, evidence: Evidence) -> str:
        text = f"{evidence.type} {evidence.finding}".lower()
        keys = {key.lower() for key, _ in self._walk_values(evidence.metadata)}
        if "port" in keys or "port" in text:
            return "port"
        if keys & {"dns", "dns_records", "record", "records"} or "dns" in text:
            return "dns"
        if keys & {"ssl", "tls", "certificate", "certificates"} or "tls" in text or "ssl" in text:
            return "tls"
        if keys & {"status", "status_code", "http", "http_response", "url"} or "http" in text:
            return "http"
        if keys & {"subdomain", "subdomains"} or "subdomain" in text:
            return "subdomain"
        if keys & {"cloud", "cloud_provider", "cloud_observations"} or "cloud" in text:
            return "cloud"
        return "unknown"

    def _scan_ids(self, evidence: Evidence) -> set[str]:
        return self._string_values(evidence.metadata, {"scan_id", "scan", "scanid"}) | ({evidence.raw_reference} if evidence.type == "scan_result" else set())

    def _finding_ids(self, evidence: Evidence) -> set[str]:
        return self._string_values(evidence.metadata, {"finding_id", "findingid"})

    def _asset_values(self, evidence: Evidence, context: InvestigationContext | None) -> set[str]:
        values = self._string_values(evidence.metadata, {"hostname", "host", "domain", "target", "scan_target", "ip", "url"})
        if not values and context and context.asset:
            values.update(value for value in (context.asset.hostname, context.asset.ip, context.asset.url) if value)
        normalized: set[str] = set()
        for value in values:
            parsed = urlsplit(value)
            normalized.add((parsed.hostname or value).lower().rstrip("."))
        return normalized

    def _string_values(self, data: dict[str, Any], wanted: set[str]) -> set[str]:
        return {str(value) for key, value in self._walk_values(data) if key.lower() in wanted and isinstance(value, (str, int))}

    def _walk_values(self, value: Any) -> Iterable[tuple[str, Any]]:
        if isinstance(value, dict):
            for key, item in value.items():
                yield str(key), item
                yield from self._walk_values(item)
        elif isinstance(value, list):
            for item in value:
                yield from self._walk_values(item)

    def _named_lists(self, value: Any, names: set[str]) -> Iterable[dict[str, Any]]:
        if isinstance(value, dict):
            for key, item in value.items():
                if key.lower() in names and isinstance(item, list):
                    yield from (entry for entry in item if isinstance(entry, dict))
                yield from self._named_lists(item, names)
        elif isinstance(value, list):
            for item in value:
                yield from self._named_lists(item, names)

    def _display(self, value: Any) -> str:
        if isinstance(value, dict):
            return ", ".join(f"{key}={item}" for key, item in value.items() if key in {"port", "status", "hostname", "name", "provider"})[:240]
        return str(value)[:240]
