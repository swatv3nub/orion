from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable
from urllib.parse import urlsplit

from app.engine.graph import EvidenceGraph
from app.models import CorrelationResult, Evidence, EvidenceRelation, InvestigationContext


RECONIX_TYPES = {
    "port": "port", "dns": "dns", "ssl": "tls", "tls": "tls", "http": "http",
    "subdomain": "subdomain", "subdomains": "subdomain", "cloud": "cloud", "whois": "whois",
    "crawl": "crawl", "javascript": "javascript", "parameters": "parameter", "fuzzing": "fuzzing", "templates": "template",
}
PROVENANCE_TYPES = {"same_scan", "same_finding", "same_source"}


class EvidenceCorrelator:
    """Normalizes scan findings and correlates only atomic observations.

    Provenance links have no reasoning weight. Hypotheses use direct evidence,
    corroboration, contradictions, and unresolved requirements, never record or
    relationship counts.
    """

    def correlate(self, context: InvestigationContext, graph: EvidenceGraph) -> CorrelationResult:
        self._normalize_scan_results(context, graph)
        canonical, duplicates = self._deduplicate(context.evidence, context)
        relations = self._relations(context.evidence, canonical, duplicates, context)
        for relation in relations:
            graph.add_edge(relation.source_evidence_id, relation.target_evidence_id, relation.relationship_type)
        return CorrelationResult(
            relationships=relations,
            unique_evidence_ids=canonical,
            duplicate_evidence_ids=list(duplicates),
            duplicate_of=duplicates,
            raw_evidence_count=len(context.evidence),
            canonical_evidence_count=len(canonical),
            semantic_relationship_count=sum(item.relationship_type not in PROVENANCE_TYPES for item in relations),
            provenance_relationship_count=sum(item.relationship_type in PROVENANCE_TYPES for item in relations),
        )

    def _normalize_scan_results(self, context: InvestigationContext, graph: EvidenceGraph) -> None:
        additions: list[Evidence] = []
        for scan in context.evidence:
            if scan.type != "scan_result":
                continue
            for finding in self._findings(scan.metadata):
                category = self._category(finding)
                detail = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else finding
                for observation in self._atomic_entries(category, detail):
                    metadata = {"observation_type": category, "scan_id": self._scan_id(scan, finding), **observation}
                    metadata["finding_id"] = str(finding.get("id") or finding.get("finding_id") or scan.metadata.get("finding_id") or "")
                    asset = self._asset(metadata, context)
                    if asset:
                        metadata["hostname"] = asset
                    additions.append(Evidence(
                        id=f"{context.investigation_id}:E-{len(context.evidence) + len(additions) + 1:03d}",
                        source=scan.source,
                        type=f"reconix_{category}_observation",
                        finding=self._text(category, metadata, asset),
                        confidence=scan.confidence,
                        raw_reference=scan.raw_reference,
                        metadata=metadata,
                        provenance=[{"source": scan.source, "scan_id": metadata["scan_id"], "finding_id": metadata["finding_id"]}],
                    ))
        for item in additions:
            context.evidence.append(item)
            graph.add_node(item.id, "evidence", item.model_dump(mode="json"))

    def _findings(self, data: Any) -> Iterable[dict[str, Any]]:
        if isinstance(data, dict):
            for key, category in RECONIX_TYPES.items():
                value = data.get(key) or data.get(f"{key}s")
                if value is not None and key in {"port", "dns", "ssl", "tls", "http", "subdomain", "cloud", "whois"}:
                    for item in value if isinstance(value, list) else [value]:
                        yield {"type": key, "evidence": item if isinstance(item, dict) else {key: item}}
            if self._category(data) != "observation" and ("evidence" in data or "type" in data or "category" in data):
                yield data
            for key, value in data.items():
                if key.lower() in {"findings", "results", "observations", "items", "data"}:
                    yield from self._findings(value)
        elif isinstance(data, list):
            for item in data:
                yield from self._findings(item)

    def _category(self, finding: dict[str, Any]) -> str:
        metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        raw = str(finding.get("type") or metadata.get("category") or finding.get("category") or "").lower()
        return RECONIX_TYPES.get(raw, "observation")

    def _atomic_entries(self, category: str, detail: dict[str, Any]) -> Iterable[dict[str, Any]]:
        if category != "whois" or "field" in detail or "value" in detail:
            yield detail
            return
        identity = {key: value for key, value in detail.items() if key in {"hostname", "domain", "url"}}
        for field, value in detail.items():
            if field not in identity and isinstance(value, (str, int, float)):
                yield {**identity, "field": field, "value": value}

    def _deduplicate(self, evidence: list[Evidence], context: InvestigationContext) -> tuple[list[str], dict[str, str]]:
        canonical: list[str] = []
        duplicates: dict[str, str] = {}
        seen: dict[tuple[str, str, tuple[tuple[str, str], ...]], Evidence] = {}
        for item in evidence:
            category = self._evidence_category(item)
            if item.type in {"scan_result", "historical_alert", "history_query"}:
                finding_id = self._finding_id(item)
                if finding_id:
                    primary = next((known for known in seen.values() if self._finding_id(known) == finding_id), None)
                    if primary:
                        item.canonical_evidence_id = primary.id
                        duplicates[item.id] = primary.id
                continue
            if category == "observation" and not item.metadata.get("contradicts"):
                continue
            key = (category, self._asset(item.metadata, context) or "", self._facts(category, item.metadata))
            if key in seen:
                item.canonical_evidence_id = seen[key].id
                item.provenance.append({"source": item.source, "raw_reference": item.raw_reference})
                seen[key].provenance.extend(item.provenance)
                duplicates[item.id] = seen[key].id
            else:
                item.canonical_evidence_id = item.id
                item.provenance.append({"source": item.source, "raw_reference": item.raw_reference})
                seen[key] = item
                canonical.append(item.id)
        return canonical, duplicates

    def _relations(self, evidence: list[Evidence], canonical: list[str], duplicates: dict[str, str], context: InvestigationContext) -> list[EvidenceRelation]:
        by_id = {item.id: item for item in evidence}
        relations: list[EvidenceRelation] = []
        added: set[tuple[str, str, str]] = set()

        def add(left: str, right: str, kind: str, confidence: float, rationale: str) -> None:
            if kind in {"same_asset", "related_service", "related_dns", "related_tls", "related_cloud", "corroborates", "contradicts"}:
                left, right = sorted((left, right))
            key = (left, right, kind)
            if left != right and key not in added:
                added.add(key)
                relations.append(EvidenceRelation(source_evidence_id=left, target_evidence_id=right, relationship_type=kind, confidence=confidence, rationale=rationale))

        for duplicate, primary in duplicates.items():
            left, right = by_id[primary], by_id[duplicate]
            if self._finding_id(left) and self._finding_id(left) == self._finding_id(right):
                add(primary, duplicate, "same_finding", 1.0, "Both records preserve the same finding provenance.")
            if left.source != right.source:
                add(primary, duplicate, "corroborates", 0.9, "Independent sources report the same atomic observation.")

        groups: dict[str, list[Evidence]] = defaultdict(list)
        for evidence_id in canonical:
            item = by_id[evidence_id]
            asset = self._asset(item.metadata, context)
            if asset:
                groups[asset].append(item)
        for asset, items in groups.items():
            categories: dict[str, list[Evidence]] = defaultdict(list)
            for item in items:
                categories[self._evidence_category(item)].append(item)
            for left in categories["port"]:
                for right in categories["port"]:
                    if left.id < right.id:
                        add(left.id, right.id, "related_service", 0.7, f"Both ports are observed on {asset}.")
                for right in categories["http"]:
                    add(left.id, right.id, "related_http", 0.8, f"The port and HTTP response describe {asset}.")
            for left in categories["dns"]:
                for right in items:
                    if right.id != left.id and self._evidence_category(right) in {"port", "http", "tls", "subdomain"}:
                        add(left.id, right.id, "related_dns", 0.6, f"DNS and service observations resolve to {asset}.")
            for left in categories["tls"]:
                for right in categories["http"] + categories["dns"] + categories["subdomain"]:
                    add(left.id, right.id, "related_tls", 0.7, f"TLS data is associated with {asset}.")
        clouds: dict[str, list[Evidence]] = defaultdict(list)
        for evidence_id in canonical:
            item = by_id[evidence_id]
            if self._evidence_category(item) == "cloud" and (family := self._cloud_family(item)):
                clouds[family].append(item)
        for family, items in clouds.items():
            for index, left in enumerate(items):
                for right in items[index + 1:]:
                    add(left.id, right.id, "related_cloud", 0.5, f"Cloud resource names share the {family} family.")
        for item in evidence:
            targets = item.metadata.get("contradicts")
            if isinstance(targets, list):
                for target in targets:
                    for candidate in canonical:
                        if target == candidate:
                            add(item.id, candidate, "contradicts", 0.9, "Evidence explicitly identifies a conflicting observation.")
        return relations

    def _evidence_category(self, item: Evidence) -> str:
        value = item.metadata.get("observation_type")
        if isinstance(value, str):
            return RECONIX_TYPES.get(value.lower(), value.lower())
        if item.type.startswith("reconix_") and item.type.endswith("_observation"):
            return item.type.removeprefix("reconix_").removesuffix("_observation")
        if item.type.endswith("_observation"):
            return item.type.removesuffix("_observation")
        if "port" in item.metadata:
            return "port"
        if "status" in item.metadata or "url" in item.metadata:
            return "http"
        return "observation"

    def _facts(self, category: str, data: dict[str, Any]) -> tuple[tuple[str, str], ...]:
        keys = {"port": ("port", "state"), "http": ("url", "status", "status_code"), "dns": ("record", "value", "ip", "address"), "tls": ("subject", "san", "certificate", "serial"), "subdomain": ("subdomain", "hostname", "name"), "cloud": ("url", "status", "status_code", "provider"), "whois": ("domain", "hostname", "field", "value")}.get(category, ())
        return tuple((key, str(data[key])) for key in keys if data.get(key) is not None)

    def _cloud_family(self, item: Evidence) -> str | None:
        url = item.metadata.get("url")
        if not isinstance(url, str):
            return None
        host = urlsplit(url).hostname or ""
        if ".s3." not in host:
            return None
        resource = host.split(".s3.", 1)[0].lower()
        for suffix in ("-dev", "-test", "-backup", "-staging"):
            if resource.endswith(suffix):
                resource = resource.removesuffix(suffix)
        return resource or None

    def _asset(self, data: dict[str, Any], context: InvestigationContext) -> str | None:
        for key in ("hostname", "host", "domain", "target", "scan_target", "url"):
            value = data.get(key)
            if isinstance(value, str) and value:
                return (urlsplit(value).hostname or value).lower().rstrip(".")
        if context.asset:
            return (context.asset.hostname or context.asset.ip or "").lower() or None
        return None

    def _scan_id(self, scan: Evidence, finding: dict[str, Any]) -> str:
        metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        return str(finding.get("scan_id") or metadata.get("scan_id") or scan.metadata.get("scan_id") or scan.raw_reference)

    def _finding_id(self, item: Evidence) -> str:
        return str(item.metadata.get("finding_id") or "")

    def _text(self, category: str, data: dict[str, Any], asset: str | None) -> str:
        host = asset or "Asset"
        if category == "port": return f"{host} has port {data.get('port', 'unknown')} open"
        if category == "http": return f"{data.get('url', host)} returned HTTP {data.get('status', data.get('status_code', 'response'))}"
        if category == "dns": return f"{host} resolves to {data.get('record', data.get('value', data.get('ip', 'a DNS record')))}"
        if category == "tls": return f"TLS certificate for {host} contains {data.get('san', data.get('subject', 'certificate data'))}"
        if category == "subdomain": return f"{data.get('subdomain', data.get('hostname', 'A subdomain'))} was discovered as a subdomain"
        if category == "cloud": return f"Cloud resource {data.get('url', host)} returned HTTP {data.get('status', data.get('status_code', 'a response'))}"
        return f"{category} observation for {host}"
