from __future__ import annotations

from typing import Any

from app.models import InvestigationContext


class EvidenceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, str]] = []

    def add_node(self, node_id: str, node_type: str, data: Any = None) -> None:
        self.nodes[node_id] = {"id": node_id, "type": node_type, "data": data}

    def add_edge(self, source: str, target: str, relation: str = "related") -> None:
        self.edges.append({"source": source, "target": target, "relation": relation})

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        return self.nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> list[dict[str, Any]]:
        ids = [e["target"] for e in self.edges if e["source"] == node_id]
        ids += [e["source"] for e in self.edges if e["target"] == node_id]
        return [self.nodes[node_id] for node_id in ids if node_id in self.nodes]

    def find_by_type(self, node_type: str) -> list[dict[str, Any]]:
        return [node for node in self.nodes.values() if node["type"] == node_type]

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": list(self.nodes.values()), "edges": self.edges}


def build_graph(context: InvestigationContext) -> EvidenceGraph:
    graph = EvidenceGraph()
    alert_id = f"alert:{context.primary_alert.alert_id}"
    finding_id = f"finding:{context.primary_alert.alert_id}"
    graph.add_node(alert_id, "alert", context.primary_alert.model_dump(mode="json"))
    graph.add_node(finding_id, "finding", context.primary_alert.finding.model_dump(mode="json"))
    graph.add_edge(alert_id, finding_id, "contains")
    if context.asset:
        asset_id = f"asset:{context.asset.hostname or context.asset.ip or context.asset.url or context.investigation_id}"
        graph.add_node(asset_id, "asset", context.asset.model_dump(mode="json"))
        graph.add_edge(alert_id, asset_id, "targets")
    for evidence in context.evidence:
        graph.add_node(evidence.id, "evidence", evidence.model_dump(mode="json"))
        graph.add_edge(finding_id, evidence.id, "supported_by")
    return graph
