from __future__ import annotations

import json


from scanner.language_learning.models import (
    GrammarAnalysis,
    GrammarMetadata,
)


class GrammarAnalyzer:
    """
    Analyzes Tree-sitter grammar metadata.
    """
    def analyze(
        self,
        grammar: GrammarMetadata,
    ) -> GrammarAnalysis:

        with grammar.node_types_file.open(
            "r",
            encoding="utf-8",
        ) as file:
            node_data = json.load(file)

        node_types = []
        named_node_types = []

        root_node = None

        field_map = {}
        children_map = {}
        subtype_map = {}

        for node in node_data:

            node_type = node.get("type")

            if node_type is None:
                continue

            node_types.append(node_type)

            if node.get("named", False):
                named_node_types.append(node_type)

            if root_node is None and node.get("subtypes"):
                root_node = node_type

            # --------------------------
            # Fields
            # --------------------------

            fields = {}

            for field_name, field in node.get("fields", {}).items():

                field_types = tuple(
                    child["type"]
                    for child in field.get("types", [])
                )

                fields[field_name] = field_types

                field_map[node_type] = fields

            # --------------------------
            # Children
            # --------------------------

            children = tuple(
                child["type"]
                for child in node.get("children", {}).get("types", [])
            )

            children_map[node_type] = children

            # --------------------------
            # Subtypes
            # --------------------------

            subtype_map[node_type] = tuple(
                subtype["type"]
                for subtype in node.get("subtypes", [])
            )
            
            statistics = {
                "total_nodes": len(node_types),
                "named_nodes": len(named_node_types),
                "nodes_with_fields": sum(
                    1 for fields in field_map.values() if fields
                ),
                "nodes_with_children": sum(
                    1 for children in children_map.values() if children
                ),
                "nodes_with_subtypes": sum(
                    1 for subtypes in subtype_map.values() if subtypes
                ),
}
        print("=" * 80)
        print("Grammar:", grammar.language)
        print("Total Nodes:", len(node_types))

        print("\nFunction Definition Fields:")
        print(field_map.get("function_definition"))

        print("\nCall Expression Fields:")
        print(field_map.get("call_expression"))

        print("\nExpression Subtypes:")
        print(subtype_map.get("expression"))

        print("=" * 80)
        return GrammarAnalysis(
            grammar=grammar,
            node_types=tuple(sorted(node_types)),
            named_node_types=tuple(sorted(named_node_types)),
            root_node=root_node,
            statistics=statistics,
            field_map=field_map,
            children_map=children_map,
            subtype_map=subtype_map,
)
        