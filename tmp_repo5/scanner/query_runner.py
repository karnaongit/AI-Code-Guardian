from tree_sitter import QueryCursor

from scanner.models import Capture


class QueryRunner:

    def run(self, query, tree):

        cursor = QueryCursor(query)

        capture_dict = cursor.captures(tree.root_node)

        output = []

        for capture_name, nodes in capture_dict.items():

            for node in nodes:

                output.append(
                    Capture(
                        capture_name=capture_name,
                        node_type=node.type,
                        text=node.text.decode("utf-8", errors="ignore"),
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        start_byte=node.start_byte,
                        end_byte=node.end_byte,
                    )
                )

        return output