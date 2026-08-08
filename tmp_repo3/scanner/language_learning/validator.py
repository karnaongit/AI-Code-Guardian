from __future__ import annotations

import time

from tree_sitter import Language, Parser, Query, QueryCursor


from scanner.language_learning.models import (
    GeneratedQuery,
    GrammarAnalysis,
    ValidationResult,
)


class QueryValidator:
    """
    Validates a generated Tree-sitter query.

    Validation Steps
    ----------------
    1. Compile query
    2. Execute query
    3. Count captures
    4. Compute coverage
    5. Compute confidence
    """

    def validate(
    self,
    language: Language,
    analysis: GrammarAnalysis,
    query: GeneratedQuery,
    source_code: str,
) -> ValidationResult:

        warnings = []
        errors = []

        start = time.perf_counter()

        try:

            parser = Parser(language)

            tree = parser.parse(
                source_code.encode("utf-8")
            )

            compiled_query = Query(
                language,
                query.source,
            )

            cursor = QueryCursor(compiled_query)

            capture_dict = cursor.captures(
                tree.root_node
            )

            capture_count = sum(
                len(nodes)
                for nodes in capture_dict.values()
            )

            named_nodes = max(
    len(analysis.named_node_types),
    1,
)

            coverage = min(
                capture_count / named_nodes,
                1.0,
            )

            confidence = (
                coverage * 0.7
                + (1.0 if capture_count else 0.0) * 0.3
            )

        except Exception as exc:
            print("=" * 80)
            print("QUERY VALIDATION FAILED - ATTEMPTING SALVAGE")
            print("=" * 80)
            print(exc)
            
            # Try to salvage valid blocks
            blocks = []
            depth = 0
            current_block = []
            
            # Simple parenthese matching to extract top-level patterns
            for char in query.source:
                current_block.append(char)
                if char == '(': depth += 1
                elif char == ')': depth -= 1
                
                if depth == 0 and char in ' \n\t\r' and current_block:
                    # Only complete block if depth is 0 and we hit whitespace after closing
                    pass
                if depth == 0 and ''.join(current_block).strip() and (char == '\n' or not current_block):
                    # We have a candidate block (wait, captures like @class might follow `)`)
                    pass
                    
            # Better approach: split by \n\n or just try line-by-line parsing
            # Let's use a simpler heuristic: look for top level (
            import re
            
            raw_blocks = []
            current = []
            depth = 0
            
            for line in query.source.split('\n'):
                # strip comments if any, though LLM is told not to use them
                line_clean = line.split(';')[0]
                
                for char in line_clean:
                    if char == '(': depth += 1
                    elif char == ')': depth -= 1
                    
                current.append(line)
                
                if depth == 0 and current:
                    text = '\n'.join(current).strip()
                    if text:
                        raw_blocks.append(text)
                    current = []
                    
            if current:
                text = '\n'.join(current).strip()
                if text:
                    raw_blocks.append(text)

            valid_blocks = []
            for block in raw_blocks:
                try:
                    Query(language, block)
                    valid_blocks.append(block)
                except Exception:
                    pass
                    
            if not valid_blocks:
                errors.append(f"{type(exc).__name__}: {exc} (Could not salvage any blocks)")
                return ValidationResult(
                    valid=False,
                    coverage=0.0,
                    captures=0,
                    confidence=0.0,
                    execution_time=0.0,
                    warnings=tuple(),
                    errors=tuple(errors),
                )
                
            recovered_query = "\n\n".join(valid_blocks)
            print("SALVAGED QUERY:")
            print(recovered_query)
            
            # Re-evaluate with recovered query
            try:
                parser = Parser(language)
                tree = parser.parse(source_code.encode("utf-8"))
                compiled_query = Query(language, recovered_query)
                cursor = QueryCursor(compiled_query)
                capture_dict = cursor.captures(tree.root_node)
                
                capture_count = sum(len(nodes) for nodes in capture_dict.values())
                named_nodes = max(len(analysis.named_node_types), 1)
                coverage = min(capture_count / named_nodes, 1.0)
                confidence = (coverage * 0.7 + (1.0 if capture_count else 0.0) * 0.3)
                
                elapsed = time.perf_counter() - start
                
                if capture_count == 0:
                    warnings.append("Recovered query produced zero captures.")
                    
                return ValidationResult(
                    valid=capture_count > 0,
                    coverage=coverage,
                    captures=capture_count,
                    confidence=confidence,
                    execution_time=elapsed,
                    warnings=tuple(warnings),
                    errors=tuple(errors),
                    recovered_query=recovered_query,
                )
            except Exception as e:
                errors.append(f"{type(e).__name__}: {e} (Failed on recovered query)")
                return ValidationResult(
                    valid=False,
                    coverage=0.0,
                    captures=0,
                    confidence=0.0,
                    execution_time=0.0,
                    warnings=tuple(),
                    errors=tuple(errors),
                )

        elapsed = time.perf_counter() - start

        if capture_count == 0:
            warnings.append("Query produced zero captures.")

        return ValidationResult(
            valid=capture_count > 0,
            coverage=coverage,
            captures=capture_count,
            confidence=confidence,
            execution_time=elapsed,
            warnings=tuple(warnings),
            errors=tuple(errors),
        )