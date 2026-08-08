from scanner.models import ParsedFile, Symbol

class ContextEnricher:
    """
    Enriches generic symbols with spatial and relational context.
    This operates completely generically, without any language-specific rules.
    """

    def enrich(self, parsed_file: ParsedFile) -> ParsedFile:
        
        self._enrich_scope(parsed_file)
        self._enrich_resolved_imports(parsed_file)
        
        return parsed_file

    def _enrich_scope(self, parsed_file: ParsedFile):
        """
        Determines the scope of each symbol by finding the tightest encompassing
        FunctionSymbol or ClassSymbol.
        """
        # All scope-providing symbols
        scopers = parsed_file.functions + parsed_file.classes

        # All symbols to enrich
        targets = (
            parsed_file.calls +
            parsed_file.variables +
            parsed_file.constants +
            parsed_file.functions + 
            parsed_file.classes
        )

        for target in targets:
            best_scoper = None
            best_len = float('inf')

            for scoper in scopers:
                if scoper is target:
                    continue

                if scoper.start_byte <= target.start_byte and scoper.end_byte >= target.end_byte:
                    length = scoper.end_byte - scoper.start_byte
                    if length < best_len:
                        best_scoper = scoper
                        best_len = length

            if best_scoper:
                target.context["scope"] = best_scoper.name
                target.context["scope_type"] = type(best_scoper).__name__

    def _enrich_resolved_imports(self, parsed_file: ParsedFile):
        """
        Attempts to resolve external dependencies for calls based on imports.
        """
        import_names = {imp.name for imp in parsed_file.imports}
        
        for call in parsed_file.calls:
            # Check if the call itself matches an import
            if call.name in import_names:
                call.context["resolved_import"] = call.name
                continue
                
            # Check if any receiver matches an import
            receivers = call.context.get("receiver", [])
            for receiver in receivers:
                if receiver in import_names:
                    call.context["resolved_import"] = receiver
                    break
