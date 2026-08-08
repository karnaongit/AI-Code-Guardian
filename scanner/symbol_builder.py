from scanner.models import (
    FunctionSymbol,
    CallSymbol,
    ClassSymbol,
    ConstantSymbol,
    ImportSymbol,
    ParsedFile,
    VariableSymbol,
)

class SymbolBuilder:
    
    def build(self, captures, language: str, filename: str = ""):
        parsed = ParsedFile(file_path=filename, language=language)
        parsed.captures = []

        primary_symbols = []
        sub_captures = []

        # Pass 1: Create primary symbols
        for capture in captures:
            capture_type = capture.capture_name.lower()
            
            if "." in capture_type:
                sub_captures.append(capture)
                continue

            symbol = None
            if capture_type.startswith("function") or capture_type.startswith("method"):
                symbol = FunctionSymbol(
                    name=capture.text,
                    line=capture.start_line,
                    snippet=capture.text,
                    end_line=capture.end_line,
                    start_byte=capture.start_byte,
                    end_byte=capture.end_byte,
                )
                parsed.functions.append(symbol)

            elif capture_type.startswith("class"):
                symbol = ClassSymbol(
                    name=capture.text,
                    line=capture.start_line,
                    snippet=capture.text,
                    end_line=capture.end_line,
                    start_byte=capture.start_byte,
                    end_byte=capture.end_byte,
                )
                parsed.classes.append(symbol)

            elif capture_type.startswith("import"):
                symbol = ImportSymbol(
                    name=capture.text,
                    line=capture.start_line,
                    snippet=capture.text,
                    end_line=capture.end_line,
                    start_byte=capture.start_byte,
                    end_byte=capture.end_byte,
                )
                parsed.imports.append(symbol)

            elif capture_type.startswith("call"):
                symbol = CallSymbol(
                    name=capture.text,
                    line=capture.start_line,
                    snippet=capture.text,
                    end_line=capture.end_line,
                    start_byte=capture.start_byte,
                    end_byte=capture.end_byte,
                )
                parsed.calls.append(symbol)

            elif capture_type.startswith("variable"):
                symbol = VariableSymbol(
                    name=capture.text,
                    line=capture.start_line,
                    snippet=capture.text,
                    end_line=capture.end_line,
                    start_byte=capture.start_byte,
                    end_byte=capture.end_byte,
                )
                parsed.variables.append(symbol)

            elif capture_type.startswith("constant"):
                symbol = ConstantSymbol(
                    name=capture.text,
                    line=capture.start_line,
                    snippet=capture.text,
                    end_line=capture.end_line,
                    start_byte=capture.start_byte,
                    end_byte=capture.end_byte,
                )
                parsed.constants.append(symbol)
                
            if symbol:
                primary_symbols.append(symbol)

        # Pass 2: Map sub-captures to context
        for capture in sub_captures:
            capture_type = capture.capture_name.lower()
            parts = capture_type.split(".", 1)
            if len(parts) != 2:
                continue
                
            primary_type, sub_field = parts
            
            # Find the tightest encompassing primary symbol of the same primary_type
            best_match = None
            best_len = float('inf')
            
            for symbol in primary_symbols:
                # Check if the symbol matches the expected primary type
                symbol_type_name = type(symbol).__name__.lower()
                if not symbol_type_name.startswith(primary_type):
                    continue

                # Basic check: the sub-capture must fall inside the primary symbol's byte range
                if symbol.start_byte <= capture.start_byte and symbol.end_byte >= capture.end_byte:
                    # To ensure we don't map to a generic wrapper if a tighter one exists
                    length = symbol.end_byte - symbol.start_byte
                    if length < best_len:
                        best_match = symbol
                        best_len = length
            
            if best_match:
                # E.g. for @call.receiver, sub_field is "receiver"
                # Store as a list in case there are multiple (e.g. multiple arguments)
                if sub_field not in best_match.context:
                    best_match.context[sub_field] = []
                best_match.context[sub_field].append(capture.text)

        # Pass 3: Parent resolution and Stable ID generation
        import hashlib
        file_id = parsed.file_id
        
        def compute_id(parent_id, sym_type, name, idx):
            basis = f"{file_id}:{parent_id}:{sym_type}:{name}:{idx}"
            return hashlib.sha1(basis.encode()).hexdigest()[:16]

        class_map = {}
        for idx, cls in enumerate(parsed.classes):
            cls.symbol_id = compute_id("root", "Class", cls.name, idx)
            class_map[idx] = cls.symbol_id
            
        func_map = {}
        for idx, func in enumerate(parsed.functions):
            parent_id = "root"
            for cls_idx, cls in enumerate(parsed.classes):
                if cls.start_byte <= func.start_byte and cls.end_byte >= func.end_byte:
                    parent_id = class_map[cls_idx]
                    func.parent_id = parent_id
                    break
            func.symbol_id = compute_id(parent_id, "Function", func.name, idx)
            func_map[idx] = func.symbol_id

        for sym_list, sym_type in [(parsed.calls, "Call"), (parsed.variables, "Variable"), (parsed.constants, "Constant"), (parsed.imports, "Import")]:
            for idx, sym in enumerate(sym_list):
                parent_id = "root"
                # Check functions first
                for func_idx, func in enumerate(parsed.functions):
                    if func.start_byte <= sym.start_byte and func.end_byte >= sym.end_byte:
                        parent_id = func_map[func_idx]
                        sym.parent_id = parent_id
                        break
                # If not in function, check classes
                if parent_id == "root":
                    for cls_idx, cls in enumerate(parsed.classes):
                        if cls.start_byte <= sym.start_byte and cls.end_byte >= sym.end_byte:
                            parent_id = class_map[cls_idx]
                            sym.parent_id = parent_id
                            break
                sym.symbol_id = compute_id(parent_id, sym_type, sym.name, idx)

        parsed.metrics = {
            "functions": len(parsed.functions),
            "classes": len(parsed.classes),
            "imports": len(parsed.imports),
            "calls": len(parsed.calls),
            "variables": len(parsed.variables),
            "constants": len(parsed.constants),
        }

        return parsed