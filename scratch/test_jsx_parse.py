import os
import sys

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from scanner.language_manager import LanguageManager
from tree_sitter import Parser

def main():
    lm = LanguageManager()
    
    # We pretend the file is .js to get the 'javascript' language
    language_name, language = lm.detect_language("test.js")
    
    parser = Parser(language)
    
    jsx_code = """
    import React from 'react';
    const App = () => {
        return (
            <div className="App">
                <h1>Hello World</h1>
                <Button onClick={() => alert('hi')}>Click me</Button>
            </div>
        );
    }
    """
    
    tree = parser.parse(jsx_code.encode("utf-8"))
    
    if tree.root_node.has_error:
        print("FAIL: The JavaScript parser encountered errors parsing JSX.")
        # print first error
        print(tree.root_node.sexp())
    else:
        print("PASS: The JavaScript parser successfully parsed JSX without errors.")
        print(tree.root_node.sexp())

if __name__ == '__main__':
    main()
