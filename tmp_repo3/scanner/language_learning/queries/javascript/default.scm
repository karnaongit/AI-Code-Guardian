(function_declaration
  name: (identifier) @function)
(function_expression
  (identifier) @function)
(arrow_function
)
(class_declaration
  name: (identifier) @class)
(method_definition
  name: (property_identifier) @method)
(class_body
  (method_definition
    name: (property_identifier) @method))
(import_statement) @import
(call_expression
  function: (identifier) @call)
(variable_declarator
  name: (identifier) @variable)
(variable_declarator
  name: (identifier) @constant
  value: (string) @constant)
(variable_declarator
  name: (identifier) @constant
  value: (number) @constant)
(variable_declarator
  name: (identifier) @constant
  value: (true) @constant)
(variable_declarator
  name: (identifier) @constant
  value: (false) @constant)
(variable_declarator
  name: (identifier) @constant
  value: (null) @constant)