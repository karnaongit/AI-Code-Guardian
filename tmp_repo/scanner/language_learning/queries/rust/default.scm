(use_declaration
  argument: (use_list (scoped_identifier path: (_) @import.source name: (identifier) @import.name)) @import
) @import

(call_expression
  function: (_) @call.function
  arguments: (arguments (_) @call.argument)
) @call

(let_declaration
  pattern: (_) @variable.name
  type: (_) @variable.type
  value: (_) @variable.value
) @variable

(const_item
  name: (identifier) @constant.name
  type: (_) @constant.type
  value: (_) @constant.value
) @constant

(static_item
  name: (identifier) @constant.name
  type: (_) @constant.type
  value: (_) @constant.value
) @constant