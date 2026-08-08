; ==========================
; Functions
; ==========================

(function_definition
    name: (identifier) @function.name) @function

; ==========================
; Classes
; ==========================

(class_definition
    name: (identifier) @class.name) @class

; ==========================
; Imports
; ==========================

(import_statement
    name: (dotted_name) @import.name) @import

(import_from_statement
    module_name: (dotted_name) @import.name) @import

; ==========================
; Variables
; ==========================

(assignment
    left: (identifier) @variable.name) @variable

; ==========================
; Calls
; ==========================

(call
    function: (identifier) @call.name) @call

(call
    function: (attribute
        attribute: (identifier) @call.name)) @call