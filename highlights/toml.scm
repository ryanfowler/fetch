; Originally taken from github.com/tree-sitter/tree-sitter-toml
; which uses the MIT license

; Properties
;-----------

(bare_key) @type
(quoted_key) @string
(pair (bare_key)) @property
(pair (dotted_key (bare_key))) @property

; Literals
;---------

(boolean) @constant.builtin
(comment) @comment
(string) @string
(integer) @number
(float) @number
(offset_date_time) @string.special
(local_date_time) @string.special
(local_date) @string.special
(local_time) @string.special

; Punctuation
;------------

"." @punctuation.delimiter
"," @punctuation.delimiter

"=" @operator

"[" @punctuation.bracket
"]" @punctuation.bracket
"[[" @punctuation.bracket
"]]" @punctuation.bracket
"{" @punctuation.bracket
"}" @punctuation.bracket
