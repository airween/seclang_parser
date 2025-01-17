/*
BSD License
Copyright (c) 2023 Felipe Zipitria
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of Tom Everett nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
Adapted from pascal.g by  Hakki Dogusan, Piet Schoutteten and Marton Papp
*/
parser grammar SecLangParser;

options { tokenVocab=SecLangLexer; }

configuration
     : stmt* EOF
     ;

stmt:
    rules_directive variables operator actions
    | engine_config_directive config_value_types
    | COMMENT;

rules_directive:
    CONFIG_SEC_RULE_REMOVE_BY_ID
    | CONFIG_SEC_RULE_REMOVE_BY_MSG
    | CONFIG_SEC_RULE_REMOVE_BY_TAG
    | CONFIG_SEC_RULE_UPDATE_ACTION_BY_ID
    | CONFIG_SEC_RULE_UPDATE_TARGET_BY_ID
    | CONFIG_SEC_RULE_UPDATE_TARGET_BY_MSG
    | CONFIG_SEC_RULE_UPDATE_TARGET_BY_TAG
    | DIRECTIVE
    | DIRECTIVE_SECRULESCRIPT
    ;

engine_config_directive:
    stmt_audit_log
    | CONFIG_COMPONENT_SIG
    | CONFIG_CONN_ENGINE
    | CONFIG_CONTENT_INJECTION
    | CONFIG_DIR_ARGS_LIMIT
    | CONFIG_DIR_DEBUG_LOG
    | CONFIG_DIR_DEBUG_LVL
    | CONFIG_DIR_GEO_DB
    | CONFIG_DIR_GSB_DB
    | CONFIG_DIR_PCRE_MATCH_LIMIT
    | CONFIG_DIR_PCRE_MATCH_LIMIT_RECURSION
    | CONFIG_DIR_REQ_BODY
    | CONFIG_DIR_REQ_BODY_JSON_DEPTH_LIMIT
    | CONFIG_DIR_REQ_BODY_LIMIT INT
    | CONFIG_DIR_REQ_BODY_LIMIT_ACTION
    | CONFIG_DIR_REQ_BODY_NO_FILES_LIMIT
    | CONFIG_DIR_RESPONSE_BODY_MP
    | CONFIG_DIR_RESPONSE_BODY_MP_CLEAR
    | CONFIG_DIR_RES_BODY
    | CONFIG_DIR_RES_BODY_LIMIT
    | CONFIG_DIR_RES_BODY_LIMIT_ACTION
    | CONFIG_DIR_RULE_ENG
    | CONFIG_DIR_SEC_ACTION
    | CONFIG_DIR_SEC_COOKIE_FORMAT
    | CONFIG_DIR_SEC_DATA_DIR
    | CONFIG_DIR_SEC_DEFAULT_ACTION
    | CONFIG_DIR_SEC_MARKER
    | CONFIG_DIR_SEC_STATUS_ENGINE
    | CONFIG_DIR_SEC_TMP_DIR
    | CONFIG_DIR_UNICODE_MAP_FILE
    | CONFIG_SEC_ARGUMENT_SEPARATOR
    | CONFIG_SEC_CACHE_TRANSFORMATIONS
    | CONFIG_SEC_CHROOT_DIR
    | CONFIG_SEC_COLLECTION_TIMEOUT
    | CONFIG_SEC_CONN_R_STATE_LIMIT
    | CONFIG_SEC_CONN_W_STATE_LIMIT
    | CONFIG_SEC_COOKIEV0_SEPARATOR
    | CONFIG_SEC_DISABLE_BACKEND_COMPRESS
    | CONFIG_SEC_GUARDIAN_LOG
    | CONFIG_SEC_HASH_ENGINE
    | CONFIG_SEC_HASH_KEY
    | CONFIG_SEC_HASH_METHOD_PM
    | CONFIG_SEC_HASH_METHOD_RX
    | CONFIG_SEC_HASH_PARAM
    | CONFIG_SEC_HTTP_BLKEY
    | CONFIG_SEC_INTERCEPT_ON_ERROR
    | CONFIG_SEC_REMOTE_RULES_FAIL_ACTION
    | CONFIG_SEC_RULE_INHERITANCE
    | CONFIG_SEC_RULE_PERF_TIME
    | CONFIG_SEC_SENSOR_ID
    | CONFIG_SEC_SERVER_SIG
    | CONFIG_SEC_STREAM_IN_BODY_INSPECTION
    | CONFIG_SEC_STREAM_OUT_BODY_INSPECTION
    | CONFIG_SEC_WEB_APP_ID IDENT
    | CONFIG_XML_EXTERNAL_ENTITY
    ;

stmt_audit_log:
    CONFIG_DIR_AUDIT_DIR_MOD
    | CONFIG_DIR_AUDIT_DIR
    | CONFIG_DIR_AUDIT_ENG
    | CONFIG_DIR_AUDIT_FILE_MODE
    | CONFIG_DIR_AUDIT_LOG2
    | CONFIG_DIR_AUDIT_LOG_P
    | CONFIG_DIR_AUDIT_LOG
    | CONFIG_DIR_AUDIT_LOG_FMT
    | CONFIG_DIR_AUDIT_STS
    | CONFIG_DIR_AUDIT_TYPE
    | CONFIG_UPLOAD_KEEP_FILES
    | CONFIG_UPLOAD_FILE_LIMIT
    | CONFIG_UPLOAD_FILE_MODE
    | CONFIG_UPLOAD_DIR
    | CONFIG_UPLOAD_SAVE_TMP_FILES
    | INT
    ;

config_value_types:
    QUOTE values QUOTE
    ;

values:
    CONFIG_VALUE_ON
    | CONFIG_VALUE_OFF
    | CONFIG_VALUE_SERIAL
    | CONFIG_VALUE_PARALLEL
    | CONFIG_VALUE_HTTPS
    | CONFIG_VALUE_RELEVANT_ONLY
    | JSON
    | NATIVE
    | CONFIG_VALUE_ABORT
    | CONFIG_VALUE_WARN
    | CONFIG_VALUE_DETC
    | CONFIG_VALUE_PROCESS_PARTIAL
    | CONFIG_VALUE_REJECT
    ;
// | CONFIG_VALUE_PATH
operator:
    QUOTE NOT? AT operator_name operator_value QUOTE
    ;

operator_name:
    OPERATOR_UNCONDITIONAL_MATCH
    | OPERATOR_DETECT_SQLI
    | OPERATOR_DETECT_XSS
    | OPERATOR_VALIDATE_URL_ENCODING
    | OPERATOR_VALIDATE_UTF8_ENCODING
    | OPERATOR_INSPECT_FILE
    | OPERATOR_FUZZY_HASH
    | OPERATOR_VALIDATE_BYTE_RANGE
    | OPERATOR_VALIDATE_DTD
    | OPERATOR_VALIDATE_HASH
    | OPERATOR_VALIDATE_SCHEMA
    | OPERATOR_VERIFY_CC
    | OPERATOR_VERIFY_CPF
    | OPERATOR_VERIFY_SSN
    | OPERATOR_VERIFY_SVNR
    | OPERATOR_GSB_LOOKUP
    | OPERATOR_RSUB
    | OPERATOR_WITHIN
    | OPERATOR_CONTAINS_WORD
    | OPERATOR_CONTAINS
    | OPERATOR_ENDS_WITH
    | OPERATOR_EQ
    | OPERATOR_GE
    | OPERATOR_GT
    | OPERATOR_IP_MATCH_FROM_FILE
    | OPERATOR_IP_MATCH
    | OPERATOR_LE
    | OPERATOR_LT
    | OPERATOR_PM_FROM_FILE
    | OPERATOR_PM
    | OPERATOR_RBL
    | OPERATOR_RX
    | OPERATOR_RX_GLOBAL
    | OPERATOR_STR_EQ
    | OPERATOR_STR_MATCH
    | OPERATOR_BEGINS_WITH
    | OPERATOR_GEOLOOKUP
    ;

operator_value:
    variable_name
    | FREE_TEXT_QUOTE_MACRO_EXPANSION
    ;

variables:
    QUOTE? NOT? VAR_COUNT? var_stmt QUOTE? (PIPE QUOTE var_stmt QUOTE)*
    ;

var_stmt:
    variable_name (':' collection_element_or_regexp)? variable_value?
    ;

collection_element_or_regexp:
    VARIABLE_NAME
    | REGEXP
    ;

variable_name:
    | VARIABLE_ARGS
    | VARIABLE_ARGS_COMBINED_SIZE
    | VARIABLE_ARGS_GET
    | VARIABLE_ARGS_GET_NAMES
    | VARIABLE_ARGS_NAMES
    | VARIABLE_ARGS_POST
    | VARIABLE_ARGS_POST_NAMES
    | VARIABLE_AUTH_TYPE
    | VARIABLE_FILES
    | VARIABLE_FILES_COMBINED_SIZE
    | VARIABLE_FILES_NAMES
    | VARIABLE_FILES_SIZES
    | VARIABLE_FILES_TMP_CONTENT
    | VARIABLE_FILES_TMP_NAMES
    | VARIABLE_FULL_REQUEST
    | VARIABLE_FULL_REQUEST_LENGTH
    | VARIABLE_GEO
    | VARIABLE_GLOBAL
    | VARIABLE_INBOUND_DATA_ERROR
    | VARIABLE_IP
    | VARIABLE_MATCHED_VAR
    | VARIABLE_MATCHED_VARS
    | VARIABLE_MATCHED_VARS_NAMES
    | VARIABLE_MATCHED_VAR_NAME
    | VARIABLE_MSC_PCRE_ERROR
    | VARIABLE_MSC_PCRE_LIMITS_EXCEEDED
    | VARIABLE_MULTIPART_BOUNDARY_SINGLE_QUOTED
    | VARIABLE_MULTIPART_BOUNDARY_WHITESPACE
    | VARIABLE_MULTIPART_CRLF_LF_LINES
    | VARIABLE_MULTIPART_DATA_AFTER
    | VARIABLE_MULTIPART_DATA_BEFORE
    | VARIABLE_MULTIPART_FILENAME
    | VARIABLE_MULTIPART_FILE_LIMIT_EXCEEDED
    | VARIABLE_MULTIPART_HEADER_FOLDING
    | VARIABLE_MULTIPART_INVALID_HEADER_FOLDING
    | VARIABLE_MULTIPART_INVALID_PART
    | VARIABLE_MULTIPART_INVALID_QUOTING
    | VARIABLE_MULTIPART_LF_LINE
    | VARIABLE_MULTIPART_MISSING_SEMICOLON
    | VARIABLE_MULTIPART_NAME
    | VARIABLE_MULTIPART_PART_HEADERS
    | VARIABLE_MULTIPART_SEMICOLON_MISSING
    | VARIABLE_MULTIPART_STRICT_ERROR
    | VARIABLE_MULTIPART_UNMATCHED_BOUNDARY
    | VARIABLE_OUTBOUND_DATA_ERROR
    | VARIABLE_PATH_INFO
    | VARIABLE_QUERY_STRING
    | VARIABLE_REMOTE_ADDR
    | VARIABLE_REMOTE_HOST
    | VARIABLE_REMOTE_PORT
    | VARIABLE_REQBODY_ERROR
    | VARIABLE_REQBODY_ERROR_MSG
    | VARIABLE_REQBODY_PROCESSOR
    | VARIABLE_REQBODY_PROCESSOR_ERROR
    | VARIABLE_REQBODY_PROCESSOR_ERROR_MSG
    | VARIABLE_REQUEST_BASENAME
    | VARIABLE_REQUEST_BODY
    | VARIABLE_REQUEST_BODY_LENGTH
    | VARIABLE_REQUEST_COOKIES
    | VARIABLE_REQUEST_COOKIES_NAMES
    | VARIABLE_REQUEST_FILE_NAME
    | VARIABLE_REQUEST_HEADERS
    | VARIABLE_REQUEST_HEADERS_NAMES
    | VARIABLE_REQUEST_LINE
    | VARIABLE_REQUEST_METHOD
    | VARIABLE_REQUEST_PROTOCOL
    | VARIABLE_REQUEST_URI
    | VARIABLE_REQUEST_URI_RAW
    | VARIABLE_RESOURCE
    | VARIABLE_RESPONSE_BODY
    | VARIABLE_RESPONSE_CONTENT_LENGTH
    | VARIABLE_RESPONSE_CONTENT_TYPE
    | VARIABLE_RESPONSE_HEADERS
    | VARIABLE_RESPONSE_HEADERS_NAMES
    | VARIABLE_RESPONSE_PROTOCOL
    | VARIABLE_RESPONSE_STATUS
    | VARIABLE_RULE
    | VARIABLE_SERVER_ADDR
    | VARIABLE_SERVER_NAME
    | VARIABLE_SERVER_PORT
    | VARIABLE_SESSION
    | VARIABLE_SESSION_ID
    | VARIABLE_STATUS
    | VARIABLE_STATUS_LINE
    | VARIABLE_TX
    | VARIABLE_UNIQUE_ID
    | VARIABLE_URL_ENCODED_ERROR
    | VARIABLE_USER
    | VARIABLE_USER_ID
    | VARIABLE_WEB_APP_ID
    | RUN_TIME_VAR_BLD
    | RUN_TIME_VAR_DUR
    | RUN_TIME_VAR_ENV
    | RUN_TIME_VAR_HSV
    | RUN_TIME_VAR_REMOTE_USER
    | RUN_TIME_VAR_TIME
    | RUN_TIME_VAR_TIME_DAY
    | RUN_TIME_VAR_TIME_EPOCH
    | RUN_TIME_VAR_TIME_HOUR
    | RUN_TIME_VAR_TIME_MIN
    | RUN_TIME_VAR_TIME_MON
    | RUN_TIME_VAR_TIME_SEC
    | RUN_TIME_VAR_TIME_WDAY
    | RUN_TIME_VAR_TIME_WDAY
    | RUN_TIME_VAR_TIME_YEAR
//    | RUN_TIME_VAR_XML
    ;

actions:
    QUOTE action (COMMA action)* QUOTE
    ;

action:
    action_with_params COLON NOT? EQUAL? action_value
    | action_only
    ;

action_only:
    ACTION_ALLOW
    | ACTION_APPEND
    | ACTION_BLOCK
    | ACTION_CAPTURE
    | ACTION_CHAIN
    | ACTION_AUDIT_LOG
    | ACTION_DENY
    | ACTION_DROP
    | ACTION_MULTI_MATCH
    | ACTION_NO_AUDIT_LOG
    | ACTION_NO_LOG
    | ACTION_LOG
    | ACTION_PASS
    | ACTION_PAUSE
    | transformation_action
    ;

action_with_params:
    ACTION_CTL
    | ACTION_PHASE
    | ACTION_PREPEND
    | ACTION_PROXY
    | ACTION_REDIRECT
    | ACTION_REV
    | ACTION_SANITISE_ARG
    | ACTION_SANITISE_MATCHED
    | ACTION_SANITISE_MATCHED_BYTES
    | ACTION_SANITISE_REQUEST_HEADER
    | ACTION_SANITISE_RESPONSE_HEADER
    | ACTION_SETENV
    | ACTION_SETRSC
    | ACTION_SETSID
    | ACTION_SETUID
    | ACTION_SETVAR
    | ACTION_SEVERITY
    | ACTION_SKIP
    | ACTION_SKIP_AFTER
    | ACTION_STATUS
    | ACTION_TAG
    | ACTION_VER
    | ACTION_XMLNS
    | ACTION_DEPRECATE_VAR
    | ACTION_EXEC
    | ACTION_EXPIRE_VAR
    | ACTION_ID
    | ACTION_INITCOL
    | ACTION_LOG_DATA
    | ACTION_MATURITY
    | ACTION_MSG

;

action_value:
    INT
    | variable_name
    | variable_value
    | setvar_action
    | ACTION_CTL_FORCE_REQ_BODY_VAR
    | ACTION_CTL_REQUEST_BODY_ACCESS
    | ACTION_CTL_RULE_ENGINE
    | ACTION_CTL_RULE_REMOVE_BY_ID
    | ACTION_CTL_RULE_REMOVE_BY_TAG
    | ACTION_CTL_RULE_REMOVE_TARGET_BY_ID
    | ACTION_CTL_RULE_REMOVE_TARGET_BY_TAG
    | ACTION_CTL_AUDIT_ENGINE
    | ACTION_CTL_AUDIT_LOG_PARTS
    | STRING_LITERAL
    | FREE_TEXT_QUOTE_MACRO_EXPANSION
    ;

transformation_action:
    ACTION_TRANSFORMATION_PARITY_ZERO_7_BIT
    | ACTION_TRANSFORMATION_PARITY_ODD_7_BIT
    | ACTION_TRANSFORMATION_PARITY_EVEN_7_BIT
    | ACTION_TRANSFORMATION_SQL_HEX_DECODE
    | ACTION_TRANSFORMATION_BASE_64_ENCODE
    | ACTION_TRANSFORMATION_BASE_64_DECODE
    | ACTION_TRANSFORMATION_BASE_64_DECODE_EXT
    | ACTION_TRANSFORMATION_CMD_LINE
    | ACTION_TRANSFORMATION_SHA1
    | ACTION_TRANSFORMATION_MD5
    | ACTION_TRANSFORMATION_ESCAPE_SEQ_DECODE
    | ACTION_TRANSFORMATION_HEX_ENCODE
    | ACTION_TRANSFORMATION_HEX_DECODE
    | ACTION_TRANSFORMATION_LOWERCASE
    | ACTION_TRANSFORMATION_UPPERCASE
    | ACTION_TRANSFORMATION_URL_DECODE_UNI
    | ACTION_TRANSFORMATION_URL_DECODE
    | ACTION_TRANSFORMATION_URL_ENCODE
    | ACTION_TRANSFORMATION_NONE
    | ACTION_TRANSFORMATION_COMPRESS_WHITESPACE
    | ACTION_TRANSFORMATION_REMOVE_WHITESPACE
    | ACTION_TRANSFORMATION_REPLACE_NULLS
    | ACTION_TRANSFORMATION_REMOVE_NULLS
    | ACTION_TRANSFORMATION_HTML_ENTITY_DECODE
    | ACTION_TRANSFORMATION_JS_DECODE
    | ACTION_TRANSFORMATION_CSS_DECODE
    | ACTION_TRANSFORMATION_TRIM
    | ACTION_TRANSFORMATION_TRIM_LEFT
    | ACTION_TRANSFORMATION_TRIM_RIGHT
    | ACTION_TRANSFORMATION_NORMALISE_PATH_WIN
    | ACTION_TRANSFORMATION_NORMALISE_PATH
    | ACTION_TRANSFORMATION_LENGTH
    | ACTION_TRANSFORMATION_UTF8_TO_UNICODE
    | ACTION_TRANSFORMATION_REMOVE_COMMENTS_CHAR
    | ACTION_TRANSFORMATION_REMOVE_COMMENTS
    | ACTION_TRANSFORMATION_REPLACE_COMMENTS
//    | var SETVAR_OPERATION_EQUALS
//    | var SETVAR_OPERATION_EQUALS_PLUS
//    | var SETVAR_OPERATION_EQUALS_MINUS
    ;

variable_value:
    DICT_ELEMENT
    | DICT_ELEMENT_REGEXP
    ;

setvar_action:
    SINGLE_QUOTE setvar_stmt assignment values SINGLE_QUOTE
    ;

setvar_stmt:
    COLLECTION_ELEMENT
    | COLLECTION_WITH_MACRO
    ;

assignment:
    EQUAL
    | EQUALS_PLUS
    | EQUALS_MINUS
    ;


