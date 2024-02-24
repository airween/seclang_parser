
lexer grammar SecLangLexer;

//WS
//	: ([ \t\r\n]+ | '\\' '\n')  -> skip
//	;

WS
	: ((' ' | '\t' | '\r' | '\n')+ | '\\' '\n') -> skip
	;

T_QUOTED
	: '"'
	;

T_QUOTES
	: '\''
	;

T_COMMA
	: ','
	;

T_SEMICOLON
	: ';'
	;

T_PIPE
	: '|'
	;

//T_CONFDIR_SECCOMPSIGNATURE
//	: 'SecComponentSignature' -> pushMode(seccompsign)
//	;

T_COMMENT
	: '#' .*? '\r'? '\n'
	;

T_EXCLUSION_MARK
	: '!'
	;
T_CONFIG_SECACTION
	: 'SecAction' -> pushMode(M_DIRECTIVE_ACTIONLIST_PRE)
	;

T_CONFIG_SECRULE
	: 'SecRule' -> pushMode(M_DIRECTIVE_VARIABLELIST)
	;

T_CONFIG_DIRECTIVE
	: (' ' | '\t')* 'Sec' [a-zA-Z0-9]+ -> pushMode(M_DIRECTIVE_ARGUMENT)
	;

T_EQUAL
	: '='
	;

T_PLUS
	: '+'
	;

T_MINUS
	: '-'
	;

T_EQUAL_PLUS
	: '=+'
	;

mode M_DIRECTIVE_ARGUMENT;

M_DIRECTIVE_ARGUMENT_WS
	: ((' ' | '\t' | '\r' | '\n')+ | '\\' '\n') -> skip
	;

M_DIRECTIVE_ARGUMENT_QUOTED
	: '"' -> type(T_QUOTED)
	;

M_DIRECTIVE_ARGUMENT_QUOTES
	: '\'' -> type(T_QUOTES)
	;

T_CONFIG_DIRECTIVE_ARGUMENT
    : ~["\n]+ -> popMode
    ;

mode M_DIRECTIVE_ACTIONLIST_PRE;

M_DIRECTIVE_ACTIONLIST_PRE_WS
	//: ((' ' | '\t' | '\r' | '\n')+ | '\\' '\n') -> skip
	: ((' ' | '\t')+ | '\\' '\n') -> skip
	;

M_DIRECTIVE_ACTIONLIST_PRE_EMPTY_LINE
	: [\r?\n] -> skip, mode(DEFAULT_MODE)
	;

T_DIRECTIVE_ACTIONLIST_PRE_QUOTED
	: '"' -> type(T_QUOTED), pushMode(M_DIRECTIVE_ACTIONLIST)
	;

mode M_DIRECTIVE_ACTIONLIST;

M_DIRECTIVE_ACTIONLIST_WS
	: ((' ' | '\t' | '\r' | '\n')+ | '\\' '\n') -> skip
	;

M_DIRECTIVE_ACTIONLIST_COMMA_SEPARATOR
	: ',' -> type(T_COMMA)
	;

T_ACTION_WITHOUT_ARGUMENT
	: ('allow'
	| 'auditlog'
	| 'block'
	| 'capture'
	| 'chain'
	| 'deny'
	| 'drop'
	| 'log'
	| 'multiMatch'
	| 'noauditlog'
	| 'nolog'
	| 'pass'
	| 'sanitiseMatched'
	| 'sanitiseMatchedBytes')
	;

T_ACTION_WITH_ARGUMENT
	: ('accuracy'
	| 'append'
	| 'deprecatevar'
	| 'exec'
	| 'expirevar'
	| 'id'
	| 'initcol'
	| 'logdata'
	| 'maturity'
	| 'msg'
	| 'pause'
	| 'phase'
	| 'prepend'
	| 'proxy'
	| 'redirect'
	| 'rev'
	| 'sanitiseArg'
	| 'sanitiseRequestHeader'
	| 'sanitiseResponseHeader'
	| 'severity'
	| 'setuid'
	| 'setrsc'
	| 'setsid'
	| 'skip'
	| 'skipAfter'
	| 'status'
	| 'tag'
	| 'ver'
	| 'xmlns') -> pushMode(M_DIRECTIVE_ACTION_COLON)
	;

T_ACTION_TRANSFORMATION
	: 't' -> pushMode(M_DIRECTIVE_ACTION_TRANSFORM_COLON)
	;

T_ACTION_SETACTION
	: ('setenv'
	| 'setvar') -> pushMode(M_DIRECTIVE_ACTION_SETACTION_COLON)
	;

T_ACTION_CTL
	: 'ctl' -> pushMode(M_ACTION_CTL_ARGUMENTS)
	;

T_ACTION_QUOTED
	//: '"' -> type(T_QUOTED), popMode, popMode, popMode, popMode
	: '"' -> type(T_QUOTED), mode(DEFAULT_MODE)
	;

mode M_DIRECTIVE_ACTION_COLON;

T_ACTIONS_COLON
	: ':' -> pushMode(M_DIRECTIVE_ACTION_ARGUMENT)
	;

mode M_DIRECTIVE_ACTION_ARGUMENT;

M_DIRECTIVE_ACTION_ARGUMENT_WS
	: ((' ' | '\t' | '\r' | '\n')+ | '\\' '\n') -> skip
	;

M_DIRECTIVE_ACTION_ARGUMENT_QUOTES
	: '\'' -> type(T_QUOTES), pushMode(M_DIRECTIVE_ACTION_QUOTE_ARGUMENT)
	;

//M_DIRECTIVE_ACTION_ARGUMENT_QUOTED
//	: '"' -> type(T_QUOTED), popMode, popMode, popMode
//	: '"' -> popMode, popMode, popMode
//	;

M_DIRECTIVE_ACTION_ARGUMENT_COMMA_SEPARATOR
	: ',' -> type(T_COMMA), popMode, popMode
	;

T_ACTION_ARGUMENT
    : ~['",]+
    ;

T_DIRECTIVE_ACTION_ARGUMENT_QUOTED
//	: '"' -> type(T_QUOTED), popMode, popMode, popMode
//	: '"' -> type(T_QUOTED), popMode, popMode, popMode
	: '"' -> type(T_QUOTED), mode(DEFAULT_MODE)
	;

mode M_DIRECTIVE_ACTION_QUOTE_ARGUMENT;

T_DIRECTIVE_ACTION_QUOTE_ARGUMENT_WS
	: ('\\' '\n') -> skip
	;

T_DIRECTIVE_ACTION_QUOTE_ARGUMENT_QUOTES
	: '\'' -> type(T_QUOTES), popMode, popMode, popMode
	;

T_DIRECTIVE_ACTION_QUOTE_ARGUMENT
    : (~['] | '\\\'')+ -> type(T_ACTION_ARGUMENT)
    ;

mode M_DIRECTIVE_ACTION_SETACTION_COLON;

T_SETACTIONS_COLON
	: ':' -> type(T_ACTIONS_COLON), pushMode(M_DIRECTIVE_ACTION_SETACTION_ARGUMENT)
	;

T_SETACTION_ARGUMENT_QUOTES
	//: '\'' -> type(T_QUOTES), popMode
	: '\''
	;

mode M_DIRECTIVE_ACTION_SETACTION_ARGUMENT;

T_DIRECTIVE_SETACTION_ARGUMENT_QUOTES
	: '\'' -> type(T_QUOTES), pushMode(M_DIRECTIVE_SETACTION_QUOTE_ARGUMENT)
	;

T_SETACTION_ARGUMENT_KEY
    : ~['=]+
    ;

T_SECACTION_ARGUMENT_EQUAL
	: '=' -> type(T_EQUAL), pushMode(M_DIRECTIVE_SECACTION_ARGUMENT_VAL)
	;

T_SECACTION_ARGUMENT_EQUAL_PLUS
	: '=+' -> type(T_EQUAL_PLUS), pushMode(M_DIRECTIVE_SECACTION_ARGUMENT_VAL)
	;

mode M_DIRECTIVE_SECACTION_ARGUMENT_VAL;

//T_SECACTION_ARGUMENT_PLUS
//	: '+' -> type(T_PLUS)
//	;

M_DIRECTIVE_SECACTION_ARGUMENT_COMMA_SEPARATOR
	: ',' -> type(T_COMMA), popMode, popMode, popMode
	;

M_DIRECTIVE_SECACTION_ARGUMENT_QUOTED
	//: '"' -> type(T_QUOTED), popMode, popMode, popMode, popMode, popMode
	: '"' -> type(T_QUOTED), mode(DEFAULT_MODE)
	;

T_SECACTION_ARGUMENT_VAL
    : ~[",]+
    ;

mode M_DIRECTIVE_SETACTION_QUOTE_ARGUMENT;

T_SETACTION_QUOTE_ARGUMENT_KEY
    : ~[=]+
    ;

T_SECACTION_QUOTE_ARGUMENT_EQUAL
	: '=' -> type(T_EQUAL), pushMode(M_DIRECTIVE_SETACTION_QUOTE_ARGUMENT_VAL)
	;

T_SECACTION_QUOTE_ARGUMENT_PLUS_EQUAL
	: '=+' -> type(T_EQUAL_PLUS), pushMode(M_DIRECTIVE_SETACTION_QUOTE_ARGUMENT_VAL)
	;

mode M_DIRECTIVE_SETACTION_QUOTE_ARGUMENT_VAL;

//T_SETACTION_QUOTE_ARGUMENT_PLUS
//	: '+' -> type(T_PLUS)
//	;

T_SETACTION_QUOTE_ARGUMENT_VAL
	//: (~['+",] | '\\\'')+
	: (~['",] | '\\\'')+
    ;

T_SETACTION_QUOTE_QUOTES
	//: '\'' -> type(T_QUOTES)
	: '\'' -> type(T_QUOTES), popMode, popMode, popMode, popMode
	;

//T_SETACTION_QUOTE_QUOTED
//	: '"' -> type(T_QUOTED), popMode, popMode, popMode, popMode, popMode
//	;

T_SETACTION_QUOTE_COMMA
	: ',' -> type(T_COMMA), popMode, popMode, popMode, popMode
	;

mode M_DIRECTIVE_ACTION_TRANSFORM_COLON;

T_TRANSFORMATIONS_COLON
	: ':' -> type(T_ACTIONS_COLON), pushMode(M_DIRECTIVE_ACTION_TRANSFORMATION_ARGUMENT)
	;

mode M_DIRECTIVE_ACTION_TRANSFORMATION_ARGUMENT;

T_ACTION_TRANSFORMATION_ARGUMENT
    : ('base64Decode'
	| 'sqlHexDecode'
	| 'base64DecodeExt'
	| 'base64Encode'
	| 'cmdLine'
	| 'compressWhitespace'
	| 'cssDecode'
	| 'escapeSeqDecode'
	| 'hexDecode'
	| 'hexEncode'
	| 'htmlEntityDecode'
	| 'jsDecode'
	| 'length'
	| 'lowercase'
	| 'md5'
	| 'none'
	| 'normalisePath'
	| 'normalizePath'
	| 'normalisePathWin'
	| 'normalizePathWin'
	| 'parityEven7bit'
	| 'parityOdd7bit'
	| 'parityZero7bit'
	| 'removeNulls'
	| 'removeWhitespace'
	| 'replaceComments'
	| 'removeCommentsChar'
	| 'removeComments'
	| 'replaceNulls'
	| 'urlDecode'
	| 'uppercase'
	| 'urlDecodeUni'
	| 'urlEncode'
	| 'utf8toUnicode'
	| 'sha1'
	| 'trimLeft'
	| 'trimRight'
	| 'trim'
	) -> popMode, popMode
    ;

mode M_ACTION_CTL_ARGUMENTS;

T_ACTION_CTL_ARGUMENT_COLON
	: ':' -> type(T_ACTIONS_COLON)
	;

T_ACTION_CTL_ARGUMENT_WITH_PARAM
    : ('auditEngine'
	| 'debugLogLevel'
	| 'forceRequestBodyVariable'
	| 'requestBodyAccess'
	| 'requestBodyLimit'
	| 'requestBodyProcessor'
	| 'responseBodyAccess'
	| 'responseBodyLimit'
	| 'ruleEngine'
	| 'ruleRemoveById'
	| 'ruleRemoveByMsg'
	| 'ruleRemoveByTag'
	| 'hashEngine'
	| 'hashEnforcement') -> pushMode(M_ACTION_CTL_ARGUMENT_PARAM_ARG)
	;

T_ACTION_CTL_ARGUMENT_WITH_EXPARAM
	: 'auditLogParts' -> pushMode(M_ACTION_CTL_ARGUMENT_EXPARAM_ARG)
	;

T_ACTION_CTL_ARGUMENT_WITH_PARAM_ARGS
	: ('ruleRemoveTargetById'
	| 'ruleRemoveTargetByMsg'
	| 'ruleRemoveTargetByTag') -> pushMode(M_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR)
	;

mode M_ACTION_CTL_ARGUMENT_PARAM_ARG;

T_ACTION_CTL_ARGUMENT_PARAM_EQUAL
	: '=' -> type(T_EQUAL)
	;

T_ACTION_CTL_ARGUMENT_PARAM_VAL
    : ~[",=]+ -> popMode, popMode
    ;

T_ACTION_CTL_ARGUMENT_PARAM_COMMA
	: ',' -> type(T_COMMA), popMode, popMode
	;

//T_ACTION_CTL_ARGUMENT_PARAM_QUOTED
//	: '"' -> type(T_QUOTED), popMode
//	;

mode M_ACTION_CTL_ARGUMENT_EXPARAM_ARG;

T_ACTION_CTL_ARGUMENT_EXPARAM_EQUAL
	: '=' -> type(T_EQUAL)
	;

T_ACTION_CTL_ARGUMENT_EXPARAM_EQUAL_PLUS
	: '=+' -> type(T_EQUAL_PLUS)
	;

T_ACTION_CTL_ARGUMENT_EXPARAM_MINUS
	: '-' -> type(T_MINUS)
	;

T_ACTION_CTL_ARGUMENT_EXPARAM_COMMA
	: ',' -> type(T_COMMA), popMode, popMode
	;

//T_ACTION_CTL_ARGUMENT_EXPARAM_QUOTED
//	: '"' -> type(T_QUOTED), popMode, popMode, popMode, popMode
//	;

T_ACTION_CTL_ARGUMENT_EXPARAM_VAL
    : ~[",=-]+
    ;

mode M_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR;

T_ACTION_CTL_ARGUMENT_PARAMARGS_EQUAL
	: '=' -> type(T_EQUAL)
	;

T_ACTION_CTL_ARGUMENT_PARAMARGS_VAL
	: ~[=;]+
	;

T_ACTION_CTL_ARGUMENT_PARAMARGS_SEMICOLON
	: ';' -> type(T_SEMICOLON), pushMode(M_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG)
	;

mode M_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG;

T_ACTION_CTL_COLON
	: ':' -> pushMode(M_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG2)
	;

//T_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG1
//    : ~[",:]+ -> popMode, popMode, popMode, popMode
//    ;

T_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG1
    : ~[",]+
    ;

T_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG_COMMA
	: ',' -> type(T_COMMA), popMode, popMode, popMode
	;

T_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG_QUOTED
//	: '"' -> type(T_QUOTED), popMode, popMode, popMode, popMode, popMode
	: '"' -> type(T_QUOTED), mode(DEFAULT_MODE)
	;

mode M_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG2;

T_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG2
    : ~[",]+
    ;

T_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG2_COMMA
	: ',' -> type(T_COMMA), popMode, popMode, popMode, popMode, popMode
	;

//T_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG2_QUOTED
//	: '"' -> type(T_QUOTED), popMode, popMode, popMode, popMode, popMode, popMode
//	;

mode M_DIRECTIVE_VARIABLELIST;

T_DIRECTIVE_VARIABLELIST_WS
	: ((' ' | '\t' | '\r' | '\n')+ | '\\' '\n') -> skip, pushMode(M_SECRULE_VARIABLES)
	;

mode M_SECRULE_VARIABLES;

T_SECRULE_VARIABLE_EXCLAMATION
	: '!'
	;

T_SECRULE_VARIABLE_AMPERSEND
	: '&'
	;

T_DIRECTIVE_VARIABLELIST_COMMA_SEPARATOR
	: ',' -> type(T_COMMA)
	;

T_DIRECTIVE_VARIABLELIST_PIPE_SEPARATOR
	: '|' -> type(T_PIPE)
	;

T_SECRULE_VARIABLE
	: ('AUTH_TYPE'
	| 'DURATION'
	| 'FILES_COMBINED_SIZE'
	| 'FULL_REQUEST'
	| 'FULL_REQUEST_LENGTH'
	| 'HIGHEST_SEVERITY'
	| 'INBOUND_DATA_ERROR'
	| 'MATCHED_VAR'
	| 'MATCHED_VAR_NAME'
	| 'MODSEC_BUILD'
	| 'MULTIPART_CRLF_LF_LINES'
	| 'MULTIPART_FILENAME'
	| 'MULTIPART_NAME'
	| 'MULTIPART_STRICT_ERROR'
	| 'MULTIPART_UNMATCHED_BOUNDARY'
	| 'OUTBOUND_DATA_ERROR'
	| 'PATH_INFO'
	| 'PERF_ALL'
	| 'PERF_COMBINED'
	| 'PERF_GC'
	| 'PERF_LOGGING'
	| 'PERF_PHASE1'
	| 'PERF_PHASE2'
	| 'PERF_PHASE3'
	| 'PERF_PHASE4'
	| 'PERF_PHASE5'
	| 'PERF_SREAD'
	| 'PERF_SWRITE'
	| 'QUERY_STRING'
	| 'REMOTE_ADDR'
	| 'REMOTE_HOST'
	| 'REMOTE_PORT'
	| 'REMOTE_USER'
	| 'REQBODY_ERROR'
	| 'REQBODY_ERROR_MSG'
	| 'REQBODY_PROCESSOR'
	| 'REQUEST_BASENAME'
	| 'REQUEST_BODY'
	| 'REQUEST_BODY_LENGTH'
	| 'REQUEST_FILENAME'
	| 'REQUEST_LINE'
	| 'REQUEST_METHOD'
	| 'REQUEST_PROTOCOL'
	| 'REQUEST_URI'
	| 'REQUEST_URI_RAW'
	| 'RESPONSE_BODY'
	| 'RESPONSE_CONTENT_LENGTH'
	| 'RESPONSE_CONTENT_TYPE'
	| 'RESPONSE_PROTOCOL'
	| 'RESPONSE_STATUS'
	| 'SCRIPT_BASENAME'
	| 'SCRIPT_FILENAME'
	| 'SCRIPT_GID'
	| 'SCRIPT_GROUPNAME'
	| 'SCRIPT_MODE'
	| 'SCRIPT_UID'
	| 'SCRIPT_USERNAME'
	| 'SDBM_DELETE_ERROR'
	| 'SERVER_ADDR'
	| 'SERVER_NAME'
	| 'SERVER_PORT'
	| 'SESSIONID'
	| 'STATUS_LINE'
	| 'STREAM_INPUT_BODY'
	| 'STREAM_OUTPUT_BODY'
	| 'TIME'
	| 'TIME_DAY'
	| 'TIME_EPOCH'
	| 'TIME_HOUR'
	| 'TIME_MIN'
	| 'TIME_MON'
	| 'TIME_SEC'
	| 'TIME_WDAY'
	| 'TIME_YEAR'
	| 'UNIQUE_ID'
	| 'URLENCODED_ERROR'
	| 'USERID'
	| 'USERAGENT_IP'
	| 'WEBAPPID'
	| 'WEBSERVER_ERROR_LOG'
	)
	;

T_SECRULE_COLLECTION
	: ('ARGS'
	| 'ARGS_COMBINED_SIZE'
	| 'ARGS_GET'
	| 'ARGS_GET_NAMES'
	| 'ARGS_NAMES'
	| 'ARGS_POST'
	| 'ARGS_POST_NAMES'
	| 'ENV'
	| 'FILES'
	| 'FILES_NAMES'
	| 'FILES_SIZES'
	| 'FILES_TMPNAMES'
	| 'FILES_TMP_CONTENT'
	| 'GEO'
	| 'MATCHED_VARS'
	| 'MATCHED_VARS_NAMES'
	| 'MULTIPART_PART_HEADERS'
	| 'PERF_RULES'
	| 'REQUEST_COOKIES'
	| 'REQUEST_COOKIES_NAMES'
	| 'REQUEST_HEADERS'
	| 'REQUEST_HEADERS_NAMES'
	| 'RESPONSE_HEADERS'
	| 'RESPONSE_HEADERS_NAMES'
	| 'RULE'
	| 'SESSION'
	| 'TX'
	| 'XML'
	) -> pushMode(M_SECRULE_COLLECTION)
	;

T_SECRULE_STORAGES
	: ('GLOBAL'
	| 'RESOURCE'
	| 'IP'
	| 'SESSION'
	| 'USER'
	) -> pushMode(M_SECRULE_COLLECTION)
	;

T_DIRECTIVE_VARIABLELIST_END_WS
	: ((' ' | '\t' | '\r' | '\n')+ | '\\' '\n') -> skip, pushMode(M_SECRULE_OPERATOR_MODE_PRE)
	;

mode M_SECRULE_COLLECTION;

T_SECRULE_COLLECTION_COMMA_SEPARATOR
	: ',' -> type(T_COMMA), popMode
	;

T_SECRULE_COLLECTION_PIPE_SEPARATOR
	: '|' -> type(T_PIPE), popMode
	;

T_SECRULE_COLLECTION_COLON
	: ':' -> pushMode(M_SECRULE_COLLECTION_PART)
	;

T_SECRULE_COLLECTION_WS
	: ((' ' | '\t' | '\r' | '\n')+ | '\\' '\n') -> skip, popMode, popMode, pushMode(M_SECRULE_OPERATOR_MODE_PRE)
	;

mode M_SECRULE_COLLECTION_PART;

T_SECRULE_COLLECTION_PART
	: ~[,| \t]+
	;

T_SECRULE_COLLECTION_PART_COMMA_SEPARATOR
	: ',' -> type(T_COMMA), popMode, popMode
	;

T_SECRULE_COLLECTION_PART_SEPARATOR
	: '|' -> type(T_PIPE), popMode, popMode
	;

T_SECRULE_COLLECTION_PART_END
	: ((' ' | '\t' | '\r' | '\n')+ | '\\' '\n') -> skip, popMode, popMode, popMode, pushMode(M_SECRULE_OPERATOR_MODE_PRE)
	;

mode M_SECRULE_OPERATOR_MODE_PRE;

T_SECRULE_OPERATOR_MODE_QUOTED
	: '"' -> type(T_QUOTED), pushMode(M_SECRULE_OPERATOR_MODE)
	;

T_SECRULE_OPERATOR_MODE_WS
	: ((' ' | '\t' | '\r' | '\n')+ | '\\' '\n') -> skip
	;

mode M_SECRULE_OPERATOR_MODE;

T_SECRULE_OPERATOR_EXCLAMATION
	: '!'
	;

T_SECRULE_OPERATOR_AT
	: '@'
	;

T_SECRULE_OPERATOR
	: ('beginsWith'
	| 'contains'
	| 'containsWord'
	| 'detectSQLi'
	| 'detectXSS'
	| 'endsWith'
	| 'fuzzyHash'
	| 'eq'
	| 'ge'
	| 'geoLookup'
	| 'gsbLookup'
	| 'gt'
	| 'inspectFile'
	| 'ipMatch'
	| 'ipMatchF'
	| 'ipMatchFromFile'
	| 'le'
	| 'lt'
	| 'noMatch'
	| 'pm'
	| 'pmf'
	| 'pmFromFile'
	| 'rbl'
	| 'rsub'
	| 'rx'
	| 'streq'
	| 'strmatch'
	| 'unconditionalMatch'
	| 'validateByteRange'
	| 'validateDTD'
	| 'validateHash'
	| 'validateSchema'
	| 'validateUrlEncoding'
	| 'validateUtf8Encoding'
	| 'verifyCC'
	| 'verifyCPF'
	| 'verifySSN'
	| 'within'
	) -> pushMode(M_SECRULE_OPERATOR_ARGUMENT_WS)
	;

T_SECRULE_OPERATOR_WS
	: [ \t]+ -> skip
	;

T_SECRULE_OPERATOR_END_QUOTED
	: '"' -> type(T_QUOTED), popMode, popMode, pushMode(M_DIRECTIVE_ACTIONLIST_PRE)
	;

mode M_SECRULE_OPERATOR_ARGUMENT_WS;

T_SECRULE_OPERATOR_ARGUMENT_WS
	: [ \t]+ -> skip, pushMode(M_SECRULE_OPERATOR_ARGUMENT)
	;

T_SECRULE_OPERATOR_ARGUMENT_WS_QUOTED
	: '"' -> type(T_QUOTED), popMode, popMode, popMode, pushMode(M_DIRECTIVE_ACTIONLIST_PRE)
	;

mode M_SECRULE_OPERATOR_ARGUMENT;

T_SECRULE_OPERATOR_ARGUMENT
	: (~["] | '\\"')+
	;

T_SECRULE_OPERATOR_ARGUMENT_END_QUOTED
	: '"' -> type(T_QUOTED), popMode, popMode, popMode, popMode, pushMode(M_DIRECTIVE_ACTIONLIST_PRE)
	;