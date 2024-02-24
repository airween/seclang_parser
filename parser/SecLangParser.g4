parser grammar SecLangParser;

options { tokenVocab=SecLangLexer; }

configuration
	: stmt* EOF
	;

stmt:
	stmnt_comment
	| configure_directive_line
	| configure_secaction_line
	| configure_secrule_line
	;

stmnt_comment:
	T_COMMENT
	;

configure_directive_line:
	configure_directive_token T_QUOTED configure_directive_argument_token T_QUOTED
	| configure_directive_token T_QUOTES configure_directive_argument_token T_QUOTES
	| configure_directive_token configure_directive_argument_token
	;

configure_directive_token:
	T_CONFIG_DIRECTIVE
	;

configure_directive_argument_token:
	T_CONFIG_DIRECTIVE_ARGUMENT
	;

configure_secaction_line:
	configure_directive_secaction T_QUOTED actionlist T_QUOTED
	;

configure_directive_secaction:
	T_CONFIG_SECACTION
	;

actionlist:
	action
	| actionlist T_COMMA action
	;

action:
	action_without_argument
	| action_with_argument T_ACTIONS_COLON action_argument
	| action_transformation T_ACTIONS_COLON action_transformation_argument
	| action_setaction T_ACTIONS_COLON action_setaction_variable action_setaction_equal action_setaction_value
	| action_setaction T_ACTIONS_COLON action_setaction_variable action_setaction_equal_plus action_setaction_value
	| action_setaction T_ACTIONS_COLON T_QUOTES action_setaction_variableq action_setaction_equal action_setaction_valueq T_QUOTES
	| action_setaction T_ACTIONS_COLON T_QUOTES action_setaction_variableq action_setaction_equal_plus action_setaction_valueq T_QUOTES
	| action_ctl T_ACTIONS_COLON action_ctl_argument T_EQUAL action_ctl_argument_val
	| action_ctl T_ACTIONS_COLON action_ctl_argument_extr T_EQUAL action_ctl_argument_extr_val
	| action_ctl T_ACTIONS_COLON action_ctl_argument_extr action_setaction_equal_plus action_ctl_argument_extr_val
	| action_ctl T_ACTIONS_COLON action_ctl_argument_with_params T_EQUAL action_ctl_argument_with_params_arg T_SEMICOLON action_ctl_argument_with_params_arg_val
	| action_ctl T_ACTIONS_COLON action_ctl_argument_with_params T_EQUAL action_ctl_argument_with_params_arg T_SEMICOLON action_ctl_argument_with_params_arg_val T_ACTION_CTL_COLON action_ctl_argument_with_params_arg_valarg
	;

action_without_argument:
	T_ACTION_WITHOUT_ARGUMENT
	;

action_with_argument:
	T_ACTION_WITH_ARGUMENT
	;

action_argument:
	action_unquoted_argument
	| T_QUOTES action_quoted_argument T_QUOTES
	;

action_unquoted_argument:
	T_ACTION_ARGUMENT
	;

action_quoted_argument:
	T_ACTION_ARGUMENT 
	;

action_transformation:
	T_ACTION_TRANSFORMATION
	;
	
action_transformation_argument:
	T_ACTION_TRANSFORMATION_ARGUMENT
	;

action_setaction:
	T_ACTION_SETACTION
	;

action_setaction_variable:
	T_SETACTION_ARGUMENT_KEY
	;

action_setaction_variableq:
	T_SETACTION_QUOTE_ARGUMENT_KEY
	;

action_setaction_value:
	T_SECACTION_ARGUMENT_VAL
	;

 action_setaction_valueq:
	T_SETACTION_QUOTE_ARGUMENT_VAL
	;

action_setaction_equal:
	T_EQUAL
	;

action_setaction_equal_plus:
	T_EQUAL_PLUS
	;

action_ctl:
	T_ACTION_CTL
	;

action_ctl_argument:
	T_ACTION_CTL_ARGUMENT_WITH_PARAM
	;

action_ctl_argument_val:
	T_ACTION_CTL_ARGUMENT_PARAM_VAL
	;

action_ctl_argument_extr:
	T_ACTION_CTL_ARGUMENT_WITH_EXPARAM
	;

action_ctl_argument_extr_val:
	T_ACTION_CTL_ARGUMENT_EXPARAM_VAL
	;

action_ctl_argument_with_params:
	T_ACTION_CTL_ARGUMENT_WITH_PARAM_ARGS
	;

action_ctl_argument_with_params_arg:
	T_ACTION_CTL_ARGUMENT_PARAMARGS_VAL
	;

action_ctl_argument_with_params_arg_val:
	T_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG1
	;

action_ctl_argument_with_params_arg_valarg:
 	T_ACTION_CTL_ARGUMENT_PARAM_ARG_VAR_ARG2
	;


configure_secrule_line:
	configure_directive_secrule secrule_variable_list T_QUOTED secrule_operator T_QUOTED T_QUOTED actionlist T_QUOTED
	| configure_directive_secrule secrule_variable_list T_QUOTED secrule_operator T_QUOTED
	;

configure_directive_secrule:
	T_CONFIG_SECRULE
	;

secrule_variable_list:
	secrule_variable
	| secrule_variable_list T_COMMA secrule_variable
	| secrule_variable_list T_PIPE secrule_variable
	;

secrule_variable:
	secrule_variable_with_argument_rule
	| negated_secrule_variable_with_argument_rule
	| single_secrule_variable
	| negated_single_secrule_variable
	| cnt_secrule_variable_with_argument_rule
	| cnt_single_secrule_variable
	;

single_secrule_variable:
	T_SECRULE_COLLECTION
	| T_SECRULE_VARIABLE
	| T_SECRULE_STORAGES
	;

negated_single_secrule_variable:
	T_SECRULE_VARIABLE_EXCLAMATION T_SECRULE_COLLECTION
	| T_SECRULE_VARIABLE_EXCLAMATION T_SECRULE_VARIABLE
	| T_SECRULE_VARIABLE_EXCLAMATION T_SECRULE_STORAGES
	;

cnt_single_secrule_variable:
	T_SECRULE_VARIABLE_AMPERSEND T_SECRULE_COLLECTION
	| T_SECRULE_VARIABLE_AMPERSEND T_SECRULE_VARIABLE
	| T_SECRULE_VARIABLE_AMPERSEND T_SECRULE_STORAGES
	;

secrule_variable_with_argument_rule:
	secrule_variable_with_argument T_SECRULE_COLLECTION_COLON secrule_collection_argument
	;

negated_secrule_variable_with_argument_rule:
	negated_secrule_variable_with_argument T_SECRULE_COLLECTION_COLON secrule_collection_argument
	;

secrule_variable_with_argument:
	T_SECRULE_COLLECTION
	| T_SECRULE_STORAGES
	;

negated_secrule_variable_with_argument:
	T_SECRULE_VARIABLE_EXCLAMATION T_SECRULE_COLLECTION
	| T_SECRULE_VARIABLE_EXCLAMATION T_SECRULE_STORAGES
	;

cnt_secrule_variable_with_argument_rule:
	cnt_secrule_variable_with_argument T_SECRULE_COLLECTION_COLON secrule_collection_argument
	;

cnt_secrule_variable_with_argument:
	T_SECRULE_VARIABLE_AMPERSEND T_SECRULE_COLLECTION
	| T_SECRULE_VARIABLE_AMPERSEND T_SECRULE_STORAGES
	;

secrule_collection_argument:
	T_SECRULE_COLLECTION_PART
	;

secrule_operator:
	negated_operator
	| operator
	| negated_operator operator_argument
	| operator operator_argument
	;

negated_operator:
	T_SECRULE_OPERATOR_EXCLAMATION T_SECRULE_OPERATOR_AT T_SECRULE_OPERATOR
	;

operator:
	T_SECRULE_OPERATOR_AT T_SECRULE_OPERATOR
	;

operator_argument:
	T_SECRULE_OPERATOR_ARGUMENT
	;