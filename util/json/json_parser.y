%{
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "json_util.h"
#define YYLTYPE struct json_loc_s

void yyerror(YYLTYPE *yylloc, json_parser_t parser, char *input, size_t input_len,
	     json_entity_t *pentity, yyscan_t scanner, const char *str)
{
	fprintf(stderr, "first_line   : %d\n", yylloc->first_line);
	fprintf(stderr, "last line    : %d\n", yylloc->last_line);
	fprintf(stderr, "first column : %d\n", yylloc->first_column);
	fprintf(stderr, "last column  : %d\n", yylloc->last_column);
	fprintf(stderr, "str           : %s\n", str);
	if (*pentity) {
		json_entity_free(*pentity);
		*pentity = NULL;
	}
}

#define YYDEBUG		1
#define YYERROR_VERBOSE 1

int yyparse(json_parser_t parser, char *input, size_t input_len, json_entity_t *entity, yyscan_t scanner);
void yy_delete_buffer(struct yy_buffer_state *);


static inline json_entity_t new_dict_val(void) {
	return json_entity_new(JSON_DICT_VALUE);
}

static inline json_entity_t add_dict_attr(json_entity_t e, json_entity_t name, json_entity_t value)
{
	json_entity_t a = json_entity_new(JSON_ATTR_VALUE, name, value);
	if (a) {
		json_attr_add(e, a);
		return e;
	}
	return NULL;
}

static inline json_entity_t new_list_val(void) {
	return json_entity_new(JSON_LIST_VALUE);
}

static inline json_entity_t add_list_item(json_entity_t e, json_entity_t v)
{
	json_item_add(e, v);
	return e;
}

%}

%define api.pure full
%locations

%lex-param { json_parser_t parser }
%lex-param { char *input }
%lex-param { size_t input_len }
%lex-param { yyscan_t scanner }

%parse-param { json_parser_t parser }
%parse-param { char *input }
%parse-param { size_t input_len }
%parse-param { json_entity_t *pentity }
%parse-param { yyscan_t scanner }

%token ',' ':'
%token '[' ']'
%token '{' '}'
%token '.'
%token '"'
%token DQUOTED_STRING_T SQUOTED_STRING_T
%token INTEGER_T FLOAT_T
%token BOOL_T
%token NULL_T

%start json

%%

json : value	{
	 $$ = *pentity = $1;
	 YYACCEPT;
	 }
	 ;

dict : '{' attr_list '}' { $$ = $2; } ;

array : '[' item_list ']' { $$ = $2; } ;

value : INTEGER_T { $$ = $1; }
	 | FLOAT_T { $$ = $1; }
	 | BOOL_T { $$ = $1; }
	 | NULL_T { $$ = $1; }
	 | string { $$ = $1; }
	 | dict { $$ = $1; }
	 | array { $$ = $1; }
	 ;

string : DQUOTED_STRING_T { $$ = $1; }
	 | SQUOTED_STRING_T { $$ = $1; }
	 ;

attr_list: /* empty */ { $$ = new_dict_val(); }
	 | string ':' value {
	     json_entity_t e = new_dict_val();
	     $$ = add_dict_attr(e, $1, $3);
	 }
	 | attr_list ',' string ':' value {
	     $$ = add_dict_attr($1, $3, $5);
	 }
     ;

item_list: /* empty */ { $$ = new_list_val(); }
	| value {
		json_entity_t a = new_list_val();
		$$ = add_list_item(a, $1);
	}
	| item_list ',' value {
		$$  = add_list_item($1, $3);
	}
    ;

%%
json_parser_t json_parser_new(size_t user_data) {
	json_parser_t p = calloc(1, sizeof *p + user_data);
	if (p)
		yylex_init(&p->scanner);
	return p;
}

void json_parser_free(json_parser_t parser)
{
	yylex_destroy(parser->scanner);
	free(parser);
}

int json_parse_buffer(json_parser_t p, char *buf, size_t buf_len, json_entity_t *pentity)
{
	*pentity = NULL;
	if (p->buffer_state) {
		/* The previous call did not reset the lexer state */
		yy_delete_buffer(p->buffer_state);
		p->buffer_state = NULL;
	}
	return yyparse(p, buf, buf_len, pentity, p->scanner);
}

int json_parse_file(json_parser_t p, const char *filename, json_entity_t *pentity)
{
	int		fd, rc;
	char		*buf = NULL;
	struct stat	fstat;

	rc = stat(filename, &fstat);
	if (rc)
		return -ENOENT;
	buf = malloc(fstat.st_size+2);
	if (!buf)
		return -ENOMEM;
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		rc = -ENOENT;
		goto err;
	}
	rc = read(fd, buf, fstat.st_size);
	if (rc < 0)
		goto err;
	/* The flex api requires the buffer to have two terminating null bytes. */
	buf[fstat.st_size]   = 0;
	buf[fstat.st_size+1] = 0;
	rc = json_parse_buffer(p, buf, rc, pentity);
	free(buf);
	return 0;

 err:
	if (buf)
		free(buf);
	return rc;
}
