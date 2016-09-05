/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         naslparse
#define yylex           nasllex
#define yyerror         naslerror
#define yydebug         nasldebug
#define yynerrs         naslnerrs


/* Copy the first part of user declarations.  */
#line 5 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:339  */

/* Nessus Attack Scripting Language version 2
 *
 * Copyright (C) 2002 - 2004 Michel Arboi and Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define YYPARSE_PARAM parm
#define YYLEX_PARAM parm

#define LNB	(((naslctxt*)parm)->line_nb)

#include <ctype.h> /* for isalpha */
#include <pcap.h> /* for islocalhost */
#include <string.h> /* for strlen */
#include <sys/stat.h> /* for stat */

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "nasl_debug.h"
#include "nasl_signature.h"

static void naslerror(naslctxt *, const char *);
#define YYERROR_VERBOSE

#line 113 "nasl_grammar.tab.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "nasl_grammar.tab.h".  */
#ifndef YY_NASL_NASL_GRAMMAR_TAB_H_INCLUDED
# define YY_NASL_NASL_GRAMMAR_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 1
#endif
#if YYDEBUG
extern int nasldebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    IF = 258,
    ELSE = 259,
    EQ = 260,
    NEQ = 261,
    SUPEQ = 262,
    INFEQ = 263,
    OR = 264,
    AND = 265,
    MATCH = 266,
    NOMATCH = 267,
    REP = 268,
    FOR = 269,
    REPEAT = 270,
    UNTIL = 271,
    FOREACH = 272,
    WHILE = 273,
    BREAK = 274,
    CONTINUE = 275,
    FUNCTION = 276,
    RETURN = 277,
    INCLUDE = 278,
    LOCAL = 279,
    GLOBAL = 280,
    PLUS_PLUS = 281,
    MINUS_MINUS = 282,
    L_SHIFT = 283,
    R_SHIFT = 284,
    R_USHIFT = 285,
    EXPO = 286,
    PLUS_EQ = 287,
    MINUS_EQ = 288,
    MULT_EQ = 289,
    DIV_EQ = 290,
    MODULO_EQ = 291,
    L_SHIFT_EQ = 292,
    R_SHIFT_EQ = 293,
    R_USHIFT_EQ = 294,
    RE_MATCH = 295,
    RE_NOMATCH = 296,
    ARROW = 297,
    IDENT = 298,
    STRING1 = 299,
    STRING2 = 300,
    INTEGER = 301,
    NOT = 302,
    UMINUS = 303,
    BIT_NOT = 304
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE YYSTYPE;
union YYSTYPE
{
#line 46 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:355  */

  int		num;
  char		*str;
  struct asciiz {
    char	*val;
    int		len;
  } data;
  tree_cell	*node;

#line 213 "nasl_grammar.tab.c" /* yacc.c:355  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int naslparse (naslctxt * parm);

#endif /* !YY_NASL_NASL_GRAMMAR_TAB_H_INCLUDED  */

/* Copy the second part of user declarations.  */
#line 56 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:358  */

static int nasllex(YYSTYPE * lvalp, void * parm);

#line 230 "nasl_grammar.tab.c" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  78
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   1029

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  73
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  43
/* YYNRULES -- Number of rules.  */
#define YYNRULES  126
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  227

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   304

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    70,     2,     2,     2,    57,    52,     2,
      61,    62,    55,    53,    63,    54,    72,    56,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    67,    66,
      48,    47,    49,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    68,     2,    69,    51,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    64,    50,    65,    71,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    58,    59,    60
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   141,   141,   146,   152,   159,   159,   162,   170,   170,
     171,   172,   180,   180,   181,   182,   196,   196,   196,   196,
     199,   199,   199,   200,   200,   200,   200,   200,   201,   205,
     209,   212,   218,   225,   231,   239,   239,   239,   239,   240,
     250,   257,   265,   274,   274,   274,   274,   277,   285,   285,
     288,   320,   327,   327,   328,   328,   334,   340,   348,   352,
     353,   354,   355,   356,   357,   358,   359,   362,   362,   364,
     364,   366,   373,   376,   377,   378,   379,   383,   384,   385,
     386,   387,   388,   389,   390,   391,   392,   393,   394,   395,
     396,   397,   398,   399,   400,   401,   402,   403,   404,   405,
     406,   407,   408,   409,   410,   411,   412,   412,   412,   412,
     412,   415,   417,   418,   422,   425,   431,   432,   436,   441,
     443,   444,   444,   446,   448,   457,   465
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "IF", "ELSE", "EQ", "NEQ", "SUPEQ",
  "INFEQ", "OR", "AND", "MATCH", "NOMATCH", "REP", "FOR", "REPEAT",
  "UNTIL", "FOREACH", "WHILE", "BREAK", "CONTINUE", "FUNCTION", "RETURN",
  "INCLUDE", "LOCAL", "GLOBAL", "PLUS_PLUS", "MINUS_MINUS", "L_SHIFT",
  "R_SHIFT", "R_USHIFT", "EXPO", "PLUS_EQ", "MINUS_EQ", "MULT_EQ",
  "DIV_EQ", "MODULO_EQ", "L_SHIFT_EQ", "R_SHIFT_EQ", "R_USHIFT_EQ",
  "RE_MATCH", "RE_NOMATCH", "ARROW", "IDENT", "STRING1", "STRING2",
  "INTEGER", "'='", "'<'", "'>'", "'|'", "'^'", "'&'", "'+'", "'-'", "'*'",
  "'/'", "'%'", "NOT", "UMINUS", "BIT_NOT", "'('", "')'", "','", "'{'",
  "'}'", "';'", "':'", "'['", "']'", "'!'", "'~'", "'.'", "$accept",
  "tiptop", "instr_decl_list", "instr_decl", "func_decl", "arg_decl",
  "arg_decl_1", "block", "instr_list", "instr", "simple_instr", "ret",
  "if_block", "loop", "for_loop", "while_loop", "repeat_loop",
  "foreach_loop", "aff_func", "rep", "string", "inc", "func_call",
  "arg_list", "arg_list_1", "arg", "aff", "lvalue", "identifier",
  "array_elem", "array_index", "post_pre_incr", "expr", "const_array",
  "list_array_data", "array_data", "atom", "simple_array_data", "var",
  "var_name", "ipaddr", "loc", "glob", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,    61,    60,    62,
     124,    94,    38,    43,    45,    42,    47,    37,   302,   303,
     304,    40,    41,    44,   123,   125,    59,    58,    91,    93,
      33,   126,    46
};
# endif

#define YYPACT_NINF -91

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-91)))

#define YYTABLE_NINF -69

#define yytable_value_is_error(Yytable_value) \
  (!!((Yytable_value) == (-69)))

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     464,   -53,   -91,   -50,   491,    -6,   -42,   -91,   -91,    -6,
     499,   -40,    -6,    -6,    -6,    -6,   -91,   259,    25,   -91,
      91,   -91,   -91,   -91,   -39,   -91,   -91,   -91,   -91,   -91,
     -91,   -91,   -91,   -91,    23,   -91,   553,   -13,   -91,   -91,
     -91,   -91,   499,    26,    29,   -30,   499,   -21,   -91,   -91,
     -18,   499,   499,    13,   499,   499,   -91,   -91,   961,   611,
     -91,   798,   -91,   -91,   -91,   -91,   -91,    19,   -91,   -91,
     -12,   -91,   -91,   -26,   -91,   -91,    -9,   123,   -91,   -91,
     -91,   499,   -91,   -91,   499,   499,   499,   499,   499,   499,
     499,   499,   499,   499,   499,   566,    -4,   -91,   -91,   -91,
     499,   499,   624,    -6,    14,    37,   682,    39,    40,   -91,
      42,     7,    22,   -91,   -91,    37,    37,   499,   499,   499,
     499,   499,   499,   499,   499,   499,   499,   499,   499,    19,
      19,   499,   499,   499,   499,   499,   499,   499,   499,   499,
     499,   -91,   -91,    28,    -6,   -91,   -91,   798,   798,   798,
     798,   798,   798,   798,   798,   798,   798,    35,   -91,    33,
     945,   798,    17,   798,   491,   499,   347,   740,   491,    36,
      16,   -91,    34,   -91,    13,   882,   882,   882,   882,   851,
     913,   882,   882,   398,   398,   398,    37,   -91,   -91,   882,
     882,   354,   337,   415,    15,    15,    37,    37,    37,   -91,
     -91,   -91,   499,   499,   -91,    83,   409,   -91,   491,   -91,
      27,    53,   -91,   -91,   -91,   798,   491,    26,   -91,   -91,
      47,   -91,    38,    56,   491,   -91,   -91
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
      30,     0,    70,     0,    30,     0,     0,    28,    29,     0,
      32,     0,     8,     8,     0,     0,    69,    30,     0,     2,
       3,     6,    17,     5,     0,    24,    18,    19,    35,    36,
      37,    38,    22,    25,    23,    20,     0,    67,    68,    21,
      26,    27,     0,    46,     0,     0,     0,     0,   118,   117,
     116,     0,     0,     0,     0,     0,   122,   107,   123,   121,
      95,    31,   110,   109,   106,   120,   108,     0,   125,     9,
      10,   126,    73,    67,    74,    13,     0,    14,     1,     4,
      16,     0,    75,    76,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    53,     0,     0,     0,    45,    43,    44,
       0,     0,     0,     8,     0,    83,     0,   118,   117,   116,
       0,     0,   112,   119,   114,    79,    84,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    48,    49,     0,     0,    12,    15,    47,    59,    60,
      61,    62,    63,    66,    64,    65,    58,     0,    52,    54,
     123,    56,     0,    72,    30,     0,     0,     0,    30,     0,
       0,    77,     0,   111,     0,   102,   103,   104,   105,    80,
      78,    96,    97,    94,    92,    93,    86,    98,    99,   100,
     101,    91,    90,    89,    81,    82,    85,    87,    88,    50,
      11,    51,     0,     0,    71,    33,     0,    41,    30,    40,
       0,     0,   115,   113,    55,    57,    30,    46,    42,     7,
       0,    34,     0,     0,    30,   124,    39
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -91,   -91,   101,   -91,   -91,   -11,   -20,   -87,    48,    12,
     -91,   -91,   -91,   -91,   -91,   -91,   -91,   -91,   -90,   -91,
     -64,   -91,     6,   -91,   -74,   -91,    24,    60,     0,    18,
     -91,    30,   209,   -91,   -45,   -91,   -52,   -41,   -91,   -91,
     -91,   -91,   -91
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,    18,    19,    20,    21,    68,    69,    22,    76,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    96,    32,
     110,    33,    56,   157,   158,   159,    57,    36,    58,    59,
     162,    60,   161,    62,   111,   112,    63,   114,    64,    65,
      66,    40,    41
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      37,   113,    71,   143,    37,    45,    34,     2,    42,    47,
      34,    43,    70,    70,    73,    73,    44,    37,    38,    46,
      37,    67,    38,    34,    35,    78,    34,    80,    35,    77,
      39,   101,    38,    38,    39,    38,    81,    16,    38,     2,
     103,    35,    94,    37,    35,   100,   128,    39,    93,    97,
      39,   144,    14,    15,   104,    94,   145,   107,   108,   109,
     170,    38,   165,   141,   142,   187,   188,    98,   128,    16,
     138,   139,   140,    99,    72,    74,   173,    37,    48,    49,
     109,   -48,   -49,    34,   172,   174,   204,   216,   211,    77,
     199,    17,   169,   160,     1,    38,   202,   201,   210,   220,
     224,    35,   225,    70,     2,     3,     4,    39,     5,     6,
       7,     8,     9,    10,    11,    12,    13,    14,    15,   223,
     113,    79,   113,   219,   200,   146,     1,   222,   214,   213,
       0,   212,     0,     0,    16,     0,     2,     3,     4,     0,
       5,     6,     7,     8,    70,    10,    11,    12,    13,    14,
      15,     0,     0,     0,     0,    17,     0,   -30,     0,     0,
       0,     0,     0,     0,    37,     0,    16,     0,    37,     0,
      34,     0,     0,     0,    34,     0,   205,     0,     0,     0,
     209,     0,    38,     0,     0,     0,    38,    17,    35,   -30,
       0,     0,    35,     0,    39,     0,     0,     0,    39,     0,
       0,     0,   160,     0,     0,     0,     0,     0,    37,     0,
       0,     0,     0,     0,    34,     0,    37,    37,     0,    61,
     218,     0,    34,    97,    37,     0,    38,     0,   221,     0,
      34,     0,    35,     0,    38,    38,   226,     0,    39,     0,
      35,    98,    38,     0,     0,     0,    39,    99,    35,     0,
       0,    95,     0,     0,    39,   102,     0,     0,     0,     0,
     105,   106,     1,   115,   116,     0,     0,     0,     0,     0,
       0,     0,     2,     3,     4,     0,     5,     6,     7,     8,
       0,    10,    11,    12,    13,    14,    15,     0,     0,     0,
     147,     0,     0,   148,   149,   150,   151,   152,   153,   154,
     155,   156,    16,   163,     0,     0,     0,     0,     0,   166,
     167,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    17,    75,     0,   175,   176,   177,   178,
     179,   180,   181,   182,   183,   184,   185,   186,     0,     0,
     189,   190,   191,   192,   193,   194,   195,   196,   197,   198,
       0,     0,   117,   118,   119,   120,   121,   122,   123,   124,
       0,     0,     0,     0,     0,   125,   126,   127,   128,     0,
       0,     0,     0,     0,   206,   125,   126,   127,   128,     0,
       0,     0,   125,   126,   127,   128,     0,   129,   130,   135,
     136,   137,   138,   139,   140,   131,   132,   133,   134,   135,
     136,   137,   138,   139,   140,   134,   135,   136,   137,   138,
     139,   140,   215,   207,   117,   118,   119,   120,   121,   122,
     123,   124,     0,     0,     0,     0,   -69,   -69,   -69,   128,
       0,     0,     0,     0,     0,     0,     0,   125,   126,   127,
     128,     0,     0,   125,   126,   127,   128,     0,     0,   129,
     130,   136,   137,   138,   139,   140,     0,   131,   132,   133,
     134,   135,   136,   137,   138,   139,   140,     1,   136,   137,
     138,   139,   140,     0,     0,   217,     0,     2,     3,     4,
       0,     5,     6,     7,     8,     9,    10,    11,    12,    13,
      14,    15,     0,     0,     1,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     2,     3,     4,    16,     5,     6,
       7,     8,     2,    10,    11,    12,    13,    14,    15,     0,
       0,     0,     0,     0,     0,    14,    15,     0,    17,     0,
       0,     0,     0,     0,    16,     0,     0,     0,     0,     0,
       0,     0,    16,    48,    49,    50,     0,     0,     0,     0,
       0,     0,     0,    51,     0,    17,     0,     0,     0,     0,
      52,     0,     0,     0,     0,     0,     0,    53,     0,    54,
      55,   117,   118,   119,   120,   121,   122,   123,   124,    82,
      83,     0,     0,     0,     0,    84,    85,    86,    87,    88,
      89,    90,    91,     0,   125,   126,   127,   128,     0,     0,
      92,     0,     0,     0,     0,     0,   129,   130,     0,     0,
       0,     0,     0,     0,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,     0,     0,     0,     0,   164,   117,
     118,   119,   120,   121,   122,   123,   124,   -68,   -68,     0,
       0,     0,     0,   -68,   -68,   -68,   -68,   -68,   -68,   -68,
     -68,     0,   125,   126,   127,   128,     0,     0,   -68,     0,
       0,     0,     0,     0,   129,   130,     0,     0,     0,     0,
       0,     0,   131,   132,   133,   134,   135,   136,   137,   138,
     139,   140,     0,     0,     0,     0,   168,   117,   118,   119,
     120,   121,   122,   123,   124,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     125,   126,   127,   128,     0,     0,     0,     0,     0,     0,
       0,     0,   129,   130,     0,     0,     0,     0,     0,     0,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
       0,     0,     0,     0,   171,   117,   118,   119,   120,   121,
     122,   123,   124,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   125,   126,
     127,   128,     0,     0,     0,     0,     0,     0,     0,     0,
     129,   130,     0,     0,     0,     0,     0,     0,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,     0,     0,
       0,     0,   208,   117,   118,   119,   120,   121,   122,   123,
     124,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   125,   126,   127,   128,
       0,     0,     0,     0,     0,     0,     0,     0,   129,   130,
       0,     0,     0,     0,     0,     0,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   117,   118,   119,   120,
       0,   122,   123,   124,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   125,
     126,   127,   128,     0,     0,     0,     0,   -69,   -69,   -69,
     -69,   129,   130,   -69,   -69,     0,     0,     0,     0,   131,
     132,   133,   134,   135,   136,   137,   138,   139,   140,     0,
     125,   126,   127,   128,     0,     0,     0,     0,   117,   118,
     119,   120,   -69,   -69,   123,   124,     0,     0,     0,     0,
     -69,   -69,   133,   134,   135,   136,   137,   138,   139,   140,
       0,   125,   126,   127,   128,     0,     0,     0,     0,     0,
       0,     0,     0,   129,   130,     0,     0,     0,     0,     0,
       0,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   -67,   -67,     0,     0,     0,     0,   -67,   -67,   -67,
     -67,   -67,   -67,   -67,   -67,     0,     0,   -67,   -67,     0,
       0,     0,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,
     -67,     0,     0,     0,     0,     0,    93,     0,   -67,     0,
       0,     0,   203,    94,     0,     0,     0,     0,     0,     0,
       0,     0,    93,     0,     0,     0,     0,     0,     0,    94
};

static const yytype_int16 yycheck[] =
{
       0,    53,    13,    67,     4,     5,     0,    13,    61,     9,
       4,    61,    12,    13,    14,    15,     4,    17,     0,    61,
      20,    61,     4,    17,     0,     0,    20,    66,     4,    17,
       0,    61,    14,    15,     4,    17,    13,    43,    20,    13,
      61,    17,    68,    43,    20,    16,    31,    17,    61,    43,
      20,    63,    26,    27,    72,    68,    65,    44,    45,    46,
      46,    43,    66,    44,    45,   129,   130,    43,    31,    43,
      55,    56,    57,    43,    14,    15,    69,    77,    44,    45,
      46,    42,    42,    77,    42,    63,    69,     4,    72,    77,
      62,    64,   103,    93,     3,    77,    63,    62,    62,    46,
      62,    77,    46,   103,    13,    14,    15,    77,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    72,
     172,    20,   174,   210,   144,    77,     3,   217,   202,   174,
      -1,   172,    -1,    -1,    43,    -1,    13,    14,    15,    -1,
      17,    18,    19,    20,   144,    22,    23,    24,    25,    26,
      27,    -1,    -1,    -1,    -1,    64,    -1,    66,    -1,    -1,
      -1,    -1,    -1,    -1,   164,    -1,    43,    -1,   168,    -1,
     164,    -1,    -1,    -1,   168,    -1,   164,    -1,    -1,    -1,
     168,    -1,   164,    -1,    -1,    -1,   168,    64,   164,    66,
      -1,    -1,   168,    -1,   164,    -1,    -1,    -1,   168,    -1,
      -1,    -1,   202,    -1,    -1,    -1,    -1,    -1,   208,    -1,
      -1,    -1,    -1,    -1,   208,    -1,   216,   217,    -1,    10,
     208,    -1,   216,   217,   224,    -1,   208,    -1,   216,    -1,
     224,    -1,   208,    -1,   216,   217,   224,    -1,   208,    -1,
     216,   217,   224,    -1,    -1,    -1,   216,   217,   224,    -1,
      -1,    42,    -1,    -1,   224,    46,    -1,    -1,    -1,    -1,
      51,    52,     3,    54,    55,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    13,    14,    15,    -1,    17,    18,    19,    20,
      -1,    22,    23,    24,    25,    26,    27,    -1,    -1,    -1,
      81,    -1,    -1,    84,    85,    86,    87,    88,    89,    90,
      91,    92,    43,    94,    -1,    -1,    -1,    -1,    -1,   100,
     101,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    64,    65,    -1,   117,   118,   119,   120,
     121,   122,   123,   124,   125,   126,   127,   128,    -1,    -1,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
      -1,    -1,     5,     6,     7,     8,     9,    10,    11,    12,
      -1,    -1,    -1,    -1,    -1,    28,    29,    30,    31,    -1,
      -1,    -1,    -1,    -1,   165,    28,    29,    30,    31,    -1,
      -1,    -1,    28,    29,    30,    31,    -1,    40,    41,    52,
      53,    54,    55,    56,    57,    48,    49,    50,    51,    52,
      53,    54,    55,    56,    57,    51,    52,    53,    54,    55,
      56,    57,   203,    66,     5,     6,     7,     8,     9,    10,
      11,    12,    -1,    -1,    -1,    -1,    28,    29,    30,    31,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    28,    29,    30,
      31,    -1,    -1,    28,    29,    30,    31,    -1,    -1,    40,
      41,    53,    54,    55,    56,    57,    -1,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,     3,    53,    54,
      55,    56,    57,    -1,    -1,    66,    -1,    13,    14,    15,
      -1,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    -1,    -1,     3,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    13,    14,    15,    43,    17,    18,
      19,    20,    13,    22,    23,    24,    25,    26,    27,    -1,
      -1,    -1,    -1,    -1,    -1,    26,    27,    -1,    64,    -1,
      -1,    -1,    -1,    -1,    43,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    43,    44,    45,    46,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    54,    -1,    64,    -1,    -1,    -1,    -1,
      61,    -1,    -1,    -1,    -1,    -1,    -1,    68,    -1,    70,
      71,     5,     6,     7,     8,     9,    10,    11,    12,    26,
      27,    -1,    -1,    -1,    -1,    32,    33,    34,    35,    36,
      37,    38,    39,    -1,    28,    29,    30,    31,    -1,    -1,
      47,    -1,    -1,    -1,    -1,    -1,    40,    41,    -1,    -1,
      -1,    -1,    -1,    -1,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    57,    -1,    -1,    -1,    -1,    62,     5,
       6,     7,     8,     9,    10,    11,    12,    26,    27,    -1,
      -1,    -1,    -1,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    28,    29,    30,    31,    -1,    -1,    47,    -1,
      -1,    -1,    -1,    -1,    40,    41,    -1,    -1,    -1,    -1,
      -1,    -1,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    57,    -1,    -1,    -1,    -1,    62,     5,     6,     7,
       8,     9,    10,    11,    12,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      28,    29,    30,    31,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    40,    41,    -1,    -1,    -1,    -1,    -1,    -1,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    57,
      -1,    -1,    -1,    -1,    62,     5,     6,     7,     8,     9,
      10,    11,    12,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    28,    29,
      30,    31,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      40,    41,    -1,    -1,    -1,    -1,    -1,    -1,    48,    49,
      50,    51,    52,    53,    54,    55,    56,    57,    -1,    -1,
      -1,    -1,    62,     5,     6,     7,     8,     9,    10,    11,
      12,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    28,    29,    30,    31,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    40,    41,
      -1,    -1,    -1,    -1,    -1,    -1,    48,    49,    50,    51,
      52,    53,    54,    55,    56,    57,     5,     6,     7,     8,
      -1,    10,    11,    12,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    28,
      29,    30,    31,    -1,    -1,    -1,    -1,     5,     6,     7,
       8,    40,    41,    11,    12,    -1,    -1,    -1,    -1,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    -1,
      28,    29,    30,    31,    -1,    -1,    -1,    -1,     5,     6,
       7,     8,    40,    41,    11,    12,    -1,    -1,    -1,    -1,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    57,
      -1,    28,    29,    30,    31,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    40,    41,    -1,    -1,    -1,    -1,    -1,
      -1,    48,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    26,    27,    -1,    -1,    -1,    -1,    32,    33,    34,
      35,    36,    37,    38,    39,    -1,    -1,    26,    27,    -1,
      -1,    -1,    47,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    -1,    -1,    -1,    -1,    61,    -1,    47,    -1,
      -1,    -1,    67,    68,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    61,    -1,    -1,    -1,    -1,    -1,    -1,    68
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     3,    13,    14,    15,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    43,    64,    74,    75,
      76,    77,    80,    82,    83,    84,    85,    86,    87,    88,
      89,    90,    92,    94,    95,    99,   100,   101,   102,   104,
     114,   115,    61,    61,    82,   101,    61,   101,    44,    45,
      46,    54,    61,    68,    70,    71,    95,    99,   101,   102,
     104,   105,   106,   109,   111,   112,   113,    61,    78,    79,
     101,    78,   100,   101,   100,    65,    81,    82,     0,    75,
      66,    13,    26,    27,    32,    33,    34,    35,    36,    37,
      38,    39,    47,    61,    68,   105,    91,    95,    99,   104,
      16,    61,   105,    61,    72,   105,   105,    44,    45,    46,
      93,   107,   108,   109,   110,   105,   105,     5,     6,     7,
       8,     9,    10,    11,    12,    28,    29,    30,    31,    40,
      41,    48,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    44,    45,    93,    63,    65,    81,   105,   105,   105,
     105,   105,   105,   105,   105,   105,   105,    96,    97,    98,
     101,   105,   103,   105,    62,    66,   105,   105,    62,    78,
      46,    62,    42,    69,    63,   105,   105,   105,   105,   105,
     105,   105,   105,   105,   105,   105,   105,    93,    93,   105,
     105,   105,   105,   105,   105,   105,   105,   105,   105,    62,
      79,    62,    63,    67,    69,    82,   105,    66,    62,    82,
      62,    72,   110,   107,    97,   105,     4,    66,    82,    80,
      46,    82,    91,    72,    62,    46,    82
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    73,    74,    75,    75,    76,    76,    77,    78,    78,
      79,    79,    80,    80,    81,    81,    82,    82,    82,    82,
      83,    83,    83,    83,    83,    83,    83,    83,    83,    83,
      83,    84,    84,    85,    85,    86,    86,    86,    86,    87,
      88,    89,    90,    91,    91,    91,    91,    92,    93,    93,
      94,    95,    96,    96,    97,    97,    98,    98,    99,    99,
      99,    99,    99,    99,    99,    99,    99,   100,   100,   101,
     101,   102,   103,   104,   104,   104,   104,   105,   105,   105,
     105,   105,   105,   105,   105,   105,   105,   105,   105,   105,
     105,   105,   105,   105,   105,   105,   105,   105,   105,   105,
     105,   105,   105,   105,   105,   105,   105,   105,   105,   105,
     105,   106,   107,   107,   108,   108,   109,   109,   109,   110,
     111,   111,   111,   112,   113,   114,   115
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     1,     1,     2,     1,     1,     6,     0,     1,
       1,     3,     3,     2,     1,     2,     2,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       0,     2,     1,     5,     7,     1,     1,     1,     1,     9,
       5,     5,     6,     1,     1,     1,     0,     3,     1,     1,
       4,     4,     1,     0,     1,     3,     1,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     1,     1,     1,
       1,     4,     1,     2,     2,     2,     2,     3,     3,     2,
       3,     3,     3,     2,     2,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     1,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     1,     1,     1,     1,
       1,     3,     1,     3,     1,     3,     1,     1,     1,     1,
       1,     1,     1,     1,     7,     2,     2
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (parm, YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, parm); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, naslctxt * parm)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  YYUSE (parm);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, naslctxt * parm)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, parm);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule, naslctxt * parm)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              , parm);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, parm); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, naslctxt * parm)
{
  YYUSE (yyvaluep);
  YYUSE (parm);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/*----------.
| yyparse.  |
`----------*/

int
yyparse (naslctxt * parm)
{
/* The lookahead symbol.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex (&yylval, parm);
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 142 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  ((naslctxt*)parm)->tree = (yyvsp[0].node);
	}
#line 1645 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 3:
#line 147 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type = NODE_INSTR_L;
	  (yyval.node)->link[0] = (yyvsp[0].node);
	}
#line 1655 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 4:
#line 153 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type = NODE_INSTR_L;
	  (yyval.node)->link[0] = (yyvsp[-1].node);
	  (yyval.node)->link[1] = (yyvsp[0].node);
	}
#line 1666 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 7:
#line 163 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, (yyvsp[-4].str));
	  (yyval.node)->type = NODE_FUN_DEF;
	  (yyval.node)->link[0] = (yyvsp[-2].node);
	  (yyval.node)->link[1] = (yyvsp[0].node);
	}
#line 1677 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 8:
#line 170 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = NULL; }
#line 1683 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 9:
#line 170 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 1689 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 10:
#line 171 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_tree_cell(LNB, (yyvsp[0].str)); (yyval.node)->type = NODE_DECL; }
#line 1695 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 11:
#line 173 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, (yyvsp[-2].str));
	  (yyval.node)->type = NODE_DECL;
	  (yyval.node)->link[0] = (yyvsp[0].node);
	}
#line 1705 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 12:
#line 180 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[-1].node); }
#line 1711 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 13:
#line 180 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = NULL; }
#line 1717 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 15:
#line 183 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  if ((yyvsp[-1].node) == NULL)
	    (yyval.node) = (yyvsp[0].node);
	  else
	    {
	      (yyval.node) = alloc_tree_cell(LNB, NULL);
	      (yyval.node)->type = NODE_INSTR_L;
	      (yyval.node)->link[0] = (yyvsp[-1].node);
	      (yyval.node)->link[1] = (yyvsp[0].node);
	    }
	}
#line 1733 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 16:
#line 196 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[-1].node); }
#line 1739 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 28:
#line 201 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type =  NODE_BREAK;
	}
#line 1748 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 29:
#line 205 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type =  NODE_CONTINUE;
	}
#line 1757 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 30:
#line 209 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = NULL; }
#line 1763 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 31:
#line 213 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type =  NODE_RETURN;
	  (yyval.node)->link[0] = (yyvsp[0].node);
	}
#line 1773 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 32:
#line 219 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type =  NODE_RETURN;
	}
#line 1782 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 33:
#line 226 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type = NODE_IF_ELSE;
	  (yyval.node)->link[0] = (yyvsp[-2].node); (yyval.node)->link[1] = (yyvsp[0].node);
	}
#line 1792 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 34:
#line 232 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type = NODE_IF_ELSE;
	  (yyval.node)->link[0] = (yyvsp[-4].node); (yyval.node)->link[1] = (yyvsp[-2].node); (yyval.node)->link[2] = (yyvsp[0].node);
	}
#line 1802 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 39:
#line 241 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type = NODE_FOR;
	  (yyval.node)->link[0] = (yyvsp[-6].node);
	  (yyval.node)->link[1] = (yyvsp[-4].node);
	  (yyval.node)->link[2] = (yyvsp[-2].node);
	  (yyval.node)->link[3] = (yyvsp[0].node);
	}
#line 1815 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 40:
#line 251 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type = NODE_WHILE;
	  (yyval.node)->link[0] = (yyvsp[-2].node);
	  (yyval.node)->link[1] = (yyvsp[0].node);
	}
#line 1826 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 41:
#line 258 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type = NODE_REPEAT_UNTIL;
	  (yyval.node)->link[0] = (yyvsp[-3].node);
	  (yyval.node)->link[1] = (yyvsp[-1].node);
	}
#line 1837 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 42:
#line 266 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, (yyvsp[-4].str));
	  (yyval.node)->type = NODE_FOREACH;
	  (yyval.node)->link[0] = (yyvsp[-2].node);
	  (yyval.node)->link[1] = (yyvsp[0].node);
	}
#line 1848 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 46:
#line 274 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = NULL; }
#line 1854 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 47:
#line 278 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type = NODE_REPEATED;
	  (yyval.node)->link[0] = (yyvsp[-2].node);
	  (yyval.node)->link[1] = (yyvsp[0].node);
	}
#line 1865 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 48:
#line 285 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.str) = (yyvsp[0].data).val; }
#line 1871 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 50:
#line 289 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  naslctxt	subctx;
	  int		x;

          subctx.always_authenticated = ((naslctxt*)parm)->always_authenticated;
          subctx.kb = ((naslctxt *) parm)->kb;
	  x = init_nasl_ctx(&subctx, (yyvsp[-1].str));
	  (yyval.node) = NULL;
	  if (x >= 0)
	    {
	      if (! naslparse(&subctx))
		{
		  (yyval.node) = subctx.tree;
		}
	      else
		nasl_perror(NULL, "%s: Parse error at or near line %d\n",
			(yyvsp[-1].str), subctx.line_nb);
	      g_free(subctx.buffer);
	      subctx.buffer = NULL;
	      fclose(subctx.fp);
	      subctx.fp = NULL;
	      g_free((yyvsp[-1].str));
	    }
          else
            {
              g_free((yyvsp[-1].str));
              return -2;
            }
	}
#line 1905 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 51:
#line 321 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, (yyvsp[-3].str));
	  (yyval.node)->type = NODE_FUN_CALL;
	  (yyval.node)->link[0] = (yyvsp[-1].node);
	}
#line 1915 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 53:
#line 327 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = NULL; }
#line 1921 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 55:
#line 329 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyvsp[-2].node)->link[1] = (yyvsp[0].node);
	  (yyval.node) = (yyvsp[-2].node);
	}
#line 1930 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 56:
#line 335 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type = NODE_ARG;
	  (yyval.node)->link[0] = (yyvsp[0].node);
	}
#line 1940 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 57:
#line 341 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, (yyvsp[-2].str));
	  (yyval.node)->type = NODE_ARG;
	  (yyval.node)->link[0] = (yyvsp[0].node);
	}
#line 1950 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 58:
#line 349 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_expr_cell(LNB, NODE_AFF, (yyvsp[-2].node), (yyvsp[0].node));
	}
#line 1958 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 59:
#line 352 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, NODE_PLUS_EQ, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1964 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 60:
#line 353 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, NODE_MINUS_EQ, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1970 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 61:
#line 354 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, NODE_MULT_EQ, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1976 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 62:
#line 355 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, NODE_DIV_EQ, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1982 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 63:
#line 356 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, NODE_MODULO_EQ, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1988 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 64:
#line 357 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, NODE_R_SHIFT_EQ, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1994 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 65:
#line 358 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, NODE_R_USHIFT_EQ, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2000 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 66:
#line 359 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, NODE_L_SHIFT_EQ, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2006 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 67:
#line 362 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_tree_cell(LNB, (yyvsp[0].str)); (yyval.node)->type = NODE_VAR; }
#line 2012 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 70:
#line 364 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.str) = strdup("x"); }
#line 2018 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 71:
#line 367 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, (yyvsp[-3].str));
	  (yyval.node)->type = NODE_ARRAY_EL;
	  (yyval.node)->link[0] = (yyvsp[-1].node);
	}
#line 2028 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 73:
#line 376 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_INCR, NULL, (yyvsp[0].node)); }
#line 2034 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 74:
#line 377 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {(yyval.node) = alloc_expr_cell(LNB, EXPR_DECR, NULL, (yyvsp[0].node)); }
#line 2040 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 75:
#line 378 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node)= alloc_expr_cell(LNB, EXPR_INCR, (yyvsp[-1].node), NULL); }
#line 2046 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 76:
#line 379 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node)= alloc_expr_cell(LNB, EXPR_DECR, (yyvsp[-1].node), NULL); }
#line 2052 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 77:
#line 383 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[-1].node); }
#line 2058 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 78:
#line 384 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {  (yyval.node) = alloc_expr_cell(LNB, EXPR_AND, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2064 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 79:
#line 385 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {  (yyval.node) = alloc_expr_cell(LNB, EXPR_NOT, (yyvsp[0].node), NULL); }
#line 2070 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 80:
#line 386 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_OR, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2076 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 81:
#line 387 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_PLUS, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2082 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 82:
#line 388 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_MINUS, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2088 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 83:
#line 389 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_U_MINUS, (yyvsp[0].node), NULL);}
#line 2094 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 84:
#line 390 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_BIT_NOT, (yyvsp[0].node), NULL);}
#line 2100 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 85:
#line 391 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_MULT, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2106 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 86:
#line 392 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_EXPO, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2112 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 87:
#line 393 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_DIV, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2118 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 88:
#line 394 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_MODULO, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2124 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 89:
#line 395 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_BIT_AND, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2130 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 90:
#line 396 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_BIT_XOR, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2136 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 91:
#line 397 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_BIT_OR, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2142 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 92:
#line 398 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_R_SHIFT, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2148 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 93:
#line 399 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_R_USHIFT, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2154 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 94:
#line 400 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, EXPR_L_SHIFT, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2160 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 96:
#line 402 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, COMP_MATCH, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2166 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 97:
#line 403 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, COMP_NOMATCH, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2172 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 98:
#line 404 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_RE_cell(LNB, COMP_RE_MATCH, (yyvsp[-2].node), (yyvsp[0].str)); }
#line 2178 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 99:
#line 405 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_RE_cell(LNB, COMP_RE_NOMATCH, (yyvsp[-2].node), (yyvsp[0].str)); }
#line 2184 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 100:
#line 406 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, COMP_LT, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2190 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 101:
#line 407 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, COMP_GT, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2196 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 102:
#line 408 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, COMP_EQ, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2202 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 103:
#line 409 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, COMP_NE, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2208 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 104:
#line 410 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, COMP_GE, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2214 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 105:
#line 411 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_expr_cell(LNB, COMP_LE, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 2220 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 111:
#line 415 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = make_array_from_elems((yyvsp[-1].node)); }
#line 2226 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 112:
#line 417 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = (yyvsp[0].node); }
#line 2232 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 113:
#line 418 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
		(yyvsp[-2].node)->link[1] = (yyvsp[0].node); (yyval.node) = (yyvsp[-2].node);
	}
#line 2240 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 114:
#line 422 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_typed_cell(ARRAY_ELEM);
	  (yyval.node)->link[0] = (yyvsp[0].node);
	}
#line 2249 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 115:
#line 425 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_typed_cell(ARRAY_ELEM);
	  (yyval.node)->link[0] = (yyvsp[0].node);
	  (yyval.node)->x.str_val = (yyvsp[-2].str);
	}
#line 2259 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 116:
#line 431 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {  (yyval.node) = alloc_typed_cell(CONST_INT); (yyval.node)->x.i_val = (yyvsp[0].num); }
#line 2265 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 117:
#line 432 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_typed_cell(CONST_STR); (yyval.node)->x.str_val = (yyvsp[0].str);
	  (yyval.node)->size = strlen((yyvsp[0].str));
	}
#line 2274 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 118:
#line 436 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_typed_cell(CONST_DATA); (yyval.node)->x.str_val = (yyvsp[0].data).val;
	  (yyval.node)->size = (yyvsp[0].data).len;
	}
#line 2283 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 120:
#line 443 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    { (yyval.node) = alloc_tree_cell(LNB, (yyvsp[0].str)); (yyval.node)->type = NODE_VAR; }
#line 2289 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 124:
#line 449 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  char *s = g_strdup_printf ("%d.%d.%d.%d", (yyvsp[-6].num), (yyvsp[-4].num), (yyvsp[-2].num), (yyvsp[0].num));
	  (yyval.node) = alloc_tree_cell(LNB, s);
	  (yyval.node)->type = CONST_STR;
	  (yyval.node)->size = strlen(s);
	}
#line 2300 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 125:
#line 458 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type = NODE_LOCAL;
	  (yyval.node)->link[0] = (yyvsp[0].node);
	}
#line 2310 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;

  case 126:
#line 466 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1646  */
    {
	  (yyval.node) = alloc_tree_cell(LNB, NULL);
	  (yyval.node)->type = NODE_GLOBAL;
	  (yyval.node)->link[0] = (yyvsp[0].node);
	}
#line 2320 "nasl_grammar.tab.c" /* yacc.c:1646  */
    break;


#line 2324 "nasl_grammar.tab.c" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (parm, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (parm, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, parm);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp, parm);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (parm, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, parm);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp, parm);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 472 "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/nasl/nasl_grammar.y" /* yacc.c:1906  */


#include <stdio.h>
#include <stdlib.h>
#include "openvas_logging.h"
#include "openvas_file.h"
#include <gcrypt.h>

static void
naslerror(naslctxt *parm, const char *s)
{
  fputs(s, stderr);
}

static GSList * inc_dirs = NULL;

/**
 * @brief Adds the given string as directory for searching for includes.
 *
 * @param dir  A directory path. This function will add a copy of this parameter
 *             to the list of include folders. This means the parameter can be
 *             freed elsewhere without affecting the list.
 *
 * @return  0 in case of success.
 *         -1 if the stat on the given directory path was unsuccessful.
 *         -2 if the given directory path was not a directory.
 */
int
add_nasl_inc_dir (const char * dir)
{
  if (dir == NULL)
    {
      return 0;
    }

  // Allow initialization with empty element
  if (*dir == '\0')
    {
      inc_dirs = g_slist_append (inc_dirs, g_strdup((gchar *)dir));
      return 0;
    }

  struct stat stat_buf;

  if (stat (dir, &stat_buf) != 0)
    return -1;

  if (S_ISDIR(stat_buf.st_mode) != 0)
    {
      inc_dirs = g_slist_append (inc_dirs, g_strdup((gchar *)dir));
      return 0;
    }
  else
    return -2;
}

/**
 * @brief Get the md5sum of a file.
 *
 * @param[in]  filename     Path to file.
 *
 * @return md5sum string, NULL otherwise.
 */
static char *
file_md5sum (const char *filename)
{
  char *content = NULL, digest[16], *result;
  size_t len = 0, i;

  if (!filename || !g_file_get_contents (filename, &content, &len, NULL))
    return NULL;

  gcry_md_hash_buffer (GCRY_MD_MD5, digest, content, len);
  result = g_malloc0 (33);
  for (i = 0; i < 16; i++)
    snprintf (result + 2 * i, 3, "%02x", (unsigned char) digest[i]);
  g_free (content);

  return result;
}

/**
 * @brief Initialize a NASL context for a NASL file.
 *
 * @param pc   The NASL context handler.
 *
 * @param name The filename of the NASL script.
 *
 * @return    0  in case of success. Then, pc->fp is set with
 *               the respective file descriptor
 *            -1 if either the filename was not found/accessable
 *               or the signature verification failed (provided
 *               signature checking is enabled.
 *               Also, the pc->fp is set to NULL.
 *            In any case, various elements of pc are modified
 *            (initialized);
 */
int
init_nasl_ctx(naslctxt* pc, const char* name)
{
  char *full_name = NULL, key_path[2048];
  GSList * inc_dir = inc_dirs; // iterator for include directories

  // initialize if not yet done (for openvas-server < 2.0.1)
  if (! inc_dirs) add_nasl_inc_dir("");

  pc->line_nb = 1;
  pc->tree = NULL;
  pc->buffer = g_malloc0 (80);
  pc->maxlen = 80;
  pc->fp = NULL;

  while (inc_dir != NULL) {
    if (full_name)
      g_free (full_name);
    full_name = g_build_filename(inc_dir->data, name, NULL);

    if ((pc->fp = fopen(full_name, "r")) != NULL)
      break;

    inc_dir = g_slist_next(inc_dir);
  }

  if (! pc->fp) {
    //log_legacy_write ("%s: Not able to open nor to locate it in include paths",
           //           name);
    g_free(full_name);
    return 0;
  }

  if (pc->always_authenticated)
    {
      g_free(full_name);
      return 0;
    }
  /* Cache the md5sum of signature verified files, so that commonly included
   * files are not verified multiple times per scan. */
  if (pc->kb)
    {
      char *check, *md5sum;

      snprintf (key_path, sizeof (key_path), "SignatureCheck/%s", full_name);
      check = kb_item_get_str (pc->kb, key_path);
      if (!check)
        ;
      else if (!strcmp (check, "0"))
        {
          g_free (full_name);
          return -1;
        }
      else
        {
          md5sum = file_md5sum (full_name);
          if (!strcmp (check, md5sum))
            {
              /* md5sum of file matches. No need to reverify. */
              g_free (full_name);
              g_free (md5sum);
              return 0;
            }
          /* Different md5sum. Reverify. */
          g_free (md5sum);
        }
    }

  if (nasl_verify_signature(full_name) != 0)
    {
      log_legacy_write ("%s: Will not execute. Bad or missing signature",
                        full_name);
      if (pc->kb)
        kb_item_add_str (pc->kb, key_path, "0");
      fclose(pc->fp);
      pc->fp = NULL;
      g_free(full_name);
      return -1;
    }
  if (pc->kb)
    {
      char *md5sum = file_md5sum (full_name);
      kb_item_add_str (pc->kb, key_path, md5sum);
      g_free (md5sum);
    }

  g_free(full_name);
  return 0;
}

void
nasl_clean_ctx(naslctxt* c)
{
#if 0
  nasl_dump_tree(c->tree);
#endif
  deref_cell(c->tree);
  g_free(c->buffer);
  c->buffer = NULL;
  if (c->fp)
    {
      fclose(c->fp);
      c->fp = NULL;
    }
}

enum lex_state {
  ST_START = 0,
  ST_SPACE,
  ST_IDENT,
  ST_ZERO,
  ST_ZEROX,
  ST_OCT,
  ST_DEC,
  ST_HEX,
  ST_COMMENT,
  ST_SUP,
  ST_INF,
  ST_SUP_EXCL,
  ST_STRING1,
  ST_STRING1_ESC,
  ST_STRING2,
  ST_PLUS,
  ST_MINUS,
  ST_MULT,
  ST_DIV,
  ST_MODULO,
  ST_R_SHIFT,
  ST_R_USHIFT,
  ST_L_SHIFT,
  ST_NOT,
  ST_EQ,
  ST_AND,
  ST_OR };

static int
mylex(lvalp, parm)
     YYSTYPE *lvalp;
     void	*parm;
{
  char		*p;
  naslctxt	*ctx = parm;
  FILE		*fp;
  int		c, st = ST_START, len, r;
  int		x, i;

  if (!ctx)
    return -1;

  fp = ctx->fp;
  p = ctx->buffer;
  len = 0;

  while ((c = getc(fp)) != EOF)
    {
      if (c ==  '\n')
	ctx->line_nb ++;

      switch(st)
	{
	case ST_START:
	  if (c == '#')
	    st = ST_COMMENT;
	  else if (isalpha(c) || c == '_')
	    {
	      st = ST_IDENT;
	      *p++ = c;
	      len ++;
	    }
	  else if (isspace(c))
	    st = ST_SPACE;
	  else if (c == '0')
	    st = ST_ZERO;
	  else if (isdigit(c))
	    {
	      st = ST_DEC;
	      *p++ = c;
	      len ++;
	    }
	  else if (c == '\'')
	    st = ST_STRING1;
	  else if (c == '"')
	    st = ST_STRING2;
	  else if (c == '+')
	    st = ST_PLUS;
	  else if (c == '-')
	    st = ST_MINUS;
	  else if (c == '*')
	    st = ST_MULT;
	  else if (c == '/')
	    st = ST_DIV;
	  else if (c == '%')
	    st = ST_MODULO;
	  else if (c == '>')
	    st =  ST_SUP;
	  else if (c == '<')
	    st = ST_INF;
	  else if (c == '=')
	    st = ST_EQ;
	  else if (c == '|')
	    st = ST_OR;
	  else if (c == '!')
	    st = ST_NOT;
	  else if (c == '&')
	    st = ST_AND;
	  else
	    {
	      return c;
	    }
	  break;

	case ST_STRING2:
	  if (c == '"')
	    goto exit_loop;
	  *p++ = c;
	  len ++;
	  break;

	case ST_STRING1:
	  if (c == '\'')
	    goto exit_loop;
	  else if (c == '\\')
	    {
	      c = getc(fp);
	      switch (c)
		{
		case EOF:
		  nasl_perror(NULL, "Unfinished string\n");
		  goto exit_loop; /* parse error? */

		case '\n':	/* escaped end of line */
		  ctx->line_nb ++;
		  break;
		case '\\':
		  *p++ ='\\'; len ++;
		  break;
		case 'n':
		  *p++ = '\n'; len++;
		  break;
		case 'f':
		  *p++ = '\f'; len ++;
		  break;
		case 't':
		  *p++ = '\t'; len ++;
		  break;
		case 'r':
		  *p++ = '\r'; len++;
		  break;
		case 'v':
		  *p++ = '\v'; len ++;
		  break;
		case '"':
		  *p ++ = '"'; len ++;
		  break;
	  /* Not yet, as we do not return the length of the string */
		case '0':
		  *p++ = '\0'; len++;
		  break;
		case '\'':
		  *p++ = '\''; len++;
		  break;

		case 'x':
		  x = 0;
		  for (i = 0; i < 2; i ++)
		    {
		      c = getc(fp);
		      if (c == EOF)
			{
			  nasl_perror(NULL, "Unfinished \\x escape sequence (EOF)\n");
			  goto exit_loop;
			}
		      if (c == '\n')
			ctx->line_nb ++;

		      c = tolower(c);
		      if (c >= '0' && c <= '9')
			x = x * 16 + (c - '0');
		      else if (c >= 'a' && c <= 'f')
			x = x * 16 + 10 + (c - 'a');
		      else
			{
			  nasl_perror(NULL, "Unfinished \\x escape sequence\n");
			  ungetc(c, fp);
			  if (c == '\n')
			    ctx->line_nb --;
			  break;
			}
		    }
		  *p++ = x; len ++;
		  break;

		default:
		  nasl_perror(NULL, "Unknown escape sequence \\%c\n", c);
		  *p++ = c; len ++;
		  break;
		}
	    }
	  else
	    {
	      *p++ = c;
	      len ++;
	    }
	  break;

	case ST_IDENT:
	  if (isalnum(c) || c == '_')
	    {
	      st = ST_IDENT;
	      *p++ = c;
	      len ++;
	    }
	  else
	    {
	      ungetc(c, fp);
	      if (c == '\n')
		ctx->line_nb --;
	      goto exit_loop;
	    }
	  break;

	case ST_ZERO:
	  if (c == 'x' || c == 'X')
	    st = ST_ZEROX;
	  else if (isdigit(c))
	    {
	      if (c <= '7')
		st = ST_OCT;
	      else
		st = ST_DEC;
	      *p ++ = c;
	      len ++;
	    }
	  else
	    {
	      ungetc(c, fp);
	      if (c == '\n')
		ctx->line_nb --;
	      goto exit_loop;
	    }
	  break;

	case ST_ZEROX:
	  if (isxdigit(c))
	    {
	      st = ST_HEX;
	      *p++ = c;
	      len ++;
	    }
	  else
	    {
	      /* This should be a parse error */
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      goto exit_loop;
	    }
	  break;

	case ST_OCT:
	  if (c >= '0')
	    {
	    if (c <= '7')
	      {
		*p++ = c;
		len ++;
		break;
	      }
	    else if (c <= '9')
	      {
		*p++ = c;
		len ++;
		st = ST_DEC;
		break;
	      }
	    }
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  goto exit_loop;

	case ST_DEC:
	  if (isdigit(c))
	    {
	      *p++ = c;
	      len ++;
	    }
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      goto exit_loop;
	    }
	  break;

	case ST_HEX:
	  if (isxdigit(c))
	    {
	      *p++ = c;
	      len ++;
	    }
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      goto exit_loop;
	    }
	  break;

	case ST_SPACE:
	  if (! isspace(c))
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      st = ST_START;
	    }
	  break;

	case ST_COMMENT:
	  if (c == '\n')
	    st = ST_START;
	  break;

	case ST_SUP_EXCL:
	  if (c == '<')
	    return NOMATCH;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      if (! isprint(c)) c = '.';
	      log_legacy_write ("lexer error: invalid token >!%c "
                                "parsed as >!< %c", c, c);
	      return NOMATCH;
	    }
	  break;

	case ST_SUP:
	  if (c == '=')
	    return SUPEQ;
	  else if (c == '<')
	    return MATCH;
	  else if (c == '>')
	    st = ST_R_SHIFT;
	  else if (c == '!')
	    st = ST_SUP_EXCL;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      return '>';
	    }
	  break;

	case ST_INF:
	  if (c == '=')
	    return INFEQ;
	  else if (c == '<')
	    st = ST_L_SHIFT;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      return '<';
	    }
	  break;

	case ST_R_SHIFT:
	  if (c == '=')
	    return R_SHIFT_EQ;
	  else if (c == '>')
	    st = ST_R_USHIFT;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      return R_SHIFT;
	    }
	  /*NOTREACHED*/
	  break;

	case ST_R_USHIFT:
	  if (c == '=')
	    return R_USHIFT_EQ;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      return R_USHIFT;
	    }
	  /*NOTREACHED*/
	  break;

	case ST_L_SHIFT:
	  if (c == '=')
	    return L_SHIFT_EQ;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      return L_SHIFT;
	    }
	  /*NOTREACHED*/
	  break;

	case ST_AND:
	  if (c == '&')
	    return AND;
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '&';

	case ST_OR:
	  if (c == '|')
	    return OR;
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '|';

	case ST_NOT:
	  if (c == '=')
	    return NEQ;
	  else if (c == '~')
	    return RE_NOMATCH;
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '!';

	case ST_EQ:
	  if (c == '=')
	    return EQ;
	  else if (c == '~')
	    return RE_MATCH;
	  else if (c == '>')
	    return ARROW;
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '=';

	case ST_PLUS:
	  if (c == '+')
	    return PLUS_PLUS;
	  else if (c == '=')
	    return PLUS_EQ;

	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '+';

	case ST_MINUS:
	  if (c == '-')
	    return MINUS_MINUS;
	  else if (c == '=')
	    return MINUS_EQ;

	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '-';

	case ST_MULT:
	  if (c == '=')
	    return MULT_EQ;
	  else if (c == '*')
	    return EXPO;
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '*';

	case ST_DIV:
	  if (c == '=')
	    return DIV_EQ;

	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '/';

	case ST_MODULO:
	  if (c == '=')
	    return MODULO_EQ;

	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '%';

	}

      if (len >= ctx->maxlen)
	{
	  int	offs = p - ctx->buffer;
	  char	*buf2;
	  ctx->maxlen += 80;
	  buf2 = g_realloc(ctx->buffer, ctx->maxlen + 1);
	  p = buf2 + offs;
	  ctx->buffer = buf2;
	}
    }

 exit_loop:
  ctx->buffer[len] = '\0';
  switch (st)
    {
    case ST_START:
    case ST_COMMENT:
    case ST_SPACE:
      return 0;

    case ST_STRING2:
      r = STRING2;
      lvalp->str = g_strdup(ctx->buffer);
      return r;

    case ST_STRING1:
      r = STRING1;
      lvalp->data.val = g_malloc0 (len+2);
      memcpy(lvalp->data.val, ctx->buffer, len+1);
      lvalp->data.len = len;
      return r;

    case ST_IDENT:
      if (strcmp(ctx->buffer, "if") == 0)
	r = IF;
      else if (strcmp(ctx->buffer, "else") == 0)
	r = ELSE;
      else if (strcmp(ctx->buffer, "for") == 0)
	r = FOR;
      else if (strcmp(ctx->buffer, "while") == 0)
	r = WHILE;
      else if (strcmp(ctx->buffer, "repeat") == 0)
	r = REPEAT;
      else if (strcmp(ctx->buffer, "until") == 0)
	r = UNTIL;
      else if (strcmp(ctx->buffer, "foreach") == 0)
	r = FOREACH;
      else if (strcmp(ctx->buffer, "function") == 0)
	r = FUNCTION;
      else if (strcmp(ctx->buffer, "return") == 0)
	r = RETURN;
      else if (strcmp(ctx->buffer, "x") == 0)
	r = REP;
      else if (strcmp(ctx->buffer, "include") == 0)
	r = INCLUDE;
      else if (strcmp(ctx->buffer, "break") == 0)
	r = BREAK;
      else if (strcmp(ctx->buffer, "continue") == 0)
	r = CONTINUE;
      else if (strcmp(ctx->buffer, "local_var") == 0)
	r = LOCAL;
      else if (strcmp(ctx->buffer, "global_var") == 0)
	r = GLOBAL;
      else
	{
	  r = IDENT;
	  lvalp->str = g_strdup(ctx->buffer);
	  return r;
	}
      return r;

    case ST_DEC:
      /* -123 is parsed as "-" and "123" so that we can write "4-2" without
       * inserting a white space after the minus operator
       * Note that strtoul would also work on negative integers */
      lvalp->num = x = strtoul(ctx->buffer, NULL, 10);
#if NASL_DEBUG > 1 && defined(ULONG_MAX) && defined(ERANGE)
      if (x == ULONG_MAX && errno == ERANGE)
	nasl_perror(NULL, "Integer overflow while converting %s at or near line %d\n", ctx->buffer, ctx->line_nb);
#endif
      return INTEGER;

    case ST_OCT:
      lvalp->num = x = strtoul(ctx->buffer, NULL, 8);
#if NASL_DEBUG > 1 && defined(ULONG_MAX) && defined(ERANGE)
      if (x == ULONG_MAX && errno == ERANGE)
	nasl_perror(NULL, "Integer overflow while converting %s at or near line %d\n", ctx->buffer, ctx->line_nb);
#endif
      return INTEGER;

    case ST_HEX:
      lvalp->num = x = strtoul(ctx->buffer, NULL, 16);
#if NASL_DEBUG > 1 && defined(ULONG_MAX)
      if (x == ULONG_MAX)
	nasl_perror(NULL, "Possible integer overflow while converting %s at or near line %d\n", ctx->buffer, ctx->line_nb);
#endif
      return INTEGER;

    case ST_ZEROX:
      nasl_perror(NULL, "Invalid token 0x parsed as 0 at line %d\n",
	      ctx->line_nb);
    case ST_ZERO:
      lvalp->num = 0;
      return INTEGER;
    default:
      abort();
    }
}

static int
nasllex(YYSTYPE * lvalp, void * parm)
{
  int	x = mylex (lvalp, parm);
  return x;
}

