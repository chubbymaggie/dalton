package engine



/*

 #define ACT_UNKNOWN             11
#define ACT_END                 10
#define ACT_FLOOD               9
#define ACT_KILL_HOST           8
#define ACT_DENIAL              7
#define ACT_DESTRUCTIVE_ATTACK  6
#define ACT_MIXED_ATTACK        5
#define ACT_ATTACK              4
#define ACT_GATHER_INFO         3
#define ACT_SETTINGS            2
#define ACT_SCANNER             1
#define ACT_INIT                0

 */

const (

	ACT_INIT = 0
	ACT_SCANNER = 1
	ACT_SETTINGS =2
	ACT_GATHER_INFO = 3
	ACT_ATTACK = 4
	ACT_MIXED_ATTACK = 5
	ACT_DESTRUCTIVE_ATTACK = 6
	ACT_DENIAL = 7
	ACT_KILL_HOST = 8
	ACT_FLOOD = 9
	ACT_END = 10
	ACT_UNKNOW = 11
)