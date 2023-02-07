// define input size for hash32 extern
#define HASH_PREFIX_WIDTH 8
#define HASH_KEY_INPUT_WIDTH 128
#define HASH_INPUT_WIDTH (HASH_PREFIX_WIDTH+HASH_KEY_INPUT_WIDTH)
#define HASH_OUTPUT_WIDTH 32


// define input size for CH/HT externs
#define TABLES_KEY_INPUT_WIDTH 128
#define TABLES_VALUE_INPUT_WIDTH 128
#define TABLES_INDEX_INPUT_WIDTH 32
// one additional bit to signal the extern to ignore the input as it's been already inserted/hit + evict signal
// ORDER (Verilog concat): { evict, ignore, index, value, key } 
#define TABLES_INPUT_WIDTH (TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH + TABLES_INDEX_INPUT_WIDTH + 1 + 1)
// additional hit/written bit   
// ORDER (Verilog concat): {  w/h, value, key }
#define TABLES_OUTPUT_WIDTH (TABLES_KEY_INPUT_WIDTH +TABLES_VALUE_INPUT_WIDTH + 1)

#define STASH_INPUT_WIDTH (TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH + 1 + 1)
#define STASH_OUTPUT_WIDTH (TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH + 1 + 1 + 32)

#define COUNTER_INPUT_SIZE 2
#define COUNTER_OUTPUT_SIZE 32
#define COUNTER_LATENCY 1
#define COUNTER_INPUT_INCREMENT 1

#define FLAG_INPUT_SIZE 2
#define FLAG_OUTPUT_SIZE 1
#define FLAG_LATENCY 1
#define FLAG_INPUT_READ 0
#define FLAG_INPUT_SET 1
#define FLAG_INPUT_RESET 2


#define LOOP_LIMIT 10

#define CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_CUCKOO(cuckoo_output, hash_output, axis_tdest, cuckoo_next_input) {\
		bit<TABLES_KEY_INPUT_WIDTH> next_key = cuckoo_output[TABLES_KEY_INPUT_WIDTH-1:0]; \
		bit<TABLES_VALUE_INPUT_WIDTH> next_value = cuckoo_output[(TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH)-1:TABLES_KEY_INPUT_WIDTH]; \
		bit<1> next_ignore_input = cuckoo_output[(TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH):(TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH)]; \
		bit<1> next_evict = axis_tdest; \
		bit<TABLES_INDEX_INPUT_WIDTH> next_index = hash_output; \
		cuckoo_next_input = next_evict ++ next_ignore_input ++ next_index ++ next_value ++ next_key; \
}

#define CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_HASH(cuckoo_output, hash_prefix, hash_next_input) {\
		bit<HASH_KEY_INPUT_WIDTH> next_key = cuckoo_output[TABLES_KEY_INPUT_WIDTH-1:0]; \
		bit<HASH_PREFIX_WIDTH> next_prefix = hash_prefix; \
		hash_next_input = next_prefix ++ next_key; \
}

#define CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_STASH(cuckoo_output, axis_tdest, stash_next_input) {\
		bit<TABLES_KEY_INPUT_WIDTH> next_key = cuckoo_output[TABLES_KEY_INPUT_WIDTH-1:0]; \
		bit<TABLES_VALUE_INPUT_WIDTH> next_value = cuckoo_output[(TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH)-1:TABLES_KEY_INPUT_WIDTH]; \
		bit<1> next_ignore_input = cuckoo_output[(TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH):(TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH)]; \
		bit<1> next_evict = axis_tdest; \
		stash_next_input = next_evict ++ next_ignore_input ++ next_value ++ next_key; \
}

#define STASH_PARSE_OUTPUT(stash_output, key, value, counter, discarded, w_h) {\
		key = stash_output[TABLES_KEY_INPUT_WIDTH-1:0]; \
		value = stash_output[(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH)-1:TABLES_KEY_INPUT_WIDTH]; \
		counter = stash_output[(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH + 32)-1:(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH)]; \
		discarded = stash_output[(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH + 32):(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH + 32)]; \
		w_h = stash_output[(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH + 32 + 1):(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH + 32 + 1)]; \
}

		
