#define KEY_VALUE_SIZE 106
#define KEY_VALUE_SIZE_BIT 106w0
#define KEY_SIZE 96
#define KEY_SIZE_BIT 96w0
#
#define INDEX_SIZE 5
// ch register
//1 additional bit for R/W
#define REGISTER_INPUT_SIZE (KEY_VALUE_SIZE+1+INDEX_SIZE) 
#define REGISTER_OUTPUT_SIZE (1+1+KEY_VALUE_SIZE)
#define REGISTER_LATENCY 1
// stash
//for stash , 1 bit evict
#define STASH_INPUT_SIZE (KEY_VALUE_SIZE+1)
#define STASH_OUTPUT_SIZE (1+1+1+32+KEY_VALUE_SIZE)
#define STASH_LATENCY 1
// hasher 
#define HASH_PREFIX_LENGTH 8
#define HASH_INPUT_SIZE (KEY_SIZE+HASH_PREFIX_LENGTH)
#define HASH_OUTPUT_SIZE 32 
#define HASH_LATENCY 1
// counter
#define COUNTER_LATENCY 1
#define COUNTER_INPUT_SIZE  2
#define COUNTER_OUTPUT_SIZE  32
#define COUNTER_INPUT_READ 2w0
#define COUNTER_INPUT_INCREMENT 2w1
#define COUNTER_INPUT_DECREMENT 2w2
#define COUNTER_INPUT_RESET 2w3
// flag 
#define FLAG_LATENCY 1
#define FLAG_INPUT_SIZE  2
#define FLAG_OUTPUT_SIZE 1 
#define FLAG_INPUT_READ 2w0
#define FLAG_INPUT_SET 2w1
#define FLAG_INPUT_RESET 2w2
// recirculator, TODO, for the moment placeholders
#define RECIRCULATION_INPUT_SIZE 30
#define RECIRCULATION_OUTPUT_SIZE 30
#define RECIRCULATION_LATENCY 1

#ifndef STASH_RECIRCULATION_THRESHOLD
	#define STASH_RECIRCULATION_THRESHOLD 1
#endif
#ifndef LOOP_LIMIT
	#define LOOP_LIMIT 50
#endif
#
#define STASH_LENGTH 8
#if STASH_LENGTH != 2

#if STASH_LENGTH != 4

#if STASH_LENGTH != 8
	#error
#endif
#endif
#endif

#if STASH_RECIRCULATION_THRESHOLD > STASH_LENGTH
	#error
#endif

#define PREPARE_CUCKOO_INPUT(index, we, key_value) ( index ++ we ++ key_value )
#define SPLIT_CUCKOO_OUTPUT(output_value, value, hit, written) { \
    value = output_value[KEY_VALUE_SIZE-1:0]; \
    hit = output_value[KEY_VALUE_SIZE:KEY_VALUE_SIZE]; \
    written = output_value[KEY_VALUE_SIZE+1:KEY_VALUE_SIZE+1]; \
}

#define CUCKOO_READ_WRITE(value, hash_prefix, cuckoo, cuckoo_length, output_value, hit, written, reverse, hasher) { \
	bit<HASH_OUTPUT_SIZE> temp_hash; \
        bit<REGISTER_OUTPUT_SIZE> temp_cuckoo_output; \
	if ((value)[KEY_SIZE-1:0] != KEY_SIZE_BIT) { \
		if (reverse == 1) { \
			hasher.apply( (value)[KEY_SIZE-1:0] ++ hash_prefix , temp_hash); \
		} else { \
			hasher.apply( hash_prefix ++ (value)[KEY_SIZE-1:0] , temp_hash); \
		} \
		temp_hash = temp_hash % cuckoo_length; \
		cuckoo.apply(PREPARE_CUCKOO_INPUT(temp_hash[INDEX_SIZE-1:0], value, 1w0), temp_cuckoo_output); \
                SPLIT_CUCKOO_OUTPUT(temp_cuckoo_output, output_value, hit, written); \
	} else { \
		output_value = value; \
		written = 1; \
	} \
}

#define CUCKOO_READ_WRITE_EVICT(value, hash_prefix, cuckoo, cuckoo_length, output_value, hit, written, reverse, hasher) { \
	bit<HASH_OUTPUT_SIZE> temp_hash; \
        bit<REGISTER_OUTPUT_SIZE> temp_cuckoo_output; \
	if ((value)[KEY_SIZE-1:0] != KEY_SIZE_BIT) { \
		if (reverse == 1) { \
			hasher.apply( (value)[KEY_SIZE-1:0] ++ hash_prefix , temp_hash); \
		} else { \
			hasher.apply( hash_prefix ++ (value)[KEY_SIZE-1:0] , temp_hash); \
		} \
		temp_hash = temp_hash % cuckoo_length; \
		cuckoo.apply(PREPARE_CUCKOO_INPUT(temp_hash[INDEX_SIZE-1:0], value, 1w1), temp_cuckoo_output); \
                SPLIT_CUCKOO_OUTPUT(temp_cuckoo_output, output_value, hit, written); \
	} else { \
		output_value = value; \
		written = 1; \
	} \
}

#define PREPARE_STASH_INPUT(key_value, evict) ( evict ++ key_value )
#define SPLIT_STASH_OUTPUT(output_value, value, hit, written, discarded, counter) { \ 
    value = output_value[KEY_VALUE_SIZE-1:0]; \
    hit = output_value[KEY_VALUE_SIZE:KEY_VALUE_SIZE]; \
    written = output_value[KEY_VALUE_SIZE+1:KEY_VALUE_SIZE+1]; \
    discarded = output_value[KEY_VALUE_SIZE+2:KEY_VALUE_SIZE+2]; \
    counter = output_value[KEY_VALUE_SIZE+34:KEY_VALUE_SIZE+3]; \
}

#define STASH_READ_WRITE(value, stash, evict, output_value, hit, written, discarded, counter) { \
        bit<STASH_OUTPUT_SIZE> temp_stash_output; \
	stash.apply(PREPARE_STASH_INPUT((value), evict), temp_stash_output); \
        SPLIT_STASH_OUTPUT(temp_stash_output, output_value, hit, written, discarded, counter); \
}

