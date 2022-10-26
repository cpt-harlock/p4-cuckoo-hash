#define KEY_VALUE_SIZE 106
#define KEY_VALUE_SIZE_BIT 106w0
#define KEY_SIZE 96
#define KEY_SIZE_BIT 96w0
#define STASH_LENGTH 8
#define SLOT_COUNT 3
#define SLOT_COUNT_BIT 32w3
//manual define, error prone ...
#define BUCKET_SIZE 318
#define BUCKET_SIZE_BIT 318w0 
#define INDEX_SIZE 32
// ch register
//1 additional bit for R/W
#define REGISTER_INPUT_SIZE BUCKET_SIZE+1+INDEX_SIZE 
#define REGISTER_OUTPUT_SIZE BUCKET_SIZE
#define REGISTER_LATENCY 1
// stash
//for stash , 1 bit R/W and 1 bit evict
#define STASH_INPUT_SIZE KEY_VALUE_SIZE+1+1
#define STASH_OUTPUT_SIZE (STASH_LENGTH*KEY_VALUE_SIZE)
#define STASH_LATENCY 1
// hasher 
#define HASH_INPUT_SIZE KEY_SIZE
#define HASH_OUTPUT_SIZE 32 
#define HASH_LATENCY 1
// counter
#define COUNTER_LATENCY 1
#define COUNTER_INPUT_SIZE  2
#define COUNTER_OUTPUT_SIZE  32
#define COUNTER_INPUT_READ 2w0
#define COUNTER_INPUT_INCREMENT 2w1
#define COUNTER_INPUT_DECREMENT 2w2
// flag 
#define FLAG_LATENCY 1
#define FLAG_INPUT_SIZE  2
#define FLAG_OUTPUT_SIZE 1 
#define FLAG_INPUT_READ 2w0
#define FLAG_INPUT_SET 2w1
#define FLAG_INPUT_RESET 2w2

#ifndef STASH_RECIRCULATION_THRESHOLD
	#define STASH_RECIRCULATION_THRESHOLD 1
#endif
#ifndef LOOP_LIMIT
	#define LOOP_LIMIT 50
#endif

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

#if SLOT_COUNT == 1
#define FIND_KEY_IN_BUCKET(key, bucket, output) FIND_IN_BUCKET_1(key, bucket, output)
#elif SLOT_COUNT == 2 
#define FIND_KEY_IN_BUCKET(key, bucket, output) FIND_IN_BUCKET_2(key, bucket, output)
#elif SLOT_COUNT == 3 
#define FIND_KEY_IN_BUCKET(key, bucket, output) FIND_IN_BUCKET_3(key, bucket, output)
#elif SLOT_COUNT == 4 
#define FIND_KEY_IN_BUCKET(key, bucket, output) FIND_IN_BUCKET_4(key, bucket, output)
#endif

#define FIND_IN_BUCKET_1(key, bucket, output) { \	
	output = (key == bucket[KEY_SIZE-1:0]); \
}

#define FIND_IN_BUCKET_2(key, bucket, output) { \	
	output = (key == bucket[KEY_SIZE-1:0]) || (key == bucket[KEY_SIZE+KEY_VALUE_SIZE-1:KEY_VALUE_SIZE]) ; \
}

#define FIND_IN_BUCKET_3(key, bucket, output) { \	
	output = (key == bucket[KEY_SIZE-1:0]) || (key == bucket[KEY_SIZE+KEY_VALUE_SIZE-1:KEY_VALUE_SIZE]) || (key == bucket[KEY_SIZE-1+2*KEY_VALUE_SIZE:2*KEY_VALUE_SIZE]); \
}

#define FIND_IN_BUCKET_4(key, bucket, output) { \	
	output = (key == bucket[KEY_SIZE-1:0]) || (key == bucket[KEY_SIZE+KEY_VALUE_SIZE-1:KEY_VALUE_SIZE]) || (key == bucket[KEY_SIZE-1+2*KEY_VALUE_SIZE:2*KEY_VALUE_SIZE]) || (key == bucket[KEY_SIZE-1+3*KEY_VALUE_SIZE:3*KEY_VALUE_SIZE]); \
}

#if SLOT_COUNT == 1
#define IS_FREE_SLOT_IN_BUCKET(bucket, output) IS_FREE_SLOT_IN_BUCKET_1(bucket, output)
#elif SLOT_COUNT == 2 
#define IS_FREE_SLOT_IN_BUCKET(bucket, output) IS_FREE_SLOT_IN_BUCKET_2(bucket, output)
#elif SLOT_COUNT == 3 
#define IS_FREE_SLOT_IN_BUCKET(bucket, output) IS_FREE_SLOT_IN_BUCKET_3(bucket, output)
#elif SLOT_COUNT == 4 
#define IS_FREE_SLOT_IN_BUCKET(bucket, output) IS_FREE_SLOT_IN_BUCKET_4(bucket, output)
#endif

#define IS_FREE_SLOT_IN_BUCKET_1(bucket, output) { \
	FIND_IN_BUCKET_1(KEY_SIZE_BIT, bucket, output); \
}

#define IS_FREE_SLOT_IN_BUCKET_2(bucket, output) { \
	FIND_IN_BUCKET_2(KEY_SIZE_BIT, bucket, output); \
}

#define IS_FREE_SLOT_IN_BUCKET_3(bucket, output) { \
	FIND_IN_BUCKET_3(KEY_SIZE_BIT, bucket, output); \
}

#define IS_FREE_SLOT_IN_BUCKET_4(bucket, output) { \
	FIND_IN_BUCKET_4(KEY_SIZE_BIT, bucket, output); \
}

#define PREPARE_CUCKOO_INPUT(index, we, key_value) { index, we, value }

#define READ_FROM_CUCKOO(value, hash_prefix, cuckoo, cuckoo_length, output, reverse, hasher) { \
	if ((value)[KEY_SIZE-1:0] != KEY_SIZE_BIT) { \
		bit<32> temp_hash; \
		if (reverse == 1) { \
			hasher.apply({ (value)[KEY_SIZE-1:0], hash_prefix }, temp_hash); \
		} else { \
			hasher.apply({ hash_prefix, (value)[KEY_SIZE-1:0] }, temp_hash); \
		} \
		cuckoo.apply(PREPARE_CUCKOO_INPUT(index, 1w0, BUCKET_SIZE_BIT), output); \
	} else { \
		output = BUCKET_SIZE_BIT; \
	} \
}

#define READ_FROM_BUCKET(bucket, value) { \
	value = bucket[KEY_VALUE_SIZE-1:0]; \
}
	

#define INSERT_INTO_BUCKET(bucket, value) { \
	bucket[KEY_VALUE_SIZE-1:0] = value; \
}

#if SLOT_COUNT == 1
#define ROTATE_BUCKET(bucket) 
#elif SLOT_COUNT == 2
#define ROTATE_BUCKET(bucket) ROTATE_BUCKET_2(bucket)
#elif SLOT_COUNT == 3
#define ROTATE_BUCKET(bucket) ROTATE_BUCKET_3(bucket)
#else
#define ROTATE_BUCKET(bucket) ROTATE_BUCKET_4(bucket)
#endif

#define ROTATE_BUCKET_2(bucket) { \
	bit<KEY_VALUE_SIZE> temp; \
	temp = bucket[KEY_VALUE_SIZE-1:0]; \
	bucket[KEY_VALUE_SIZE-1:0] = bucket[(2*KEY_VALUE_SIZE)-1:KEY_VALUE_SIZE]; \
	bucket[(2*KEY_VALUE_SIZE)-1:KEY_VALUE_SIZE] = temp; \
}

#define ROTATE_BUCKET_3(bucket) { \
	bit<KEY_VALUE_SIZE> temp; \
	temp = bucket[(3*KEY_VALUE_SIZE)-1:(2*KEY_VALUE_SIZE)]; \
	bucket[(3*KEY_VALUE_SIZE)-1:(2*KEY_VALUE_SIZE)] = bucket[(2*KEY_VALUE_SIZE)-1:KEY_VALUE_SIZE] ; \
	bucket[(2*KEY_VALUE_SIZE)-1:KEY_VALUE_SIZE] = bucket[KEY_VALUE_SIZE-1:0]; \
	bucket[KEY_VALUE_SIZE-1:0] = temp; \
}

#define ROTATE_BUCKET_4(bucket) { \
	bit<KEY_VALUE_SIZE> temp; \
	temp = bucket[(4*KEY_VALUE_SIZE)-1:(3*KEY_VALUE_SIZE)]; \
	bucket[(4*KEY_VALUE_SIZE)-1:(3*KEY_VALUE_SIZE)] = bucket[(3*KEY_VALUE_SIZE)-1:(2*KEY_VALUE_SIZE)] ; \
	bucket[(3*KEY_VALUE_SIZE)-1:(2*KEY_VALUE_SIZE)] = bucket[(2*KEY_VALUE_SIZE)-1:KEY_VALUE_SIZE]; \
	bucket[(2*KEY_VALUE_SIZE)-1:KEY_VALUE_SIZE] = bucket[KEY_VALUE_SIZE-1:0]; \
	bucket[KEY_VALUE_SIZE-1:0] = temp; \
}


#define INSERT_INTO_CUCKOO(value, hash_prefix, cuckoo, cuckoo_length, output, reverse, hasher) { \
	bit<HASH_OUTPUT_SIZE> temp_hash; \
	bit<BUCKET_SIZE> bucket; \
	bit<BUCKET_SIZE> dummy_read; \
	if ((value)[KEY_SIZE-1:0] != KEY_SIZE_BIT) { \
		if (reverse == 1) { \
			hasher.apply({ (value)[KEY_SIZE-1:0], hash_prefix }, temp_hash); \
		} else { \
			hasher.apply({ hash_prefix, (value)[KEY_SIZE-1:0] }, temp_hash); \
		} \
		cuckoo.apply(PREPARE_CUCKOO_INPUT(index, 1w0, BUCKET_SIZE_BIT), bucket); \
		ROTATE_BUCKET(bucket); \ 
		READ_FROM_BUCKET(bucket, output); \
		INSERT_INTO_BUCKET(bucket, value); \ 	
		cuckoo.apply(PREPARE_CUCKOO_INPUT(index, 1w1, bucket), dummy_read); \
	} else { \
		output = value; \
	} \
}
// insert into generic stash
#define INSERT_INTO_STASH_GENERIC(value, stash, stash_size, count, key_increment) { \
	bit<STASH_OUTPUT_SIZE> stash_read; \
	bit<COUNTER_OUTPUT_SIZE> inserted_keys_read; \
	bit<COUNTER_OUTPUT_SIZE> discarded_keys_read; \
	bit<COUNTER_OUTPUT_SIZE> kicked_keys_read; \
	if ((value)[KEY_SIZE-1:0] != KEY_SIZE_BIT) { \
		if (count < stash_size) { \
			// insert value without evicting
			stash.apply(PREPARE_STASH_INPUT(value, 1w1, 1w0), stash_read); \
			//counter.write(0, counter_read + 1); \
			if (key_increment == 1)  { \
				inserted_keys.apply(COUNTER_INPUT_INCREMENT, inserted_keys_read); \
			} \
		} else { \
			if (key_increment == 1) { \
				discarded_keys.apply(COUNTER_INPUT_INCREMENT, discarded_keys_read); \
				stop_flag.apply(FLAG_INPUT_SET, 1); \
			} else { \
				kicked_keys.apply(COUNTER_INPUT_INCREMENT, kicked_keys_read); \
			} \
		} \
	} \
}

#define INSERT_INTO_STASH(value, stash, counter, key_increment) { \
	INSERT_INTO_STASH_GENERIC(value, stash, STASH_LENGTH, counter, key_increment); \
}

#define STASH_READY_FOR_RECIRCULATION(stash_counter) ({ \
	bit<32> stash_counter_read_value; \
	stash_counter.read(stash_counter_read_value, 0); \
	if ( stash_counter_read_value >= STASH_LENGTH/STASH_RECIRCULATION_LOAD_FACTOR) { \
		true; \
	} else { \
		false; \
	} \
})

#define PREPARE_STASH_INPUT(key_value, rw, evict) { key_value, rw, evict } 

#define COMPUTE_STASH_COUNT(value1, value2, value3, value4, value5, value6, value7, value8, output) { \
	bit<32> temp_count = 0; \
	if (value1[KEY_SIZE-1:0] != KEY_SIZE_BIT) \
		temp_count += 1; \
	if (value2[KEY_SIZE-1:0] != KEY_SIZE_BIT) \
		temp_count += 1; \
	if (value3[KEY_SIZE-1:0] != KEY_SIZE_BIT) \
		temp_count += 1; \
	if (value4[KEY_SIZE-1:0] != KEY_SIZE_BIT) \
		temp_count += 1; \
	if (value5[KEY_SIZE-1:0] != KEY_SIZE_BIT) \
		temp_count += 5; \
	if (value6[KEY_SIZE-1:0] != KEY_SIZE_BIT) \
		temp_count += 5; \
	if (value7[KEY_SIZE-1:0] != KEY_SIZE_BIT) \
		temp_count += 5; \
	if (value8[KEY_SIZE-1:0] != KEY_SIZE_BIT) \
		temp_count += 1; \
	output = temp_count; \
}
// read till 8 values 
#define READ_FROM_STASH(stash, value1, value2, value3, value4, value5, value6, value7, value8) { \
	bit<KEY_VALUE_SIZE*STASH_LENGTH> stash_read; \
	stash.apply(PREPARE_STASH_INPUT(KEY_VALUE_SIZE_BIT, 1w0, 1w0), stash_read); \
	value1 = stash_read[KEY_VALUE_SIZE-1:0]; \
	value2 = stash_read[2*KEY_VALUE_SIZE-1:KEY_VALUE_SIZE]; \
	if (STASH_LENGTH > 2)  { \
		value3 = stash_read[3*KEY_VALUE_SIZE-1:2*KEY_VALUE_SIZE]; \
		value4 = stash_read[4*KEY_VALUE_SIZE-1:3*KEY_VALUE_SIZE]; \
	} \ 
	if (STASH_LENGTH > 4)  { \
		value5 = stash_read[5*KEY_VALUE_SIZE-1:4*KEY_VALUE_SIZE]; \
		value6 = stash_read[6*KEY_VALUE_SIZE-1:5*KEY_VALUE_SIZE]; \
		value7 = stash_read[7*KEY_VALUE_SIZE-1:6*KEY_VALUE_SIZE]; \
		value8 = stash_read[8*KEY_VALUE_SIZE-1:7*KEY_VALUE_SIZE]; \
	} \ 
}

#define EVICT_FROM_STASH(stash, stash_counter, output) { \
	bit<32> stash_counter_read; \
	stash_counter.read(stash_counter_read, 0); \
	if  (stash_counter_read == 0) { \
		output = KEY_VALUE_SIZE_BIT; \
	} else { \
		stash.read(output, stash_counter_read - 1); \
		stash.write(stash_counter_read - 1, KEY_VALUE_SIZE_BIT); \
		stash_counter.write(0, stash_counter_read - 1); \
	} \
}

#define STASH_MIX_2(stash, stash_counter) { \
	bit<KEY_VALUE_SIZE> temp_1; \
	bit<KEY_VALUE_SIZE> temp_2; \
	bit<32> stash_counter_read; \
	stash_counter.read(stash_counter_read, 0); \
	if (stash_counter_read == 2) { \
		stash.read(temp_1, 0); \
		stash.read(temp_2, 1); \
		stash.write(0, temp_2); \
		stash.write(1, temp_1); \
	} \
}

#define STASH_MIX_4(stash, stash_counter) { \
	bit<KEY_VALUE_SIZE> temp_1; \
	bit<KEY_VALUE_SIZE> temp_2; \
	bit<KEY_VALUE_SIZE> temp_3; \
	bit<KEY_VALUE_SIZE> temp_4; \
	bit<32> stash_counter_read; \
	stash_counter.read(stash_counter_read, 0); \
	if (stash_counter_read == 2) { \
		stash.read(temp_1, 0); \
		stash.read(temp_2, 1); \
		stash.write(0, temp_2); \
		stash.write(1, temp_1); \
	} \
	if (stash_counter_read == 3) { \
		stash.read(temp_1, 0); \
		stash.read(temp_2, 1); \
		stash.read(temp_3, 2); \
		stash.write(0, temp_3); \
		stash.write(1, temp_1); \
		stash.write(2, temp_2); \
	} \
	if (stash_counter_read == 4) { \
		stash.read(temp_1, 0); \
		stash.read(temp_2, 1); \
		stash.read(temp_3, 2); \
		stash.read(temp_4, 3); \
		stash.write(0, temp_4); \
		stash.write(1, temp_1); \
		stash.write(2, temp_2); \
		stash.write(3, temp_3); \
	} \
}

#define STASH_MIX_8(stash, stash_counter) { \
	bit<KEY_VALUE_SIZE> temp_1; \
	bit<KEY_VALUE_SIZE> temp_2; \
	bit<KEY_VALUE_SIZE> temp_3; \
	bit<KEY_VALUE_SIZE> temp_4; \
	bit<KEY_VALUE_SIZE> temp_5; \
	bit<KEY_VALUE_SIZE> temp_6; \
	bit<KEY_VALUE_SIZE> temp_7; \
	bit<KEY_VALUE_SIZE> temp_8; \
	bit<32> stash_counter_read; \
	stash_counter.read(stash_counter_read, 0); \
	if (stash_counter_read == 2) { \
		stash.read(temp_1, 0); \
		stash.read(temp_2, 1); \
		stash.write(0, temp_2); \
		stash.write(1, temp_1); \
	} \
	if (stash_counter_read == 3) { \
		stash.read(temp_1, 0); \
		stash.read(temp_2, 1); \
		stash.read(temp_3, 2); \
		stash.write(0, temp_3); \
		stash.write(1, temp_1); \
		stash.write(2, temp_2); \
	} \
	if (stash_counter_read == 4) { \
		stash.read(temp_1, 0); \
		stash.read(temp_2, 1); \
		stash.read(temp_3, 2); \
		stash.read(temp_4, 3); \
		stash.write(0, temp_4); \
		stash.write(1, temp_1); \
		stash.write(2, temp_2); \
		stash.write(3, temp_3); \
	} \
	if (stash_counter_read == 5) { \
		stash.read(temp_1, 0); \
		stash.read(temp_2, 1); \
		stash.read(temp_3, 2); \
		stash.read(temp_4, 3); \
		stash.read(temp_5, 4); \
		stash.write(0, temp_5); \
		stash.write(1, temp_1); \
		stash.write(2, temp_2); \
		stash.write(3, temp_3); \
		stash.write(4, temp_4); \
	} \
	if (stash_counter_read == 6) { \
		stash.read(temp_1, 0); \
		stash.read(temp_2, 1); \
		stash.read(temp_3, 2); \
		stash.read(temp_4, 3); \
		stash.read(temp_5, 4); \
		stash.read(temp_6, 5); \
		stash.write(0, temp_6); \
		stash.write(1, temp_1); \
		stash.write(2, temp_2); \
		stash.write(3, temp_3); \
		stash.write(4, temp_4); \
		stash.write(5, temp_5); \
	} \
	if (stash_counter_read == 7) { \
		stash.read(temp_1, 0); \
		stash.read(temp_2, 1); \
		stash.read(temp_3, 2); \
		stash.read(temp_4, 3); \
		stash.read(temp_5, 4); \
		stash.read(temp_6, 5); \
		stash.read(temp_7, 6); \
		stash.write(0, temp_7); \
		stash.write(1, temp_1); \
		stash.write(2, temp_2); \
		stash.write(3, temp_3); \
		stash.write(4, temp_4); \
		stash.write(5, temp_5); \
		stash.write(6, temp_6); \
	} \
	if (stash_counter_read == 8) { \
		stash.read(temp_1, 0); \
		stash.read(temp_2, 1); \
		stash.read(temp_3, 2); \
		stash.read(temp_4, 3); \
		stash.read(temp_5, 4); \
		stash.read(temp_6, 5); \
		stash.read(temp_7, 6); \
		stash.read(temp_8, 7); \
		stash.write(0, temp_8); \
		stash.write(1, temp_1); \
		stash.write(2, temp_2); \
		stash.write(3, temp_3); \
		stash.write(4, temp_4); \
		stash.write(5, temp_5); \
		stash.write(6, temp_6); \
		stash.write(7, temp_7); \
	} \
}

#if STASH_LENGTH == 2
#define STASH_MIX(stash, stash_counter)	STASH_MIX_2(stash, stash_counter)
#elseif STASH_LENGTH == 4
#define STASH_MIX(stash, stash_counter) STASH_MIX_4(stash, stash_counter)
#else
#define STASH_MIX(stash, stash_counter) STASH_MIX_8(stash, stash_counter) 
#endif


