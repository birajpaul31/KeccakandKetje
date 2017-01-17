#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ketje.h"
#include "keccak.h"

/* Useful macros */
// Convert a bit length in the corresponding byte length, rounding up.
#define BYTE_LEN(x) ((x/8)+(x%8?1:0))

unsigned int b = 1600;
unsigned int n_start = 12;
unsigned int n_step = 1;
unsigned int n_stride = 6;
unsigned int rho_constant = 256;
unsigned int rate = 260;
int A_blocks = 0;
int B_blocks = 0;
unsigned char *keypack = NULL;
unsigned char *kpack_with_nonce = NULL;
unsigned char *temp_A_block = NULL;
unsigned char *temp_A_block_zz = NULL;
unsigned char *temp_B_block = NULL;
unsigned char *temp_B_block_zz = NULL;
unsigned char *state = NULL;
unsigned char *step_return = NULL;
unsigned int tag_length = 0;

/* Perform the Ketje Major authenticated encryption operation on a message.
 *
 * cryptogram - the output buffer for the ciphertext, allocated by the caller.
 *              The buffer is the same size as the "data" plaintext buffer.
 * tag        - the output buffer for the tag, allocated by the caller.
 * t_len      - the requested tag length in bits.
 * key        - the key, provided by the caller.
 * k_len      - the key length in bits.
 * nonce      - the nonce, provided by the caller.
 * n_len      - the nonce length in bits.
 * data       - the plaintext, provided by the caller.
 * d_len      - the plaintext length in bits.
 * header     - the additional plaintext, provided by the caller.
 * h_len      - the additional plaintext length in bits.
 */
void ketje_mj_e(unsigned char *cryptogram,
		unsigned char *tag, unsigned int t_len,
		const unsigned char *key, unsigned int k_len,
		const unsigned char *nonce, unsigned int n_len,
		const unsigned char *data, unsigned long d_len,
		const unsigned char *header, unsigned long h_len)
{
	/* Ketje Major-specific parameters:
	 *   f        = KECCAK-p*[1600]
	 *   rho      = 256
	 * For all Ketje instances:
	 *   n_start  = 12
	 *   n_step   = 1
	 *   n_stride = 6
	 */

	/* Implement this function */
	
	/* 
	 * MonekeyDuplex init : D.start(keypack(K, |K| + 16)||N)
	 */
	 
	unsigned long keypack_len;
	unsigned long kpack_w_nonce_len;
	unsigned long A_block_cursor = 0;
	unsigned long A_block_len = 0;
	unsigned long B_block_cursor = 0;
	unsigned long B_block_len = 0;
	unsigned int Z_iter = 0;
	
	unsigned char *Z = NULL;
	
	unsigned char tag_last_step = 0x00;
	unsigned char *last_step_ptr = NULL;
	unsigned char *last_step_ptr_conc = NULL;
	
	keypack_len = key_pack(key, k_len, k_len + 16);
	kpack_w_nonce_len = concatenate(&kpack_with_nonce, keypack, keypack_len, nonce, n_len);
	
	monkey_dup_start(kpack_w_nonce_len);
	
	/* 
	 * MonkeyWrap: (C, T) = W.wrap(A, B, ℓ)
	 */
	
	temp_A_block = calloc(rho_constant/8, sizeof(unsigned char));

	A_blocks = (h_len / rho_constant) + (h_len % rho_constant ? 1 : 0);
	B_blocks = (d_len / rho_constant) + (d_len % rho_constant ? 1 : 0);
	
	/*
	 * Operation on the header. 
	 */

	for(int i = 0 ; i <= (A_blocks - 2) ; i++) {
		memcpy(temp_A_block , header + A_block_cursor, rho_constant/8);
		A_block_cursor += rho_constant/8;
		A_block_len = concatenate_00(&temp_A_block_zz, temp_A_block, rho_constant);
		monkey_dup_step_stride(temp_A_block_zz, A_block_len, 0, step_return, n_step);
	}
	
	if(header != NULL) {
		cpynbits(temp_A_block, 0, header, A_block_cursor, ((h_len % rho_constant ) ? h_len % rho_constant : rho_constant));
	}
	A_block_len = concatenate_01(&temp_A_block_zz, temp_A_block, (h_len == 0 ? 0 : ((h_len % rho_constant) ? h_len % rho_constant : rho_constant)));
	
	printf("%d\n", A_block_len);
	for(int i = 0; i < 8; i++) {
		printf("%p\t", temp_A_block_zz[i]);
	}
	
	Z = monkey_dup_step_stride(temp_A_block_zz, A_block_len, (d_len/rho_constant > 0 ? rho_constant : d_len ), step_return, n_step);
	
	temp_B_block = calloc(rho_constant/8, sizeof(unsigned char));
	if(data != NULL) {

		cpynbits(temp_B_block, 0, data, B_block_cursor, ((d_len / rho_constant > 0) ? rho_constant : d_len));
	}
	
	for(unsigned int i = 0; i < (d_len/rho_constant > 0 ? rho_constant/8 : (d_len/8 + (d_len % 8 ? 1 : 0))); i++) {
		cryptogram[i] = temp_B_block[i] ^ Z[i];
	}
	
	/*
	 * Operation on the data
	 */
	
	for(int i = 0 ; i <= (B_blocks - 2) ; i++) {
		memcpy(temp_B_block , data + B_block_cursor, rho_constant/8);
		B_block_cursor += rho_constant/8;
		B_block_len = concatenate_11(&temp_B_block_zz, temp_B_block, rho_constant);
		Z = monkey_dup_step_stride(temp_B_block_zz, B_block_len, (i == (B_blocks - 2) ? (d_len % rho_constant ? (d_len % rho_constant) : rho_constant ) : rho_constant), step_return, n_step);
		Z_iter = 0;
		for(unsigned int k = B_block_cursor; k < (B_block_cursor + (i == (B_blocks - 2) ? (d_len % rho_constant ? ( (d_len % rho_constant)/8 + ((d_len % rho_constant) % 8 ? 1 : 0)) : rho_constant/8 ) : rho_constant/8)); k++) {
			cryptogram[k] = temp_B_block[Z_iter] ^ Z[Z_iter];
			Z_iter++;
		}
	}
	
	if(data != NULL) {
		cpynbits(temp_B_block, 0, data, B_block_cursor, (d_len % rho_constant ? d_len % rho_constant : rho_constant));
	}
	B_block_len = concatenate_10(&temp_B_block_zz, temp_B_block, (d_len == 0 ? 0 : (d_len % rho_constant ? d_len % rho_constant : rho_constant)));
	Z = monkey_dup_step_stride(temp_B_block_zz, B_block_len, rho_constant, step_return, n_stride);
	
	tag_length = rho_constant;
	
	while(tag_length < t_len){
		last_step_ptr = monkey_dup_step_stride(&tag_last_step, 1, rho_constant, step_return, n_step);
		concatenate(&last_step_ptr_conc, Z, rho_constant, last_step_ptr, rho_constant);
		tag_length += rho_constant;
		Z = last_step_ptr_conc;
	}
	
	cpynbits(tag, 0, Z, 0, t_len);

	free(Z);
	free(last_step_ptr);
	free(last_step_ptr_conc);
	free(temp_A_block);
	free(temp_A_block_zz);
	free(temp_B_block);
	free(temp_B_block_zz);
	free(keypack);
	free(kpack_with_nonce);
	free(state);
	free(step_return);
	
	return;
}

//keypack(K, l) = enc8(l/8)||K||pad10*[l − 8](|K|)
/*
 * Performs the key pack operation at the beginning of the process
 * Inputs:
 * key		- Pointer to the key array
 * key_len	- Length of the key in bits
 * l 		- Length of the keypack in bits
 * Outputs:
 * 			- Length of the keypack
 */

unsigned int key_pack(const unsigned char *key, unsigned int key_len, unsigned int l) 
{
	unsigned char eight_bit_ksize;
	unsigned char *temp_concat_key = NULL;
	unsigned char *temp_pad = NULL;
	unsigned int temp_conc_len = 0;
	unsigned int final_conc_len = 0;
	unsigned long pad_len = 0;

	eight_bit_ksize = l/8;
	temp_conc_len = concatenate(&temp_concat_key, &eight_bit_ksize, 8, key, key_len);

	pad_len = pad10x(&temp_pad, l - 8, key_len);
	final_conc_len = concatenate(&keypack, temp_concat_key, temp_conc_len, temp_pad, pad_len);

	return final_conc_len;
}

/*
 * Performs the Monkey duplex start operation
 * Inputs:
 * keypack_len 		- the length of the keypack.
 */
void monkey_dup_start(unsigned long keypack_len)
{
	unsigned char *temp_pad = NULL;
	unsigned long temp_pad_len;
	unsigned char *concat_key = NULL;
	unsigned long concat_key_len;
	
	temp_pad_len = pad10x1(&temp_pad, b, keypack_len);
	concat_key_len = concatenate(&concat_key, kpack_with_nonce, keypack_len, temp_pad, temp_pad_len);

	state = keccak_p_star(concat_key, concat_key_len, n_start, 6);	
}

/*
 * Performs the Monkey Duplex step and stride operation. The two operations only differ by the number of rounds. So the same interface is used.
 * Inputs:
 * A_block 		- Pointer to the current block under operation.
 * A_block_len	- Length of the current block in bits
 * l 			- Truncation parameter. (Number of bits to keep)
 * s_return		- return address of the modified block.
 * n_rounds		- Number of rounds for this operation.
 * Outputs:
 *				- Return address of the new block.
 */
 
unsigned char *monkey_dup_step_stride(unsigned char *A_block, unsigned int A_block_len, unsigned int l, unsigned char *s_return, unsigned int n_rounds) 
{
	unsigned char *P = NULL;
	unsigned int P_len = 0;
	unsigned char *temp_pad = NULL;
	unsigned int temp_pad_len = 0;
	unsigned char *P_concat = NULL;
	unsigned char *zero_pad = NULL;
	unsigned int zero_pad_len = 0;
	
	temp_pad_len = pad10x1(&temp_pad, rate, A_block_len);
	P_len = concatenate(&P, A_block, A_block_len, temp_pad, temp_pad_len);
	zero_pad_len = pad0x(&zero_pad, rate);
	concatenate(&P_concat, P, P_len, zero_pad, zero_pad_len);
	
	for(unsigned int i = 0; i < b/8 ; i++) {
		state[i] = state[i] ^ P_concat[i];
	}
	
	
	
	state = keccak_p_star(state, b, n_rounds, 6);
	
	printf("\n");
	for(int i = 0; i < 1600/8; i++) {
		printf("%p\t", state[i]);
	}
	printf("\n");
	
	
	
	free(P);
	free(temp_pad);
	free(P_concat);
	free(zero_pad);
	
	if(l > 0) {
		s_return = calloc((l/8 + (l%8 ? 1 : 0)), sizeof(unsigned char));
		cpynbits(s_return, 0, state, 0, l);
		return s_return;
	} else {
		return NULL;
	}
}