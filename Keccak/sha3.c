#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "sha3.h"

/* Useful macros */
/* Rotate a 64b word to the left by n positions */
#define ROL64(a, n) ((((n)%64) != 0) ? ((((uint64_t)a) << ((n)%64)) ^ (((uint64_t)a) >> (64-((n)%64)))) : a)

unsigned long concatenate(unsigned char **Z, const unsigned char *X,
			  unsigned long X_len, const unsigned char *Y,
			  unsigned long Y_len);
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len);
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m);
unsigned char rc(unsigned int t);
unsigned char *sponge(unsigned char *m, unsigned int d);
void keccak_p(unsigned char *S);
unsigned int power(unsigned int base, unsigned int exp);


/* Compute the SHA-3 hash for a message.
 *
 * d - the output buffer
 * s - size of the output buffer in bits
 * m - the input message
 * l - size of the input message in bits
 */
void sha3(unsigned char *d, unsigned int s, const unsigned char *m,
	  unsigned int l)
{
	/* The hash size must be one of the supported ones */
	if (s != 224 && s != 256 && s != 384 && s != 512)
		return;
	
	unsigned char *N;
	unsigned long N_len;

	N_len = concatenate_01(&N, m, l);

	memcpy(d, sponge(N, N_len), 32);
}

/* Sponge Function (Algorithm 8 : NIST)
 *
 * Parameters:
 *
 * m -> Input message with 01 concatenated at the end
 * d -> length of input message
 *
 * Output:
 *
 * Z -> String of length 256 (SHA-3 Hash)
 */

unsigned char *sponge(unsigned char *m, unsigned int d){
	unsigned int r = 1600 - 512;
	unsigned long c = 1600 - r;
	unsigned long n;
	unsigned short loop = 1;
	
	unsigned char *Z = NULL ; 		/* output string */
	unsigned int Z_len;
	unsigned char *Z_temp = NULL;
	unsigned int Z_temp_len;
	
	unsigned char *P = NULL; 		/* input message with padding 10*1 */
	unsigned long P_len;
	
	unsigned char *p10x1 = NULL;
	unsigned int p10x1_len;
	
	unsigned char *P_block = NULL;	/* Char array to hold each block of string of length r bits*/
	unsigned char *concat_P_block = NULL;
	unsigned char *P_block_sup = NULL;
	unsigned long p_byte_cursor = 0;
	
	unsigned char S[200] = {0}; 	/* Char array to hold each block of string of length b bits*/
	unsigned char S_trun[136] = {0};
	unsigned char temp_S[200] = {0};
	
	/*Steps 1 to 6 of Algorithm 8
	 */
	 
	p10x1_len = pad10x1(&p10x1, r, d);
	P_len = concatenate(&P, m, d, p10x1, p10x1_len);
	n = P_len / r;
	P_block = (unsigned char *)calloc(r/8, sizeof(unsigned char));
	P_block_sup = (unsigned char *)calloc(c/8, sizeof(unsigned char));
	
	for(unsigned int i = 0 ; i < n ; i++){
		memcpy(P_block, P + p_byte_cursor, 136);
		p_byte_cursor += r/8;
		concatenate(&concat_P_block, P_block, r, P_block_sup, c);
		for(int j = 0 ; j < 200 ;  j++) {
			temp_S[j] = S[j] ^ concat_P_block[j] ;
		}
		keccak_p(temp_S);
		for(int j = 0 ; j < 200 ;  j++) {
			S[j] = temp_S[j];
			temp_S[j] = 0;
		}		
	}
	
	/* Steps 8 to 10 of Algorithm 8
	 */
	 
	while(loop) {
		memcpy(S_trun, S, 136);
		if(Z != NULL) {
			Z_temp_len = concatenate(&Z_temp, Z, Z_len, S_trun, r);
		} else {
			Z_temp = (unsigned char *)calloc(r/8, sizeof(unsigned char));
			memcpy(Z_temp, S, 136);
			Z_temp_len = r;
		}
		
		if(Z_temp_len >= 256){
			if(Z != NULL){
				Z = NULL;
			}
			Z = (unsigned char *)calloc(32, sizeof(unsigned char));
			memcpy(Z, Z_temp, 32);
			break;
		} else {
			if(Z != NULL) {
				Z = NULL;
			}
				Z = calloc((Z_temp_len / 8) + (Z_temp_len % 8 ? 1 : 0) , sizeof(unsigned char));
				memcpy(Z, Z_temp, Z_temp_len/8);
				Z_len = Z_temp_len;
				Z_temp_len = 0;
			
			
			for(int j = 0 ; j < 200 ;  j++) {
				temp_S[j] = S[j] ;
			}
			keccak_p(temp_S);
			for(int j = 0 ; j < 200 ;  j++) {
				S[j] = temp_S[j];
				temp_S[j] = 0;
			}
		}
	}
	
	free(P);
	free(p10x1);
	free(P_block);
	free(concat_P_block);
	free(P_block_sup);
	free(Z_temp);
	
	return Z;
}

/* Implemenation of Keccak-p[1600, 24] function
 * Inputs:
 * 
 * S - The message string with the padded bits
 */

void keccak_p(unsigned char *S) {
	uint64_t A[5][5];	/* State array */
	uint64_t C[5];
	uint64_t D[5];
	uint64_t A_temp[5][5];
	uint64_t input_temp = 0;
	
	for(int i = 0 ; i < 5 ; i++) {
		for(int j = 0; j < 5 ; j++) {
			memcpy(&A[i][j], &S[(8 * ((5 * i) + j))] , 8);   /* Conversion of input string to state array */
		}
	}

	for(unsigned int i_r = 0 ; i_r < 24 ; i_r++){
		
		/* Theta Step
		*/
		
		for(int i = 0 ; i < 5 ; i++){
			C[i] = A[0][i] ^ A[1][i] ^ A[2][i] ^ A[3][i] ^ A[4][i] ;
		}
			
		for(int i = 0 ; i < 5 ; i++){
			input_temp = ROL64(C[(i + 1) % 5] , 1);
			D[i] = C[( i + 4) % 5] ^ input_temp;
			input_temp = 0;
		}
		
		for(int i = 0 ; i < 5 ; i++) {
			for(int j = 0; j < 5 ; j++) {
				A[j][i] = A[j][i] ^ D[i];
			}
		}
		
		
		/* Rho Step
		*/
		
		A_temp[0][0] = A[0][0];
			
		int i_rho = 1, j_rho = 0, temp_i_rho = 0, temp_j_rho = 0;
		unsigned int rho_rot = 0;
		for(int t = 0 ; t < 24 ; t++){
			rho_rot = ((((t + 1) * (t + 2)) / 2) % 64);
			A_temp[j_rho][i_rho] = ROL64(A[j_rho][i_rho] , rho_rot);
			temp_i_rho = j_rho;
			temp_j_rho = (((2 * i_rho) + (3 * j_rho)) % 5);
			i_rho = temp_i_rho;
			j_rho = temp_j_rho;
		}
		
		for(int i = 0 ; i < 5 ; i++) {
			for(int j = 0; j < 5 ; j++) {
				A[i][j] = A_temp[i][j];
				A_temp[i][j] = 0;
			}
		}
		
		/* Pi Step
		*/
		
		for(int i = 0 ; i < 5 ; i++) {
			for(int j = 0; j < 5 ; j++) {
				A_temp[(( 3 * i ) + (2 * j)) % 5][i] = A[i][j];
				//A_temp[i][j] = A[(i + (3 * j))][i];
			}
		}
		
		for(int i = 0 ; i < 5 ; i++) {
			for(int j = 0; j < 5 ; j++) {
				A[i][j] = A_temp[i][j];
				A_temp[i][j] = 0;
			}
		}
		
		/* Chi Step
		*/
		
		for(int i = 0 ; i < 5 ; i++) {
			for(int j = 0; j < 5 ; j++) {
				A_temp[i][j] = A[i][j] ^ (~(A[i][(j + 1) % 5]) & (A[i][(j + 2) % 5]));
			}
		}
		
		for(int i = 0 ; i < 5 ; i++) {
			for(int j = 0; j < 5 ; j++) {
				A[i][j] = A_temp[i][j];
				A_temp[i][j] = 0;
			}
		}
		
		/* Iota Step
		*/
		
		uint64_t R = 0;
		for(unsigned int j = 0 ; j <= 6 ; j++){
			R ^= ((uint64_t)rc(j + (7 * i_r)) << (power(2, j) - 1));   /* Computation of round constants */
		}
		
		A[0][0] ^= R;
	}
	
	for(int i = 0; i < 5; i++){
		for(int j =0; j < 5; j++){
			memcpy(&S[(8 * ((5 * i) + j))], &A[i][j], 8);   /* Conversion of State array to String */
		}
	}
}

/* Function to return the power of base to exp
 * Inputs:
 * 
 * base - Base of the power 
 * exp  - Exponent of the power
 *
 * Outputs:
 * 
 * base - The base raised to the power of exp
 */
 
unsigned int power(unsigned int base, unsigned int exp) {
	if(exp == 0)
		return 1;
	for(unsigned int i = 1; i < exp; i++){
		base *= 2;
	}
	return base;
}

/* Concatenate two bit strings (X||Y)
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the first bit string
 * X_len - the length of the first string in bits
 * Y     - the second bit string
 * Y_len - the length of the second string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate(unsigned char **Z, const unsigned char *X,
			  unsigned long X_len, const unsigned char *Y,
			  unsigned long Y_len)
{
	/* The bit length of Z: the sum of X_len and Y_len */
	unsigned long Z_bit_len = X_len + Y_len;
	/* The byte length of Z:
	 * the least multiple of 8 greater than X_len + Y_len */
	unsigned long Z_byte_len = (Z_bit_len / 8) + (Z_bit_len % 8 ? 1 : 0);
	// Allocate the output string and initialize it to 0
	*Z = calloc(Z_byte_len, sizeof(unsigned char));
	if (*Z == NULL)
		return 0;
	// Copy X_len/8 bytes from X to Z
	memcpy(*Z, X, X_len / 8);
	// Copy X_len%8 bits from X to Z
	for (unsigned int i = 0; i < X_len % 8; i++) {
		(*Z)[X_len / 8] |= (X[X_len / 8] & (1 << i));
	}
	// Copy Y_len bits from Y to Z
	unsigned long Z_byte_cursor = X_len / 8, Z_bit_cursor = X_len % 8;
	unsigned long Y_byte_cursor = 0, Y_bit_cursor = 0;
	unsigned int v;
	for (unsigned long i = 0; i < Y_len; i++) {
		// Get the bit
		v = ((Y[Y_byte_cursor] >> Y_bit_cursor) & 1);
		// Set the bit
		(*Z)[Z_byte_cursor] |= (v << Z_bit_cursor);
		// Increment cursors
		if (++Y_bit_cursor == 8) {
			Y_byte_cursor++;
			Y_bit_cursor = 0;
		}
		if (++Z_bit_cursor == 8) {
			Z_byte_cursor++;
			Z_bit_cursor = 0;
		}
	}
	return Z_bit_len;
}

/* Concatenate the 01 bit string to a given bit string (X||01)
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the bit string
 * X_len - the length of the string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len)
{
	/* Due to the SHA-3 bit string representation convention, the 01
	 * bit string is represented in hexadecimal as 0x02.
	 * See Appendix B.1 of the Standard.
	 */
	unsigned char zeroone[] = { 0x02 };
	return concatenate(Z, X, X_len, zeroone, 2);
}

/* Performs the pad10*1(x, m) algorithm
 *
 * P - the output bit string. The array is allocated by this function: the
 *     caller must take care of freeing it after use.
 * x - the alignment value
 * m - the existing string length in bits
 *
 * Returns the length in bits of the output bit string.
 */
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m)
{
	/* 1. j = (-m-2) mod x */
	long j = x - ((m + 2) % x);
	/* 2. P = 1 || zeroes(j) || 1 */
	// Compute P bit and byte length
	unsigned long P_bit_len = 2 + j;
	unsigned long P_byte_len = (P_bit_len / 8) + (P_bit_len % 8 ? 1 : 0);
	// Allocate P and initialize to 0
	*P = calloc(P_byte_len, sizeof(unsigned char));
	if (*P == NULL)
		return 0;
	// Set the 1st bit of P to 1
	(*P)[0] |= 1;
	// Set the last bit of P to 1
	(*P)[P_byte_len - 1] |= (1 << (P_bit_len - 1) % 8);

	return P_bit_len;
}

/* Perform the rc(t) algorithm
 *
 * t - the number of rounds to perform in the LFSR
 *
 * Returns a single bit stored as the LSB of an unsigned char.
 */
unsigned char rc(unsigned int t)
{
	unsigned int tmod = t % 255;
	/* 1. If t mod255 = 0, return 1 */
	if (tmod == 0)
		return 1;
	/* 2. Let R = 10000000
	 *    The LSB is on the right: R[0] = R &0x80, R[8] = R &1 */
	unsigned char R = 0x80, R0;
	/* 3. For i from 1 to t mod 255 */
	for (unsigned int i = 1; i <= tmod; i++) {
		/* a. R = 0 || R */
		R0 = 0;
		/* b. R[0] ^= R[8] */
		R0 ^= (R & 1);
		/* c. R[4] ^= R[8] */
		R ^= (R & 0x1) << 4;
		/* d. R[5] ^= R[8] */
		R ^= (R & 0x1) << 3;
		/* e. R[6] ^= R[8] */
		R ^= (R & 0x1) << 2;
		/* Shift right by one */
		R >>= 1;
		/* Copy the value of R0 in */
		R ^= R0 << 7;
	}
	/* 4. Return R[0] */
	return R >> 7;
}
