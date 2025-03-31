#include <stdint.h>

#define INFINITE_ROUNDS(s) (((s)*(s))/8)
//INFINITE_BUFFERSIZE is the maximum nonce size.
#define INFINITE_BUFFERSIZE(s) (1ull<<((s)-2))
//INFINITE_BUFFERSTRUCTURESIZE is the size of a buffer structure allocation.
#define INFINITE_BUFFERSTRUCTURESIZE(s) (128+2*INFINITE_BUFFERSIZE(s))
//INFINITE_TAGSIZE is the space required for the authentication tag.
#define INFINITE_TAGSIZE(t) (1ull<<((t)-3))

#if defined(__cplusplus)
	extern "C" {
#endif
//A null pointer can be passed as buffer structure, in that case the init function will automatically make a suitable allocation. The returned pointer is the buffer structure pointer, or a null pointer in case of an error. buffer_structure_length is checked to be large enough.
void* infinite_init(void* buffer_structure,uint64_t buffer_structure_length,uint8_t strength,uint8_t tag_size,const void* key,uint64_t key_length);
//The buffer structure pointer must have been previously initialised using the init function. out_length and tag_out_length are checked to be large enough, but do not otherwise influence the operation.
int64_t infinite_encrypt(void* buffer_structure,const void* nonce,uint64_t nonce_length,const void* plaintext,uint64_t plaintext_length,void* out,uint64_t out_length,void* tag_out,uint64_t tag_out_length);
int64_t infinite_decrypt(void* buffer_structure,const void* nonce,uint64_t nonce_length,const void* ciphertext,uint64_t ciphertext_length,void* out,uint64_t out_length,const void* tag);
#if defined(__cplusplus)
	}
#endif
