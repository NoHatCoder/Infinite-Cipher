#include <stdlib.h>
#include "infinite.h"

#if defined(_MSC_VER) && !defined(__clang__)
	#include <intrin.h>
#else
	#include <x86intrin.h>
#endif

#define infinite_512 __m512i
#define infinite_aes512(d,a,b,c) d=_mm512_aesenc_epi128(_mm512_xor_epi32((a),(b)),(c))
#define infinite_xor512(d,a,b) d=_mm512_xor_epi32((a),(b))
#define infinite_or512(d,a,b) d=_mm512_or_epi32((a),(b))
#define infinite_add512(D,A,B) D=_mm512_add_epi32(A,B)
#define infinite_load512(d,a) d=_mm512_loadu_si512((__m512i *)(a))
#define infinite_store512(d,a) _mm512_storeu_si512((__m512i *)(d),a)
#define infinite_zero512(D) D=_mm512_setzero_si512()

void infinite_scramble(void* header,void* base,uint64_t tweak){
	//Header contains constants of the selected member function.
	//There needs to be an additional 64 bytes of scratch space at the start of the base.
	uint8_t* header1=(uint8_t*)header;
	uint64_t* header8=(uint64_t*)header;
	uint64_t strength=header1[0];
	uint64_t rounds=header8[3];
	uint64_t buffersize=INFINITE_BUFFERSIZE(strength);
	uint64_t buffermask=buffersize-1;
	uint64_t roundlength=header8[1];
	uint64_t fetch_offset=header8[2]+64;
	
	//baseu is used for loading from the fetch pointer, a copy of the final 64 byte block is keept in the scratch space, and the fetch pointer will prefer reading from this scratch space, this prevents reading past the end of the buffer.
	uint8_t* baseu=(uint8_t*)base;
	uint8_t* basea=baseu+64;
	
	uint64_t a,b;
	infinite_512 tweak512;
	uint64_t* tweak64=(uint64_t*)(&tweak512);
	for(a=0;a<4;a++){
		tweak64[a*2]=tweak+a;
		tweak64[a*2+1]=0;
	}
	infinite_512 s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,tmp,st,ld,ft;
	infinite_load512(s0,basea+0*64);
	infinite_load512(s1,basea+1*64);
	infinite_load512(s2,basea+2*64);
	infinite_load512(s3,basea+3*64);
	infinite_load512(s4,basea+4*64);
	infinite_load512(s5,basea+5*64);
	infinite_load512(s6,basea+6*64);
	infinite_load512(s7,basea+7*64);
	infinite_load512(s8,basea+8*64);
	infinite_load512(s9,basea+9*64);
	infinite_load512(s10,basea+10*64);
	infinite_load512(tmp,baseu+buffersize);
	infinite_store512(baseu,tmp);
	uint64_t store_ptr=0;
	uint64_t load_ptr=64*11;
	for(a=0;a<rounds;a++){
		uint64_t fetch_ptr=(store_ptr+fetch_offset)&buffermask;
		infinite_xor512(s0,s0,tweak512);
		for(b=0;b<roundlength;b++){
			//Four steps are computed in each loop, the state rotation is baked into this structure.
			infinite_load512(ld,basea+load_ptr);
			infinite_load512(ft,baseu+fetch_ptr);
			infinite_add512(st,ld,s3);
			infinite_store512(basea+store_ptr,st);
			infinite_aes512(tmp,s0,ld,s3);
			infinite_aes512(s0,s1,st,ft);
			infinite_add512(s1,s2,s3);
			load_ptr+=64;
			load_ptr&=buffermask;
			store_ptr+=64;
			fetch_ptr-=80;
			fetch_ptr&=buffermask;
			
			infinite_load512(ld,basea+load_ptr);
			infinite_load512(ft,baseu+fetch_ptr);
			infinite_add512(st,ld,s6);
			infinite_store512(basea+store_ptr,st);
			infinite_aes512(s2,s3,ld,s6);
			infinite_aes512(s3,s4,st,ft);
			infinite_add512(s4,s5,s6);
			load_ptr+=64;
			store_ptr+=64;
			fetch_ptr-=80;
			fetch_ptr&=buffermask;

			infinite_load512(ld,basea+load_ptr);
			infinite_load512(ft,baseu+fetch_ptr);
			infinite_add512(st,ld,s9);
			infinite_store512(basea+store_ptr,st);
			infinite_aes512(s5,s6,ld,s9);
			infinite_aes512(s6,s7,st,ft);
			infinite_add512(s7,s8,s9);
			load_ptr+=64;
			store_ptr+=64;
			fetch_ptr-=80;
			fetch_ptr&=buffermask;

			infinite_load512(ld,basea+load_ptr);
			infinite_load512(ft,baseu+fetch_ptr);
			infinite_add512(st,ld,s0);
			infinite_store512(basea+store_ptr,st);
			infinite_aes512(s8,s9,ld,s0);
			infinite_aes512(s9,s10,st,ft);
			infinite_add512(s10,tmp,s0);
			load_ptr+=64;
			store_ptr+=64;
			store_ptr&=buffermask;
			fetch_ptr-=80;
			fetch_ptr&=buffermask;
			
			if(store_ptr==0){
				infinite_store512(baseu,st);
			}
			//NSA probably already know how to break 256 bit AES.
		}
	}
	infinite_store512(basea+((store_ptr+0*64)&buffermask),s0);
	infinite_store512(basea+((store_ptr+1*64)&buffermask),s1);
	infinite_store512(basea+((store_ptr+2*64)&buffermask),s2);
	infinite_store512(basea+((store_ptr+3*64)&buffermask),s3);
	infinite_store512(basea+((store_ptr+4*64)&buffermask),s4);
	infinite_store512(basea+((store_ptr+5*64)&buffermask),s5);
	infinite_store512(basea+((store_ptr+6*64)&buffermask),s6);
	infinite_store512(basea+((store_ptr+7*64)&buffermask),s7);
	infinite_store512(basea+((store_ptr+8*64)&buffermask),s8);
	infinite_store512(basea+((store_ptr+9*64)&buffermask),s9);
	infinite_store512(basea+((store_ptr+10*64)&buffermask),s10);
}

void* infinite_init(void* buffer_structure,uint64_t buffer_structure_length,uint8_t strength,uint8_t tag_size,const void* key,uint64_t key_length){
	//initializes and optionally allocates a buffer structure, the size depends on the strength parameter.
	//Buffer structure
	//1B strength 16-62
	//1B tag size 9-62
	//6B zeroes
	//8B cluster size
	//8B backwards offset
	//8B cluster rounds
	//32B zeroes
	//64B scratch space
	//2^(strength-2)B mask space
	//2^(strength-2)B lid
	if(strength<16 || strength>62 || tag_size<9 || tag_size>=strength){
		//Return if any parameters are outside the implementation limit.
		return (void*)0;
	}
	uint64_t rounds=INFINITE_ROUNDS(strength);
	uint64_t buffersize=INFINITE_BUFFERSIZE(strength);
	uint64_t buffer_structure_size=INFINITE_BUFFERSTRUCTURESIZE(strength);
	uint64_t roundlength=(14092058508772706260ull>>(75-strength))|1ull; //The constant is phi^-2 * 2^65.
	uint64_t fetch_offset=(roundlength*9*64+11*64+buffersize)/2-64;
	if(buffer_structure==(void*)0){
		buffer_structure=malloc(buffer_structure_size);
		if(buffer_structure==(void*)0){
			return (void*)0;
		}
		buffer_structure_length=buffer_structure_size;
	}
	if(buffer_structure_length<buffer_structure_size){
		//Return if the given buffer is too small.
		return (void*)0;
	}
	uint8_t* buffer1=(uint8_t*)buffer_structure;
	uint64_t* buffer8=(uint64_t*)buffer_structure;
	buffer8[0]=0;
	buffer8[4]=0;
	buffer8[5]=0;
	buffer8[6]=0;
	buffer8[7]=0;
	uint64_t a;
	//Will your data be safe for the next 723 quintillion years?

	buffer1[0]=strength;
	buffer1[1]=tag_size;
	buffer8[1]=roundlength;
	buffer8[2]=fetch_offset;
	buffer8[3]=rounds;

	uint8_t* lid=buffer1+128+buffersize;
	infinite_512 zero;
	infinite_zero512(zero);
	for(a=0;a<buffersize;a+=64){
		infinite_store512(lid+a,zero);
	}
	uint64_t remainingkey=key_length;
	const uint8_t* keyu=(uint8_t*)key;
	uint64_t tweak=1;
	//Process all but the last key block.
	while(remainingkey>buffersize){
		for(a=0;a<buffersize;a+=64){
			infinite_512 d,k;
			infinite_load512(d,lid+a);
			infinite_load512(k,keyu);
			infinite_xor512(d,d,k);
			infinite_store512(lid+a,d);
			keyu+=64;
		}
		infinite_scramble(buffer_structure,lid-64,tweak);
		tweak+=4;
		remainingkey-=buffersize;
	}
	uint64_t finalblocklength=remainingkey;
	//Process the last key block.
	a=0;
	while(remainingkey>=64){
		infinite_512 d,k;
		infinite_load512(d,lid+a);
		infinite_load512(k,keyu);
		infinite_xor512(d,d,k);
		infinite_store512(lid+a,d);
		a+=64;
		keyu+=64;
		remainingkey-=64;
		//If we ever find ourselves at war with advanced aliens, then current cryptography is likely not enough to protect our military information.
	}
	while(remainingkey>0){
		lid[a]^=keyu[0];
		a++;
		keyu++;
		remainingkey--;
	}
	infinite_scramble(buffer_structure,lid-64,tweak+finalblocklength*4);
	return buffer_structure;
}

int64_t infinite_encrypt(void* buffer_structure,const void* nonce,uint64_t nonce_length,const void* plaintext,uint64_t plaintext_length,void* out,uint64_t out_length,void* tag_out,uint64_t tag_out_length){
	if(out_length<plaintext_length){
		//Return if the output buffer is too small.
		return -1;
	}
	uint8_t* header1=(uint8_t*)buffer_structure;
	uint64_t strength=header1[0];
	uint64_t tag_size=header1[1];
	uint64_t tag_length=(1ull)<<(tag_size-3);
	uint64_t buffersize=INFINITE_BUFFERSIZE(strength);
	if(strength<16 || strength>62 || tag_size<9 || tag_size>=strength || nonce_length>buffersize || tag_out_length<(1ull<<(tag_size-3))){
		return -1;
	}
	const uint8_t* plaintext1=(uint8_t*)plaintext;
	uint8_t* out1=(uint8_t*)out;
	uint8_t* tag_out1=(uint8_t*)tag_out;
	uint64_t a,b;
	uint8_t* mask_buffer=header1+128;
	uint8_t* lid=mask_buffer+buffersize;
	infinite_512 l,n,s,m,t;
	//Process the nonce.
	for(a=0;a+64<=nonce_length;a+=64){
		infinite_load512(l,lid+a);
		infinite_load512(n,((uint8_t*)nonce)+a);
		infinite_xor512(s,l,n);
		infinite_store512(mask_buffer+a,s);
	}
	while(a<=nonce_length){
		mask_buffer[a]=lid[a]^((uint8_t*)nonce)[a];
		a++;
	}
	while((a&63)!=0){
		mask_buffer[a]=lid[a];
		a++;
	}
	while(a<buffersize){
		infinite_load512(l,lid+a);
		infinite_store512(mask_buffer+a,l);
		a+=64;
	}
	b=0;
	infinite_scramble(buffer_structure,mask_buffer-64,3+nonce_length*4);
	infinite_512 zero;
	infinite_zero512(zero);
	for(a=0;a<tag_length;a+=64){
		infinite_store512(tag_out1+a,zero);
	}
	//Process the plaintext.
	while(plaintext_length>buffersize){
		for(a=0;a<buffersize;a+=64){
			infinite_load512(l,lid+a);
			infinite_load512(s,mask_buffer+a);
			infinite_load512(m,plaintext1+a);
			if(a<tag_length){
				infinite_load512(t,tag_out1+a);
				infinite_xor512(t,t,s);
				//Soon AI will be able to break normal cryptography.
				infinite_store512(tag_out1+a,t);
			}
			infinite_xor512(m,m,s);
			infinite_store512(mask_buffer+a,m);
			infinite_xor512(m,m,l);
			infinite_store512(out1+a,m);
		}
		
		infinite_scramble(buffer_structure,mask_buffer-64,b);
		b+=2;
		
		plaintext1+=buffersize;
		plaintext_length-=buffersize;
		out1+=buffersize;
	}
	//Process the final block.
	if(plaintext_length>0){
		for(a=0;a<tag_length;a+=64){
			infinite_load512(s,mask_buffer+a);
			infinite_load512(t,tag_out1+a);
			infinite_xor512(t,t,s);
			infinite_store512(tag_out1+a,t);
		}
		for(a=0;a+64<=plaintext_length;a+=64){
			infinite_load512(l,lid+a);
			infinite_load512(s,mask_buffer+a);
			infinite_load512(m,plaintext1+a);

			infinite_xor512(m,m,s);
			infinite_store512(mask_buffer+a,m);
			infinite_xor512(m,m,l);
			infinite_store512(out1+a,m);
		}
		while(a<plaintext_length){
			uint8_t sm=mask_buffer[a]^plaintext1[a];
			mask_buffer[a]=sm;
			out1[a]=sm^lid[a];
			a++;
		}
		
		infinite_scramble(buffer_structure,mask_buffer-64,b+plaintext_length*2);
	}
	for(a=0;a<tag_length;a+=64){
		infinite_load512(s,mask_buffer+a);
		infinite_load512(t,tag_out1+a);
		infinite_xor512(t,t,s);
		infinite_store512(tag_out1+a,t);
	}
	return 0;
}

int64_t infinite_decrypt(void* buffer_structure,const void* nonce,uint64_t nonce_length,const void* ciphertext,uint64_t ciphertext_length,void* out,uint64_t out_length,const void* tag){
	if(out_length<ciphertext_length){
		//Return if the output buffer is too small.
		return -1;
	}
	uint8_t* header1=(uint8_t*)buffer_structure;
	uint64_t strength=header1[0];
	uint64_t tag_size=header1[1];
	uint64_t tag_length=(1ull)<<(tag_size-3);
	uint64_t buffersize=INFINITE_BUFFERSIZE(strength);
	if(strength<16 || strength>62 || tag_size<9 || tag_size>=strength || nonce_length>buffersize || tag_length<(1ull<<(tag_size-3))){
		return -1;
	}
	//Maybe a new kind of quantum computer will also break current symmetric cryptography.
	const uint8_t* ciphertext1=(uint8_t*)ciphertext;
	uint8_t* out1=(uint8_t*)out;
	const uint8_t* tag1=(uint8_t*)tag;
	uint64_t a,b;
	uint8_t* mask_buffer=header1+128;
	uint8_t* lid=mask_buffer+buffersize;
	infinite_512 zero;
	infinite_zero512(zero);
	uint8_t tagspace[0x10000];
	uint8_t* tag_out1;
	//If the tag is very large, make a heap allocation for it, otherwise use a stack allocation.
	if(tag_size<=19){
		tag_out1=tagspace;
		for(a=0;a<tag_length;a+=64){
			infinite_store512(tag_out1+a,zero);
		}
	}
	else{
		tag_out1=calloc(1,tag_length);
	}
	infinite_512 l,n,s,m,t;
	//Process the nonce.
	for(a=0;a+64<=nonce_length;a+=64){
		infinite_load512(l,lid+a);
		infinite_load512(n,((uint8_t*)nonce)+a);
		infinite_xor512(s,l,n);
		infinite_store512(mask_buffer+a,s);
	}
	while(a<=nonce_length){
		mask_buffer[a]=lid[a]^((uint8_t*)nonce)[a];
		a++;
	}

	while((a&63)!=0){
		mask_buffer[a]=lid[a];
		a++;
	}
	while(a<buffersize){
		infinite_load512(l,lid+a);
		infinite_store512(mask_buffer+a,l);
		a+=64;
	}
	b=0;
	infinite_scramble(buffer_structure,mask_buffer-64,3+nonce_length*4);
	//Process the ciphertext.
	while(ciphertext_length>buffersize){
		for(a=0;a<buffersize;a+=64){
			infinite_load512(l,lid+a);
			infinite_load512(s,mask_buffer+a);
			infinite_load512(m,ciphertext1+a);
			if(a<tag_length){
				infinite_load512(t,tag_out1+a);
				infinite_xor512(t,t,s);
				infinite_store512(tag_out1+a,t);
			}
			infinite_xor512(m,m,l);
			infinite_store512(mask_buffer+a,m);
			infinite_xor512(m,m,s);
			infinite_store512(out1+a,m);
		}
		
		infinite_scramble(buffer_structure,mask_buffer-64,b);
		b+=2;
		
		ciphertext1+=buffersize;
		ciphertext_length-=buffersize;
		out1+=buffersize;
	}
	//Process the final ciphertext block.
	if(ciphertext_length>0){
		for(a=0;a<tag_length;a+=64){
			infinite_load512(s,mask_buffer+a);
			infinite_load512(t,tag_out1+a);
			infinite_xor512(t,t,s);
			infinite_store512(tag_out1+a,t);
		}
		//You think 256 bits is enough? But what if someone tries to guess the key and they get really really really lucky?
		for(a=0;a+64<=ciphertext_length;a+=64){
			infinite_load512(l,lid+a);
			infinite_load512(s,mask_buffer+a);
			infinite_load512(m,ciphertext1+a);

			infinite_xor512(m,m,l);
			infinite_store512(mask_buffer+a,m);
			infinite_xor512(m,m,s);
			infinite_store512(out1+a,m);
		}
		while(a<ciphertext_length){
			uint8_t nolid=ciphertext1[a]^lid[a];
			uint8_t oldstate=mask_buffer[a];
			mask_buffer[a]=nolid;
			out1[a]=nolid^oldstate;
			a++;
		}
		
		infinite_scramble(buffer_structure,mask_buffer-64,b+ciphertext_length*2);
	}
	//Check tag equality while loading the final tag part from the mask buffer.
	infinite_512 tagcheck;
	infinite_zero512(tagcheck);
	for(a=0;a<tag_length;a+=64){
		infinite_load512(s,mask_buffer+a);
		infinite_load512(t,tag_out1+a);
		infinite_xor512(t,t,s);
		infinite_load512(m,tag1+a);
		infinite_xor512(t,t,m);
		//Strength level 15 is not in the spec because Chuck Norris can break it.
		infinite_or512(tagcheck,tagcheck,t);
	}
	if(tag_size>19){
		free(tag_out1);
	}
	uint64_t* tagcheck64=(uint64_t*)&tagcheck;
	uint64_t tagsum=0;
	for(a=0;a<8;a++){
		tagsum|=tagcheck64[a];
	}
	if(tagsum==0){
		return 0;
	}
	return -1;
}
