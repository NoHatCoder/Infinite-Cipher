//NOTE: infinite512.c is the preferred implementation file for reading along with the specification.

#include <stdlib.h>
#include "infinite.h"

#if defined(_MSC_VER) && !defined(__clang__)
	#if defined(_M_AMD64) || defined(_M_IX86)
		#include <intrin.h>
		#define INFINITE_X86
	#elif defined(_M_ARM64)
		#include <arm64_neon.h>
		#define INFINITE_ARM
	#elif defined(_M_ARM)
		#include <arm_neon.h>
		#define INFINITE_ARM
	#endif
#else
	#if defined(__x86_64__) || defined(__i386__)
		#include <x86intrin.h>
		#define INFINITE_X86
	#elif defined(__aarch64__) || defined(__arm__)
		#include <arm_neon.h>
		#define INFINITE_ARM
	#endif
#endif

#if defined(INFINITE_ARM)
	#define infinite_128 uint8x16_t
	#define infinite_xor(D,A,B) D=veorq_u8(A,B)
	#define infinite_or(D,A,B) D=vorrq_u8(A,B)
	#define infinite_add(D,A,B) D=(uint8x16_t)vaddq_u32((uint32x4_t)(A),(uint32x4_t)(B))
	#define infinite_aes(D,A,B,C) D=veorq_u8(vaesmcq_u8(vaeseq_u8(A,B)),C)
	#define infinite_load(D,A) D=vld1q_u8((uint8_t*)(A))
	#define infinite_store(A,B) vst1q_u8((uint8_t*)(A),B)
	#define infinite_zero(D) D=vdupq_n_u8(0)
#elif defined(INFINITE_X86)
	#define infinite_128 __m128i
	#define infinite_xor(D,A,B) D=_mm_xor_si128(A,B)
	#define infinite_or(D,A,B) D=_mm_or_si128(A,B)
	#define infinite_add(D,A,B) D=_mm_add_epi32(A,B)
	#define infinite_aes(D,A,B,C) D=_mm_aesenc_si128(_mm_xor_si128(A,B),C)
	#define infinite_load(D,A) D=_mm_loadu_si128((__m128i *)(A))
	#define infinite_store(A,B) _mm_storeu_si128((__m128i *)(A),B)
	#define infinite_zero(D) D=_mm_setzero_si128()
#endif

void infinite_scramble(void* header,void* state,uint64_t tweak){
	uint8_t* header1=(uint8_t*)header;
	uint64_t* header8=(uint64_t*)header;
	uint64_t strength=header1[0];
	uint64_t rounds=header8[3];
	uint64_t buffersize=INFINITE_BUFFERSIZE(strength);
	uint64_t buffermask=buffersize-1;
	uint64_t clustersize=header8[1];
	uint64_t back_offset=header8[2];

	uint8_t* statea=(uint8_t*)state+64;
	
	uint64_t a,b,c;
	infinite_128 tweak128[4];
	uint64_t* tweak64=(uint64_t*)(tweak128);
	for(a=0;a<4;a++){
		tweak64[a*2]=tweak+a;
		tweak64[a*2+1]=0;
	}
	infinite_128 s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,tmp,st,ld,ft;
	for(a=0;a<rounds;a++){
		for(c=0;c<4;c++){
			uint64_t storeoffset=(a*clustersize*256+c*16)&buffermask;
			uint64_t loadoffset=(storeoffset+64*11)&buffermask;
			uint64_t fetchoffset=(storeoffset+back_offset)&buffermask;
			infinite_load(s0,statea+((storeoffset+0*64)&buffermask));
			infinite_load(s1,statea+((storeoffset+1*64)&buffermask));
			infinite_load(s2,statea+((storeoffset+2*64)&buffermask));
			infinite_load(s3,statea+((storeoffset+3*64)&buffermask));
			infinite_load(s4,statea+((storeoffset+4*64)&buffermask));
			infinite_load(s5,statea+((storeoffset+5*64)&buffermask));
			infinite_load(s6,statea+((storeoffset+6*64)&buffermask));
			infinite_load(s7,statea+((storeoffset+7*64)&buffermask));
			infinite_load(s8,statea+((storeoffset+8*64)&buffermask));
			infinite_load(s9,statea+((storeoffset+9*64)&buffermask));
			infinite_load(s10,statea+((storeoffset+10*64)&buffermask));
			infinite_xor(s0,s0,tweak128[c]);
			for(b=0;b<clustersize;b++){
				infinite_load(ld,statea+loadoffset);
				infinite_load(ft,statea+fetchoffset);
				infinite_add(st,ld,s3);
				infinite_store(statea+storeoffset,st);
				infinite_aes(tmp,s0,ld,s3);
				infinite_aes(s0,s1,st,ft);
				infinite_add(s1,s2,s3);
				loadoffset+=64;
				loadoffset&=buffermask;
				storeoffset+=64;
				fetchoffset-=80;
				fetchoffset&=buffermask;
				
				infinite_load(ld,statea+loadoffset);
				infinite_load(ft,statea+fetchoffset);
				infinite_add(st,ld,s6);
				infinite_store(statea+storeoffset,st);
				infinite_aes(s2,s3,ld,s6);
				infinite_aes(s3,s4,st,ft);
				infinite_add(s4,s5,s6);
				loadoffset+=64;
				storeoffset+=64;
				fetchoffset-=80;
				fetchoffset&=buffermask;

				infinite_load(ld,statea+loadoffset);
				infinite_load(ft,statea+fetchoffset);
				infinite_add(st,ld,s9);
				infinite_store(statea+storeoffset,st);
				infinite_aes(s5,s6,ld,s9);
				infinite_aes(s6,s7,st,ft);
				infinite_add(s7,s8,s9);
				loadoffset+=64;
				storeoffset+=64;
				fetchoffset-=80;
				fetchoffset&=buffermask;

				infinite_load(ld,statea+loadoffset);
				infinite_load(ft,statea+fetchoffset);
				infinite_add(st,ld,s0);
				infinite_store(statea+storeoffset,st);
				infinite_aes(s8,s9,ld,s0);
				infinite_aes(s9,s10,st,ft);
				infinite_add(s10,tmp,s0);
				loadoffset+=64;
				storeoffset+=64;
				storeoffset&=buffermask;
				fetchoffset-=80;
				fetchoffset&=buffermask;
			}
			infinite_store(statea+((storeoffset+0*64)&buffermask),s0);
			infinite_store(statea+((storeoffset+1*64)&buffermask),s1);
			infinite_store(statea+((storeoffset+2*64)&buffermask),s2);
			infinite_store(statea+((storeoffset+3*64)&buffermask),s3);
			infinite_store(statea+((storeoffset+4*64)&buffermask),s4);
			infinite_store(statea+((storeoffset+5*64)&buffermask),s5);
			infinite_store(statea+((storeoffset+6*64)&buffermask),s6);
			infinite_store(statea+((storeoffset+7*64)&buffermask),s7);
			infinite_store(statea+((storeoffset+8*64)&buffermask),s8);
			infinite_store(statea+((storeoffset+9*64)&buffermask),s9);
			infinite_store(statea+((storeoffset+10*64)&buffermask),s10);
		}
	}
}

void* infinite_init(void* buffer,uint64_t buffer_length,uint8_t strength,uint8_t tag_size,const void* key,uint64_t key_length){
	if(strength<16 || strength>62 || tag_size<9 || tag_size>=strength){
		return (void*)0;
	}
	uint64_t rounds=INFINITE_ROUNDS(strength);
	uint64_t buffersize=INFINITE_BUFFERSIZE(strength);
	uint64_t statesize=INFINITE_BUFFERSTRUCTURESIZE(strength);
	uint64_t clustersize=(14092058508772706260ull>>(75-strength))|1ull;
	uint64_t back_offset=(clustersize*9*64+11*64+buffersize)/2-64;
	if(buffer==(void*)0){
		buffer=malloc(statesize);
		if(buffer==(void*)0){
			return (void*)0;
		}
		buffer_length=statesize;
	}
	if(buffer_length<statesize){
		return (void*)0;
	}
	uint8_t* buffer1=(uint8_t*)buffer;
	uint64_t* buffer8=(uint64_t*)buffer;
	buffer8[0]=0;
	buffer8[4]=0;
	buffer8[5]=0;
	buffer8[6]=0;
	buffer8[7]=0;
	uint64_t a;

	buffer1[0]=strength;
	buffer1[1]=tag_size;
	buffer8[1]=clustersize;
	buffer8[2]=back_offset;
	buffer8[3]=rounds;

	uint8_t* lid=buffer1+128+buffersize;
	infinite_128 zero;
	infinite_zero(zero);
	for(a=0;a<buffersize;a+=16){
		infinite_store(lid+a,zero);
	}
	uint64_t remainingkey=key_length;
	const uint8_t* keyu=(uint8_t*)key;
	uint64_t tweak=1;
	while(remainingkey>buffersize){
		for(a=0;a<buffersize;a+=16){
			infinite_128 d,k;
			infinite_load(d,lid+a);
			infinite_load(k,keyu);
			infinite_xor(d,d,k);
			infinite_store(lid+a,d);
			keyu+=16;
		}
		infinite_scramble(buffer,lid-64,tweak);
		tweak+=4;
		remainingkey-=buffersize;
	}
	uint64_t finalblocklength=remainingkey;
	a=0;
	while(remainingkey>=16){
		infinite_128 d,k;
		infinite_load(d,lid+a);
		infinite_load(k,keyu);
		infinite_xor(d,d,k);
		infinite_store(lid+a,d);
		a+=16;
		keyu+=16;
		remainingkey-=16;
	}
	while(remainingkey>0){
		lid[a]^=keyu[0];
		a++;
		keyu++;
		remainingkey--;
	}
	infinite_scramble(buffer,lid-64,tweak+finalblocklength*4);
	return buffer;
}

int64_t infinite_encrypt(void* buffer,const void* nonce,uint64_t nonce_length,const void* message,uint64_t message_length,void* out,uint64_t out_length,void* tag_out,uint64_t tag_out_length){
	if(out_length<message_length){
		return -1;
	}
	uint8_t* header1=(uint8_t*)buffer;
	uint64_t strength=header1[0];
	uint64_t tag_size=header1[1];
	uint64_t tag_length=(1ull)<<(tag_size-3);
	uint64_t buffersize=INFINITE_BUFFERSIZE(strength);
	if(strength<16 || strength>62 || tag_size<9 || tag_size>=strength || nonce_length>buffersize || tag_out_length<(1ull<<(tag_size-3))){
		return -1;
	}
	const uint8_t* message1=(uint8_t*)message;
	uint8_t* out1=(uint8_t*)out;
	uint8_t* tag_out1=(uint8_t*)tag_out;
	uint64_t a,b;
	uint8_t* state=header1+128;
	uint8_t* lid=state+buffersize;
	infinite_128 l,n,s,m,t;
	for(a=0;a+16<=nonce_length;a+=16){
		infinite_load(l,lid+a);
		infinite_load(n,((uint8_t*)nonce)+a);
		infinite_xor(s,l,n);
		infinite_store(state+a,s);
	}
	while(a<=nonce_length){
		state[a]=lid[a]^((uint8_t*)nonce)[a];
		a++;
	}
	while((a&15)!=0){
		state[a]=lid[a];
		a++;
	}
	while(a<buffersize){
		infinite_load(l,lid+a);
		infinite_store(state+a,l);
		a+=16;
	}
	b=0;
	infinite_scramble(buffer,state-64,3+nonce_length*4);
	infinite_128 zero;
	infinite_zero(zero);
	for(a=0;a<tag_length;a+=16){
		infinite_store(tag_out1+a,zero);
	}
	while(message_length>buffersize){
		for(a=0;a<buffersize;a+=16){
			infinite_load(l,lid+a);
			infinite_load(s,state+a);
			infinite_load(m,message1+a);
			if(a<tag_length){
				infinite_load(t,tag_out1+a);
				infinite_xor(t,t,s);
				infinite_store(tag_out1+a,t);
			}
			infinite_xor(m,m,s);
			infinite_store(state+a,m);
			infinite_xor(m,m,l);
			infinite_store(out1+a,m);
		}
		
		infinite_scramble(buffer,state-64,b);
		b+=2;
		
		message1+=buffersize;
		message_length-=buffersize;
		out1+=buffersize;
	}
	if(message_length>0){
		for(a=0;a<tag_length;a+=16){
			infinite_load(s,state+a);
			infinite_load(t,tag_out1+a);
			infinite_xor(t,t,s);
			infinite_store(tag_out1+a,t);
		}
		for(a=0;a+16<=message_length;a+=16){
			infinite_load(l,lid+a);
			infinite_load(s,state+a);
			infinite_load(m,message1+a);

			infinite_xor(m,m,s);
			infinite_store(state+a,m);
			infinite_xor(m,m,l);
			infinite_store(out1+a,m);
		}
		while(a<message_length){
			uint8_t sm=state[a]^message1[a];
			state[a]=sm;
			out1[a]=sm^lid[a];
			a++;
		}
		
		infinite_scramble(buffer,state-64,b+message_length*2);
	}
	for(a=0;a<tag_length;a+=16){
		infinite_load(s,state+a);
		infinite_load(t,tag_out1+a);
		infinite_xor(t,t,s);
		infinite_store(tag_out1+a,t);
	}
	return 0;
}

int64_t infinite_decrypt(void* buffer,const void* nonce,uint64_t nonce_length,const void* message,uint64_t message_length,void* out,uint64_t out_length,const void* tag){
	if(out_length<message_length){
		return -1;
	}
	uint8_t* header1=(uint8_t*)buffer;
	uint64_t strength=header1[0];
	uint64_t tag_size=header1[1];
	uint64_t tag_length=(1ull)<<(tag_size-3);
	uint64_t buffersize=INFINITE_BUFFERSIZE(strength);
	if(strength<16 || strength>62 || tag_size<9 || tag_size>=strength || nonce_length>buffersize || tag_length<(1ull<<(tag_size-3))){
		return -1;
	}
	const uint8_t* message1=(uint8_t*)message;
	uint8_t* out1=(uint8_t*)out;
	const uint8_t* tag1=(uint8_t*)tag;
	uint64_t a,b;
	uint8_t* state=header1+128;
	uint8_t* lid=state+buffersize;
	infinite_128 zero;
	infinite_zero(zero);
	uint8_t tagspace[0x10000];
	uint8_t* tag_out1;
	if(tag_size<=19){
		tag_out1=tagspace;
		for(a=0;a<tag_length;a+=16){
			infinite_store(tag_out1+a,zero);
		}
	}
	else{
		tag_out1=calloc(1,tag_length);
	}
	infinite_128 l,n,s,m,t;
	for(a=0;a+16<=nonce_length;a+=16){
		infinite_load(l,lid+a);
		infinite_load(n,((uint8_t*)nonce)+a);
		infinite_xor(s,l,n);
		infinite_store(state+a,s);
	}
	while(a<=nonce_length){
		state[a]=lid[a]^((uint8_t*)nonce)[a];
		a++;
	}
	while((a&15)!=0){
		state[a]=lid[a];
		a++;
	}
	while(a<buffersize){
		infinite_load(l,lid+a);
		infinite_store(state+a,l);
		a+=16;
	}
	b=0;
	infinite_scramble(buffer,state-64,3+nonce_length*4);
	while(message_length>buffersize){
		for(a=0;a<buffersize;a+=16){
			infinite_load(l,lid+a);
			infinite_load(s,state+a);
			infinite_load(m,message1+a);
			if(a<tag_length){
				infinite_load(t,tag_out1+a);
				infinite_xor(t,t,s);
				infinite_store(tag_out1+a,t);
			}
			infinite_xor(m,m,l);
			infinite_store(state+a,m);
			infinite_xor(m,m,s);
			infinite_store(out1+a,m);
		}
		
		infinite_scramble(buffer,state-64,b);
		b+=2;
		
		message1+=buffersize;
		message_length-=buffersize;
		out1+=buffersize;
	}
	if(message_length>0){
		for(a=0;a<tag_length;a+=16){
			infinite_load(s,state+a);
			infinite_load(t,tag_out1+a);
			infinite_xor(t,t,s);
			infinite_store(tag_out1+a,t);
		}
		for(a=0;a+16<=message_length;a+=16){
			infinite_load(l,lid+a);
			infinite_load(s,state+a);
			infinite_load(m,message1+a);

			infinite_xor(m,m,l);
			infinite_store(state+a,m);
			infinite_xor(m,m,s);
			infinite_store(out1+a,m);
		}
		while(a<message_length){
			uint8_t nolid=message1[a]^lid[a];
			uint8_t oldstate=state[a];
			state[a]=nolid;
			out1[a]=nolid^oldstate;
			a++;
		}
		
		infinite_scramble(buffer,state-64,b+message_length*2);
	}
	infinite_128 tagcheck;
	infinite_zero(tagcheck);
	for(a=0;a<tag_length;a+=16){
		infinite_load(s,state+a);
		infinite_load(t,tag_out1+a);
		infinite_xor(t,t,s);
		infinite_load(m,tag1+a);
		infinite_xor(t,t,m);
		infinite_or(tagcheck,tagcheck,t);
	}
	if(tag_size>19){
		free(tag_out1);
	}
	uint64_t* tagcheck64=(uint64_t*)&tagcheck;
	uint64_t tagsum=0;
	for(a=0;a<2;a++){
		tagsum|=tagcheck64[a];
	}
	if(tagsum==0){
		return 0;
	}
	return -1;
}
