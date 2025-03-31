#define TIMEFACTOR 1

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "infinite.h"
#define TIME_PLEASE (uint64_t)clock()
#define TIME_DIVIDER CLOCKS_PER_SEC
#define OUTPUT(...) printf(__VA_ARGS__)
//char textout[1000000];
//int64_t textoutused=0;
//#define OUTPUT(...) ((textoutused<999999)&&(textoutused+=snprintf(textout+textoutused, 999999-textoutused, __VA_ARGS__)));

typedef struct r{
	uint64_t power;
	uint64_t scramble;
} r;
void r_init(r* state,uint64_t a,uint64_t b){
	state->power=(a*123454321)|1;
	state->scramble=b*34567;
}
uint64_t r_g(r* state){
	uint64_t result=state->scramble;
	state->scramble=state->scramble^(state->scramble>>18)^state->power;
	state->scramble*=123456789;
	state->power*=44332211;
	return result;
}
void r_fill(r* state,void* dst,uint64_t len){
	uint8_t* dst1=(uint8_t*)dst;
	while(len>=8){
		uint64_t value=r_g(state);
		dst1[0]=value;
		dst1[1]=value>>8;
		dst1[2]=value>>16;
		dst1[3]=value>>24;
		dst1[4]=value>>32;
		dst1[5]=value>>40;
		dst1[6]=value>>48;
		dst1[7]=value>>56;
		dst1+=8;
		len-=8;
	}
	if(len>0){
		uint64_t value=r_g(state);
		while(len>0){
			dst1[0]=value;
			dst1+=1;
			len-=1;
			value>>=8;
		}
	}
}
uint64_t r_skew(r* state){
	uint64_t initial=r_g(state);
	uint64_t mask=(1<<((initial%21)+3))-1;
	return mask&initial;
}
uint64_t r_skew2(r* state,uint64_t longtest){
	uint64_t initial=r_g(state);
	uint64_t mask;
	if(longtest==1){
		mask=(1<<((initial%21)+3))-1;
	}
	else{
		mask=(1<<((initial%19)+3))-1;
	}
	return mask&initial;
}
uint64_t r_lim(r* state,uint64_t min,uint64_t max){
	return r_g(state)%(max-min+1)+min;
}
uint64_t hash(void* src,uint64_t len){
	uint64_t state=len;
	uint8_t* src1=(uint8_t*)src;
	while(len>=8){
		uint64_t in=
			((uint64_t)(src1[0])<<0)
			|((uint64_t)(src1[1])<<8)
			|((uint64_t)(src1[2])<<16)
			|((uint64_t)(src1[3])<<24)
			|((uint64_t)(src1[4])<<32)
			|((uint64_t)(src1[5])<<40)
			|((uint64_t)(src1[6])<<48)
			|((uint64_t)(src1[7])<<56);
		state*=1357913579;
		state=state^(state>>21)^in;
		src1+=8;
		len-=8;
	}
	while(len>0){
		state*=56789;
		state=state^(state>>17)^src1[0];
		src1++;
		len--;
	}
	return state;
}
double time_to_seconds(uint64_t ticks){
	return (double)ticks/(double)TIME_DIVIDER;
}

uint8_t* key;
uint8_t* nonce;
uint8_t* plaintext;
uint8_t* encrypted;
uint8_t* decrypted;
uint8_t* token;
uint8_t* buffer;

int main(){
	uint64_t now=TIME_PLEASE;
	uint64_t seed=125;//now;
	OUTPUT("Seed: %llu\n",seed);
	r gen;
	r_init(&gen,seed,seed);
	key=malloc(20000000);
	nonce=malloc(20000000);
	plaintext=malloc(20000000);
	encrypted=malloc(20000000);
	decrypted=malloc(20000000);
	token=malloc(20000000);
	buffer=malloc(INFINITE_BUFFERSTRUCTURESIZE(24));
	r_fill(&gen,key,20000000);
	r_fill(&gen,nonce,20000000);
	r_fill(&gen,plaintext,20000000);
	r_fill(&gen,encrypted,20000000);
	r_fill(&gen,decrypted,20000000);
	r_fill(&gen,token,20000000);
	uint64_t strength;
	uint64_t a;
	uint64_t hashall=0;
	uint64_t longtest;
	for(longtest=0;longtest<2;longtest++){
		for(strength=16;strength<=24;strength++){
			uint64_t begint=TIME_PLEASE;
			uint64_t count=20;
			if(strength>=18){
				count=5;
			}
			if(strength>=20){
				count=2;
			}
			if(strength>=25){
				count=1;
			}
			if(longtest==0 && strength<=24){
				count=10;
			}
			if(longtest==0 && strength<=22){
				count=50;
			}
			if(longtest==0 && strength<=20){
				count=200;
			}
			if(longtest==0 && strength<=17){
				count=2000;
			}
			count*=TIMEFACTOR;
			for(a=0;a<count;a++){
				uint64_t intendederror=r_lim(&gen,0,5);
				uint64_t keysize=r_skew2(&gen,longtest);
				uint64_t noncesize=r_skew(&gen)%INFINITE_BUFFERSIZE(strength);
				uint64_t plaintextsize=r_skew2(&gen,longtest);
				uint64_t tokenstrength=r_lim(&gen,9,strength-1);
				uint64_t keyoffset=r_skew(&gen);
				uint64_t nonceoffset=r_skew(&gen);
				uint64_t plaintextoffset=r_skew(&gen);
				uint64_t encryptedoffset=r_skew(&gen);
				uint64_t decryptedoffset=r_skew(&gen);
				uint64_t tokenoffset=r_skew(&gen);
				r_fill(&gen,key+keyoffset,keysize);
				r_fill(&gen,nonce+nonceoffset,noncesize);
				r_fill(&gen,plaintext+plaintextoffset,plaintextsize);
				uint8_t* bufferreturned=infinite_init(buffer,INFINITE_BUFFERSTRUCTURESIZE(27),strength,tokenstrength,key+keyoffset,keysize);
				if(bufferreturned!=buffer){
					OUTPUT("Wrong buffer.\n");
					OUTPUT("%llu %llu , %llu %llu\n%llu %llu , %llu %llu\n%llu %llu %llu\n%llu\n"
					,intendederror,keysize , noncesize,plaintextsize
					,tokenstrength,keyoffset , nonceoffset,plaintextoffset
					,encryptedoffset,decryptedoffset,tokenoffset
					,a);
					return 1;
				}
				int64_t encryptresult=infinite_encrypt(buffer,nonce+nonceoffset,noncesize,plaintext+plaintextoffset,plaintextsize,encrypted+encryptedoffset,20000000-encryptedoffset,token+tokenoffset,20000000-tokenoffset);
				if(encryptresult!=0){
					OUTPUT("Failed encrypt.\n");
					OUTPUT("%llu %llu , %llu %llu\n%llu %llu , %llu %llu\n%llu %llu %llu\n%llu\n"
					,intendederror,keysize , noncesize,plaintextsize
					,tokenstrength,keyoffset , nonceoffset,plaintextoffset
					,encryptedoffset,decryptedoffset,tokenoffset
					,a);
					return 1;
				}
				hashall^=hash(encrypted+encryptedoffset,plaintextsize)^hash(token+tokenoffset,INFINITE_TAGSIZE(tokenstrength));
				if(intendederror==0){
					if(plaintextsize==0){
						plaintextsize=1;
					}
					if(plaintextsize%5==4){
						plaintextsize--;
					}
					else if(plaintextsize%5==3){
						plaintextsize++;
					}
					else{
						uint64_t index=r_lim(&gen,0,plaintextsize-1);
						(encrypted+encryptedoffset)[index]^=r_lim(&gen,1,255);
					}
				}
				if(intendederror==1){
					if(noncesize==0){
						noncesize=1;
					}
					if(noncesize%5==4){
						noncesize--;
					}
					else if(noncesize%5==3){
						noncesize++;
					}
					else{
						uint64_t index=r_lim(&gen,0,noncesize-1);
						(nonce+nonceoffset)[index]^=r_lim(&gen,1,255);
					}
				}
				if(intendederror==2){
					uint64_t index=r_lim(&gen,0,(INFINITE_TAGSIZE(tokenstrength))-1);
					(token+tokenoffset)[index]^=r_lim(&gen,1,255);
				}
				int64_t decryptresult=infinite_decrypt(buffer,nonce+nonceoffset,noncesize,encrypted+encryptedoffset,plaintextsize,decrypted+decryptedoffset,20000000-decryptedoffset,token+tokenoffset);
				if(intendederror<=2){
					if(decryptresult!=-1){
						OUTPUT("Failed to fail decrypt.\n");
						OUTPUT("%llu %llu , %llu %llu\n%llu %llu , %llu %llu\n%llu %llu %llu\n%llu\n"
						,intendederror,keysize , noncesize,plaintextsize
						,tokenstrength,keyoffset , nonceoffset,plaintextoffset
						,encryptedoffset,decryptedoffset,tokenoffset
						,a);
						return 1;
					}
				}
				else{
					if(decryptresult!=0){
						OUTPUT("Failed decrypt.\n");
						OUTPUT("%llu %llu , %llu %llu\n%llu %llu , %llu %llu\n%llu %llu %llu\n%llu\n"
						,intendederror,keysize , noncesize,plaintextsize
						,tokenstrength,keyoffset , nonceoffset,plaintextoffset
						,encryptedoffset,decryptedoffset,tokenoffset
						,a);
						return 1;
					}
					if(hash(plaintext+plaintextoffset,plaintextsize)!=hash(decrypted+decryptedoffset,plaintextsize)){
						OUTPUT("Plaintext and decrypted are different.\n");
						OUTPUT("%llu %llu , %llu %llu\n%llu %llu , %llu %llu\n%llu %llu %llu\n%llu\n"
						,intendederror,keysize , noncesize,plaintextsize
						,tokenstrength,keyoffset , nonceoffset,plaintextoffset
						,encryptedoffset,decryptedoffset,tokenoffset
						,a);
						return 1;
					}
				}
			}
			uint64_t endt=TIME_PLEASE;
			OUTPUT("Strength %llu test complete in %.3lf\n",strength,time_to_seconds(endt-begint));
		}
	}

	uint64_t now2=TIME_PLEASE;
	OUTPUT("Elapsed: %.3lf\n",time_to_seconds(now2-now));
	OUTPUT("All hash: %llu\n",hashall);
	
	r_fill(&gen,key,1024*1024);
	r_fill(&gen,plaintext,16*1024*1024);
	uint64_t starthash=hash(plaintext,16*1024*1024);
	infinite_init(buffer,INFINITE_BUFFERSTRUCTURESIZE(24),16,9,key,1024*1024);
	uint64_t benchlength=100*TIMEFACTOR;
	uint64_t now3=TIME_PLEASE;
	for(a=1;a<=benchlength;a++){
		int64_t erro=infinite_encrypt(buffer,&a,8,plaintext,16*1024*1024,plaintext,20000000,token+a*64,64);
		if(erro!=0){
			OUTPUT("Error during benchmark encrypt.\n");
		}
	}
	for(a=benchlength;a>=1;a--){
		int64_t erro=infinite_decrypt(buffer,&a,8,plaintext,16*1024*1024,plaintext,20000000,token+a*64);
		if(erro!=0){
			OUTPUT("Error during benchmark decrypt.\n");
		}
	}
	uint64_t now4=TIME_PLEASE;
	if(starthash!=hash(plaintext,16*1024*1024)){
		OUTPUT("Benchmark did not return original message.\n");
	}
	
	OUTPUT("Benchmark elapsed: %.3lf\n",time_to_seconds(now4-now3));
	OUTPUT("%.3lf GB/s\n",(double)benchlength*(double)(16*1024*1024)*2.0/(time_to_seconds(now4-now3)*(double)1000000000));
	
	return 0;
}