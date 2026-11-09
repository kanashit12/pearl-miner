// PEARL v2 PoW miner: cari nonce s.t. keccak256(abi.encode(seed, nonce)) <= target
// abi.encode(bytes32, uint256) = seed(32B) || nonce(32B big-endian)
// Pakai: miner --seed <hex> --target <hex> --start N --step N --threads N --max-seconds N [--out FILE]
//        miner --seed <hex> --once <nonce>     -> cetak digest satu nonce
//        miner --bench <detik>                  -> ukur hashrate (target 0, tak pernah cocok)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

static const uint64_t RC[24] = {
 0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
 0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
 0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
 0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
 0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
 0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
static const int RHO[25] = {0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
static const int PI[25] = {0,10,20,5,15,16,1,11,21,6,7,17,2,12,22,23,8,18,3,13,14,24,9,19,4};

static inline uint64_t rol(uint64_t x, int n){ return n ? (x<<n)|(x>>(64-n)) : x; }

static void keccakf(uint64_t a[25]){
  for(int r=0;r<24;r++){
    uint64_t c[5], d[5], b[25];
    for(int x=0;x<5;x++) c[x]=a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20];
    for(int x=0;x<5;x++) d[x]=c[(x+4)%5]^rol(c[(x+1)%5],1);
    for(int i=0;i<25;i++) a[i]^=d[i%5];
    for(int i=0;i<25;i++) b[PI[i]]=rol(a[i], RHO[i]);
    for(int y=0;y<5;y++) for(int x=0;x<5;x++)
      a[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]);
    a[0]^=RC[r];
  }
}

// state dasar: seed di lane 0..3 (LE), nonce BE di byte 32..63 -> hanya lane 7 berubah (nonce<2^64)
static uint64_t BASE[25];
static uint64_t TGT[4]; // target sebagai 4 word big-endian (w0 paling signifikan)
static void build_base(const uint8_t seed[32]){
  memset(BASE,0,sizeof(BASE));
  for(int i=0;i<4;i++){ uint64_t v=0; for(int j=0;j<8;j++) v|=(uint64_t)seed[i*8+j]<<(8*j); BASE[i]=v; }
  BASE[8]=0x0000000000000001ULL;   // padding 0x01 di byte 64
  BASE[16]=0x8000000000000000ULL;  // padding 0x80 di byte 135
}
static inline void digest_for(uint64_t nonce, uint64_t out_be[4]){
  uint64_t a[25]; memcpy(a,BASE,sizeof(a));
  a[7]=__builtin_bswap64(nonce); // byte 56..63 = 8 byte terakhir uint256 BE; lane LE = bswap64(nonce)
  keccakf(a);
  for(int i=0;i<4;i++) out_be[i]=__builtin_bswap64(a[i]);
}
static inline int below_target(const uint64_t w[4]){
  for(int i=0;i<4;i++){ if(w[i]<TGT[i]) return 1; if(w[i]>TGT[i]) return 0; }
  return 1;
}

static atomic_ullong g_hashes; static atomic_int g_stop;
static uint64_t g_start, g_step; static int g_threads; static long g_deadline;
static uint64_t g_found_nonce; static uint64_t g_found_w[4]; static atomic_int g_found;

static void* worker(void* arg){
  long tid=(long)arg;
  uint64_t step_total = g_step * (uint64_t)g_threads;
  uint64_t nonce = g_start + g_step * (uint64_t)tid;
  uint64_t local=0; uint64_t w[4];
  while(!atomic_load(&g_stop) && !atomic_load(&g_found)){
    digest_for(nonce, w);
    if(below_target(w)){
      if(!atomic_exchange(&g_found,1)){
        g_found_nonce=nonce; memcpy(g_found_w,w,sizeof(w));
      }
      break;
    }
    nonce += step_total; local++;
    if((local & 0x3FFF)==0){
      atomic_fetch_add(&g_hashes, 0x4000);
      if(g_deadline && time(NULL)>=g_deadline) break;
    }
  }
  atomic_fetch_add(&g_hashes, local & 0x3FFF);
  return NULL;
}

static int hexval(int c){ if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; }
static void parse_hex32(const char* s, uint8_t out[32]){
  if(s[0]=='0'&&(s[1]=='x'||s[1]=='X')) s+=2;
  for(int i=0;i<32;i++) out[i]=(uint8_t)((hexval(s[2*i])<<4)|hexval(s[2*i+1]));
}
static void print_digest_hex(const uint64_t w[4]){
  // w[i] sudah big-endian word dari digest: cetak apa adanya = urutan byte digest
  for(int i=0;i<4;i++) printf("%016lx",(unsigned long)w[i]);
}

int main(int argc, char** argv){
  uint8_t seed[32]={0}, tgtb[32]={0};
  uint64_t start=0, step=1, once=0; int threads=1, maxsec=0, bench=0, do_once=0;
  const char* outfile=NULL;
  for(int i=1;i<argc;i++){
    if(!strcmp(argv[i],"--seed")) parse_hex32(argv[++i], seed);
    else if(!strcmp(argv[i],"--target")) parse_hex32(argv[++i], tgtb);
    else if(!strcmp(argv[i],"--start")) start=strtoull(argv[++i],NULL,10);
    else if(!strcmp(argv[i],"--step")) step=strtoull(argv[++i],NULL,10);
    else if(!strcmp(argv[i],"--threads")) threads=atoi(argv[++i]);
    else if(!strcmp(argv[i],"--max-seconds")) maxsec=atoi(argv[++i]);
    else if(!strcmp(argv[i],"--once")){ do_once=1; once=strtoull(argv[++i],NULL,10); }
    else if(!strcmp(argv[i],"--bench")){ bench=atoi(argv[++i]); }
    else if(!strcmp(argv[i],"--out")) outfile=argv[++i];
  }
  build_base(seed);
  for(int i=0;i<4;i++){ uint64_t v=0; for(int j=0;j<8;j++) v=(v<<8)|tgtb[i*8+j]; TGT[i]=v; }
  if(do_once){
    uint64_t w[4]; digest_for(once,w);
    printf("digest=0x"); print_digest_hex(w); printf("\n"); return 0;
  }
  if(bench){ maxsec=bench; memset(tgtb,0,sizeof(tgtb)); for(int i=0;i<4;i++) TGT[i]=0; }
  g_start=start; g_step=step?step:1; g_threads=threads>0?threads:1;
  g_deadline = maxsec ? time(NULL)+maxsec : 0;
  pthread_t th[64]; if(g_threads>64) g_threads=64;
  struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
  for(long i=0;i<g_threads;i++) pthread_create(&th[i],NULL,worker,(void*)i);
  for(int i=0;i<g_threads;i++) pthread_join(th[i],NULL);
  clock_gettime(CLOCK_MONOTONIC,&t1);
  double dt=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
  unsigned long long h=atomic_load(&g_hashes);
  if(bench){ printf("BENCH hashes=%llu detik=%.1f hashrate=%.2f MH/s\n", h, dt, h/dt/1e6); return 0; }
  if(atomic_load(&g_found)){
    printf("FOUND nonce=%llu digest=0x",(unsigned long long)g_found_nonce);
    print_digest_hex(g_found_w); printf(" hashes=%llu\n", h);
    if(outfile){ FILE* f=fopen(outfile,"w"); if(f){ fprintf(f,"nonce=%llu\n",(unsigned long long)g_found_nonce); fclose(f);} }
    return 0;
  }
  printf("EXHAUSTED hashes=%llu\n", h);
  return 2;
}
