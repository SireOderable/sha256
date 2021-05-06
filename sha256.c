#include "sha256.h"

uint32_t addmod_32(uint32_t x, uint32_t y){
    return (x + y) & UINT32_MAX;
}

uint32_t *padding(char *m, uint64_t len)
{
    int k;
    k = (512 * (1 + ((len + 1 + 64) / 512))) - (len + 1 + 64);

    int L = (len + 1 + k + 64) / 32;

    uint32_t *msg = (uint32_t *) calloc(L, sizeof(uint32_t));

    if(msg == NULL)
        perror("calloc padding");

    memcpy(msg, m, len/8);

    int i = len / 32;
    int j = len % 32;

    msg[i] |= 1 << j;

    uint32_t temp = (uint32_t)len;
    temp = htonl(temp);
    msg[L-1] = temp;

    temp = (uint32_t) (len >> 32);
    temp = htonl(temp);
    msg[L-2] = temp;    

    return msg;
}

void print_octets(uint32_t * msg, int len){
    for(int i=0; i < len; i++){
        printf(" |%x| ", *((char*) msg+i));
    }
    printf("\n\n");
}

uint32_t *hash(uint32_t *msg, int block)
{

    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    for (int rep = 0; rep < block; rep++)
    {

        uint32_t * w = (uint32_t *)calloc(64, sizeof(uint32_t));

        if(w == NULL)
            perror("calloc hash boucle");

        memcpy(w, msg + (16 * rep), 64);

        uint32_t s0;
        uint32_t s1;

        for (int i = 16; i <= 63; i++)
        {
            s0 = Sig0(w[i - 15]);
            s1 = Sig1(w[i - 2]);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        uint32_t ch;
        uint32_t maj;
        uint32_t temp1;
        uint32_t temp2;

        for (int i = 0; i <= 63; i++)
        {
            s1 = Eps1(e);
            ch = Ch(e, f, g);
            temp1 = addmod_32( addmod_32 (addmod_32 ( addmod_32(h, s1), ch), K[i]), w[i]);
            s0 = Eps0(a);
            maj = Maj(a, b, c);
            temp2 = addmod_32(s0, maj);

            h = g;
            g = f;
            f = e;
            e = addmod_32(d, temp1);
            d = c;
            c = b;
            b = a;
            a = addmod_32(temp1, temp2);
        }

        h0 = addmod_32(h0, a);
        h1 = addmod_32(h1, b);
        h2 = addmod_32(h2, c);
        h3 = addmod_32(h3, d);
        h4 = addmod_32(h4, e);
        h5 = addmod_32(h5, f);
        h6 = addmod_32(h6, g);
        h7 = addmod_32(h7, h);

        free(w);
    }
    uint32_t * hash = (uint32_t *)calloc(4, sizeof(uint32_t)); 

    if(hash == NULL)
        perror("calloc fin hash");

    hash[0] = h0;
    hash[1] = h1;
    hash[2] = h2;
    hash[3] = h3;
    /*hash[4] = h4;
    hash[5] = h5;
    hash[6] = h6;
    hash[7] = h7;*/


    return hash;
}

uint32_t * sha256(char * m, int l){
    uint64_t len = l * 8;
    uint32_t * padded = padding(m, len);


    int block = len / 512;
    if(len % 512 > 0)
        block++;

    print_octets(padded, block * 64);

    uint32_t * msg = hash(padded, block);

    print_octets(msg, block * 32);

    return msg; 
}

uint32_t * networkHash(Data ** data, int len){
    uint32_t * nodes_hash = (uint32_t *)calloc(len * 4, sizeof(uint32_t));
    uint32_t * hash;

    for(int i= 0; i < len; i++){
        char * msg = calloc( 1542, 1);

        memcpy(msg, data[len]->node_id, 4);
        memcpy(msg, data[len]->node_id, 2);
        memcpy(msg, data[len]->node_id, 1536);

        uint32_t * node_hash;

        node_hash = sha256(msg, 1542);

        memcpy(nodes_hash + (4 * i), node_hash, 16);

        free(msg);
    }

    return sha256((char *) nodes_hash, len * 16);
}

int main()
{
    char *test = "szczaw";

    uint32_t *msg = sha256(test, 6);


    free(msg);
    return 0;
}
