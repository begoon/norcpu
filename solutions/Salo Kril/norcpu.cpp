
#define DEST_COUNT  0xF1FE
extern WORD mem[];

/*
    Secret code: 139471
*/
void reconstructed_fn(void)
{
    int i, j;
    WORD src, dest, key, count, hash, hash_OK, key_const;

    src = mem[0xF1BA];     // input string
    count = mem[0xF1ED];   // input string length
    dest = mem[0xF1BB];    // 0xf1ff
    hash_OK = mem[0xF1BC]; // 0x1c89
    hash = mem[0xF1B9];    // 0x1040


    for(i = 0; i < count; i++)
    {
        hash ^= mem[src + i] & 0xFF;

        for (j = 0; j < 8; j++)
        {
            if ((hash & 1) == 0)
                hash = hash >> 1;
            else
                hash = (hash >> 1) ^ 0x1408;
        }
    }

    if (hash == hash_OK)
    {
        src = mem[0x6EB6];              // "Secret code: 139471"
        count = mem[0xF1C7];            // 19
        key = ((hash >> 8) ^ hash) + 1;
        key_const = mem[0x6EA8];        // 11
    }
    else
    {
        src = mem[0x5EBE];          // "Wrong password!"
        count = mem[0xF1DC];        // 15
        key = mem[0xF1BD];
        key_const = mem[0xF1BE];    // 17
    }

    mem[DEST_COUNT] = count;
    for (i = 0; i < count; i++)
    {
        mem[dest + i] = mem[src + i] ^ key;
        key = key * 3 + key_const;
    }
}


/*
--------------------------------------------------------------------------------------------
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
--------------------------------------------------------------------------------------------
*/
WORD and(WORD w1, WORD w2)
{
    return w1 & w2;
}

WORD or(WORD w1, WORD w2)
{
    return w1 | w2;
}

WORD xor(WORD w1, WORD w2)
{
    return w1 ^ w2;
}

WORD rol(WORD w1, WORD n)
{
    return (w1 << n) | (w1 >> (16 - n));
}

WORD ror(WORD w1, WORD n)
{
    return (w1 >> n) | (w1 << (16 - n));
}
WORD extend_16(WORD k1)
{
    int i, k2;

    for (i = 0, k2 = 0; i < 16; i++)
    {
        k2 = or(k2, k1);
        k1 = rol(k1, 1);
    }

    return k2;
}

WORD add(WORD *kk1, WORD a, WORD b)
{
    WORD mask_bit, aa0, aa1, tmp1, i, k1, k2;
    k1 = 0;
    k2 = 0;
    mask_bit = 1;

    for (i = 0; i < 16; i++)
    {
        k1 = and(k1, mask_bit);
        aa0 = xor(a, b);
        tmp1 = xor(aa0, k1);
        tmp1 = and(tmp1, mask_bit);
        k2 = or(tmp1, k2);
        aa1 = and(a, b);
        aa0 = and(k1, aa0);
        k1 = or(aa1, aa0);
        k1 = rol(k1, 1);
        mask_bit = rol(mask_bit, 1);
    }
    k1 = and(k1, mask_bit);
    *kk1 = extend_16(k1);
    
    return k2;
}

void reconstr(void)
{
    WORD k1, k2, src, dest, tmp1, key, count, tmp2, tmp3, i, ks, ks_OK, key_a;
    WORD mask_bit, aa1, aa0;

    k1 = mem[0xF1AF];    // 0x88
    k2 = mem[0xF1A3];    // 0x47
    src = mem[0xF1BA];   // input string
    count = mem[0xF1ED]; // input string length
    dest = mem[0xF1BB];  // 0xf1ff
    ks_OK = mem[0xF1BC]; // 0x1c89             "w":ks=0x0ACC   "WWW":0x0FCE   "123456789":ks=0x05E3
    ks = mem[0xF1B9];    // 0x1040
    

l_0006:
    ks = xor(ks, and(mem[src], 0xFF));
    i = 8;

l_006D:
    tmp3 = and(ks, 1);
    ks = ror(ks, 1);
    ks = and(ks, 0x7FFF);
    tmp2 = add(&k2, tmp3, -1);
    if(k2 != 0)
    {
        ks = xor(ks, 0x1408);
    }

l_1145:
    i = add(&k1, i, -1);
    tmp2 = add(&k2, i, -1);
    if(k2 != 0) 
        goto l_006D;

l_304B:
    src = add(&k1, src, 1);
    count = add(&k1, count, -1);
    tmp2 = add(&k2, count, -1);
    if(k2 != 0) 
        goto l_0006;


    src = mem[0x5EBE];    // Wrong password!
    count = mem[0xF1DC];  // 15
    key = mem[0xF1BD];
    key_a = mem[0xF1BE];
    ks_OK = xor(ks_OK, ks);
    tmp2 = add(&k2, ks_OK, -1);

    if(k2 != 0) 
        goto l_8552;

l_6E9B:
    src = mem[0x6EB6];     // Secret code: 139471
    count = mem[0xF1C7];   // 19
    key = ks;
    key_a = mem[0x6EA8];

    key = ror(key, 8);
    key = and(key, 0xFF);
    key = xor(ks, key);
    key = and(key, 0x7FFF);
    key = add(&k1, key, 1);


l_8552:
    mem[DEST_COUNT] = count;
l_8558:
    mem[dest] = xor(mem[src], key);
    tmp3 = add(&k1, key, key);
    key = add(&k1, key, tmp3);
    key = add(&k1, key, key_a);
    src = add(&k1, src, 1);
    dest = add(&k1, dest, 1);
    count = add(&k1, count, -1);
    tmp2 = add(&k2, count, -1);
    if(k2 != 0) 
        goto l_8558;

l_F186:
    mem[0xF1B2] = mem[0xF193]; // nc
}
