// Генерация паролей

// Brute_force(3);

WORD ks_f(char *buff, int len)
{
   int i, j;
   WORD ks = 0x1040;

   for (i = 0; i < len; i++)
   {
       ks ^= buff[i];
       for (j = 0; j < 8; j++)
       {
           if((ks & 1) == 0)
               ks = ks >> 1;
           else
               ks = (ks >> 1) ^ 0x1408;
       }
   }
   return ks;
}

void Brute_force(int n)
{
   int i;
   static char alphabet[] =
       "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
       "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F"
       "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F"
       "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F"
       "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F"
       "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E";

   if(n == 0)
   {
       if(ks_f(buff_bf, BF_N) == 0x1c89)
           printf("%s\n",buff_bf);
       return;
   }

   n--;
   for (i = 0; alphabet[i]; i++)
   {
       buff_bf[n] = alphabet[i];
       Brute_force(n);
   }
}
