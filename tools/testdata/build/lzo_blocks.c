/* stdin -> stdout as mkifs stores an LZO-compressed image file system:
 * 64 KiB blocks, each a 2-byte big-endian length and its LZO1X-999 bytes,
 * a zero length at the end. Built by make_ifs_images.py (liblzo2). */
#include <stdio.h>
#include <stdlib.h>
#include <lzo/lzo1x.h>

int main(void)
{
    static unsigned char in[0x10000], out[0x10000 + 0x10000 / 16 + 64 + 3];
    static unsigned char work[LZO1X_999_MEM_COMPRESS];
    size_t n;
    if (lzo_init() != LZO_E_OK)
        return 1;
    while ((n = fread(in, 1, sizeof in, stdin)) > 0) {
        lzo_uint length = 0;
        if (lzo1x_999_compress(in, n, out, &length, work) != LZO_E_OK ||
                length > 0xFFFF)
            return 2;
        putchar((int)(length >> 8));
        putchar((int)(length & 0xFF));
        fwrite(out, 1, length, stdout);
    }
    putchar(0);
    putchar(0);
    return 0;
}
