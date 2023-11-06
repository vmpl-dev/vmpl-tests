#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <zlib.h>

#include "benchmark.h"

int test_zlib(int argc, char *argv[]) {
    char text[] = "zlib test text";
    char buf[1024];

    z_stream defstream;
    defstream.zalloc = Z_NULL;
    defstream.zfree = Z_NULL;
    defstream.opaque = Z_NULL;

    // setup "text" as the input and "buf" as the compressed output
    defstream.avail_in = (uInt)strlen(text) + 1; // size of input, string + terminator
    defstream.next_in = (Bytef *)text; // input char array
    defstream.avail_out = (uInt)sizeof(buf); // size of output
    defstream.next_out = (Bytef *)buf; // output char array

    // the actual compression work.
    deflateInit(&defstream, Z_BEST_COMPRESSION);
    deflate(&defstream, Z_FINISH);
    deflateEnd(&defstream);

    // This is one way of getting the size of the output
    printf("Compressed size is: %lu\n", strlen(buf));
    printf("Compressed string is: %s\n", buf);

    return 0;
}