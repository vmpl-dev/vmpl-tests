#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <zlib.h>

#include "benchmark.h"

#ifdef HAVE_ZLIB
#include <zlib.h>

START_TEST(test_zlib_inflate)
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

    // This is another way of getting the size of the output
    printf("Compressed size is: %lu\n", defstream.total_out);
    printf("Compressed string is: %s\n", buf);

    // Now the inflate part
    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;

    // setup "buf" as the input and "text" as the compressed output
    infstream.avail_in = (uInt)((char *)defstream.next_out - buf); // size of input
    infstream.next_in = (Bytef *)buf; // input char array
    infstream.avail_out = (uInt)sizeof(text); // size of output
    infstream.next_out = (Bytef *)text; // output char array

    // the actual DE-compression work.
    inflateInit(&infstream);
    inflate(&infstream, Z_NO_FLUSH);
    inflateEnd(&infstream);

    printf("Uncompressed size is: %lu\n", strlen(text));
    printf("Uncompressed string is: %s\n", text);

    ck_assert_str_eq(text, "zlib test text");
END_TEST
#endif

START_TEST(test_zlib)
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
END_TEST

Suite *zlib_suite(void)
{
    
}