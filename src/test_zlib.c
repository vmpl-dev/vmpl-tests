#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <check.h>
#include <zlib.h>

#include "benchmark.h"

#ifdef HAVE_ZLIB
START_TEST(test_zlib_compress)
{
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
    ck_assert_int_eq(deflateInit(&defstream, Z_BEST_COMPRESSION), Z_OK);
    ck_assert_int_eq(deflate(&defstream, Z_FINISH), Z_STREAM_END);
    ck_assert_int_eq(deflateEnd(&defstream), Z_OK);

    // verify compression worked
    ck_assert_uint_gt(strlen(text), defstream.total_out);
}
END_TEST

START_TEST(test_zlib_decompress)
{
    char original_text[] = "zlib test text";
    char compressed[1024];
    char decompressed[1024];
    z_stream defstream;
    z_stream infstream;

    // First compress the text
    defstream.zalloc = Z_NULL;
    defstream.zfree = Z_NULL;
    defstream.opaque = Z_NULL;
    defstream.avail_in = (uInt)strlen(original_text) + 1;
    defstream.next_in = (Bytef *)original_text;
    defstream.avail_out = (uInt)sizeof(compressed);
    defstream.next_out = (Bytef *)compressed;

    ck_assert_int_eq(deflateInit(&defstream, Z_BEST_COMPRESSION), Z_OK);
    ck_assert_int_eq(deflate(&defstream, Z_FINISH), Z_STREAM_END);
    ck_assert_int_eq(deflateEnd(&defstream), Z_OK);

    // Now decompress
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;
    infstream.avail_in = defstream.total_out;
    infstream.next_in = (Bytef *)compressed;
    infstream.avail_out = (uInt)sizeof(decompressed);
    infstream.next_out = (Bytef *)decompressed;

    ck_assert_int_eq(inflateInit(&infstream), Z_OK);
    ck_assert_int_eq(inflate(&infstream, Z_NO_FLUSH), Z_STREAM_END);
    ck_assert_int_eq(inflateEnd(&infstream), Z_OK);

    // Verify the decompressed data matches the original
    ck_assert_str_eq(original_text, decompressed);
}
END_TEST

Suite *zlib_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("zlib");

    /* Core test case */
    tc_core = tcase_create("Core");
#ifdef HAVE_ZLIB
    tcase_add_test(tc_core, test_zlib_compress);
    tcase_add_test(tc_core, test_zlib_decompress);
#endif
    suite_add_tcase(s, tc_core);

    return s;
}
#endif