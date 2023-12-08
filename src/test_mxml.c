#include <stdio.h>
#include <mxml.h>

#include "benchmark.h"

START_TEST(test_mxml_write)
    int ret;
    mxml_node_t *tree;
    mxml_node_t *node;
    FILE *fp;

    tree = mxmlNewXML("1.0");
    ck_assert_ptr_ne(tree, NULL);

    node = mxmlNewElement(tree, "node");
    ck_assert_ptr_ne(node, NULL);

    mxmlElementSetAttr(node, "name", "test");

    fp = fopen("data.xml", "w");
    ck_assert_ptr_ne(fp, NULL);

    ret = mxmlSaveFile(tree, fp, MXML_TEXT_CALLBACK);
    ck_assert_int_eq(ret, 0);

    mxmlDelete(tree);
END_TEST

START_TEST(test_mxml_read)
    int ret;
    char *str;
    mxml_node_t *tree;
    mxml_node_t *node;
    FILE *fp;

    fp = fopen("data.xml", "r");
    ck_assert_ptr_ne(fp, NULL);

    tree = mxmlLoadFile(NULL, fp, MXML_TEXT_CALLBACK);
    ck_assert_ptr_ne(tree, NULL);

    fclose(fp);

    node = mxmlFindElement(tree, tree, "node", NULL, NULL, MXML_DESCEND);
    ck_assert_ptr_ne(node, NULL);

    str = mxmlElementGetAttr(node, "name");
    ck_assert_ptr_ne(str, NULL);

    printf("node: %s\n", str);

    mxmlDelete(tree);
END_TEST

START_TEST(test_mxml)
    mxml_node_t *xml;    /* <?xml ... ?> */
    mxml_node_t *data;   /* <data> */
    mxml_node_t *node;   /* <node> */

    /* 创建一个新的 XML 文档 */
    xml = mxmlNewXML("1.0");
    ck_assert_ptr_ne(xml, NULL);

    /* 创建一个新的 <data> 节点 */
    data = mxmlNewElement(xml, "data");
    ck_assert_ptr_ne(data, NULL);

    /* 创建一个新的 <node> 节点，并设置其文本内容为 "value" */
    node = mxmlNewElement(data, "node");
    ck_assert_ptr_ne(node, NULL);

    mxmlNewText(node, 0, "value");

    /* 将 XML 文档保存到文件 */
    FILE *fp = fopen("data.xml", "w");
    ck_assert_ptr_ne(fp, NULL);

    mxmlSaveFile(xml, fp, MXML_NO_CALLBACK);
    fclose(fp);

    /* 释放 XML 文档 */
    mxmlDelete(xml);
END_TEST

Suite *xml_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("XML");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_mxml_write);
    tcase_add_test(tc_core, test_mxml_read);
    tcase_add_test(tc_core, test_mxml);
    suite_add_tcase(s, tc_core);

    return s;
}