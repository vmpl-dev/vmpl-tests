#include <stdio.h>
#include <mxml.h>

#include "benchmark.h"

int test_mxml(int argc, char *argv[]) {
    mxml_node_t *xml;    /* <?xml ... ?> */
    mxml_node_t *data;   /* <data> */
    mxml_node_t *node;   /* <node> */

    /* 创建一个新的 XML 文档 */
    xml = mxmlNewXML("1.0");

    /* 创建一个新的 <data> 节点 */
    data = mxmlNewElement(xml, "data");

    /* 创建一个新的 <node> 节点，并设置其文本内容为 "value" */
    node = mxmlNewElement(data, "node");
    mxmlNewText(node, 0, "value");

    /* 将 XML 文档保存到文件 */
    FILE *fp = fopen("test.xml", "w");
    if (fp) {
        mxmlSaveFile(xml, fp, MXML_NO_CALLBACK);
        fclose(fp);
    }

    /* 释放 XML 文档 */
    mxmlDelete(xml);

    return 0;
}