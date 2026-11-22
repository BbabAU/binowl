/* dyn_ls.c — 自构造「发行版风格」动态 PIE ELF（M2.5d：bin_ls.elf 的可分发替代品）
 * 语义对齐 bin_ls（发行版构建特征）：
 *   - 多个符号版本化 GLIBC 导入（qsort/snprintf/puts/strdup/strlen/printf/free）
 *     → PLT + .rela.plt(JMPREL) + .rela.dyn(GLOB_DAT) + .gnu.version_r 全链路
 *   - 自定义全局/静态符号群（g_count/names/cmp/main）
 *   - strip（无 .symtab）+ objcopy -R .comment（无编译器指纹——发行版语义）
 *   - PIE 动态链接
 * 期望值只来自实采 readelf 快照（TASK_m25d A2/A3），本源码注释不作为期望值来源。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

int g_count = 8;
static const char *names[] = {"elf", "pe", "rich", "plt", "got", "rela", "dynsym", "checksec"};

int main(int argc, char **argv) {
    int arr[8];
    for (int i = 0; i < g_count; i++) arr[i] = (int)names[i][0] + i * 7;
    qsort(arr, g_count, sizeof(int), cmp);
    char buf[64];
    for (int i = 0; i < g_count && argc < 64; i++) {
        snprintf(buf, sizeof buf, "%s=%d", names[i], arr[i]);
        puts(buf);
    }
    char *d = strdup("binowl-dyn-ls\017\061anchor");  /* 数据含 0F 31 字节（rdtsc 指令编码）：
        字节级匹配/指令级无 → R43 观察层语义复刻（bin_ls 场景）；等长替换零锚点变动 */
    printf("len=%zu\n", strlen(d));
    free(d);
    return g_count;
}
