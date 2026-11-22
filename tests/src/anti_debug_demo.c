/* anti_debug_demo.c — 2026-11-17 加餐期青铜补课 2
 * 五大家族反调试技法的 Linux 侧表达（ground truth 构造样本）：
 *   家族5 反附加：ptrace(PTRACE_TRACEME)
 *   家族2 计时：  rdtsc 成对差值
 *   家族3 断点：  0xCC 陷阱字节自检
 *   家族4 环境：  LD_PRELOAD 检查 + /proc/self/status TracerPid 解析
 *   家族4b 关系： getppid 孤儿化检查
 * 编译：gcc -O0 -o anti_debug_demo anti_debug_demo.c（-O0 防内联吞噬）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>

/* 家族5：反附加——自我附加失败 = 已被调试 */
static int anti_trace(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
        return 1;
    return 0;
}

/* 家族2：rdtsc 成对计时——单步/断点会在两读之间引入巨大周期差 */
static int anti_timing(void) {
    unsigned int lo, hi;
    unsigned long long a, b;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    a = ((unsigned long long)hi << 32) | lo;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    b = ((unsigned long long)hi << 32) | lo;
    return (b - a) > 0x1000000ULL ? 1 : 0;
}

/* 家族3：0xCC 自检——扫描目标函数首 64 字节找 INT3 */
static void anti_bp_target(void);
static int anti_bp(void) {
    unsigned char *fn = (unsigned char *)&anti_bp_target;
    for (int i = 0; i < 64; i++) {
        if (fn[i] == 0xCC)
            return 1;
    }
    return 0;
}
static void anti_bp_target(void) { __asm__ volatile("nop"); }

/* 家族4：环境自检——LD_PRELOAD 劫持检测 */
static int anti_preload(void) {
    return getenv("LD_PRELOAD") != NULL;
}

/* 家族4：环境自检——TracerPid 非零 = 被追踪 */
static int anti_tracerpid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    int traced = 0;
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            traced = (atoi(line + 10) != 0);
            break;
        }
    }
    fclose(f);
    return traced;
}

/* 家族4b：进程关系——父进程为 init(1) 提示被孤儿化（调试器脱离迹象） */
static int anti_parent(void) {
    return getppid() == 1;
}

int main(void) {
    if (anti_trace() || anti_timing() || anti_bp() ||
        anti_preload() || anti_tracerpid() || anti_parent()) {
        puts("protection triggered");
        return 1;
    }
    puts("clean run");
    return 0;
}
