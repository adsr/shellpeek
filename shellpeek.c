#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <regex.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHELLPEEK_VERSION "0.1.0"

#ifndef SHELLPEEK_STR_SIZE
#define SHELLPEEK_STR_SIZE 1024
#endif

enum {
    SHELLPEEK_OK = 0,
    SHELLPEEK_ERR,
    SHELLPEEK_NOTFOUND,
};

#define if_err_return(rv, expr) if (((rv) = (expr)) != SHELLPEEK_OK) return (rv)
#define if_err_break(rv, expr)  if (((rv) = (expr)) != SHELLPEEK_OK) break

struct bash_bucket_contents;
struct bash_hash_table;
struct bash_var_context;
struct bash_variable;
struct bash_array_element;
struct bash_array;

struct bash_bucket_contents {
    struct bash_bucket_contents *next;
    char *key;
    void *data;
    unsigned int khash;
    int times_found;
};

struct bash_hash_table {
    struct bash_bucket_contents **bucket_array;
    int nbuckets;
    int nentries;
};

struct bash_var_context {
    char *name;
    int scope;
    int flags;
    struct bash_var_context *up;
    struct bash_var_context *down;
    struct bash_hash_table *table;
};

struct bash_variable {
    char *name;
    char *value;
    char *exportstr;
    void *dynamic_value;
    void *assign_func;
    int attributes;
    int context;
};

struct bash_array_element {
    long ind;
    char *value;
    struct bash_array_element *next;
    struct bash_array_element *prev;
};

struct bash_array {
    long max_index;
    long num_elements;
    struct bash_array_element *head;
    struct bash_array_element *lastref;
};

struct shellpeek_context {
    pid_t pid;
    uintptr_t shell_variables_addr;
    uintptr_t root_shell_variables_addr;
    uintptr_t line_number_addr;
    char *var_name;
    regex_t var_regex;
    int var_regex_set;
    int var_all;
    int max_depth;
    long num_stack_frames;
    char tmp[SHELLPEEK_STR_SIZE];
    useconds_t sleep_usec;
    int repeat;
    int pause_process;
    int exit_code;
    int peek_var_frame;
    struct bash_array array_func;
    struct bash_array array_source;
    struct bash_array array_lineno;
    struct bash_var_context var_context;
};

static void run(struct shellpeek_context *ctx);
static int peek(struct shellpeek_context *ctx);
static int peek_stack(struct shellpeek_context *ctx, int frame);
static int peek_var(struct shellpeek_context *ctx, int frame, char *var_name, struct bash_variable *out_var);
static int peek_array(struct shellpeek_context *ctx, char *var_name, struct bash_array *out_arr);
static int peek_array_element(struct shellpeek_context *ctx, struct bash_array *arr, int i, char *buf, size_t nbuf);
static int peek_hash(struct shellpeek_context *ctx, struct bash_hash_table *ht, int frame, char *var_name, struct bash_variable *out_var);
static int print_var(struct shellpeek_context *ctx, char *name, struct bash_variable *var, int frame);
static void print_ansic_quoted(unsigned char *value);
static unsigned int hash_string(char *s);
static void set_var_regex(struct shellpeek_context *ctx, char *regex);
static void usage(struct shellpeek_context *ctx, FILE *fp, int exit_code);
static void parse_args(int argc, char **argv, struct shellpeek_context *ctx);
static void cleanup(struct shellpeek_context *ctx);
static void print_version(struct shellpeek_context *ctx);
static int copy_proc_mem(pid_t pid, uintptr_t raddri, void *laddr, size_t size, char *what_fmt, ...);
static int get_symbol_addr(pid_t pid, char *symbol, uintptr_t *raddr);
static int get_bash_bin_path(pid_t pid, char *path_root, size_t path_root_size, char *path, size_t path_size);
static int get_bash_base_addr(pid_t pid, char *path, uintptr_t *raddr);
static int get_symbol_offset(char *path_root, char *symbol, uintptr_t *raddr);
static int popen_read_line(char *buf, size_t buf_size, char *cmd_fmt, ...);
static int shell_escape(char *arg, char *buf, size_t buf_size, char *what);
static int pause_pid(pid_t pid);
static int unpause_pid(pid_t pid);

static int rv;

int main(int argc, char **argv) {
    struct shellpeek_context ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.repeat = 1;
    ctx.max_depth = 0;
    ctx.sleep_usec = 49999; // ~50ms

    parse_args(argc, argv, &ctx);
    run(&ctx);
    cleanup(&ctx);

    return ctx.exit_code;
}

static void run(struct shellpeek_context *ctx) {
    int iter = 0;
    while (1) {
        if (ctx->pause_process) if_err_break(rv, pause_pid(ctx->pid));
        if_err_break(rv, peek(ctx));
        if (ctx->pause_process) if_err_break(rv, unpause_pid(ctx->pid));

        ++iter;
        if (ctx->repeat != 0 && iter >= ctx->repeat) break;

        usleep(ctx->sleep_usec);
    }

    ctx->exit_code = rv;
}

static int peek(struct shellpeek_context *ctx) {
    if (!ctx->shell_variables_addr) {
        uintptr_t shell_variables_ptr_addr;
        if_err_return(rv, get_symbol_addr(ctx->pid, "shell_variables", &shell_variables_ptr_addr));
        if_err_return(rv, copy_proc_mem(ctx->pid, shell_variables_ptr_addr, &ctx->shell_variables_addr, sizeof(ctx->shell_variables_addr), "%s:shell_variables_ptr_addr", __func__));
        if_err_return(rv, get_symbol_addr(ctx->pid, "line_number", &ctx->line_number_addr));
    }

    ctx->peek_var_frame = 0;

    int frame = 0;
    while (1) {
        if_err_return(rv, peek_stack(ctx, frame));
        rv = peek_var(ctx, frame, NULL, NULL);
        if (rv != SHELLPEEK_OK && rv != SHELLPEEK_NOTFOUND) return rv;
        ++frame;
        if (frame >= ctx->num_stack_frames) break;
        if (ctx->max_depth > 0 && frame >= ctx->max_depth) break;
    }
    printf("\n");

    return SHELLPEEK_OK;
}

static int peek_stack(struct shellpeek_context *ctx, int frame) {
    char func[SHELLPEEK_STR_SIZE];
    char source[SHELLPEEK_STR_SIZE];
    char lineno[32];

    if (frame == 0) {
        if_err_return(rv, peek_array(ctx, "FUNCNAME", &ctx->array_func));
        if_err_return(rv, peek_array(ctx, "BASH_SOURCE", &ctx->array_source));
        if_err_return(rv, peek_array(ctx, "BASH_LINENO", &ctx->array_lineno));

        ctx->num_stack_frames = ctx->array_func.num_elements;
    }

    int rframe = ctx->num_stack_frames - 1 - frame;

    if (rframe <= 0) {
        if (ctx->array_func.num_elements > 0) {
            if_err_return(rv, peek_array_element(ctx, &ctx->array_func, 0, func, sizeof(func)));
            if_err_return(rv, peek_array_element(ctx, &ctx->array_source, 0, source, sizeof(source)));
        } else {
            sprintf(func, "<main>");
            sprintf(source, "<main>");
        }
        int lineno_int;
        if_err_return(rv, copy_proc_mem(ctx->pid, ctx->line_number_addr, &lineno_int, sizeof(lineno_int), "%s:line_number", __func__));
        printf("%5s %3d %s:%d %s\n", "frame", frame, source, lineno_int, func);
    } else {
        if_err_return(rv, peek_array_element(ctx, &ctx->array_func, rframe, func, sizeof(func)));
        if_err_return(rv, peek_array_element(ctx, &ctx->array_source, rframe, source, sizeof(source)));
        if_err_return(rv, peek_array_element(ctx, &ctx->array_lineno, rframe - 1, lineno, sizeof(lineno)));
        printf("%5s %3d %s:%s %s\n", "frame", frame, source, lineno, func);
    }

    return SHELLPEEK_OK;
}

static int peek_var(struct shellpeek_context *ctx, int frame, char *var_name, struct bash_variable *out_var) {
    // variables.c:var_lookup
    struct bash_var_context tmp = {0};
    struct bash_var_context *vc;

    if (var_name) {
        vc = &tmp;
    } else {
        vc = &ctx->var_context;
        assert(frame == ctx->peek_var_frame);
        ++ctx->peek_var_frame;
    }

    if (frame == 0) {
        if (!ctx->root_shell_variables_addr) {
            vc->down = (struct bash_var_context *)ctx->shell_variables_addr;
            while (vc->down) {
                ctx->root_shell_variables_addr = (uintptr_t)vc->down;
                if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)vc->down, vc, sizeof(*vc), "%s:vc->down", __func__));
            }
        }
        vc->up = (struct bash_var_context *)ctx->root_shell_variables_addr;
    }

    if (vc->up) {
        if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)vc->up, vc, sizeof(*vc), "%s:vc->up", __func__));
        if (!vc->table) return SHELLPEEK_NOTFOUND;

        struct bash_hash_table ht;
        if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)vc->table, &ht, sizeof(ht), "%s:vc->table", __func__));

        return peek_hash(ctx, &ht, frame, var_name, out_var);
    }

    return SHELLPEEK_NOTFOUND;
}

static int peek_array(struct shellpeek_context *ctx, char *var_name, struct bash_array *out_arr) {
    int rv;
    struct bash_variable var;
    if_err_return(rv, peek_var(ctx, 0, var_name, &var));
    if (var.attributes && 0x04) { // array
        if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)var.value, out_arr, sizeof(*out_arr), "%s:var.value", __func__));
        return SHELLPEEK_OK;
    }
    return SHELLPEEK_NOTFOUND;
}

static int peek_array_element(struct shellpeek_context *ctx, struct bash_array *arr, int i, char *buf, size_t nbuf) {
    // array.c:array_reference
    if (!arr || arr->num_elements <= 0) {
        return SHELLPEEK_NOTFOUND;
    }

    struct bash_array_element head, head_next;
    if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)arr->head, &head, sizeof(head), "%s:arr->head", __func__));
    if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)head.next, &head_next, sizeof(head_next), "%s:head.next", __func__));

    if (i > arr->max_index || i < head_next.ind) {
        return SHELLPEEK_NOTFOUND;
    }

    int direction = i >= head_next.ind ? 1 : -1;
    struct bash_array_element *ae, *el;
    struct bash_array_element tmp;
    for (ae = &head_next, el = &head_next; ae != arr->head; ) {
        if (el->ind == i) {
            if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)el->value, buf, nbuf, "%s:el->value", __func__));
            return SHELLPEEK_OK;
        }

        ae = direction == 1 ? el->next : el->prev;
        if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)ae, &tmp, sizeof(tmp), "%s:ae", __func__));
        el = &tmp;
    }

    return SHELLPEEK_NOTFOUND;
}

static int peek_hash(struct shellpeek_context *ctx, struct bash_hash_table *ht, int frame, char *var_name, struct bash_variable *out_var) {
    if (!ht->bucket_array) return SHELLPEEK_NOTFOUND;

    char *key = var_name ? var_name : ctx->var_name;

    int hash_bucket_start, hash_bucket_end;
    unsigned int hash_val;
    if (key) {
        hash_val = hash_string(key);
        hash_bucket_start = hash_val & (ht->nbuckets - 1);
        hash_bucket_end = hash_bucket_start;
    } else {
        hash_bucket_start = 0;
        hash_bucket_end = ht->nbuckets - 1;
    }

    int hash_bucket;
    for (hash_bucket = hash_bucket_start; hash_bucket <= hash_bucket_end; hash_bucket++) {
        uintptr_t bucket_addr;
        if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)(ht->bucket_array + hash_bucket), &bucket_addr, sizeof(bucket_addr), "%s:ht->bucket_array[bucket]", __func__));

        struct bash_bucket_contents bucket;
        for (; bucket_addr != 0; bucket_addr = (uintptr_t)bucket.next) {
            if_err_return(rv, copy_proc_mem(ctx->pid, bucket_addr, &bucket, sizeof(bucket), "%s:bucket", __func__));

            if (key && hash_val != bucket.khash) continue;

            char bucket_key[SHELLPEEK_STR_SIZE];
            if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)bucket.key, bucket_key, sizeof(bucket_key), "%s:bucket.key", __func__));

            if (0
                || (key && strcmp(key, bucket_key) == 0)
                || (ctx->var_regex_set && regexec(&ctx->var_regex, bucket_key, 0, NULL, 0) == 0)
                || ctx->var_all
            ) {
                struct bash_variable tmp;
                struct bash_variable *var = var_name ? out_var : &tmp;

                if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)bucket.data, var, sizeof(*var), "%s:var", __func__));

                if (var_name) {
                    return SHELLPEEK_OK;
                } else if (var->value) {
                    if_err_return(rv, print_var(ctx, bucket_key, var, frame));
                }
            }
        }
    }

    if (var_name) return SHELLPEEK_NOTFOUND;
    return SHELLPEEK_OK;
}

static int print_var(struct shellpeek_context *ctx, char *name, struct bash_variable *var, int frame) {
    unsigned char buf[SHELLPEEK_STR_SIZE];

    printf("%5s %3d %s=", "var", frame, name);

    if (var->attributes & 0x04) { // array
        struct bash_array arr;
        if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)var->value, &arr, sizeof(arr), "%s:var->value:array", __func__));
        putchar('(');
        long i;
        for (i = 0; i < arr.num_elements; i++) {
            peek_array_element(ctx, &arr, i, (char *)buf, sizeof(buf));
            print_ansic_quoted((unsigned char *)buf);
            if (i < arr.num_elements - 1) putchar(' ');
        }
        putchar(')');
    } else if (var->attributes & 0x40) { // assoc
        struct bash_hash_table ht;
        if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)var->value, &ht, sizeof(ht), "%s:var->value:assoc", __func__));
        putchar('(');
        int hash_bucket;
        uintptr_t bucket_addr;
        struct bash_bucket_contents bucket;
        int remaining = ht.nentries;
        for (hash_bucket = 0; hash_bucket < ht.nbuckets; hash_bucket++) {
            if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)(ht.bucket_array + hash_bucket), &bucket_addr, sizeof(bucket_addr), "%s:ht->bucket_array[bucket]", __func__));
            for (; bucket_addr != 0; bucket_addr = (uintptr_t)bucket.next) {
                putchar('[');
                if_err_return(rv, copy_proc_mem(ctx->pid, bucket_addr, &bucket, sizeof(bucket), "%s:bucket", __func__));
                if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)bucket.key, buf, sizeof(buf), "%s:bucket.key", __func__));
                buf[SHELLPEEK_STR_SIZE - 1] = '\0';
                print_ansic_quoted(buf);
                printf("]=");
                if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)bucket.data, buf, sizeof(buf), "%s:bucket.data", __func__));
                buf[SHELLPEEK_STR_SIZE - 1] = '\0';
                print_ansic_quoted(buf);
                --remaining;
                if (remaining > 0) putchar(' ');
            }
        }
        putchar(')');
    } else {
        if_err_return(rv, copy_proc_mem(ctx->pid, (uintptr_t)var->value, buf, sizeof(buf), "%s:var->value:string", __func__));
        buf[SHELLPEEK_STR_SIZE - 1] = '\0';
        print_ansic_quoted(buf);
    }
    putchar('\n');
    return SHELLPEEK_OK;
}

static void print_ansic_quoted(unsigned char *value) {
    printf("$'");
    for (; *value != 0; value++) {
        if (*value >= 0x20 && *value <= 0x7e) {
            putchar(*value);
        } else {
            printf("\\x%02x", *value);
        }
    }
    putchar('\'');
}

static unsigned int hash_string(char *s) {
    unsigned int i;
    for (i = 2166136261; *s; s++) {
        i += (i<<1) + (i<<4) + (i<<7) + (i<<8) + (i<<24);
        i ^= *s;
    }
    return i;
}

static void set_var_regex(struct shellpeek_context *ctx, char *regex) {
    if (ctx->var_regex_set) {
        regfree(&ctx->var_regex);
        ctx->var_regex_set = 0;
    }
    if ((rv = regcomp(&ctx->var_regex, regex, REG_EXTENDED | REG_NOSUB)) != 0) {
        char errbuf[256];
        regerror(rv, &ctx->var_regex, errbuf, sizeof(errbuf));
        fprintf(stderr, "regcomp: %s\n", errbuf);
        exit(1);
    }
    ctx->var_regex_set = 1;
}

static void usage(struct shellpeek_context *ctx, FILE *fp, int exit_code) {
    fprintf(fp, "Usage:\n");
    fprintf(fp, "  shellpeek [options] -p <pid>\n");
    fprintf(fp, "\n");
    fprintf(fp, "Options:\n");
    fprintf(fp, "  -h, --help              Show this help.\n");
    fprintf(fp, "  -v, --version           Show program version.\n");
    fprintf(fp, "  -p, --pid=<pid>         Trace Bash process at `pid`.\n");
    fprintf(fp, "  -n, --repeat=<num>      Repeat trace `num` times. (0=forever, default=%d)\n", ctx->repeat);
    fprintf(fp, "  -i, --interval=<usec>   Sleep `usec` microseconds between each trace (default=%d).\n", ctx->sleep_usec);
    fprintf(fp, "  -a, --var-name=<name>   Dump variable with `name`.\n");
    fprintf(fp, "  -r, --var-regex=<regex> Dump variables matching `regex`.\n");
    fprintf(fp, "  -x, --var-all           Dump all variables.\n");
    fprintf(fp, "  -d, --max-depth=<num>   Descend a maximum of `num` stack frames. (0=unlimited, default=%d)\n", ctx->max_depth);
    fprintf(fp, "  -S, --pause-process     Pause process while tracing.\n");
    cleanup(ctx);
    exit(exit_code);
}

static void parse_args(int argc, char **argv, struct shellpeek_context *ctx) {
    struct option long_opts[] = {
        { "help",                  no_argument,       NULL, 'h' },
        { "version",               no_argument,       NULL, 'v' },
        { "pid",                   required_argument, NULL, 'p' },
        { "repeat",                required_argument, NULL, 'n' },
        { "interval",              required_argument, NULL, 'i' },
        { "var-name",              required_argument, NULL, 'a' },
        { "var-regex",             required_argument, NULL, 'r' },
        { "var-all",               no_argument,       NULL, 'x' },
        { "max-depth",             required_argument, NULL, 'd' },
        { "pause-process",         no_argument,       NULL, 'S' },
        { 0 }
    };

    while (1) {
        int c = getopt_long(argc, argv, "hvp:n:i:a:r:xd:S", long_opts, NULL);
        if (c == -1) break;

        switch (c) {
            case 'h': usage(ctx, stdout, 0);                      break;
            case 'v': print_version(ctx);                         break;
            case 'p': ctx->pid = (pid_t)atoi(optarg);             break;
            case 'n': ctx->repeat = atoi(optarg);                 break;
            case 'i': ctx->sleep_usec = (useconds_t)atoi(optarg); break;
            case 'a': ctx->var_name = optarg;                     break;
            case 'r': set_var_regex(ctx, optarg);                 break;
            case 'x': ctx->var_all = 1;                           break;
            case 'd': ctx->max_depth = atoi(optarg);              break;
            case 'S': ctx->pause_process = 1;                     break;
            default:  usage(ctx, stderr, 1);                      break;
        }
    }
}

static void cleanup(struct shellpeek_context *ctx) {
    if (ctx->var_regex_set) {
        regfree(&ctx->var_regex);
        ctx->var_regex_set = 0;
    }
}

static void print_version(struct shellpeek_context *ctx) {
    printf("shellpeek v%s\n", SHELLPEEK_VERSION);
    cleanup(ctx);
    exit(0);
}

static int copy_proc_mem(pid_t pid, uintptr_t raddri, void *laddr, size_t size, char *what_fmt, ...) {
    struct iovec local[1];
    struct iovec remote[1];
    void *raddr = (void *)raddri;

    char what[4096];
    va_list vl;
    va_start(vl, what_fmt);
    vsnprintf(what, sizeof(what), what_fmt, vl);
    va_end(vl);

    if (raddr == NULL) {
        fprintf(stderr, "copy_proc_mem: Not copying %s; raddr is NULL\n", what_fmt);
        return SHELLPEEK_ERR;
    }

    local[0].iov_base = laddr;
    local[0].iov_len = size;
    remote[0].iov_base = raddr;
    remote[0].iov_len = size;

    if (process_vm_readv(pid, local, 1, remote, 1, 0) == -1) {
        if (errno == ESRCH) { // No such process
            perror("process_vm_readv");
            return SHELLPEEK_ERR;
        }
        fprintf(stderr, "copy_proc_mem: Failed to copy %s; err=%s raddr=%p size=%lu\n", what, strerror(errno), raddr, size);
        return SHELLPEEK_ERR;
    }

    return SHELLPEEK_OK;
}

static int get_symbol_addr(pid_t pid, char *symbol, uintptr_t *raddr) {
    char path[SHELLPEEK_STR_SIZE];
    char path_root[SHELLPEEK_STR_SIZE];
    uintptr_t base_addr;
    uintptr_t addr_offset;
    if_err_return(rv, get_bash_bin_path(pid, path_root, sizeof(path_root), path, sizeof(path)));
    if_err_return(rv, get_bash_base_addr(pid, path, &base_addr));
    if_err_return(rv, get_symbol_offset(path_root, symbol, &addr_offset));
    *raddr = base_addr + addr_offset;
    return SHELLPEEK_OK;
}

static int get_bash_bin_path(pid_t pid, char *path_root, size_t path_root_size, char *path, size_t path_size) {
    char *cmd_fmt = "readlink /proc/%d/exe";
    if (popen_read_line(path, path_size, cmd_fmt, (int)pid) != SHELLPEEK_OK) {
        fprintf(stderr, "get_bash_bin_path: Failed to readlink /proc/%d/exe\n", (int)pid);
        return SHELLPEEK_ERR;
    }
    if (snprintf(path_root, path_root_size, "/proc/%d/root/%s", (int)pid, path) > (int)(path_root_size - 1)) {
        fprintf(stderr, "get_bash_bin_path: snprintf overflow\n");
        return SHELLPEEK_ERR;
    }
    if (access(path_root, F_OK) != 0) {
        snprintf(path_root, path_root_size, "/proc/%d/exe", (int)pid);
    }
    return SHELLPEEK_OK;
}

static int get_bash_base_addr(pid_t pid, char *path, uintptr_t *raddr) {
    char path_esc[SHELLPEEK_STR_SIZE];
    if_err_return(rv, shell_escape(path, path_esc, sizeof(path_esc), "path"));

    char *awk_fmt = "awk -vp=%s '$2 ~ /x/ && $NF == p {print $1 \",\" $3; exit}' /proc/%d/maps";
    char addr_line[SHELLPEEK_STR_SIZE];
    if (popen_read_line(addr_line, sizeof(addr_line), awk_fmt, path_esc, (int)pid) != SHELLPEEK_OK) {
        fprintf(stderr, "get_bash_base_addr: Failed to awk /proc/%d/maps\n", (int)pid);
        return SHELLPEEK_ERR;
    }

    uintptr_t start_addr = strtoull(addr_line, NULL, 16);

    char *offset_line = strchr(addr_line, ',');
    if (!offset_line) {
        fprintf(stderr, "get_bash_base_addr: Failed to parse awk output\n");
        return SHELLPEEK_ERR;
    }
    ++offset_line;

    uintptr_t offset_addr = strtoull(offset_line, NULL, 16);

    *raddr = start_addr - offset_addr;
    return SHELLPEEK_OK;
}

static int get_symbol_offset(char *path_root, char *symbol, uintptr_t *raddr) {
    char path_root_esc[SHELLPEEK_STR_SIZE];
    if_err_return(rv, shell_escape(path_root, path_root_esc, sizeof(path_root_esc), "path_root"));

    char *cmd_fmt = "objdump -Tt %s | awk '/ %s$/{print $1; exit}'";
    char symbol_line[SHELLPEEK_STR_SIZE];
    if (popen_read_line(symbol_line, sizeof(symbol_line), cmd_fmt, path_root_esc, symbol) != SHELLPEEK_OK) {
        fprintf(stderr, "get_symbol_offset: Failed to get symbol offset\n");
        return SHELLPEEK_ERR;
    }
    *raddr = strtoull(symbol_line, NULL, 16);
    return SHELLPEEK_OK;
}

static int popen_read_line(char *buf, size_t buf_size, char *cmd_fmt, ...) {
    FILE *fp;
    int buf_len;
    va_list cmd_args;
    va_start(cmd_args, cmd_fmt);
    char cmd[SHELLPEEK_STR_SIZE];
    if (vsnprintf(cmd, sizeof(cmd), cmd_fmt, cmd_args) >= (int)(sizeof(cmd) - 1)) {
        fprintf(stderr, "popen_read_line: vsnprintf overflow\n");
        return SHELLPEEK_ERR;
    }
    va_end(cmd_args);
    if (!(fp = popen(cmd, "r"))) {
        perror("popen");
        return SHELLPEEK_ERR;
    }
    if (fgets(buf, buf_size-1, fp) == NULL) {
        fprintf(stderr, "popen_read_line: No stdout; cmd=%s\n", cmd);
        pclose(fp);
        return SHELLPEEK_ERR;
    }
    pclose(fp);
    buf_len = strlen(buf);
    while (buf_len > 0 && buf[buf_len-1] == '\n') {
        --buf_len;
    }
    if (buf_len < 1) {
        fprintf(stderr, "popen_read_line: Expected strlen(buf)>0; cmd=%s\n", cmd);
        return SHELLPEEK_ERR;
    }
    buf[buf_len] = '\0';
    return SHELLPEEK_OK;
}

static int shell_escape(char *arg, char *buf, size_t buf_size, char *what) {
    rv = SHELLPEEK_OK;
    char *const buf_end = buf + buf_size;
    *buf++ = '\'';

    while (*arg) {
        // Based on https://stackoverflow.com/a/3669819
        if (*arg == '\'') {
            if (buf_end - buf < 4) {
                rv = SHELLPEEK_ERR;
                goto shell_escape_end;
            }

            *buf++ = '\''; // close quoting
            *buf++ = '\\'; // escape ...
            *buf++ = '\''; // ... a single quote
            *buf++ = '\''; // reopen quoting
            arg++;
        } else {
            if (buf_end - buf < 1) {
                rv = SHELLPEEK_ERR;
                goto shell_escape_end;
            }

            *buf++ = *arg++;
        }
    }

    if (buf_end - buf < 2) {
        rv = SHELLPEEK_ERR;
        goto shell_escape_end;
    }

    *buf++ = '\'';
    *buf = '\0';

shell_escape_end:
    if (rv != SHELLPEEK_OK) {
        fprintf(stderr, "shell_escape: Buffer too small to escape %s: %s\n", what, arg);
    }

    return rv;
}

static int pause_pid(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        perror("ptrace");
        return SHELLPEEK_ERR;
    }
    if (waitpid(pid, NULL, 0) < 0) {
        perror("waitpid");
        return SHELLPEEK_ERR;
    }
    return SHELLPEEK_OK;
}

static int unpause_pid(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
        perror("ptrace");
        return SHELLPEEK_ERR;
    }
    return SHELLPEEK_OK;
}
