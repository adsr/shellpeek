#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/uio.h>

#define SHELLPEEK_OK 0
#define SHELLPEEK_ERR -1
#define SHELLPEEK_NOTFOUND -2

#define SHELLPEEK_STR_SIZE 1024

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

static int get_symbol_addr(pid_t pid, const char *symbol, uintptr_t *raddr);
static int get_bash_bin_path(pid_t pid, char *path_root, size_t path_root_size, char *path, size_t path_size);
static int get_bash_base_addr(pid_t pid, char *path, uintptr_t *raddr);
static int get_symbol_offset(char *path_root, const char *symbol, uintptr_t *raddr);
static int popen_read_line(char *buf, size_t buf_size, char *cmd_fmt, ...);
static int shell_escape(const char *arg, char *buf, size_t buf_size, const char *what);
static int copy_proc_mem(pid_t pid, uintptr_t raddri, void *laddr, size_t size, const char *what);
static int var_copy(pid_t pid, uintptr_t shell_variables_ptr_addr, const char *varname, struct bash_variable *var);
static int var_dump(pid_t pid, uintptr_t shell_variables_ptr_addr);
static int var_scan(pid_t pid, uintptr_t shell_variables_ptr_addr, const char *varname, struct bash_variable *var);
static int var_copy_str(pid_t pid, uintptr_t shell_variables_ptr_addr, const char *varname, char *buf, size_t nbuf);
static int var_copy_array(pid_t pid, uintptr_t shell_variables_ptr_addr, const char *varname, struct bash_array *arr);
static int var_copy_array_element(pid_t pid, struct bash_array *arr, int i, char *buf, size_t nbuf);
static int hash_lookup(pid_t pid, struct bash_hash_table *ht, const char *key, struct bash_variable *out_var);
static int hash_dump(pid_t pid, struct bash_hash_table *ht);
static int hash_scan(pid_t pid, struct bash_hash_table *ht, const char *key, struct bash_variable *out_var);
static unsigned int hash_string(const char *s);

static int rv;

// TODO: make hash_scan and var_scan cleaner with callbacks
// TODO: get symbol table for each frame in stacktrace
// TODO: print vars in `typeset -p ...` format
// TODO: detect var type before printing
// TODO: getopt

int main(int argc, char **argv) {
    if (argc < 3) return 1;

    pid_t pid = atoi(argv[1]);
    char *varname = argv[2];

    uintptr_t shell_variables_addr;
    if_err_return(rv, get_symbol_addr(pid, "shell_variables", &shell_variables_addr));

    uintptr_t line_number_addr;
    if_err_return(rv, get_symbol_addr(pid, "line_number", &line_number_addr));

    uintptr_t shell_variables_ptr_addr;
    if_err_return(rv, copy_proc_mem(pid, shell_variables_addr, &shell_variables_ptr_addr, sizeof(shell_variables_ptr_addr), "shell_variables_ptr"));

    //char buf[SHELLPEEK_STR_SIZE];
    //if_err_return(rv, var_copy_str(pid, shell_variables_ptr_addr, varname, buf, sizeof(buf)));
    //printf("%s=%s\n", varname, buf);
    (void)varname;

    var_dump(pid, shell_variables_ptr_addr);

    struct bash_array arr_funcname, arr_source, arr_lineno;
    if_err_return(rv, var_copy_array(pid, shell_variables_ptr_addr, "FUNCNAME", &arr_funcname));
    if_err_return(rv, var_copy_array(pid, shell_variables_ptr_addr, "BASH_SOURCE", &arr_source));
    if_err_return(rv, var_copy_array(pid, shell_variables_ptr_addr, "BASH_LINENO", &arr_lineno));

    char funcname[SHELLPEEK_STR_SIZE], source[SHELLPEEK_STR_SIZE], lineno[SHELLPEEK_STR_SIZE];
    int line_number;
    if_err_return(rv, var_copy_array_element(pid, &arr_funcname, 0, funcname, sizeof(funcname)));
    if_err_return(rv, var_copy_array_element(pid, &arr_source, 0, source, sizeof(source)));
    if_err_return(rv, copy_proc_mem(pid, line_number_addr, &line_number, sizeof(line_number), "line_number"));

    printf("%s:%d %s\n", source, line_number, funcname);

    int i = 0;
    while (1) {
        if_err_break(rv, var_copy_array_element(pid, &arr_funcname, i + 1, funcname, sizeof(funcname)));
        if_err_break(rv, var_copy_array_element(pid, &arr_source, i + 1, source, sizeof(source)));
        if_err_break(rv, var_copy_array_element(pid, &arr_lineno, i, lineno, sizeof(lineno)));
        printf("%s:%s %s\n", source, lineno, funcname);
        ++i;
    }

    return 0;
}

static int get_symbol_addr(pid_t pid, const char *symbol, uintptr_t *raddr) {
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

static int get_symbol_offset(char *path_root, const char *symbol, uintptr_t *raddr) {
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

static int shell_escape(const char *arg, char *buf, size_t buf_size, const char *what) {
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

static int copy_proc_mem(pid_t pid, uintptr_t raddri, void *laddr, size_t size, const char *what) {
    struct iovec local[1];
    struct iovec remote[1];
    void *raddr = (void *)raddri;

    if (raddr == NULL) {
        fprintf(stderr, "copy_proc_mem: Not copying %s; raddr is NULL\n", what);
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

static int var_copy(pid_t pid, uintptr_t shell_variables_ptr_addr, const char *varname, struct bash_variable *var) {
    return var_scan(pid, shell_variables_ptr_addr, varname, var);
}

static int var_dump(pid_t pid, uintptr_t shell_variables_ptr_addr) {
    return var_scan(pid, shell_variables_ptr_addr, NULL, NULL);
}

static int var_scan(pid_t pid, uintptr_t shell_variables_ptr_addr, const char *varname, struct bash_variable *var) {
    // variables.c:var_lookup
    struct bash_var_context vc;

    vc.down = (struct bash_var_context *)shell_variables_ptr_addr;

    while (vc.down) {
        if_err_return(rv, copy_proc_mem(pid, (uintptr_t)vc.down, &vc, sizeof(vc), "vc.down"));
        if (!vc.table) continue;

        struct bash_hash_table ht;
        if_err_return(rv, copy_proc_mem(pid, (uintptr_t)vc.table, &ht, sizeof(ht), "vc.table"));

        if (varname) {
            if ((rv = hash_lookup(pid, &ht, varname, var)) == SHELLPEEK_OK) {
                return SHELLPEEK_OK;
            } else if (rv != SHELLPEEK_NOTFOUND) {
                return rv;
            }
        } else {
            if_err_return(rv, hash_dump(pid, &ht));
        }
    }
    if (varname) return SHELLPEEK_NOTFOUND;
    return SHELLPEEK_OK;
}


static int var_copy_str(pid_t pid, uintptr_t shell_variables_ptr_addr, const char *varname, char *buf, size_t nbuf) {
    int rv;
    struct bash_variable var;
    if_err_return(rv, var_copy(pid, shell_variables_ptr_addr, varname, &var));
    if_err_return(rv, copy_proc_mem(pid, (uintptr_t)var.value, buf, nbuf, "var.value (char *)"));
    return SHELLPEEK_OK;
}

static int var_copy_array(pid_t pid, uintptr_t shell_variables_ptr_addr, const char *varname, struct bash_array *arr) {
    int rv;
    struct bash_variable var;
    if_err_return(rv, var_copy(pid, shell_variables_ptr_addr, varname, &var));
    if (var.attributes && 0x0000004) { // array_att
        if_err_return(rv, copy_proc_mem(pid, (uintptr_t)var.value, arr, sizeof(*arr), "var.value (bash_array *)"));
        return SHELLPEEK_OK;
    }
    return SHELLPEEK_NOTFOUND;
}

static int var_copy_array_element(pid_t pid, struct bash_array *arr, int i, char *buf, size_t nbuf) {
    // array.c:array_reference
    if (!arr || arr->num_elements <= 0) {
        return SHELLPEEK_NOTFOUND;
    }

    struct bash_array_element head, head_next;
    if_err_return(rv, copy_proc_mem(pid, (uintptr_t)arr->head, &head, sizeof(head), "arr->head"));
    if_err_return(rv, copy_proc_mem(pid, (uintptr_t)head.next, &head_next, sizeof(head_next), "head.next"));

    if (i > arr->max_index || i < head_next.ind) {
        return SHELLPEEK_NOTFOUND;
    }

    int direction = i >= head_next.ind ? 1 : -1;
    struct bash_array_element *ae, *el;
    struct bash_array_element tmp;
    for (ae = &head_next, el = &head_next; ae != arr->head; ) {
        if (el->ind == i) {
            if_err_return(rv, copy_proc_mem(pid, (uintptr_t)el->value, buf, nbuf, "el->value (char *)"));
            return SHELLPEEK_OK;
        }

        ae = direction == 1 ? el->next : el->prev;
        if_err_return(rv, copy_proc_mem(pid, (uintptr_t)ae, &tmp, sizeof(tmp), "ae"));
        el = &tmp;
    }

    return SHELLPEEK_NOTFOUND;
}

static int hash_lookup(pid_t pid, struct bash_hash_table *ht, const char *key, struct bash_variable *out_var) {
    return hash_scan(pid, ht, key, out_var);
}

static int hash_dump(pid_t pid, struct bash_hash_table *ht) {
    return hash_scan(pid, ht, NULL, NULL);
}

static int hash_scan(pid_t pid, struct bash_hash_table *ht, const char *key, struct bash_variable *out_var) {
    if (!ht->bucket_array) return SHELLPEEK_NOTFOUND;

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
        if_err_return(rv, copy_proc_mem(pid, (uintptr_t)(ht->bucket_array + hash_bucket), &bucket_addr, sizeof(bucket_addr), "ht->bucket_array[bucket]"));

        struct bash_bucket_contents bucket;
        for (; bucket_addr != 0; bucket_addr = (uintptr_t)bucket.next) {
            if_err_return(rv, copy_proc_mem(pid, bucket_addr, &bucket, sizeof(bucket), "bucket"));

            if (key && hash_val != bucket.khash) continue;

            char bucket_key[SHELLPEEK_STR_SIZE];
            if_err_return(rv, copy_proc_mem(pid, (uintptr_t)bucket.key, bucket_key, sizeof(bucket_key), "bucket.key"));

            if (!key || strcmp(bucket_key, key) == 0) {
                struct bash_variable tmp;
                struct bash_variable *var = key ? out_var : &tmp;
                uintptr_t data_addr = (uintptr_t)bucket.data;
                if_err_return(rv, copy_proc_mem(pid, data_addr, var, sizeof(*var), "var"));
                if (key) {
                    return SHELLPEEK_OK;
                } else if (var->value) {
                    char buf[SHELLPEEK_STR_SIZE];
                    if_err_return(rv, copy_proc_mem(pid, (uintptr_t)var->value, buf, sizeof(buf), "var.value (char *)"));
                    printf("%s=%s\n", bucket_key, buf);
                }
            }
        }
    }

    if (key) return SHELLPEEK_NOTFOUND;
    return SHELLPEEK_OK;
}

static unsigned int hash_string(const char *s) {
    unsigned int i;
    for (i = 2166136261; *s; s++) {
        i += (i<<1) + (i<<4) + (i<<7) + (i<<8) + (i<<24);
        i ^= *s;
    }
    return i;
}
