#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

typedef enum {
    ASPM_DISABLED = 0x0,
    ASPM_L0S      = 0x1,
    ASPM_L1       = 0x2,
    ASPM_L0SL1    = 0x3
} ASPM;

typedef struct {
    char addr[16];
    ASPM mode;
} Device;

typedef struct {
    Device *items;
    size_t len;
    size_t cap;
} DeviceList;

static int silent = 0;
static char device_filter[16] = {0};

static const char *aspm_name(ASPM mode) {
    switch (mode) {
        case ASPM_DISABLED: return "DISABLED";
        case ASPM_L0S:      return "L0s";
        case ASPM_L1:       return "L1";
        case ASPM_L0SL1:    return "L0sL1";
        default:            return "UNKNOWN";
    }
}

static int command_ok(const char *cmd) {
    char buf[256];
    snprintf(buf, sizeof(buf), "command -v %s >/dev/null 2>&1", cmd);
    return system(buf) == 0;
}

static void run_prerequisites(void) {
    struct utsname u;

    if (uname(&u) != 0 || strcmp(u.sysname, "Linux") != 0) {
        fprintf(stderr, "This program only runs on Linux-based systems\n");
        exit(1);
    }

    if (getenv("SUDO_UID") == NULL && geteuid() != 0) {
        fprintf(stderr, "This program needs root privileges to run\n");
        exit(1);
    }

    if (!command_ok("lspci")) {
        fprintf(stderr, "lspci not detected. Please install pciutils\n");
        exit(1);
    }

    if (!command_ok("setpci")) {
        fprintf(stderr, "setpci not detected. Please install pciutils\n");
        exit(1);
    }
}

static char *run_command_capture(const char *cmd, int *exit_status) {
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return NULL;
    }

    size_t cap = 4096;
    size_t len = 0;
    char *out = malloc(cap);
    if (!out) {
        pclose(fp);
        return NULL;
    }

    out[0] = '\0';

    char tmp[1024];
    while (fgets(tmp, sizeof(tmp), fp)) {
        size_t n = strlen(tmp);

        if (len + n + 1 > cap) {
            while (len + n + 1 > cap) {
                cap *= 2;
            }

            char *new_out = realloc(out, cap);
            if (!new_out) {
                free(out);
                pclose(fp);
                return NULL;
            }

            out = new_out;
        }

        memcpy(out + len, tmp, n);
        len += n;
        out[len] = '\0';
    }

    int rc = pclose(fp);

    if (exit_status) {
        if (WIFEXITED(rc)) {
            *exit_status = WEXITSTATUS(rc);
        } else {
            *exit_status = rc;
        }
    }

    return out;
}

static int valid_pci_addr(const char *s) {
    const char *p = s;

    if (isxdigit((unsigned char)p[0]) &&
        isxdigit((unsigned char)p[1]) &&
        isxdigit((unsigned char)p[2]) &&
        isxdigit((unsigned char)p[3]) &&
        p[4] == ':') {
        p += 5;
    }

    return isxdigit((unsigned char)p[0]) &&
           isxdigit((unsigned char)p[1]) &&
           p[2] == ':' &&
           isxdigit((unsigned char)p[3]) &&
           isxdigit((unsigned char)p[4]) &&
           p[5] == '.' &&
           isxdigit((unsigned char)p[6]) &&
           p[7] == '\0';
}

static char *get_device_name(const char *addr) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "lspci -s %s", addr);

    int status = 0;
    char *out = run_command_capture(cmd, &status);
    if (!out || status != 0 || out[0] == '\0') {
        free(out);
        return NULL;
    }

    char *newline = strchr(out, '\n');
    if (newline) {
        *newline = '\0';
    }

    return out;
}

static size_t read_all_bytes(const char *device, uint8_t bytes[256]) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "lspci -s %s -xxx", device);

    char *device_name = get_device_name(device);
    if (!device_name) {
        fprintf(stderr, "%s: failed to read device name\n", device);
        return 0;
    }

    int status = 0;
    char *out = run_command_capture(cmd, &status);
    if (!out || status != 0) {
        fprintf(stderr, "%s: failed to read PCI config bytes\n", device);
        free(device_name);
        free(out);
        return 0;
    }

    size_t count = 0;

    char *saveptr = NULL;
    for (char *line = strtok_r(out, "\n", &saveptr);
         line;
         line = strtok_r(NULL, "\n", &saveptr)) {

        if (strstr(line, device_name)) {
            continue;
        }

        char *colon = strstr(line, ": ");
        if (!colon) {
            continue;
        }

        char *p = colon + 2;

        while (*p && count < 256) {
            while (*p && isspace((unsigned char)*p)) {
                p++;
            }

            if (!isxdigit((unsigned char)p[0]) ||
                !isxdigit((unsigned char)p[1])) {
                break;
            }

            char hex[3] = { p[0], p[1], '\0' };
            bytes[count++] = (uint8_t)strtoul(hex, NULL, 16);
            p += 2;
        }
    }

    free(device_name);
    free(out);

    return count;
}

static int find_byte_to_patch(const uint8_t bytes[256]) {
    int pos = bytes[0x34]; 

    for (int guard = 0; guard < 64; guard++) {
        if (pos == 0 || pos >= 256) {
            return -1;
        }

        if (bytes[pos] == 0x10) {
            int patch_pos = pos + 0x10;
            return patch_pos < 256 ? patch_pos : -1;
        }

        if (pos + 1 >= 256) {
            return -1;
        }

        pos = bytes[pos + 1];
    }

    return -1;
}

static void patch_byte(const char *device, int position, uint8_t value) {
    char cmd[128];
    snprintf(
        cmd,
        sizeof(cmd),
        "setpci -s %s 0x%x.B=0x%x",
        device,
        position,
        value
    );

    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "%s: setpci failed at offset 0x%x\n", device, position);
    }
}

static void patch_device(const char *addr, ASPM aspm_value) {
    uint8_t endpoint_bytes[256] = {0};

    size_t n = read_all_bytes(addr, endpoint_bytes);
    if (n < 256) {
        fprintf(stderr, "%s: could not read full 256-byte PCI config space\n", addr);
        return;
    }

    int byte_position_to_patch = find_byte_to_patch(endpoint_bytes);
    if (byte_position_to_patch < 0) {
        fprintf(stderr, "%s: PCI Express capability not found\n", addr);
        return;
    }

    uint8_t current = endpoint_bytes[byte_position_to_patch];

    if ((current & 0x3) != (uint8_t)aspm_value) {
        uint8_t patched = current;
        patched >>= 2;
        patched <<= 2;
        patched |= (uint8_t)aspm_value;

        patch_byte(addr, byte_position_to_patch, patched);
        if (!silent) printf("%s: Enabled ASPM %s\n", addr, aspm_name(aspm_value));
    } else {
        if (!silent) printf("%s: Already has ASPM %s enabled\n", addr, aspm_name(aspm_value));
    }
}

static void device_list_push(DeviceList *list, const char *addr, ASPM mode) {
    if (list->len == list->cap) {
        size_t new_cap = list->cap ? list->cap * 2 : 16;
        Device *new_items = realloc(list->items, new_cap * sizeof(Device));

        if (!new_items) {
            fprintf(stderr, "Out of memory\n");
            exit(1);
        }

        list->items = new_items;
        list->cap = new_cap;
    }

    snprintf(list->items[list->len].addr, sizeof(list->items[list->len].addr), "%s", addr);
    list->items[list->len].mode = mode;
    list->len++;
}

static int extract_aspm_mode(const char *block, ASPM *mode_out) {
    if (!strstr(block, "ASPM")) {
        return 0;
    }

    if (strstr(block, "ASPM not supported")) {
        return 0;
    }

    const char *p = block;

    while ((p = strstr(p, "ASPM ")) != NULL) {
        p += strlen("ASPM ");

        const char *comma = strchr(p, ',');
        if (!comma) {
            continue;
        }

        size_t len = (size_t)(comma - p);
        if (len == 0 || len > 64) {
            continue;
        }

        char mode_str[65];
        memcpy(mode_str, p, len);
        mode_str[len] = '\0';

        ASPM mode = ASPM_DISABLED;

        if (strstr(mode_str, "L0s")) {
            mode = (ASPM)(mode | ASPM_L0S);
        }

        if (strstr(mode_str, "L1")) {
            mode = (ASPM)(mode | ASPM_L1);
        }

        if (mode != ASPM_DISABLED) {
            *mode_out = mode;
            return 1;
        }
    }

    return 0;
}

static DeviceList list_supported_devices(void) {
    DeviceList list = {0};

    int status = 0;
    char *out = run_command_capture("lspci -vv", &status);
    if (!out || status != 0) {
        fprintf(stderr, "Failed to run lspci -vv\n");
        free(out);
        return list;
    }

    char current_addr[16] = {0};
    char *block = NULL;
    size_t block_len = 0;
    size_t block_cap = 0;

    char *saveptr = NULL;
    for (char *line = strtok_r(out, "\n", &saveptr);
         line;
         line = strtok_r(NULL, "\n", &saveptr)) {

        int starts_device = valid_pci_addr(line);

        if (starts_device) {
            if (current_addr[0] && block) {
                ASPM mode;
                if (extract_aspm_mode(block, &mode)) {
                    device_list_push(&list, current_addr, mode);
                }
            }

            snprintf(current_addr, sizeof(current_addr), "%.7s", line);

            block_len = 0;
            if (block) {
                block[0] = '\0';
            }
        }

        size_t line_len = strlen(line);
        if (block_len + line_len + 2 > block_cap) {
            size_t new_cap = block_cap ? block_cap * 2 : 4096;

            while (block_len + line_len + 2 > new_cap) {
                new_cap *= 2;
            }

            char *new_block = realloc(block, new_cap);
            if (!new_block) {
                fprintf(stderr, "Out of memory\n");
                free(block);
                free(out);
                exit(1);
            }

            block = new_block;
            block_cap = new_cap;
        }

        memcpy(block + block_len, line, line_len);
        block_len += line_len;
        block[block_len++] = '\n';
        block[block_len] = '\0';
    }

    if (current_addr[0] && block) {
        ASPM mode;
        if (extract_aspm_mode(block, &mode)) {
            device_list_push(&list, current_addr, mode);
        }
    }

    free(block);
    free(out);

    return list;
}

static int get_supported_mode_for_device(const char *addr, ASPM *mode_out) {
    char cmd[128];

    snprintf(cmd, sizeof(cmd), "lspci -s %s -vv", addr);

    int status = 0;
    char *out = run_command_capture(cmd, &status);

    if (!out || status != 0 || out[0] == '\0') {
        fprintf(stderr, "%s: failed to read PCI device information\n", addr);
        free(out);
        return 0;
    }

    int ok = extract_aspm_mode(out, mode_out);

    if (!ok) {
        fprintf(stderr, "%s: ASPM not supported or not detected\n", addr);
    }

    free(out);
    return ok;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 ||
            strcmp(argv[i], "--silent") == 0) {
            silent = 1;
        } else if (strcmp(argv[i], "-d") == 0 ||
                   strcmp(argv[i], "--device") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s requires a PCI device address\n", argv[i]);
                return 1;
            }

            i++;

            if (!valid_pci_addr(argv[i])) {
                fprintf(stderr, "Invalid PCI device address: %s\n", argv[i]);
                fprintf(stderr, "Expected format like 02:00.0 or 0000:02:00.0 may be accepted by lspci, but this program expects short form\n");
                return 1;
            }

            snprintf(device_filter, sizeof(device_filter), "%s", argv[i]);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    run_prerequisites();

    if (device_filter[0]) {
        ASPM mode;

        if (get_supported_mode_for_device(device_filter, &mode)) {
            patch_device(device_filter, mode);
        }

        return 0;
    }

    DeviceList devices = list_supported_devices();

    for (size_t i = 0; i < devices.len; i++) {
        patch_device(devices.items[i].addr, devices.items[i].mode);
    }

    free(devices.items);
    return 0;
}