/*
 * Project 54: Supply Chain Product Tracking System
 * -------------------------------------------------
 * Features:
 *   - Struct-based products and checkpoints
 *   - Dynamic product list and dynamic checkpoint arrays (malloc/realloc/free)
 *   - Add checkpoints, view history, verify chain integrity
 *   - Anomaly detection: skipped nodes, out-of-order stages/timestamps,
 *     delays between checkpoints, missing updates, bad delivery status
 *   - Tamper detection using a chained checksum stored in the log file
 *   - File handling: save/load tracking log (tracking_log.txt)
 *
 * Compile:  gcc supply_chain_tracker.c -o tracker
 * Run:      ./tracker        (Windows: tracker.exe)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ID_LEN        20
#define NAME_LEN      50
#define LOC_LEN       50
#define STATUS_LEN    20
#define LINE_LEN      256
#define NUM_STAGES    5
#define MAX_GAP_HOURS  48.0   /* max allowed time between two checkpoints  */
#define MAX_IDLE_HOURS 72.0   /* max time without update before "missing"  */
#define DATA_FILE     "tracking_log.txt"

/* Fixed supply-chain route: every product must pass these in order */
static const char *STAGE_NAMES[NUM_STAGES] = {
    "Factory",
    "Warehouse",
    "Distribution Center",
    "Transport Hub",
    "Retail Store"
};

static const char *STATUS_OPTIONS[4] = {
    "DISPATCHED", "IN_TRANSIT", "RECEIVED", "DELIVERED"
};

/* ---------------------------- Structures ---------------------------- */

typedef struct {
    int    stage;                 /* index into STAGE_NAMES (0..4) */
    char   location[LOC_LEN];
    time_t timestamp;
    char   status[STATUS_LEN];
} Checkpoint;

typedef struct {
    char        id[ID_LEN];       /* tracking ID */
    char        name[NAME_LEN];
    Checkpoint *cps;              /* dynamic array of checkpoints */
    int         count;
    int         capacity;
} Product;

typedef struct {
    Product *items;               /* dynamic array of products */
    int      count;
    int      capacity;
} ProductList;

/* ------------------------- Helper functions ------------------------- */

static void read_line(const char *prompt, char *buf, size_t size)
{
    size_t i;
    printf("%s", prompt);
    if (fgets(buf, (int)size, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    buf[strcspn(buf, "\r\n")] = '\0';
    /* '|' is used as a field separator in the file, so remove it */
    for (i = 0; buf[i]; i++)
        if (buf[i] == '|')
            buf[i] = '-';
}

static int read_int(const char *prompt, int lo, int hi)
{
    char line[LINE_LEN];
    int v;
    while (1) {
        read_line(prompt, line, sizeof line);
        if (sscanf(line, "%d", &v) == 1 && v >= lo && v <= hi)
            return v;
        printf("  Invalid input. Enter a number between %d and %d.\n", lo, hi);
    }
}

static void format_time(time_t t, char *out, size_t size)
{
    struct tm *tmv = localtime(&t);
    if (tmv)
        strftime(out, size, "%Y-%m-%d %H:%M", tmv);
    else
        snprintf(out, size, "invalid");
}

static time_t make_time(int y, int mo, int d, int h, int mi)
{
    struct tm tmv;
    memset(&tmv, 0, sizeof tmv);
    tmv.tm_year = y - 1900;
    tmv.tm_mon = mo - 1;
    tmv.tm_mday = d;
    tmv.tm_hour = h;
    tmv.tm_min = mi;
    tmv.tm_isdst = -1;
    return mktime(&tmv);
}

/* Accepts "YYYY-MM-DD HH:MM"; empty input means "now" */
static time_t read_timestamp(void)
{
    char line[LINE_LEN];
    int y, mo, d, h, mi;
    while (1) {
        read_line("  Timestamp (YYYY-MM-DD HH:MM, Enter = now): ", line, sizeof line);
        if (line[0] == '\0')
            return time(NULL);
        if (sscanf(line, "%d-%d-%d %d:%d", &y, &mo, &d, &h, &mi) == 5 &&
            mo >= 1 && mo <= 12 && d >= 1 && d <= 31 &&
            h >= 0 && h <= 23 && mi >= 0 && mi <= 59) {
            time_t t = make_time(y, mo, d, h, mi);
            if (t != (time_t)-1)
                return t;
        }
        printf("  Invalid format. Example: 2026-11-17 14:30\n");
    }
}

/* ------------------ Dynamic memory: list management ------------------ */

static void init_list(ProductList *list)
{
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void free_list(ProductList *list)
{
    int i;
    for (i = 0; i < list->count; i++)
        free(list->items[i].cps);
    free(list->items);
    init_list(list);
}

/* NOTE: the returned pointer is valid only until the next add_product_raw */
static Product *find_product(ProductList *list, const char *id)
{
    int i;
    for (i = 0; i < list->count; i++)
        if (strcmp(list->items[i].id, id) == 0)
            return &list->items[i];
    return NULL;
}

static Product *add_product_raw(ProductList *list, const char *id, const char *name)
{
    Product *p;
    if (list->count == list->capacity) {
        int newcap = list->capacity ? list->capacity * 2 : 4;
        Product *tmp = realloc(list->items, newcap * sizeof(Product));
        if (!tmp) {
            printf("Memory allocation failed!\n");
            return NULL;
        }
        list->items = tmp;
        list->capacity = newcap;
    }
    p = &list->items[list->count++];
    strncpy(p->id, id, ID_LEN - 1);
    p->id[ID_LEN - 1] = '\0';
    strncpy(p->name, name, NAME_LEN - 1);
    p->name[NAME_LEN - 1] = '\0';
    p->cps = NULL;
    p->count = 0;
    p->capacity = 0;
    return p;
}

static int add_checkpoint_raw(Product *p, int stage, const char *loc,
                              time_t ts, const char *status)
{
    Checkpoint *c;
    if (p->count == p->capacity) {
        int newcap = p->capacity ? p->capacity * 2 : 4;
        Checkpoint *tmp = realloc(p->cps, newcap * sizeof(Checkpoint));
        if (!tmp) {
            printf("Memory allocation failed!\n");
            return 0;
        }
        p->cps = tmp;
        p->capacity = newcap;
    }
    c = &p->cps[p->count++];
    c->stage = stage;
    strncpy(c->location, loc, LOC_LEN - 1);
    c->location[LOC_LEN - 1] = '\0';
    c->timestamp = ts;
    strncpy(c->status, status, STATUS_LEN - 1);
    c->status[STATUS_LEN - 1] = '\0';
    return 1;
}

/* ---------------- Chained checksum (tamper detection) ---------------- */

static unsigned long mix_str(unsigned long h, const char *s)
{
    while (*s)
        h = ((h << 5) + h) + (unsigned char)*s++;   /* djb2 */
    return h;
}

static unsigned long mix_num(unsigned long h, long long v)
{
    char buf[40];
    snprintf(buf, sizeof buf, "%lld", v);
    return mix_str(h, buf);
}

/* Each checkpoint's hash depends on all the previous ones (like a chain) */
static unsigned long compute_chain_hash(const Product *p)
{
    unsigned long h = 5381;
    int i;
    h = mix_str(h, p->id);
    for (i = 0; i < p->count; i++) {
        const Checkpoint *c = &p->cps[i];
        h = mix_num(h, c->stage);
        h = mix_str(h, c->location);
        h = mix_num(h, (long long)c->timestamp);
        h = mix_str(h, c->status);
    }
    return h;
}

/* ------------------------- Core operations -------------------------- */

static void add_product(ProductList *list)
{
    char id[ID_LEN], name[NAME_LEN];
    read_line("Enter tracking ID: ", id, sizeof id);
    if (id[0] == '\0') {
        printf("Tracking ID cannot be empty.\n");
        return;
    }
    if (find_product(list, id)) {
        printf("A product with this tracking ID already exists.\n");
        return;
    }
    read_line("Enter product name: ", name, sizeof name);
    if (add_product_raw(list, id, name))
        printf("Product '%s' added.\n", id);
}

static void add_checkpoint(ProductList *list)
{
    char id[ID_LEN], loc[LOC_LEN];
    Product *p;
    int i, stage, st;
    time_t ts;

    read_line("Enter tracking ID: ", id, sizeof id);
    p = find_product(list, id);
    if (!p) {
        printf("No product found with ID '%s'.\n", id);
        return;
    }

    printf("  Stages:\n");
    for (i = 0; i < NUM_STAGES; i++)
        printf("    %d. %s\n", i + 1, STAGE_NAMES[i]);
    stage = read_int("  Select stage (1-5): ", 1, NUM_STAGES) - 1;

    read_line("  Location: ", loc, sizeof loc);
    if (loc[0] == '\0')
        strcpy(loc, "Unknown");

    ts = read_timestamp();

    printf("  Status:\n");
    for (i = 0; i < 4; i++)
        printf("    %d. %s\n", i + 1, STATUS_OPTIONS[i]);
    st = read_int("  Select status (1-4): ", 1, 4) - 1;

    /* Warn immediately, but still record what actually happened */
    if (p->count > 0) {
        const Checkpoint *last = &p->cps[p->count - 1];
        if (stage > last->stage + 1)
            printf("  WARNING: stage(s) skipped before '%s'.\n", STAGE_NAMES[stage]);
        else if (stage <= last->stage)
            printf("  WARNING: stage is not after the previous one.\n");
        if (ts < last->timestamp)
            printf("  WARNING: timestamp is earlier than previous checkpoint.\n");
    } else if (stage != 0) {
        printf("  WARNING: first checkpoint is not at the Factory.\n");
    }

    if (add_checkpoint_raw(p, stage, loc, ts, STATUS_OPTIONS[st]))
        printf("Checkpoint added to %s.\n", p->id);
}

static void view_history(const Product *p)
{
    int i;
    char tbuf[32];
    printf("\n=== History for %s (%s) ===\n", p->id, p->name);
    if (p->count == 0) {
        printf("  No checkpoints recorded yet.\n");
        return;
    }
    printf("  %-3s %-20s %-22s %-17s %-12s\n",
           "#", "Stage", "Location", "Timestamp", "Status");
    printf("  ---------------------------------------------------------------------------\n");
    for (i = 0; i < p->count; i++) {
        const Checkpoint *c = &p->cps[i];
        format_time(c->timestamp, tbuf, sizeof tbuf);
        printf("  %-3d %-20s %-22s %-17s %-12s\n",
               i + 1, STAGE_NAMES[c->stage], c->location, tbuf, c->status);
    }
}

/*
 * Verifies the chain of one product. Returns the number of anomalies.
 * If verbose != 0, every anomaly is printed.
 */
static int verify_chain(const Product *p, int verbose)
{
    int i, s, anomalies = 0;
    char t1[32], t2[32];

    if (p->count == 0) {
        if (verbose)
            printf("  [INFO] No checkpoints recorded for %s.\n", p->id);
        return 0;
    }

    /* Rule 1: chain must start at the factory */
    if (p->cps[0].stage != 0) {
        anomalies++;
        if (verbose)
            printf("  [ANOMALY] Chain does not start at Factory (starts at %s).\n",
                   STAGE_NAMES[p->cps[0].stage]);
    }

    for (i = 1; i < p->count; i++) {
        const Checkpoint *prev = &p->cps[i - 1];
        const Checkpoint *cur  = &p->cps[i];
        int diff = cur->stage - prev->stage;
        double hours = difftime(cur->timestamp, prev->timestamp) / 3600.0;

        /* Rule 2: skipped nodes */
        if (diff > 1) {
            anomalies++;
            if (verbose) {
                printf("  [ANOMALY] Skipped node(s) between %s and %s: ",
                       STAGE_NAMES[prev->stage], STAGE_NAMES[cur->stage]);
                for (s = prev->stage + 1; s < cur->stage; s++)
                    printf("%s%s", STAGE_NAMES[s], (s + 1 < cur->stage) ? ", " : "\n");
            }
        }
        /* Rule 3: repeated or backward stage */
        else if (diff <= 0) {
            anomalies++;
            if (verbose)
                printf("  [ANOMALY] Out-of-order/duplicate stage at checkpoint %d (%s after %s).\n",
                       i + 1, STAGE_NAMES[cur->stage], STAGE_NAMES[prev->stage]);
        }

        /* Rule 4: timestamps must not go backwards */
        if (hours < 0) {
            anomalies++;
            if (verbose)
                printf("  [ANOMALY] Timestamp goes backwards at checkpoint %d.\n", i + 1);
        }
        /* Rule 5: delay between two checkpoints */
        else if (hours > MAX_GAP_HOURS) {
            anomalies++;
            if (verbose) {
                format_time(prev->timestamp, t1, sizeof t1);
                format_time(cur->timestamp, t2, sizeof t2);
                printf("  [DELAY] %.1f hours between %s (%s) and %s (%s) "
                       "- limit is %.0f hours.\n",
                       hours, STAGE_NAMES[prev->stage], t1,
                       STAGE_NAMES[cur->stage], t2, MAX_GAP_HOURS);
            }
        }
    }

    /* Rule 6: DELIVERED is only valid at the final stage */
    for (i = 0; i < p->count; i++) {
        if (strcmp(p->cps[i].status, "DELIVERED") == 0 &&
            p->cps[i].stage != NUM_STAGES - 1) {
            anomalies++;
            if (verbose)
                printf("  [ANOMALY] Status DELIVERED at non-final stage (%s).\n",
                       STAGE_NAMES[p->cps[i].stage]);
        }
    }

    /* Rule 7: missing update - shipment unfinished and silent for too long */
    {
        const Checkpoint *last = &p->cps[p->count - 1];
        int finished = (last->stage == NUM_STAGES - 1 &&
                        strcmp(last->status, "DELIVERED") == 0);
        if (!finished) {
            double idle = difftime(time(NULL), last->timestamp) / 3600.0;
            if (idle > MAX_IDLE_HOURS) {
                anomalies++;
                if (verbose)
                    printf("  [MISSING UPDATE] No update for %.1f hours since %s "
                           "(limit %.0f hours).\n",
                           idle, STAGE_NAMES[last->stage], MAX_IDLE_HOURS);
            }
        }
    }

    return anomalies;
}

static void verify_product(const Product *p)
{
    int a;
    printf("\n=== Chain verification for %s (%s) ===\n", p->id, p->name);
    a = verify_chain(p, 1);
    if (a == 0)
        printf("  Chain is VALID. No anomalies found.\n");
    else
        printf("  Chain is INVALID. %d anomaly(ies) found.\n", a);
}

static void report_all(const ProductList *list)
{
    int i, bad = 0;
    printf("\n=== Anomaly & Delay Report (all products) ===\n");
    if (list->count == 0) {
        printf("  No products registered.\n");
        return;
    }
    for (i = 0; i < list->count; i++) {
        const Product *p = &list->items[i];
        int a = verify_chain(p, 0);
        printf("\n  %s (%s): %s\n", p->id, p->name,
               a == 0 ? "OK" : "PROBLEMS FOUND");
        if (a > 0) {
            bad++;
            verify_chain(p, 1);
        }
    }
    printf("\nSummary: %d of %d product(s) have anomalies.\n", bad, list->count);
}

static void list_products(const ProductList *list)
{
    int i;
    printf("\n=== Registered products (%d) ===\n", list->count);
    for (i = 0; i < list->count; i++) {
        const Product *p = &list->items[i];
        printf("  %-12s %-25s checkpoints: %d\n", p->id, p->name, p->count);
    }
}

/* --------------------------- File handling --------------------------- */

/*
 * File format:
 *   P|id|name|checkpointCount|chainHash
 *   C|stage|location|timestamp|status      (repeated checkpointCount times)
 */
static int save_log(const ProductList *list)
{
    FILE *fp = fopen(DATA_FILE, "w");
    int i, j;
    if (!fp) {
        printf("Error: cannot open '%s' for writing.\n", DATA_FILE);
        return 0;
    }
    for (i = 0; i < list->count; i++) {
        const Product *p = &list->items[i];
        fprintf(fp, "P|%s|%s|%d|%lu\n", p->id, p->name, p->count,
                compute_chain_hash(p));
        for (j = 0; j < p->count; j++) {
            const Checkpoint *c = &p->cps[j];
            fprintf(fp, "C|%d|%s|%lld|%s\n", c->stage, c->location,
                    (long long)c->timestamp, c->status);
        }
    }
    fclose(fp);
    printf("Saved %d product(s) to %s.\n", list->count, DATA_FILE);
    return 1;
}

static int load_log(ProductList *list, int quiet)
{
    FILE *fp = fopen(DATA_FILE, "r");
    char line[LINE_LEN];
    int loaded = 0;

    if (!fp) {
        if (!quiet)
            printf("No log file '%s' found.\n", DATA_FILE);
        return 0;
    }

    free_list(list);

    while (fgets(line, sizeof line, fp)) {
        char id[ID_LEN], name[NAME_LEN];
        int cnt, j;
        unsigned long stored_hash;

        if (line[0] != 'P')
            continue;
        if (sscanf(line, "P|%19[^|]|%49[^|]|%d|%lu",
                   id, name, &cnt, &stored_hash) != 4)
            continue;

        {
            Product *p = add_product_raw(list, id, name);
            if (!p)
                break;
            for (j = 0; j < cnt; j++) {
                int stage;
                long long ts;
                char loc[LOC_LEN], status[STATUS_LEN];
                if (!fgets(line, sizeof line, fp))
                    break;
                if (sscanf(line, "C|%d|%49[^|]|%lld|%19[^\r\n]",
                           &stage, loc, &ts, status) == 4 &&
                    stage >= 0 && stage < NUM_STAGES)
                    add_checkpoint_raw(p, stage, loc, (time_t)ts, status);
            }
            if (p->count != cnt || compute_chain_hash(p) != stored_hash)
                printf("WARNING: log for '%s' failed integrity check "
                       "(file edited or corrupted)!\n", p->id);
            loaded++;
        }
    }
    fclose(fp);
    if (!quiet || loaded > 0)
        printf("Loaded %d product(s) from %s.\n", loaded, DATA_FILE);
    return loaded;
}

/* ---------------------------- Demo data ----------------------------- */

static void load_demo(ProductList *list)
{
    Product *p;

    if (!find_product(list, "TRK1001")) {      /* perfect shipment */
        p = add_product_raw(list, "TRK1001", "Laptop Batch A");
        if (p) {
            add_checkpoint_raw(p, 0, "Shenzhen Plant",   make_time(2026, 10, 1, 9, 0),  "DISPATCHED");
            add_checkpoint_raw(p, 1, "Mumbai Warehouse", make_time(2026, 10, 2, 15, 0), "RECEIVED");
            add_checkpoint_raw(p, 2, "Pune DC",          make_time(2026, 10, 3, 10, 0), "RECEIVED");
            add_checkpoint_raw(p, 3, "Delhi Hub",        make_time(2026, 10, 4, 8, 0),  "IN_TRANSIT");
            add_checkpoint_raw(p, 4, "Lucknow Store",    make_time(2026, 10, 5, 12, 0), "DELIVERED");
        }
    }
    if (!find_product(list, "TRK1002")) {      /* skipped node + delay */
        p = add_product_raw(list, "TRK1002", "Smartphone Batch B");
        if (p) {
            add_checkpoint_raw(p, 0, "Noida Plant",      make_time(2026, 10, 1, 9, 0),  "DISPATCHED");
            add_checkpoint_raw(p, 1, "Delhi Warehouse",  make_time(2026, 10, 2, 9, 0),  "RECEIVED");
            add_checkpoint_raw(p, 3, "Kanpur Hub",       make_time(2026, 10, 8, 9, 0),  "IN_TRANSIT");
            add_checkpoint_raw(p, 4, "Varanasi Store",   make_time(2026, 10, 9, 9, 0),  "DELIVERED");
        }
    }
    if (!find_product(list, "TRK1003")) {      /* stalled shipment */
        p = add_product_raw(list, "TRK1003", "Medicine Pack C");
        if (p) {
            add_checkpoint_raw(p, 0, "Hyderabad Plant",  make_time(2026, 11, 1, 9, 0),  "DISPATCHED");
            add_checkpoint_raw(p, 1, "Nagpur Warehouse", make_time(2026, 11, 2, 9, 0),  "RECEIVED");
        }
    }
    printf("Demo data loaded (TRK1001 valid, TRK1002 skipped node + delay, "
           "TRK1003 missing update).\n");
}

/* ------------------------------- Menu -------------------------------- */

static void print_menu(void)
{
    printf("\n========== SUPPLY CHAIN PRODUCT TRACKING ==========\n");
    printf(" 1. Add new product\n");
    printf(" 2. Add checkpoint to a product\n");
    printf(" 3. View product history\n");
    printf(" 4. Verify chain integrity of a product\n");
    printf(" 5. Anomaly & delay report (all products)\n");
    printf(" 6. List all products\n");
    printf(" 7. Save tracking log to file\n");
    printf(" 8. Load tracking log from file\n");
    printf(" 9. Load demo data\n");
    printf(" 0. Save & exit\n");
    printf("===================================================\n");
}

int main(void)
{
    ProductList list;
    int choice;
    char id[ID_LEN];
    Product *p;

    init_list(&list);
    load_log(&list, 1);                 /* auto-load previous session if present */

    do {
        print_menu();
        choice = read_int("Enter choice: ", 0, 9);

        switch (choice) {
        case 1: add_product(&list); break;
        case 2: add_checkpoint(&list); break;
        case 3:
        case 4:
            read_line("Enter tracking ID: ", id, sizeof id);
            p = find_product(&list, id);
            if (!p)
                printf("No product found with ID '%s'.\n", id);
            else if (choice == 3)
                view_history(p);
            else
                verify_product(p);
            break;
        case 5: report_all(&list); break;
        case 6: list_products(&list); break;
        case 7: save_log(&list); break;
        case 8: load_log(&list, 0); break;
        case 9: load_demo(&list); break;
        case 0:
            save_log(&list);
            printf("Goodbye!\n");
            break;
        }
    } while (choice != 0);

    free_list(&list);                   /* release all dynamic memory */
    return 0;
}