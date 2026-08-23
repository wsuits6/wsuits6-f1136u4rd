#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/keysym.h>
#include <X11/cursorfont.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <libgen.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* ================================================================
 * CONFIGURATION
 * ================================================================ */
#define APP_NAME         "FileGuard"
#define APP_VERSION      "1.0.0"
#define WIN_W            720
#define WIN_H            520
#define VAULT_DIR        ".fileguard"
#define VAULT_FILE       "vault.enc"
#define MASTER_FILE      "master.sha256"
#define MAX_FILES        512
#define PATH_MAX_LEN     4096
#define MAX_ITEMS_VIS    18
#define PADDING          8
#define BTN_H            32
#define ITEM_H           24
#define INPUT_H          28
#define TITLE_H          40
#define STATUSBAR_H      24

/* Colors (dark theme) */
#define COL_BG           0x1E1E2E
#define COL_SURFACE      0x2D2D3F
#define COL_PRIMARY      0x7C3AED
#define COL_PRIMARY_HV   0x8B5CF6
#define COL_TEXT         0xCDD6F4
#define COL_TEXT_DIM     0x6C7086
#define COL_ACCENT       0xA78BFA
#define COL_DANGER       0xEF4444
#define COL_DANGER_HV    0xF87171
#define COL_SUCCESS      0x22C55E
#define COL_BORDER       0x45475A
#define COL_INPUT_BG     0x1E1E2E
#define COL_LIST_BG      0x181825
#define COL_HIDDEN       0xF59E0B

/* ================================================================
 * DATA STRUCTURES
 * ================================================================ */
typedef struct {
    int x, y, w, h;
    int type; /* 0=label, 1=button, 2=input, 3=list */
    char text[512];
    int state; /* 0=normal, 1=hover, 2=pressed */
    int focused;
    int value; /* toggle, scroll offset, etc */
    int tag;   /* widget identifier */
    void (*on_click)(int tag);
    void (*on_change)(int tag, const char *text);
} Widget;

typedef struct {
    char path[PATH_MAX_LEN];
    int hidden; /* 1=currently hidden */
} ProtectedFile;

typedef struct {
    int win_w, win_h;
    int screen;
    Widget widgets[64];
    int widget_count;
    int current_view; /* 0=login, 1=setup, 2=main */
    int running;
    int show_password;
    /* vault state */
    ProtectedFile files[MAX_FILES];
    int file_count;
    int list_scroll;
    int selected_idx;
    char master_pwd[256];
    int authenticated;
    int list_sel[64];
    int list_sel_count;
} AppState;

/* ================================================================
 * GLOBALS
 * ================================================================ */
static Display *dpy;
static Window win;
static GC gc;
static XFontStruct *font_fixed;
static XFontStruct *font_bold;
static AppState state;
static Atom wm_delete;
static Atom wm_protocols;
static Cursor hand_cursor;
static Cursor text_cursor;

/* ================================================================
 * UTILITY FUNCTIONS
 * ================================================================ */
static void get_vault_path(char *buf, size_t sz) {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    snprintf(buf, sz, "%s/%s", home, VAULT_DIR);
}

static void get_file_path(const char *fname, char *buf, size_t sz) {
    char vp[PATH_MAX_LEN];
    get_vault_path(vp, sizeof(vp));
    snprintf(buf, sz, "%s/%s", vp, fname);
}

static void ensure_vault_dir(void) {
    char vp[PATH_MAX_LEN];
    get_vault_path(vp, sizeof(vp));
    struct stat st;
    if (stat(vp, &st) < 0)
        mkdir(vp, 0700);
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void sha256_hash(const char *input, unsigned char *output) {
    SHA256((unsigned char *)input, strlen(input), output);
}

static void hex_encode(const unsigned char *in, int inlen, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < inlen; i++) {
        out[i*2]   = hex[(in[i] >> 4) & 0xf];
        out[i*2+1] = hex[in[i] & 0xf];
    }
    out[inlen*2] = 0;
}

static int aes_encrypt(const unsigned char *plain, int plen,
                       const unsigned char *key, unsigned char **cipher, int *clen) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    unsigned char iv[16];
    RAND_bytes(iv, 16);
    int outlen, tmplen;
    *clen = 16 + plen + 32;
    *cipher = malloc(*clen);
    memcpy(*cipher, iv, 16);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); free(*cipher); return 0; }
    if (EVP_EncryptUpdate(ctx, *cipher + 16, &outlen, plain, plen) != 1) { EVP_CIPHER_CTX_free(ctx); free(*cipher); return 0; }
    int total = outlen;
    if (EVP_EncryptFinal_ex(ctx, *cipher + 16 + outlen, &tmplen) != 1) { EVP_CIPHER_CTX_free(ctx); free(*cipher); return 0; }
    total += tmplen;
    *clen = 16 + total;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

static int aes_decrypt(const unsigned char *cipher, int clen,
                       const unsigned char *key, unsigned char **plain, int *plen) {
    if (clen < 16) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    unsigned char iv[16];
    memcpy(iv, cipher, 16);
    int outlen, tmplen;
    *plen = clen - 16 + 32;
    *plain = malloc(*plen);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); free(*plain); return 0; }
    if (EVP_DecryptUpdate(ctx, *plain, &outlen, cipher + 16, clen - 16) != 1) { EVP_CIPHER_CTX_free(ctx); free(*plain); return 0; }
    int total = outlen;
    if (EVP_DecryptFinal_ex(ctx, *plain + outlen, &tmplen) != 1) { EVP_CIPHER_CTX_free(ctx); free(*plain); return 0; }
    total += tmplen;
    *plen = total;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

static void derive_key(const char *password, unsigned char *key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password, strlen(password), hash);
    memcpy(key, hash, 32);
}

/* ================================================================
 * VAULT MANAGEMENT
 * ================================================================ */
static int vault_save(const char *password) {
    char vp[PATH_MAX_LEN], fp[PATH_MAX_LEN];
    get_vault_path(vp, sizeof(vp));
    get_file_path(VAULT_FILE, fp, sizeof(fp));
    ensure_vault_dir();

    /* serialize files */
    char buf[1024 * MAX_FILES];
    int off = 0;
    for (int i = 0; i < state.file_count; i++) {
        off += snprintf(buf + off, sizeof(buf) - off, "%s|%d\n",
                        state.files[i].path, state.files[i].hidden);
        if (off >= (int)sizeof(buf) - 1) break;
    }
    if (off == 0) { buf[off++] = '\n'; }
    buf[off] = 0;

    unsigned char key[32];
    derive_key(password, key);
    unsigned char *cipher;
    int clen;
    if (!aes_encrypt((unsigned char *)buf, off, key, &cipher, &clen)) return 0;

    FILE *f = fopen(fp, "wb");
    if (!f) { free(cipher); return 0; }
    fwrite(cipher, 1, clen, f);
    fclose(f);
    free(cipher);
    return 1;
}

static int vault_load(const char *password) {
    char fp[PATH_MAX_LEN];
    get_file_path(VAULT_FILE, fp, sizeof(fp));

    FILE *f = fopen(fp, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsz <= 0) { fclose(f); return 0; }
    unsigned char *filedata = malloc(fsz);
    fread(filedata, 1, fsz, f);
    fclose(f);

    unsigned char key[32];
    derive_key(password, key);
    unsigned char *plain;
    int plen;
    if (!aes_decrypt(filedata, fsz, key, &plain, &plen)) { free(filedata); return 0; }
    free(filedata);
    plain[plen] = 0;

    state.file_count = 0;
    char *line = strtok((char *)plain, "\n");
    while (line && state.file_count < MAX_FILES) {
        char *p = strrchr(line, '|');
        if (p) {
            *p = 0;
            strncpy(state.files[state.file_count].path, line, PATH_MAX_LEN - 1);
            state.files[state.file_count].hidden = atoi(p + 1);
            state.file_count++;
        }
        line = strtok(NULL, "\n");
    }
    free(plain);
    return 1;
}

static int master_pwd_exists(void) {
    char fp[PATH_MAX_LEN];
    get_file_path(MASTER_FILE, fp, sizeof(fp));
    return file_exists(fp);
}

static int verify_master_pwd(const char *pwd) {
    char fp[PATH_MAX_LEN];
    get_file_path(MASTER_FILE, fp, sizeof(fp));
    FILE *f = fopen(fp, "r");
    if (!f) return 0;
    char stored_hash[65] = {0};
    fread(stored_hash, 1, 64, f);
    fclose(f);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256_hash(pwd, hash);
    char computed[65];
    hex_encode(hash, SHA256_DIGEST_LENGTH, computed);
    return strcmp(stored_hash, computed) == 0;
}

static int set_master_pwd(const char *pwd) {
    char fp[PATH_MAX_LEN];
    get_file_path(MASTER_FILE, fp, sizeof(fp));
    ensure_vault_dir();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256_hash(pwd, hash);
    char hex[65];
    hex_encode(hash, SHA256_DIGEST_LENGTH, hex);
    FILE *f = fopen(fp, "w");
    if (!f) return 0;
    fwrite(hex, 1, 64, f);
    fclose(f);
    return 1;
}

static int hide_file(const char *path) {
    char dir[PATH_MAX_LEN], base[PATH_MAX_LEN];
    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = 0;
    char *bn = basename(dir);
    strncpy(base, bn, sizeof(base) - 1);
    strncpy(dir, path, sizeof(dir) - 1);
    char *dn = dirname(dir);

    char newpath[PATH_MAX_LEN];
    if (base[0] == '.') {
        snprintf(newpath, sizeof(newpath), "%s/%s", dn, base + 1);
        return rename(path, newpath) == 0 ? 2 : 0; /* 2=unhidden */
    } else {
        snprintf(newpath, sizeof(newpath), "%s/.%s", dn, base);
        return rename(path, newpath) == 0 ? 1 : 0; /* 1=hidden */
    }
}

static int is_hidden_file(const char *path) {
    char base[PATH_MAX_LEN];
    strncpy(base, path, sizeof(base) - 1);
    return basename(base)[0] == '.';
}

/* ================================================================
 * X11 DRAWING HELPERS
 * ================================================================ */
static unsigned long alloc_color(unsigned long hex) {
    XColor c;
    c.red   = ((hex >> 16) & 0xff) * 257;
    c.green = ((hex >> 8)  & 0xff) * 257;
    c.blue  = (hex         & 0xff) * 257;
    c.flags = DoRed | DoGreen | DoBlue;
    XAllocColor(dpy, DefaultColormap(dpy, DefaultScreen(dpy)), &c);
    return c.pixel;
}

static void draw_rect(int x, int y, int w, int h, unsigned long color) {
    XSetForeground(dpy, gc, color);
    XFillRectangle(dpy, win, gc, x, y, w, h);
}

static void draw_round_rect(int x, int y, int w, int h, unsigned long color, int r) {
    XSetForeground(dpy, gc, color);
    XFillArc(dpy, win, gc, x, y, r*2, r*2, 0, 360*64);
    XFillArc(dpy, win, gc, x+w-r*2, y, r*2, r*2, 0, 360*64);
    XFillArc(dpy, win, gc, x, y+h-r*2, r*2, r*2, 0, 360*64);
    XFillArc(dpy, win, gc, x+w-r*2, y+h-r*2, r*2, r*2, 0, 360*64);
    XFillRectangle(dpy, win, gc, x+r, y, w-r*2, h);
    XFillRectangle(dpy, win, gc, x, y+r, w, h-r*2);
}

static void draw_border(int x, int y, int w, int h, unsigned long color) {
    XSetForeground(dpy, gc, color);
    XDrawRectangle(dpy, win, gc, x, y, w-1, h-1);
}

static void draw_line(int x1, int y1, int x2, int y2, unsigned long color) {
    XSetForeground(dpy, gc, color);
    XDrawLine(dpy, win, gc, x1, y1, x2, y2);
}

static void draw_text(int x, int y, const char *text, unsigned long color, XFontStruct *font) {
    XSetFont(dpy, gc, font->fid);
    XSetForeground(dpy, gc, color);
    XDrawString(dpy, win, gc, x, y + font->ascent, text, strlen(text));
}

static int text_width(const char *text, XFontStruct *font) {
    return XTextWidth(font, text, strlen(text));
}

static void draw_centered_text(int x, int y, int w, int h, const char *text,
                                unsigned long color, XFontStruct *font) {
    int tw = text_width(text, font);
    int tx = x + (w - tw) / 2;
    int ty = y + (h - font->ascent) / 2 + font->ascent;
    draw_text(tx, ty, text, color, font);
}

/* ================================================================
 * WIDGET SYSTEM
 * ================================================================ */
static int add_widget(int type, int x, int y, int w, int h, const char *text, int tag) {
    if (state.widget_count >= 64) return -1;
    Widget *wd = &state.widgets[state.widget_count++];
    memset(wd, 0, sizeof(Widget));
    wd->x = x; wd->y = y; wd->w = w; wd->h = h;
    wd->type = type;
    wd->tag = tag;
    wd->state = 0;
    strncpy(wd->text, text, sizeof(wd->text) - 1);
    wd->focused = 0;
    wd->value = 0;
    wd->on_click = NULL;
    wd->on_change = NULL;
    return state.widget_count - 1;
}

static Widget *find_widget(int x, int y) {
    for (int i = state.widget_count - 1; i >= 0; i--) {
        Widget *wd = &state.widgets[i];
        if (x >= wd->x && x < wd->x + wd->w && y >= wd->y && y < wd->y + wd->h)
            return wd;
    }
    return NULL;
}

static Widget *find_widget_by_tag(int tag) {
    for (int i = 0; i < state.widget_count; i++) {
        if (state.widgets[i].tag == tag) return &state.widgets[i];
    }
    return NULL;
}

static void clear_widgets(void) {
    state.widget_count = 0;
}

/* ================================================================
 * UI COLORS
 * ================================================================ */
static unsigned long c_bg, c_surface, c_primary, c_primary_hv, c_text;
static unsigned long c_text_dim, c_accent, c_danger, c_danger_hv, c_success;
static unsigned long c_border, c_input_bg, c_list_bg, c_hidden, c_overlay;
static void init_colors(void) {
    c_bg       = alloc_color(COL_BG);
    c_surface  = alloc_color(COL_SURFACE);
    c_primary  = alloc_color(COL_PRIMARY);
    c_primary_hv = alloc_color(COL_PRIMARY_HV);
    c_text     = alloc_color(COL_TEXT);
    c_text_dim = alloc_color(COL_TEXT_DIM);
    c_accent   = alloc_color(COL_ACCENT);
    c_danger   = alloc_color(COL_DANGER);
    c_danger_hv = alloc_color(COL_DANGER_HV);
    c_success  = alloc_color(COL_SUCCESS);
    c_border   = alloc_color(COL_BORDER);
    c_input_bg = alloc_color(COL_INPUT_BG);
    c_list_bg  = alloc_color(COL_LIST_BG);
    c_hidden   = alloc_color(COL_HIDDEN);
    c_overlay  = alloc_color(0x000000);
}

/* ================================================================
 * VIEW: SETUP PASSWORD
 * ================================================================ */
enum { TAG_SETUP_PWD, TAG_SETUP_CONFIRM, TAG_SETUP_BTN, TAG_SETUP_SHOW,
       TAG_LOGIN_PWD, TAG_LOGIN_BTN, TAG_LOGIN_SHOW,
       TAG_ADD_BTN, TAG_REMOVE_BTN, TAG_HIDE_BTN, TAG_UNHIDE_BTN,
       TAG_PWD_CHANGE, TAG_EXIT_BTN, TAG_PWD_LIST,
       TAG_NEW_PWD, TAG_NEW_CONFIRM, TAG_CHANGE_OK, TAG_CHANGE_CANCEL,
       TAG_ABOUT_BTN };

static void setup_view(void) {
    clear_widgets();
    state.current_view = 1;
    int cw = 360, ch = 260;
    int cx = (state.win_w - cw) / 2, cy = (state.win_h - ch) / 2 - 20;
    draw_rect(0, 0, state.win_w, state.win_h, c_bg);
    draw_round_rect(cx, cy, cw, ch, c_surface, 8);
    draw_border(cx, cy, cw, ch, c_border);

    draw_centered_text(cx, cy + 10, cw, 36, "Create Master Password", c_text, font_bold);
    draw_centered_text(cx, cy + 50, cw, 20, "Set a password to protect your vault", c_text_dim, font_fixed);

    add_widget(2, cx + 30, cy + 80, cw - 60, INPUT_H, "Password", TAG_SETUP_PWD);
    add_widget(2, cx + 30, cy + 120, cw - 60, INPUT_H, "Confirm Password", TAG_SETUP_CONFIRM);
    add_widget(0, cx + cw - 70, cy + 122, 50, 20, "Show", TAG_SETUP_SHOW);
    add_widget(1, cx + 30, cy + 170, cw - 60, BTN_H, "Create Vault", TAG_SETUP_BTN);
}

/* ================================================================
 * VIEW: LOGIN
 * ================================================================ */
static void login_view(void) {
    clear_widgets();
    state.current_view = 0;
    int cw = 360, ch = 220;
    int cx = (state.win_w - cw) / 2, cy = (state.win_h - ch) / 2 - 20;
    draw_rect(0, 0, state.win_w, state.win_h, c_bg);
    draw_round_rect(cx, cy, cw, ch, c_surface, 8);
    draw_border(cx, cy, cw, ch, c_border);

    draw_centered_text(cx, cy + 10, cw, 36, "FileGuard", c_primary, font_bold);
    draw_centered_text(cx, cy + 48, cw, 20, "Enter your master password", c_text_dim, font_fixed);

    add_widget(2, cx + 30, cy + 78, cw - 60, INPUT_H, "", TAG_LOGIN_PWD);
    add_widget(0, cx + cw - 70, cy + 80, 50, 20, "Show", TAG_LOGIN_SHOW);
    add_widget(1, cx + 30, cy + 128, cw - 60, BTN_H, "Unlock", TAG_LOGIN_BTN);
}

/* ================================================================
 * VIEW: MAIN
 * ================================================================ */
static void main_view(void) {
    clear_widgets();
    state.current_view = 2;
    state.show_password = 0;

    int bw = state.win_w;
    int bh = state.win_h;

    /* title bar */
    draw_rect(0, 0, bw, TITLE_H, c_primary);
    draw_text(PADDING, TITLE_H/2 - 7, "FileGuard - Protected Files", c_text, font_bold);

    /* status separator */
    draw_rect(0, bh - STATUSBAR_H, bw, STATUSBAR_H, c_surface);
    char status[128];
    int hidden_count = 0;
    for (int i = 0; i < state.file_count; i++)
        if (state.files[i].hidden == 1) hidden_count++;
    snprintf(status, sizeof(status), "Files: %d  |  Hidden: %d  |  Visible: %d",
             state.file_count, hidden_count, state.file_count - hidden_count);
    draw_text(PADDING, bh - STATUSBAR_H/2 - 5, status, c_text_dim, font_fixed);

    /* left panel - file list */
    int lx = PADDING, ly = TITLE_H + PADDING;
    int lw = bw - 220 - PADDING * 3;
    int lh = bh - TITLE_H - STATUSBAR_H - PADDING * 2;

    draw_rect(lx, ly, lw, lh, c_list_bg);
    draw_border(lx, ly, lw, lh, c_border);

    /* header */
    draw_rect(lx + 1, ly + 1, lw - 2, ITEM_H, c_surface);
    draw_text(lx + 8, ly + ITEM_H/2 - 6, "Protected Files & Directories", c_accent, font_fixed);

    /* file items */
    int start = state.list_scroll;
    int max_show = (lh - ITEM_H - 2) / ITEM_H;
    if (max_show < 0) max_show = 0;

    for (int i = 0; i < max_show && (start + i) < state.file_count; i++) {
        int fi = start + i;
        int iy = ly + ITEM_H + 2 + i * ITEM_H;
        int selected = 0;
        for (int s = 0; s < state.list_sel_count; s++)
            if (state.list_sel[s] == fi) { selected = 1; break; }
        if (selected) {
            draw_rect(lx + 2, iy, lw - 4, ITEM_H - 1, c_primary);
        } else if (i % 2 == 0) {
            draw_rect(lx + 2, iy, lw - 4, ITEM_H - 1, 0x1a1a2a);
        }
        char display[512];
        const char *name = state.files[fi].path;
            /* show base name */
        char tmp[PATH_MAX_LEN];
        strncpy(tmp, name, sizeof(tmp) - 1);
        const char *base = basename(tmp);
        if (state.files[fi].hidden == 1) {
            snprintf(display, sizeof(display), " [HIDDEN]  %s", base);
            draw_text(lx + 6, iy + ITEM_H/2 - 6, display, c_hidden, font_fixed);
        } else if (state.files[fi].hidden == -1) {
            snprintf(display, sizeof(display), " [MISSING] %s", base);
            draw_text(lx + 6, iy + ITEM_H/2 - 6, display, c_danger, font_fixed);
        } else {
            snprintf(display, sizeof(display), " [VISIBLE] %s", base);
            draw_text(lx + 6, iy + ITEM_H/2 - 6, display, c_text, font_fixed);
        }
    }

    /* scroll indicators */
    if (state.list_scroll > 0) {
        draw_centered_text(lx, ly + ITEM_H + 2, lw, 16, "^", c_text_dim, font_fixed);
    }
    if (start + max_show < state.file_count) {
        int sy = ly + lh - 16;
        draw_centered_text(lx, sy, lw, 16, "v", c_text_dim, font_fixed);
    }

    /* right panel - buttons */
    int rx = lx + lw + PADDING;
    int ry = TITLE_H + PADDING;
    int rw = 200;

    draw_round_rect(rx, ry, rw, 200, c_surface, 6);
    draw_text(rx + 12, ry + 14, "Actions", c_accent, font_bold);
    draw_line(rx + 10, ry + 28, rx + rw - 10, ry + 28, c_border);

    add_widget(1, rx + 10, ry + 36, rw - 20, BTN_H, "Add File",     TAG_ADD_BTN);
    add_widget(1, rx + 10, ry + 76, rw - 20, BTN_H, "Remove",       TAG_REMOVE_BTN);
    add_widget(1, rx + 10, ry + 116, rw - 20, BTN_H, "Hide",     TAG_HIDE_BTN);
    add_widget(1, rx + 10, ry + 156, rw - 20, BTN_H, "Unhide",   TAG_UNHIDE_BTN);

    int ry2 = ry + 210;
    draw_round_rect(rx, ry2, rw, 120, c_surface, 6);
    draw_text(rx + 12, ry2 + 14, "Settings", c_accent, font_bold);
    draw_line(rx + 10, ry2 + 28, rx + rw - 10, ry2 + 28, c_border);

    add_widget(1, rx + 10, ry2 + 36, rw - 20, BTN_H, "Change Password", TAG_PWD_CHANGE);
    add_widget(1, rx + 10, ry2 + 76, rw - 20, BTN_H, "Exit",        TAG_EXIT_BTN);

    /* About button */
    add_widget(1, rx + 10, bh - STATUSBAR_H - BTN_H - PADDING, rw - 20, BTN_H,
               "About", TAG_ABOUT_BTN);
}

/* ================================================================
 * DIALOG: CHANGE PASSWORD
 * ================================================================ */
static int change_pwd_active = 0;
static char new_pwd_1[256] = {0};
static char new_pwd_2[256] = {0};
static char pwd_err[256] = {0};
static int pwd_show_new = 0, pwd_show_confirm = 0;

static void change_pwd_dialog(void) {
    change_pwd_active = 1;
    new_pwd_1[0] = 0;
    new_pwd_2[0] = 0;
    pwd_err[0] = 0;
    pwd_show_new = 0;
    pwd_show_confirm = 0;
}

static void draw_change_pwd(void) {
    if (!change_pwd_active) return;
    int dw = 380, dh = 280;
    int dx = (state.win_w - dw) / 2, dy = (state.win_h - dh) / 2 - 20;

    draw_rect(0, 0, state.win_w, state.win_h, c_overlay);
    draw_round_rect(dx, dy, dw, dh, c_surface, 8);
    draw_border(dx, dy, dw, dh, c_border);

    draw_centered_text(dx + 8, dy + 12, dw - 16, 28, "Change Master Password", c_text, font_bold);

    draw_text(dx + 20, dy + 52, "New Password:", c_text_dim, font_fixed);
    draw_text(dx + 20, dy + 108, "Confirm:", c_text_dim, font_fixed);

    /* input fields */
    add_widget(2, dx + 20, dy + 66, dw - 40, INPUT_H, "", TAG_NEW_PWD);
    add_widget(2, dx + 20, dy + 122, dw - 40, INPUT_H, "", TAG_NEW_CONFIRM);

    Widget *np = find_widget_by_tag(TAG_NEW_PWD);
    Widget *nc = find_widget_by_tag(TAG_NEW_CONFIRM);
    if (np) strncpy(np->text, new_pwd_1, sizeof(np->text)-1);
    if (nc) strncpy(nc->text, new_pwd_2, sizeof(nc->text)-1);

    /* show/hide toggles */
    add_widget(1, dx + dw - 80, dy + 68, 60, 22, pwd_show_new ? "Hide" : "Show", TAG_LOGIN_SHOW + 100);
    add_widget(1, dx + dw - 80, dy + 124, 60, 22, pwd_show_confirm ? "Hide" : "Show", TAG_LOGIN_SHOW + 101);

    /* error message */
    if (pwd_err[0]) {
        draw_centered_text(dx, dy + 165, dw, 20, pwd_err, c_danger, font_fixed);
    }

    add_widget(1, dx + 20, dy + 195, (dw - 50) / 2, BTN_H, "OK", TAG_CHANGE_OK);
    add_widget(1, dx + 30 + (dw - 50) / 2, dy + 195, (dw - 50) / 2, BTN_H, "Cancel", TAG_CHANGE_CANCEL);
}

/* ================================================================
 * DIALOG: ABOUT
 * ================================================================ */
static int about_active = 0;
static void about_dialog(void) {
    about_active = 1;
}

static void draw_about(void) {
    if (!about_active) return;
    int dw = 340, dh = 200;
    int dx = (state.win_w - dw) / 2, dy = (state.win_h - dh) / 2 - 20;

    draw_rect(0, 0, state.win_w, state.win_h, c_overlay);
    draw_round_rect(dx, dy, dw, dh, c_surface, 8);
    draw_border(dx, dy, dw, dh, c_border);

    draw_centered_text(dx, dy + 15, dw, 30, "FileGuard v" APP_VERSION, c_primary, font_bold);
    draw_centered_text(dx, dy + 55, dw, 20, "File Protection Service", c_text, font_fixed);
    draw_centered_text(dx, dy + 82, dw, 20, "Hide sensitive files with", c_text_dim, font_fixed);
    draw_centered_text(dx, dy + 100, dw, 20, "AES-256 encrypted vault", c_text_dim, font_fixed);
    draw_centered_text(dx, dy + 135, dw, 20, "2026 FileGuard", c_text_dim, font_fixed);

    add_widget(1, dx + (dw - 100) / 2, dy + dh - 50, 100, BTN_H, "OK", 9999);
}

/* ================================================================
 * APP LOGIC
 * ================================================================ */
static void add_file_action(void) {
    /* use zenity for file selection */
    FILE *fp = popen("zenity --file-selection --title=\"Select a file or directory to protect\" 2>/dev/null", "r");
    if (!fp) return;
    char path[PATH_MAX_LEN];
    if (!fgets(path, sizeof(path), fp)) { pclose(fp); return; }
    pclose(fp);
    int len = strlen(path);
    while (len > 0 && (path[len-1] == '\n' || path[len-1] == '\r')) path[--len] = 0;
    if (len == 0) return;
    /* check if already in list */
    for (int i = 0; i < state.file_count; i++)
        if (strcmp(state.files[i].path, path) == 0) return;
    if (state.file_count >= MAX_FILES) return;
    strncpy(state.files[state.file_count].path, path, PATH_MAX_LEN - 1);
    state.files[state.file_count].hidden = is_hidden_file(path) ? 1 : 0;
    state.file_count++;
    vault_save(state.master_pwd);
    main_view();
}

static void remove_file_action(void) {
    if (state.list_sel_count == 0) return;
    int new_count = 0;
    for (int i = 0; i < state.file_count; i++) {
        int should_remove = 0;
        for (int s = 0; s < state.list_sel_count; s++)
            if (state.list_sel[s] == i) { should_remove = 1; break; }
        if (!should_remove) {
            state.files[new_count++] = state.files[i];
        }
    }
    state.file_count = new_count;
    state.list_sel_count = 0;
    state.list_scroll = 0;
    vault_save(state.master_pwd);
    main_view();
}

static void hide_selected(void) {
    for (int s = 0; s < state.list_sel_count; s++) {
        int i = state.list_sel[s];
        int res = hide_file(state.files[i].path);
        if (res == 1) {
            state.files[i].hidden = 1;
            /* update path to include dot */
            char dir[PATH_MAX_LEN];
            strncpy(dir, state.files[i].path, sizeof(dir)-1);
            char *dn = dirname(dir);
            char base[PATH_MAX_LEN];
            strncpy(base, state.files[i].path, sizeof(base)-1);
            const char *bn = basename(base);
            char newp[PATH_MAX_LEN];
            snprintf(newp, sizeof(newp), "%s/.%s", dn, bn);
            strncpy(state.files[i].path, newp, PATH_MAX_LEN-1);
        }
    }
    vault_save(state.master_pwd);
    main_view();
}

static void unhide_selected(void) {
    for (int s = 0; s < state.list_sel_count; s++) {
        int i = state.list_sel[s];
        int res = hide_file(state.files[i].path);
        if (res == 2) {
            state.files[i].hidden = 0;
            /* strip the dot */
            char dir[PATH_MAX_LEN];
            strncpy(dir, state.files[i].path, sizeof(dir)-1);
            char *dn = dirname(dir);
            char base[PATH_MAX_LEN];
            strncpy(base, state.files[i].path, sizeof(base)-1);
            const char *bn = basename(base);
            if (bn[0] == '.') {
                char newp[PATH_MAX_LEN];
                snprintf(newp, sizeof(newp), "%s/%s", dn, bn + 1);
                strncpy(state.files[i].path, newp, PATH_MAX_LEN-1);
            }
        }
    }
    vault_save(state.master_pwd);
    main_view();
}

static void change_pwd_ok(void) {
    int pwlen = strlen(new_pwd_1);
    if (pwlen < 4) {
        snprintf(pwd_err, sizeof(pwd_err), "Password must be at least 4 characters");
        return;
    }
    if (strcmp(new_pwd_1, new_pwd_2) != 0) {
        snprintf(pwd_err, sizeof(pwd_err), "Passwords do not match");
        return;
    }
    set_master_pwd(new_pwd_1);
    strncpy(state.master_pwd, new_pwd_1, sizeof(state.master_pwd)-1);
    vault_save(state.master_pwd);
    change_pwd_active = 0;
    about_active = 0;
    main_view();
}

/* ================================================================
 * DRAWING FUNCTIONS
 * ================================================================ */
static void draw_widget(Widget *wd) {
    switch (wd->type) {
    case 1: { /* button */
        unsigned long bg = c_primary;
        unsigned long fg = c_text;
        if (wd->state == 1) bg = c_primary_hv;
        if (wd->state == 2) bg = c_accent;
        if (wd->tag == TAG_EXIT_BTN || wd->tag == TAG_CHANGE_CANCEL) {
            bg = c_danger;
            if (wd->state == 1) bg = c_danger_hv;
        }
        if (wd->tag == TAG_SETUP_BTN || wd->tag == TAG_LOGIN_BTN || wd->tag == TAG_CHANGE_OK) {
            bg = c_success;
            if (wd->state == 1) bg = 0x2ECC71;
        }
        draw_round_rect(wd->x, wd->y, wd->w, wd->h, bg, 4);
        if (wd->tag == TAG_LOGIN_SHOW || wd->tag == TAG_LOGIN_SHOW+100 ||
            wd->tag == TAG_LOGIN_SHOW+101) {
            bg = c_surface;
            draw_round_rect(wd->x, wd->y, wd->w, wd->h, bg, 4);
            draw_border(wd->x, wd->y, wd->w, wd->h, c_border);
        }
        draw_centered_text(wd->x, wd->y, wd->w, wd->h, wd->text, fg, font_fixed);
        break;
    }
    case 2: { /* input */
        draw_round_rect(wd->x, wd->y, wd->w, wd->h, c_input_bg, 4);
        draw_border(wd->x, wd->y, wd->w, wd->h, wd->focused ? c_primary : c_border);
        char display[512];
        int show = 1;
        if (wd->tag == TAG_SETUP_PWD || wd->tag == TAG_SETUP_CONFIRM ||
            wd->tag == TAG_LOGIN_PWD || wd->tag == TAG_NEW_PWD ||
            wd->tag == TAG_NEW_CONFIRM) {
            show = 0;
            if ((wd->tag == TAG_SETUP_PWD || wd->tag == TAG_SETUP_CONFIRM) && state.show_password)
                show = 1;
            if (wd->tag == TAG_LOGIN_PWD && state.show_password)
                show = 1;
            if (wd->tag == TAG_NEW_PWD && pwd_show_new)
                show = 1;
            if (wd->tag == TAG_NEW_CONFIRM && pwd_show_confirm)
                show = 1;
        }
        if (show) {
            strncpy(display, wd->text, sizeof(display)-1);
        } else {
            int l = strlen(wd->text);
            for (int i = 0; i < l && i < (int)sizeof(display)-1; i++)
                display[i] = '*';
            display[l] = 0;
        }
        draw_text(wd->x + 8, wd->y + (wd->h - font_fixed->ascent)/2 + font_fixed->ascent - 2,
                  display, c_text, font_fixed);
        /* cursor */
        if (wd->focused) {
            int cx = wd->x + 8 + text_width(display, font_fixed);
            if (cx < wd->x + wd->w - 4) {
                XSetForeground(dpy, gc, c_text);
                XDrawLine(dpy, win, gc, cx, wd->y + 4, cx, wd->y + wd->h - 4);
            }
        }
        break;
    }
    }
}

static void redraw(void) {
    XClearWindow(dpy, win);

    switch (state.current_view) {
    case 0: login_view(); break;
    case 1: setup_view(); break;
    case 2: main_view(); break;
    }

    if (change_pwd_active) draw_change_pwd();
    if (about_active) draw_about();

    for (int i = 0; i < state.widget_count; i++)
        draw_widget(&state.widgets[i]);

    XFlush(dpy);
}

/* ================================================================
 * EVENT HANDLING
 * ================================================================ */
static void handle_key_event(XKeyEvent *ev) {
    char buf[32];
    KeySym ks;
    int len = XLookupString(ev, buf, sizeof(buf), &ks, NULL);

    /* find focused input */
    Widget *input = NULL;
    for (int i = 0; i < state.widget_count; i++) {
        if (state.widgets[i].type == 2 && state.widgets[i].focused) {
            input = &state.widgets[i];
            break;
        }
    }
    if (!input) {
        /* If in main view and no focused input, handle Enter on selection */
        if (ev->type == KeyPress && ks == XK_Return && state.current_view == 2) {
            /* could do toggle on selected item */
        }
        return;
    }

    if (ev->type != KeyPress) return;

    int tag = input->tag;
    int maxlen = sizeof(input->text) - 1;

    if (ks == XK_BackSpace) {
        int l = strlen(input->text);
        if (l > 0) input->text[l - 1] = 0;
        /* sync to local vars */
        if (tag == TAG_NEW_PWD) { strncpy(new_pwd_1, input->text, sizeof(new_pwd_1)-1); }
        if (tag == TAG_NEW_CONFIRM) { strncpy(new_pwd_2, input->text, sizeof(new_pwd_2)-1); }
        return;
    }
    if (ks == XK_Return) {
        if (state.current_view == 0) {
            /* login */
            if (verify_master_pwd(input->text)) {
                strncpy(state.master_pwd, input->text, sizeof(state.master_pwd)-1);
                vault_load(state.master_pwd);
                state.authenticated = 1;
                main_view();
            } else {
                /* wrong password */
                input->text[0] = 0;
                redraw();
            }
        } else if (state.current_view == 1) {
            /* setup - find both fields */
            Widget *pwd = find_widget_by_tag(TAG_SETUP_PWD);
            Widget *cnf = find_widget_by_tag(TAG_SETUP_CONFIRM);
            if (pwd && cnf && strlen(pwd->text) >= 4 &&
                strcmp(pwd->text, cnf->text) == 0) {
                set_master_pwd(pwd->text);
                strncpy(state.master_pwd, pwd->text, sizeof(state.master_pwd)-1);
                vault_save(state.master_pwd);
                state.authenticated = 1;
                main_view();
            }
        }
        return;
    }
    if (ks == XK_Tab) {
        /* cycle focus */
        int cur = -1;
        for (int i = 0; i < state.widget_count; i++) {
            if (state.widgets[i].type == 2 && state.widgets[i].focused) { cur = i; break; }
        }
        if (cur >= 0) {
            state.widgets[cur].focused = 0;
            int next = (cur + 1) % state.widget_count;
            int tries = 0;
            while (state.widgets[next].type != 2 && tries < state.widget_count) {
                next = (next + 1) % state.widget_count;
                tries++;
            }
            if (state.widgets[next].type == 2) state.widgets[next].focused = 1;
        } else {
            for (int i = 0; i < state.widget_count; i++) {
                if (state.widgets[i].type == 2) { state.widgets[i].focused = 1; break; }
            }
        }
        return;
    }
    if (ks >= XK_F1 && ks <= XK_F12) return;
    if (len > 0 && buf[0] >= 32) {
        int l = strlen(input->text);
        if (l < maxlen) {
            input->text[l] = buf[0];
            input->text[l+1] = 0;
        }
        /* sync local for change pwd */
        if (tag == TAG_NEW_PWD) strncpy(new_pwd_1, input->text, sizeof(new_pwd_1)-1);
        if (tag == TAG_NEW_CONFIRM) strncpy(new_pwd_2, input->text, sizeof(new_pwd_2)-1);
    }
}

static void handle_button_event(XButtonEvent *ev) {
    if (change_pwd_active && about_active) {
        about_active = 0;
        redraw();
        return;
    }

    if (change_pwd_active) {
        if (ev->type == ButtonPress) {
            Widget *wd = find_widget(ev->x, ev->y);
            if (!wd) return;
            if (wd->tag == TAG_CHANGE_OK) { change_pwd_ok(); redraw(); return; }
            if (wd->tag == TAG_CHANGE_CANCEL) { change_pwd_active = 0; redraw(); return; }
            if (wd->tag == TAG_LOGIN_SHOW+100) { pwd_show_new = !pwd_show_new; redraw(); return; }
            if (wd->tag == TAG_LOGIN_SHOW+101) { pwd_show_confirm = !pwd_show_confirm; redraw(); return; }
        }
        return;
    }

    if (about_active) {
        if (ev->type == ButtonPress) {
            Widget *wd = find_widget(ev->x, ev->y);
            if (wd && wd->tag == 9999) { about_active = 0; redraw(); return; }
        }
        return;
    }

    if (ev->type == ButtonPress) {
        Widget *wd = find_widget(ev->x, ev->y);
        if (!wd) {
            /* maybe click on list item */
            if (state.current_view == 2) {
                int lx = PADDING, ly = TITLE_H + PADDING;
                int lw = state.win_w - 220 - PADDING * 3;
                int lh = state.win_h - TITLE_H - STATUSBAR_H - PADDING * 2;
                if (ev->x >= lx && ev->x < lx + lw && ev->y >= ly + ITEM_H + 2 &&
                    ev->y < ly + lh) {
                    int idx = (ev->y - ly - ITEM_H - 2) / ITEM_H + state.list_scroll;
                    if (idx >= 0 && idx < state.file_count) {
                        /* toggle selection */
                        int found = -1;
                        for (int s = 0; s < state.list_sel_count; s++)
                            if (state.list_sel[s] == idx) { found = s; break; }
                        if (found >= 0) {
                            for (int s = found; s < state.list_sel_count - 1; s++)
                                state.list_sel[s] = state.list_sel[s+1];
                            state.list_sel_count--;
                        } else {
                            state.list_sel[state.list_sel_count++] = idx;
                        }
                        redraw();
                    }
                }
            }
            return;
        }

        /* focus input */
        if (wd->type == 2) {
            for (int i = 0; i < state.widget_count; i++)
                state.widgets[i].focused = (state.widgets[i].type == 2 && &state.widgets[i] == wd);
        }

        /* handle button click */
        if (wd->type == 1) {
            if (state.current_view == 0) { /* login */
                if (wd->tag == TAG_LOGIN_BTN) {
                    Widget *pwd = find_widget_by_tag(TAG_LOGIN_PWD);
                    if (pwd && verify_master_pwd(pwd->text)) {
                        strncpy(state.master_pwd, pwd->text, sizeof(state.master_pwd)-1);
                        vault_load(state.master_pwd);
                        state.authenticated = 1;
                        main_view();
                        redraw();
                    } else if (pwd) {
                        pwd->text[0] = 0;
                        redraw();
                    }
                }
                if (wd->tag == TAG_LOGIN_SHOW) {
                    state.show_password = !state.show_password;
                    redraw();
                }
            } else if (state.current_view == 1) { /* setup */
                if (wd->tag == TAG_SETUP_BTN) {
                    Widget *pwd = find_widget_by_tag(TAG_SETUP_PWD);
                    Widget *cnf = find_widget_by_tag(TAG_SETUP_CONFIRM);
                    if (pwd && cnf && strlen(pwd->text) >= 4 &&
                        strcmp(pwd->text, cnf->text) == 0) {
                        set_master_pwd(pwd->text);
                        strncpy(state.master_pwd, pwd->text, sizeof(state.master_pwd)-1);
                        vault_save(state.master_pwd);
                        state.authenticated = 1;
                        main_view();
                        redraw();
                    } else if (pwd && cnf && strlen(pwd->text) < 4) {
                        strncpy(pwd->text, "Too short!", sizeof(pwd->text)-1);
                        pwd->focused = 0;
                        cnf->focused = 0;
                        redraw();
                    } else if (pwd && cnf && strcmp(pwd->text, cnf->text) != 0) {
                        strncpy(pwd->text, "No match!", sizeof(pwd->text)-1);
                        pwd->focused = 0;
                        cnf->focused = 0;
                        redraw();
                    }
                }
                if (wd->tag == TAG_SETUP_SHOW) {
                    state.show_password = !state.show_password;
                    redraw();
                }
            } else if (state.current_view == 2) { /* main */
                switch (wd->tag) {
                case TAG_ADD_BTN:    add_file_action(); redraw(); break;
                case TAG_REMOVE_BTN: remove_file_action(); redraw(); break;
                case TAG_HIDE_BTN:   hide_selected(); redraw(); break;
                case TAG_UNHIDE_BTN: unhide_selected(); redraw(); break;
                case TAG_PWD_CHANGE: change_pwd_dialog(); redraw(); break;
                case TAG_EXIT_BTN:   state.running = 0; break;
                case TAG_ABOUT_BTN:  about_dialog(); redraw(); break;
                }
            }
        }
    }
}

static void handle_motion_event(XMotionEvent *ev) {
    int changed = 0;
    for (int i = 0; i < state.widget_count; i++) {
        Widget *wd = &state.widgets[i];
        if (wd->type != 1) continue;
        int hover = (ev->x >= wd->x && ev->x < wd->x + wd->w &&
                     ev->y >= wd->y && ev->y < wd->y + wd->h);
        if (hover != (wd->state == 1)) { wd->state = hover ? 1 : 0; changed = 1; }
    }
    if (changed) {
        for (int i = 0; i < state.widget_count; i++)
            draw_widget(&state.widgets[i]);
        XFlush(dpy);
    }
}

/* ================================================================
 * EVENT LOOP
 * ================================================================ */
static void event_loop(void) {
    XEvent ev;
    while (state.running) {
        XNextEvent(dpy, &ev);
        switch (ev.type) {
        case Expose:
            if (ev.xexpose.count == 0) redraw();
            break;
        case ConfigureNotify:
            if (ev.xconfigure.width != state.win_w || ev.xconfigure.height != state.win_h) {
                state.win_w = ev.xconfigure.width;
                state.win_h = ev.xconfigure.height;
                redraw();
            }
            break;
        case KeyPress:
            handle_key_event(&ev.xkey);
            redraw();
            break;
        case ButtonPress:
        case ButtonRelease:
            handle_button_event(&ev.xbutton);
            break;
        case MotionNotify:
            handle_motion_event(&ev.xmotion);
            break;
        case ClientMessage:
            if ((Atom)ev.xclient.data.l[0] == wm_delete)
                state.running = 0;
            break;
        }
    }
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(void) {
    dpy = XOpenDisplay(NULL);
    if (!dpy) {
        fprintf(stderr, "FileGuard: Cannot open display\n");
        return 1;
    }

    int scr = DefaultScreen(dpy);
    Window root = RootWindow(dpy, scr);

    font_fixed = XLoadQueryFont(dpy, "fixed");
    if (!font_fixed) font_fixed = XLoadQueryFont(dpy, "6x10");
    if (!font_fixed) font_fixed = XLoadQueryFont(dpy, "7x13");
    if (!font_fixed) {
        fprintf(stderr, "FileGuard: Cannot load any font\n");
        return 1;
    }
    font_bold = XLoadQueryFont(dpy, "9x15bold");
    if (!font_bold) font_bold = font_fixed;

    /* create window */
    state.win_w = WIN_W;
    state.win_h = WIN_H;

    win = XCreateSimpleWindow(dpy, root, 100, 100, state.win_w, state.win_h,
                               0, alloc_color(COL_BORDER), alloc_color(COL_BG));

    /* window properties */
    XStoreName(dpy, win, APP_NAME);
    XSetIconName(dpy, win, APP_NAME);

    /* input masks */
    XSelectInput(dpy, win, ExposureMask | KeyPressMask | ButtonPressMask |
                         ButtonReleaseMask | PointerMotionMask |
                         StructureNotifyMask | FocusChangeMask);

    /* WM close button */
    wm_delete = XInternAtom(dpy, "WM_DELETE_WINDOW", False);
    wm_protocols = XInternAtom(dpy, "WM_PROTOCOLS", False);
    XSetWMProtocols(dpy, win, &wm_delete, 1);

    /* cursors */
    hand_cursor = XCreateFontCursor(dpy, XC_hand2);
    text_cursor = XCreateFontCursor(dpy, XC_xterm);

    gc = XCreateGC(dpy, win, 0, NULL);
    init_colors();

    XMapWindow(dpy, win);

    /* initialize state */
    memset(&state, 0, sizeof(state));
    state.running = 1;

    /* check if master password exists */
    ensure_vault_dir();
    if (master_pwd_exists()) {
        login_view();
    } else {
        setup_view();
    }

    redraw();
    event_loop();

    /* cleanup */
    XFreeGC(dpy, gc);
    XDestroyWindow(dpy, win);
    XCloseDisplay(dpy);
    return 0;
}
