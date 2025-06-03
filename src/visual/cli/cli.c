#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>

#define JULIE_IMPL
#include "julie.h"

#define TERM_BLACK                   "\033[0;30m"
#define TERM_BLUE                    "\033[0;34m"
#define TERM_GREEN                   "\033[0;32m"
#define TERM_CYAN                    "\033[0;36m"
#define TERM_RED                     "\033[0;31m"
#define TERM_PURPLE                  "\033[0;35m"
#define TERM_BROWN                   "\033[0;33m"
#define TERM_GRAY                    "\033[0;37m"
#define TERM_DARK_GRAY               "\033[1;30m"
#define TERM_LIGHT_BLUE              "\033[1;34m"
#define TERM_LIGHT_GREEN             "\033[1;32m"
#define TERM_LIGHT_CYAN              "\033[1;36m"
#define TERM_LIGHT_RED               "\033[1;31m"
#define TERM_LIGHT_PURPLE            "\033[1;35m"
#define TERM_YELLOW                  "\033[1;33m"
#define TERM_WHITE                   "\033[1;37m"
#define TERM_BG_BLACK                "\033[0;40m"
#define TERM_BG_BLUE                 "\033[0;44m"
#define TERM_BG_GREEN                "\033[0;42m"
#define TERM_BG_CYAN                 "\033[0;46m"
#define TERM_BG_RED                  "\033[0;41m"
#define TERM_BG_PURPLE               "\033[0;45m"
#define TERM_BG_GREY                 "\033[0;47m"
#define TERM_BG_WHITE                "\033[1;47m"
#define TERM_INVERSE                 "\033[7m"
#define TERM_SAVE                    "\0337"
#define TERM_RESTORE                 "\0338"
#define TERM_RESET                   "\033[0m"

#define TERM_ALT_SCREEN              "\033[?1049h"
#define TERM_STD_SCREEN              "\033[?1049l"
#define TERM_CLEAR_SCREEN            "\033[2J"
#define TERM_CLEAR_LINE_L            "\033[1K"
#define TERM_CLEAR_LINE_R            "\033[0K"
#define TERM_CLEAR_LINE              "\033[2K"
#define TERM_SCROLL_UP               "\033[1U"
#define TERM_SCROLL_DOWN             "\033[1S"

#define TERM_CURSOR_HOME             "\033[H"
#define TERM_CURSOR_HIDE             "\033[?25l"
#define TERM_CURSOR_SHOW             "\033[?25h"
#define TERM_CURSOR_MOVE_BEG         "\033["
#define TERM_CURSOR_MOVE_SEP         ";"
#define TERM_CURSOR_MOVE_END         "H"
#define TERM_ENABLE_BRACKETED_PASTE  "\033[?2004h"
#define TERM_DISABLE_BRACKETED_PASTE "\033[?2004l"

#define TERM_MOUSE_BUTTON_ENABLE     "\033[?1002h"
#define TERM_MOUSE_BUTTON_DISABLE    "\033[?1002l"
#define TERM_MOUSE_ANY_ENABLE        "\033[?1003h"
#define TERM_MOUSE_ANY_DISABLE       "\033[?1003l"
#define TERM_SGR_1006_ENABLE         "\033[?1006h"
#define TERM_SGR_1006_DISABLE        "\033[?1006l"

#define TERM_DEFAULT_READ_TIMEOUT (3)

enum {
    KEY_NULL  = 0,    /* NULL      */
    CTRL_A    = 1,    /* Ctrl-a    */
    CTRL_B    = 2,    /* Ctrl-b    */
    CTRL_C    = 3,    /* Ctrl-c    */
    CTRL_D    = 4,    /* Ctrl-d    */
    CTRL_E    = 5,    /* Ctrl-e    */
    CTRL_F    = 6,    /* Ctrl-f    */
    CTRL_G    = 7,    /* Ctrl-g    */
    CTRL_H    = 8,    /* Ctrl-h    */
    TAB       = 9,    /* Tab       */
    CTRL_J    = 10,   /* Ctrl-j    */
    NEWLINE   = 10,   /* Newline   */
    CTRL_K    = 11,   /* Ctrl-k    */
    CTRL_L    = 12,   /* Ctrl-l    */
    ENTER     = 13,   /* Enter     */
    CTRL_N    = 14,   /* Ctrl-n    */
    CTRL_O    = 15,   /* Ctrl-o    */
    CTRL_P    = 16,   /* Ctrl-p    */
    CTRL_Q    = 17,   /* Ctrl-q    */
    CTRL_R    = 18,   /* Ctrl-r    */
    CTRL_S    = 19,   /* Ctrl-s    */
    CTRL_T    = 20,   /* Ctrl-t    */
    CTRL_U    = 21,   /* Ctrl-u    */
    CTRL_V    = 22,   /* Ctrl-v    */
    CTRL_W    = 23,   /* Ctrl-w    */
    CTRL_X    = 24,   /* Ctrl-x    */
    CTRL_Y    = 25,   /* Ctrl-y    */
    CTRL_Z    = 26,   /* Ctrl-z    */
    ESC       = 27,   /* Escape    */
    CTRL_FS   = 31,   /* Ctrl-/    */
    BACKSPACE = 127,  /* Backspace */

    ASCII_KEY_MAX = 256,

    /* The following are just soft codes, not really reported by the
     * terminal directly. */
    ARROW_LEFT = 300,
    ARROW_RIGHT,
    ARROW_UP,
    ARROW_DOWN,
    CTRL_ARROW_LEFT,
    CTRL_ARROW_RIGHT,
    CTRL_ARROW_UP,
    CTRL_ARROW_DOWN,
    DEL_KEY,
    HOME_KEY,
    END_KEY,
    PAGE_UP,
    PAGE_DOWN,
    SHIFT_TAB,
    FN1 = 330,
    FN2 = 331,
    FN3 = 332,
    FN4 = 333,
    FN5 = 334,
    FN6 = 335,
    FN7 = 336,
    FN8 = 337,
    FN9 = 338,
    FN10 = 339,
    FN11 = 340,
    FN12 = 341,
    MENU_KEY,
};

#define CTRL_KEY(c) ((c) & 0x9F)

#define IS_ARROW(k) ((k) >= ARROW_LEFT && (k) <= ARROW_DOWN)

#define MOUSE_PRESS        (0)
#define MOUSE_RELEASE      (1)
#define MOUSE_DRAG         (2)
#define MOUSE_OVER         (3)

#define MOUSE_BUTTON_LEFT   (0)
#define MOUSE_BUTTON_MIDDLE (1)
#define MOUSE_BUTTON_RIGHT  (2)
#define MOUSE_WHEEL_UP      (3)
#define MOUSE_WHEEL_DOWN    (4)

#define IS_MOUSE(k) ((k) < 0)

#define MOUSE_KIND(k)   (((k) >> 28) & 0x7)
#define MOUSE_BUTTON(k) (((k) >> 24) & 0xf)
#define MOUSE_ROW(k)    (((k) >> 12) & 0xfff)
#define MOUSE_COL(k)    (((k) >> 0)  & 0xfff)

#define MK_MOUSE(k, b, r, c) \
    (((((k) & 0x7)   << 28) \
    | (((b) & 0xf)   << 24) \
    | (((r) & 0xfff) << 12) \
    | (((c) & 0xfff) << 0)) \
    | 0x80000000)


typedef union {
    char          c;
    unsigned char u_c;
    unsigned char bytes[4];
} Glyph;

#define G_IS_ASCII(g) (!((g)->u_c >> 7))

static const unsigned char _utf8_lens[] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 4, 1
};

#define glyph_len(g)                          \
    (likely(G_IS_ASCII(g))                    \
        ? 1                                   \
        : (int)(_utf8_lens[(g)->u_c >> 3ULL]))

typedef struct {
    int      bg_set;
    unsigned bg;
    int      fg_set;
    unsigned fg;
    Glyph    glyph;
    int      dirty;
} Screen_Cell;

typedef struct {
    int          cur_bg_set;
    unsigned     cur_bg;
    int          cur_fg_set;
    unsigned     cur_fg;
    unsigned     cur_row;
    unsigned     cur_col;
    Screen_Cell *cells;
} Screen;




static Julie_Interp   *interp;
static struct termios  save_term;
static int             term_set;
static unsigned        term_height;
static unsigned        term_width;
static int             term_resized;
static Screen          screen1;
static Screen          screen2;
static Screen         *update_screen = &screen1;
static Screen         *render_screen = &screen2;


static void on_julie_error(Julie_Error_Info *info);
static void set_term(void);
static void restore_term(void);
static int  read_keys(int *input);
static void init_event(void);
static void resize_term(void);
static void resize_event(void);
static void mouse_event(int key);
static void key_event(int key);

static Julie_Status j_term_exit(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result);
static Julie_Status j_term_clear(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result);
static Julie_Status j_term_flush(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result);
static Julie_Status j_term_set_cell_bg(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result);
static Julie_Status j_term_set_cell_fg(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result);
static Julie_Status j_term_set_cell_char(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result);

#undef JULIE_BIND_FN
#define JULIE_BIND_FN(_name, _fn) julie_bind_fn(interp, julie_get_string_id(interp, (_name)), (_fn))

int render_visual(char **names, char **julie_code, int *julie_code_len, int argc, char **argv) {
    Julie_Status status;
    int          n;
    int          input[32];
    int          i;
    char         **code;
    int          *len;
    char         **name;

    interp = julie_init_interp();
    julie_set_error_callback(interp, on_julie_error);

    JULIE_BIND_FN("@term:exit",          j_term_exit);
    JULIE_BIND_FN("@term:clear",         j_term_clear);
    JULIE_BIND_FN("@term:flush",         j_term_flush);
    JULIE_BIND_FN("@term:set-cell-bg",   j_term_set_cell_bg);
    JULIE_BIND_FN("@term:set-cell-fg",   j_term_set_cell_fg);
    JULIE_BIND_FN("@term:set-cell-char", j_term_set_cell_char);

    julie_set_argv(interp, argc, argv);
    
    len = julie_code_len;
    code = julie_code;
    name = names;
    while ((*code) && (*len) && (*name)) {
        julie_set_cur_file(interp, julie_get_string_id(interp, *name));
        julie_parse(interp, (const char*)(*code), *len);
        code++;
        len++;
        name++;
    }

    set_term();

    status = julie_interp(interp);

    if (status != JULIE_SUCCESS) {
        restore_term();
        return status;
    }

    init_event();

    for (;;) {
        if (term_resized) {
            resize_term();
            resize_event();
        }

        n = read_keys(input);
        for (i = 0; i < n; i += 1) {
            if (IS_MOUSE(input[0])) {
                mouse_event(input[0]);
            } else {
                key_event(input[0]);
            }
        }
    }
    
    julie_free(interp);
    restore_term();
    
    return 0;
}

static void on_julie_error(Julie_Error_Info *info) {
    Julie_Status           status;
    const char           *blue;
    const char           *red;
    const char           *cyan;
    const char           *reset;
    char                 *s;
    unsigned              i;
    Julie_Backtrace_Entry *it;

    restore_term();

    status = info->status;

    if (isatty(2)) {
        blue  = "\033[34m";
        red   = "\033[31m";
        cyan  = "\033[36m";
        reset = "\033[0m";
    } else {
        blue = red = cyan = reset = "";
    }

    fprintf(stderr, "%s%s:%llu:%llu:%s %serror: %s",
            blue,
            info->file_id == NULL ? "<?>" : julie_get_cstring(info->file_id),
            info->line,
            info->col,
            reset,
            red,
            julie_error_string(status));

    switch (status) {
        case JULIE_ERR_LOOKUP:
            if (info->lookup.sym != NULL) {
                fprintf(stderr, " (%s)", info->lookup.sym);
            }
            break;
        case JULIE_ERR_RELEASE_WHILE_BORROWED:
            if (info->release_while_borrowed.sym != NULL) {
                fprintf(stderr, " (%s)", info->release_while_borrowed.sym);
            }
            break;
        case JULIE_ERR_REF_OF_TRANSIENT:
            if (info->ref_of_transient.sym != NULL) {
                fprintf(stderr, " (%s)", info->ref_of_transient.sym);
            }
            break;
        case JULIE_ERR_REF_OF_OBJECT_KEY:
            if (info->ref_of_object_key.sym != NULL) {
                fprintf(stderr, " (%s)", info->ref_of_object_key.sym);
            }
            break;
        case JULIE_ERR_NOT_LVAL:
            if (info->not_lval.sym != NULL) {
                fprintf(stderr, " (%s)", info->not_lval.sym);
            }
            break;
        case JULIE_ERR_MODIFY_WHILE_ITER:
            if (info->modify_while_iter.sym != NULL) {
                fprintf(stderr, " (%s)", info->modify_while_iter.sym);
            }
            break;
        case JULIE_ERR_ARITY:
            fprintf(stderr, " (wanted %s%llu, got %llu)",
                    info->arity.at_least ? "at least " : "",
                    info->arity.wanted_arity,
                    info->arity.got_arity);
            break;
        case JULIE_ERR_TYPE:
            fprintf(stderr, " (wanted %s, got %s)",
                    julie_type_string(info->type.wanted_type),
                    julie_type_string(info->type.got_type));
            break;
        case JULIE_ERR_BAD_APPLY:
            fprintf(stderr, " (got %s)", julie_type_string(info->bad_application.got_type));
            break;
        case JULIE_ERR_BAD_INDEX:
            s = julie_to_string(info->interp, info->bad_index.bad_index, 0);
            fprintf(stderr, " (index: %s)", s);
            free(s);
            break;
        case JULIE_ERR_FILE_NOT_FOUND:
        case JULIE_ERR_FILE_IS_DIR:
        case JULIE_ERR_MMAP_FAILED:
            fprintf(stderr, " (%s)", info->file.path);
            break;
        case JULIE_ERR_LOAD_PACKAGE_FAILURE:
            fprintf(stderr, " (%s) %s", info->load_package_failure.path, info->load_package_failure.package_error_message);
            break;
        default:
            break;
    }

    fprintf(stderr, "%s\n", reset);

    for (i = info->interp->apply_depth; i > 0; i -= 1) {
        if (i == info->interp->apply_depth) { continue; }

        it = &(((Julie_Apply_Context*)julie_array_elem(info->interp->apply_contexts, i - 1))->bt_entry);

        s = julie_to_string(info->interp, it->fn, 0);
        fprintf(stderr, "    %s%s:%llu:%llu%s %s%s%s\n",
                blue,
                it->file_id == NULL ? "<?>" : julie_get_cstring(it->file_id),
                it->line,
                it->col,
                reset,
                cyan,
                s,
                reset);
        free(s);
    }

    julie_free_error_info(info);

    exit(status);
}


static inline int s_to_i(const char *s) {
    int i;

    sscanf(s, "%d", &i);

    return i;
}

static int esc_timeout(int *input) {
    char c;

    /* input[0] is ESC */

    if (read(0, &c, 1) == 0) {
        return 1;
    }
    input[1] = c;

    if (input[1] != '['
    &&  input[1] != 'O'
    &&  input[1] != ESC) {
        return 2;
    }

    if (read(0, &c, 1) == 0) {
        return 2;
    }
    input[2] = c;

    return 3;
}

static int esc_sequence(int *input) {
    char c;
    char buff[64];
    int  i;
    int  k;
    int  b;
    int  x;
    int  y;
    int  mouse_mode;

    /* the input length is 3 */
    /* input[0] is ESC */

    if (input[1] == '[') { /* ESC [ sequences. */
        if (input[2] >= '0' && input[2] <= '9') {
            /* Extended escape, read additional byte. */
            if (read(0, &c, 1) == 0) {
                return 3;
            } else if (input[2] == '1') {
                input[3] = c;
                if (c == '~') {
                    input[0] = HOME_KEY;
                    return 1;
                } else if (c == ';') {
                    if (read(0, &c, 1) == 0) { return 4; }
                    input[4] = c;
                    if (c == '3') {
                        if (read(0, &c, 1) == 0) { return 5; }
                        input[5] = c;
                        switch (c) {
                            case 'A':
                                input[1] = ARROW_UP;
                                return 2;
                            case 'B':
                                input[1] = ARROW_DOWN;
                                return 2;
                            case 'C':
                                input[1] = ARROW_RIGHT;
                                return 2;
                            case 'D':
                                input[1] = ARROW_LEFT;
                                return 2;
                        }
                        return 6;
                    } else if (c == '5') {
                        if (read(0, &c, 1) == 0) { return 5; }
                        input[5] = c;
                        switch (c) {
                            case 'A':
                                input[1] = CTRL_ARROW_UP;
                                return 2;
                            case 'B':
                                input[1] = CTRL_ARROW_DOWN;
                                return 2;
                            case 'C':
                                input[1] = CTRL_ARROW_RIGHT;
                                return 2;
                            case 'D':
                                input[1] = CTRL_ARROW_LEFT;
                                return 2;
                        }
                        return 6;
                    }
                    return 5;
                } else if (c == '5') {
                    if (read(0, &c, 1) == 0) { return 4; }
                    input[4] = c;
                    if (c == '~') {
                        input[0] = FN5;
                        return 1;
                    }
                    return 5;
                } else if (c == '7') {
                    if (read(0, &c, 1) == 0) { return 4; }
                    input[4] = c;
                    if (c == '~') {
                        input[0] = FN6;
                        return 1;
                    }
                    return 5;
                } else if (c == '8') {
                    if (read(0, &c, 1) == 0) { return 4; }
                    input[4] = c;
                    if (c == '~') {
                        input[0] = FN7;
                        return 1;
                    }
                    return 5;
                } else if (c == '9') {
                    if (read(0, &c, 1) == 0) { return 4; }
                    input[4] = c;
                    if (c == '~') {
                        input[0] = FN8;
                        return 1;
                    }
                    return 5;
                }
                return 4;
            } else if (input[2] == '2') {
                if (c == '0') {
                    input[3] = c;

                    if (read(0, &c, 1) == 0) { return 4; }
                    input[4] = c;

                    if (c == '~') {
                        input[0] = FN9;
                        return 1;
                    }
                    return 5;
                } else if (c == '1') {
                    input[3] = c;
                    if (read(0, &c, 1) == 0) { return 4; }
                    input[4] = c;
                    if (c == '~') {
                        input[0] = FN10;
                        return 1;
                    }
                    return 5;
                } else if (c == '3') {
                    input[3] = c;
                    if (read(0, &c, 1) == 0) { return 4; }
                    input[4] = c;
                    if (c == '~') {
                        input[0] = FN11;
                        return 1;
                    }
                    return 5;
                } else if (c == '4') {
                    input[3] = c;
                    if (read(0, &c, 1) == 0) { return 4; }
                    input[4] = c;
                    if (c == '~') {
                        input[0] = FN12;
                        return 1;
                    }
                    return 5;
                }
                return 4;
            } else if (c == '~') {
                switch (input[2]) {
                    case '1':    { input[0] = HOME_KEY;  break; }
                    case '3':    { input[0] = DEL_KEY;   break; }
                    case '4':    { input[0] = END_KEY;   break; }
                    case '5':    { input[0] = PAGE_UP;   break; }
                    case '6':    { input[0] = PAGE_DOWN; break; }
                }
                return 1;
            } else if (input[2] == '5') {
                if (c == '7') {
                    input[3] = c;

                    if (read(0, &c, 1) == 0) { return 4; }
                    input[4] = c;
                    if (c == '3') {
                        if (read(0, &c, 1) == 0) { return 5; }
                        input[5] = c;
                        if (c == '6') {
                            if (read(0, &c, 1) == 0) { return 6; }
                            input[6] = c;
                            if (c == '3') {
                                if (read(0, &c, 1) == 0) { return 7; }
                                input[7] = c;
                                if (c == 'u') {
                                    input[0] = MENU_KEY;
                                    return 1;
                                }
                                return 8;
                            }
                            return 7;
                        }

                        return 6;
                    }
                    return 5;
                }
                return 4;
            }
        } else {
            switch (input[2]) {
                case 'A':    { input[0] = ARROW_UP;    break; }
                case 'B':    { input[0] = ARROW_DOWN;  break; }
                case 'C':    { input[0] = ARROW_RIGHT; break; }
                case 'D':    { input[0] = ARROW_LEFT;  break; }
                case 'H':    { input[0] = HOME_KEY;    break; }
                case 'F':    { input[0] = END_KEY;     break; }
                case 'P':    { input[0] = DEL_KEY;     break; }
                case 'Z':    { input[0] = SHIFT_TAB;   break; }
                case '<':    {
                    k = 0;

                    memset(buff, 0, sizeof(buff));
                    for (i = 0; read(0, &c, 1) && c != ';'; i += 1) { buff[i] = c; }
                    buff[i] = 0;
                    b = s_to_i(buff);

                    memset(buff, 0, sizeof(buff));
                    for (i = 0; read(0, &c, 1) && c != ';'; i += 1) { buff[i] = c; }
                    buff[i] = 0;
                    x = s_to_i(buff);

                    memset(buff, 0, sizeof(buff));
                    for (i = 0; read(0, &c, 1) && toupper(c) != 'M'; i += 1) { buff[i] = c; }
                    buff[i] = 0;
                    y = s_to_i(buff);
                    
                    mouse_mode = (b >> 5) & 3;
                    switch (mouse_mode) {
                        case 0:
                            /* Button event */
                            /* b is already the correct value */
                            k = (c == 'M') ? MOUSE_PRESS : MOUSE_RELEASE;
                            break;
                        case 1:
                            /* Movement event */
                            b = b - 32;
                            k = (b == 3) ? MOUSE_OVER : MOUSE_DRAG;
                            break;
                        case 2:
                            /* Wheel event */
                            b = MOUSE_WHEEL_UP + (b - 64);
                            k = MOUSE_PRESS;
                            break;
                        default:
                            return 0;
                    }

                    input[0] = MK_MOUSE(k, b, y, x);

                    break;
                }
            }
            return 1;
        }
    } else if (input[1] == 'O') { /* ESC O sequences. */
        switch (input[2]) {
            case 'A':    { input[0] = ARROW_UP;   break; }
            case 'B':    { input[0] = ARROW_DOWN; break; }
            case 'H':    { input[0] = HOME_KEY;   break; }
            case 'F':    { input[0] = END_KEY;    break; }
            case 'P':    { input[0] = FN1;        break; }
            case 'Q':    { input[0] = FN2;        break; }
            case 'R':    { input[0] = FN3;        break; }
            case 'S':    { input[0] = FN4;        break; }
        }
        return 1;
    }

    if (input[1] == ESC) {
        if (read(0, &c, 1)) {
            input[3] = c;
            if (input[2] == ESC && input[3] == ESC) { return 4; }
            return 1 + esc_sequence(input + 1);
        }
    }

    return 3;
}

static int read_keys(int *input) {
    int  len;
    int  nread;
    char c;

    len = 0;

    nread = read(0, &c, 1);
    if (nread <= 0) { return 0; }

    if (c == ESC) {
        input[0] = c;

        len = esc_timeout(input);

        if (len == 3) {
            len = esc_sequence(input);
        }
    } else if (c > 0) {
        input[0] = c;
        len      = 1;
    }

    return len;
}

char *key_to_string(int key) {
    char key_buff[16];

    switch (key) {
        case CTRL_A:
        case CTRL_B:
        case CTRL_C:
        case CTRL_D:
        case CTRL_E:
        case CTRL_F:
        case CTRL_G:
        case CTRL_H:
        case CTRL_J:
        case CTRL_K:
        case CTRL_L:
        case CTRL_N:
        case CTRL_O:
        case CTRL_P:
        case CTRL_Q:
        case CTRL_R:
        case CTRL_S:
        case CTRL_T:
        case CTRL_U:
        case CTRL_V:
        case CTRL_W:
        case CTRL_X:
        case CTRL_Y:
        case CTRL_Z:
            snprintf(key_buff, sizeof(key_buff), "ctrl-%c", 'a' + (key - CTRL_A));
            break;

        case CTRL_ARROW_LEFT:
            snprintf(key_buff, sizeof(key_buff), "ctrl-left");
            break;
        case CTRL_ARROW_RIGHT:
            snprintf(key_buff, sizeof(key_buff), "ctrl-right");
            break;
        case CTRL_ARROW_UP:
            snprintf(key_buff, sizeof(key_buff), "ctrl-up");
            break;
        case CTRL_ARROW_DOWN:
            snprintf(key_buff, sizeof(key_buff), "ctrl-down");
            break;

        case TAB:
            snprintf(key_buff, sizeof(key_buff), "tab");
            break;

        case ' ':
            snprintf(key_buff, sizeof(key_buff), "spc");
            break;

        case ENTER:
            snprintf(key_buff, sizeof(key_buff), "enter");
            break;

        case ESC:
            snprintf(key_buff, sizeof(key_buff), "esc");
            break;

        case CTRL_FS:
            snprintf(key_buff, sizeof(key_buff), "ctrl-/");
            break;

        case BACKSPACE:
            snprintf(key_buff, sizeof(key_buff), "bsp");
            break;

        case ARROW_LEFT:
            snprintf(key_buff, sizeof(key_buff), "left");
            break;
        case ARROW_RIGHT:
            snprintf(key_buff, sizeof(key_buff), "right");
            break;
        case ARROW_UP:
            snprintf(key_buff, sizeof(key_buff), "up");
            break;
        case ARROW_DOWN:
            snprintf(key_buff, sizeof(key_buff), "down");
            break;

        case DEL_KEY:
            snprintf(key_buff, sizeof(key_buff), "del");
            break;

        case HOME_KEY:
            snprintf(key_buff, sizeof(key_buff), "home");
            break;
        case END_KEY:
            snprintf(key_buff, sizeof(key_buff), "end");
            break;
        case PAGE_UP:
            snprintf(key_buff, sizeof(key_buff), "pageup");
            break;
        case PAGE_DOWN:
            snprintf(key_buff, sizeof(key_buff), "pagedown");
            break;

        case SHIFT_TAB:
            snprintf(key_buff, sizeof(key_buff), "shift-tab");
            break;

        case FN1:
        case FN2:
        case FN3:
        case FN4:
        case FN5:
        case FN6:
        case FN7:
        case FN8:
        case FN9:
        case FN10:
        case FN11:
        case FN12:
            snprintf(key_buff, sizeof(key_buff), "fn-%d", 1 + (key - FN1));
            break;

        case MENU_KEY:
            snprintf(key_buff, sizeof(key_buff), "menu");
            break;

        default:
            if (key < ASCII_KEY_MAX) {
                if (!isprint(key)) { return NULL; }
                snprintf(key_buff, sizeof(key_buff), "%c", (char)key);
            }
    }

    return strdup(key_buff);
}

static void init_event(void) {
    Julie_Value *fn;
    Julie_Value *list;
    Julie_Value *result;

    fn = julie_lookup(interp, julie_get_string_id(interp, "@on-init"));
    if (fn == NULL) { return; }

    list = julie_list_value(interp);
    JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "@on-init")));
    JULIE_ARRAY_PUSH(list->list, julie_sint_value(interp, term_height));
    JULIE_ARRAY_PUSH(list->list, julie_sint_value(interp, term_width));

    julie_eval(interp, list, &result);
    if (result != NULL) {
        julie_free_value(interp, result);
    }
    julie_free_value(interp, list);
}

static void resize_event(void) {
    Julie_Value *fn;
    Julie_Value *list;
    Julie_Value *result;

    fn = julie_lookup(interp, julie_get_string_id(interp, "@on-resize"));
    if (fn == NULL) { return; }

    list = julie_list_value(interp);
    JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "@on-resize")));
    JULIE_ARRAY_PUSH(list->list, julie_sint_value(interp, term_height));
    JULIE_ARRAY_PUSH(list->list, julie_sint_value(interp, term_width));

    julie_eval(interp, list, &result);
    if (result != NULL) {
        julie_free_value(interp, result);
    }
    julie_free_value(interp, list);
}

static void clear_screen(Screen *screen) {
    int n_cells;
    int n_bytes;

    n_cells = term_height * term_width;
    n_bytes = n_cells * sizeof(Screen_Cell);

    memset(screen->cells, 0, n_bytes);
}

static void get_term_size(void) {
    struct winsize ws;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != -1 && ws.ws_col > 0) {
        term_width  = ws.ws_col;
        term_height = ws.ws_row;
    }
}

static void resize_term(void) {
    int          n_cells;
    int          n_bytes;
    Screen_Cell *cell;
    int          i;

    get_term_size();

    n_cells = term_height * term_width;
    n_bytes = n_cells * sizeof(Screen_Cell);

    update_screen->cells = realloc(update_screen->cells, n_bytes);
    render_screen->cells = realloc(render_screen->cells, n_bytes);

    clear_screen(update_screen);
    clear_screen(render_screen);

    cell = render_screen->cells;
    for (i = 0; i < n_cells; i += 1) {
        cell->dirty  = 1;
        cell        += 1;
    }

    term_resized = 0;

    printf(TERM_RESET TERM_CURSOR_HOME TERM_CLEAR_SCREEN);
}

static void mouse_event(int mouse) {
    Julie_Value *fn;
    Julie_Value *list;
    Julie_Value *result;

    fn = julie_lookup(interp, julie_get_string_id(interp, "@on-mouse"));
    if (fn == NULL) { return; }

    list = julie_list_value(interp);
    JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "@on-mouse")));
    JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "'mouse")));
    if (MOUSE_KIND(mouse) == MOUSE_PRESS) {
        JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "'down")));
    } else if (MOUSE_KIND(mouse) == MOUSE_RELEASE) {
        JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "'up")));
    } else if (MOUSE_KIND(mouse) == MOUSE_DRAG) {
        JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "'drag")));
    } else if (MOUSE_KIND(mouse) == MOUSE_OVER) {
        JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "'over")));
    } else {
        JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "'???")));
    }
    if (MOUSE_BUTTON(mouse) == MOUSE_BUTTON_LEFT) {
        JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "'left")));
    } else if (MOUSE_BUTTON(mouse) == MOUSE_BUTTON_MIDDLE) {
        JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "'middle")));
    } else if (MOUSE_BUTTON(mouse) == MOUSE_BUTTON_RIGHT) {
        JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "'right")));
    } else {
        JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "'???")));
    }
    JULIE_ARRAY_PUSH(list->list, julie_sint_value(interp, MOUSE_ROW(mouse)));
    JULIE_ARRAY_PUSH(list->list, julie_sint_value(interp, MOUSE_COL(mouse)));

    julie_eval(interp, list, &result);
    if (result != NULL) {
        julie_free_value(interp, result);
    }
    julie_free_value(interp, list);
}

static void key_event(int code) {
    Julie_Value *fn;
    char        *str;
    Julie_Value *list;
    Julie_Value *result;

    fn = julie_lookup(interp, julie_get_string_id(interp, "@on-key"));
    if (fn == NULL) { return; }

    str = key_to_string(code);
    if (str == NULL) { return; }

    list = julie_list_value(interp);
    JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, "@on-key")));
    JULIE_ARRAY_PUSH(list->list, julie_string_value(interp, str));

    free(str);

    julie_eval(interp, list, &result);
    if (result != NULL) {
        julie_free_value(interp, result);
    }
    julie_free_value(interp, list);
}

static void sig_handler(int sig) {
    struct sigaction act;

    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;
    sigemptyset (&act.sa_mask);
    sigaction(sig, &act, NULL);

    /* Exit the terminal. */
    restore_term();

    /* Do the real signal. */
    kill(0, sig);
}

static void winch_handler(int sig) {
    term_resized = 1;
}

static void set_term(void) {
    struct termios   raw_term;
    struct sigaction sa;

    tcgetattr(0, &save_term);
    raw_term = save_term;

    raw_term.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

    /* output modes - disable post processing */
    /* raw_term.c_oflag &= ~(OPOST); */
    /* control modes - set 8 bit chars */
    raw_term.c_cflag |= (CS8);
    /* local modes - choing off, canonical off, no extended functions */
    raw_term.c_lflag &= ~(ECHO | ICANON | IEXTEN);


    /* control chars - set return condition: min number of bytes and timer. */

    /* Return each byte, or zero for timeout. */
    raw_term.c_cc[VMIN] = 0;
    /* 300 ms timeout (unit is tens of second). */
    raw_term.c_cc[VTIME] = TERM_DEFAULT_READ_TIMEOUT;

    tcsetattr(0, TCSAFLUSH, &raw_term);

    setvbuf(stdout, NULL, _IONBF, 0);

    sigemptyset(&sa.sa_mask);
    sa.sa_flags   = 0;
    sa.sa_handler = sig_handler;

    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGTSTP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);

    sigemptyset(&sa.sa_mask);
    sa.sa_flags   = 0;
    sa.sa_handler = winch_handler;
    sigaction(SIGWINCH,  &sa, NULL);

    printf(TERM_ALT_SCREEN);
/*     printf(TERM_MOUSE_BUTTON_ENABLE); */
    printf(TERM_MOUSE_ANY_ENABLE);
    printf(TERM_SGR_1006_ENABLE);
    printf(TERM_CURSOR_HIDE);

    printf(TERM_RESET TERM_CURSOR_HOME TERM_CLEAR_SCREEN);

    fflush(stdout);

    resize_term();

    term_set = 1;
}

static void restore_term(void) {
    if (!term_set) { return; }

    printf(TERM_MOUSE_ANY_DISABLE);
    printf(TERM_SGR_1006_DISABLE);
/*     printf(TERM_MOUSE_BUTTON_DISABLE); */
    printf(TERM_STD_SCREEN);
    printf(TERM_CURSOR_SHOW);

    fflush(stdout);

    tcsetattr(0, TCSAFLUSH, &save_term);
}

static void set_cell_bg(unsigned row, unsigned col, unsigned color) {
    unsigned     idx;
    Screen_Cell *cell;

    if (row == 0 || col == 0 || row > term_height || col > term_width) { return; }

    idx = ((row - 1) * term_width) + (col - 1);

    cell         = &(update_screen->cells[idx]);
    cell->bg     = color;
    cell->bg_set = 1;
}

static void set_cell_fg(unsigned row, unsigned col, unsigned color) {
    unsigned     idx;
    Screen_Cell *cell;

    if (row == 0 || col == 0 || row > term_height || col > term_width) { return; }

    idx = ((row - 1) * term_width) + (col - 1);

    cell         = &(update_screen->cells[idx]);
    cell->fg     = color;
    cell->fg_set = 1;
}

static void set_cell_glyph(unsigned row, unsigned col, const char *s) {
    unsigned     idx;
    Screen_Cell *cell;
    Glyph       *g;

    if (row == 0 || col == 0 || row > term_height || col > term_width) { return; }

    idx = ((row - 1) * term_width) + (col - 1);

    cell = &(update_screen->cells[idx]);

    memset(cell->glyph.bytes, 0, sizeof(cell->glyph.bytes));
    g = (Glyph*)s;
    memcpy(cell->glyph.bytes, g->bytes, glyph_len(g));
}

static void diff_and_swap_screens(void) {
    int          n_cells;
    Screen_Cell *ucell;
    Screen_Cell *rcell;
    int          i;
    int          rlen;
    int          ulen;
    int          dirty;
    int          j;

    n_cells = term_height * term_width;
    ucell   = update_screen->cells;
    rcell   = render_screen->cells;

    for (i = 0; i < n_cells; i += 1) {
        rlen  = glyph_len(&rcell->glyph);
        ulen  = glyph_len(&ucell->glyph);

        dirty = 0;

        if (rlen != ulen) {
            dirty = 1;
        } else {
            for (j = 0; j < rlen; j += 1) {
                if (rcell->glyph.bytes[j] != ucell->glyph.bytes[j]) {
                    dirty = 1;
                    break;
                }
            }
            if (!dirty) {
                dirty =    (rcell->bg_set     != ucell->bg_set)
                        || (rcell->bg         != ucell->bg)
                        || (rcell->fg_set     != ucell->fg_set)
                        || (rcell->fg         != ucell->fg);
            }
        }

        *rcell       = *ucell;
        rcell->dirty = dirty;

        ucell += 1;
        rcell += 1;
    }
}

void flush_screen(void) {
    Screen_Cell *cell;
    unsigned     row;
    unsigned     col;

    diff_and_swap_screens();

    printf("\033[?2026h");

    printf(TERM_CURSOR_HOME);
    render_screen->cur_col = render_screen->cur_row = 1;

    render_screen->cur_bg_set = 0;
    render_screen->cur_bg     = 0;
    render_screen->cur_fg_set = 0;
    render_screen->cur_fg     = 0;
    printf(TERM_RESET);

    cell = render_screen->cells;

    for (row = 1; row <= term_height; row += 1) {
        for (col = 1; col <= term_width; col += 1) {
            if (cell->dirty) {
                if (render_screen->cur_row != row
                &&  render_screen->cur_col != col) {
                    printf("\033[%d;%dH", row, col);
                    render_screen->cur_row = row;
                    render_screen->cur_col = col;
                } else if (render_screen->cur_row != row) {
                    printf("\033[%dd", row);
                    render_screen->cur_row = row;
                } else if (render_screen->cur_col != col) {
                    printf("\033[%dG", col);
                    render_screen->cur_col = col;
                }

                if ((cell->bg_set     != render_screen->cur_bg_set)
                ||  (cell->bg         != render_screen->cur_bg)
                ||  (cell->fg_set     != render_screen->cur_fg_set)
                ||  (cell->fg         != render_screen->cur_fg)) {

                    printf("\033[0m");

                    if (cell->bg_set) {
                        printf("\033[48;2;%d;%d;%dm",
                            (cell->bg & 0xff0000) >> 16,
                            (cell->bg & 0x00ff00) >> 8,
                            cell->bg & 0x0000ff);
                    }

                    if (cell->fg_set) {
                        printf("\033[38;2;%d;%d;%dm",
                            (cell->fg & 0xff0000) >> 16,
                            (cell->fg & 0x00ff00) >> 8,
                            cell->fg & 0x0000ff);
                    }

                    render_screen->cur_bg     = cell->bg;
                    render_screen->cur_bg_set = cell->bg_set;
                    render_screen->cur_fg     = cell->fg;
                    render_screen->cur_fg_set = cell->fg_set;
                }

                if (cell->glyph.bytes[0]) {
                    fwrite(&cell->glyph.c, 1, glyph_len(&cell->glyph), stdout);
                } else {
                    fwrite(" ", 1, 1, stdout);
                }

                render_screen->cur_col += 1;
            }

            cell->dirty = 0;
            cell += 1;
        }
    }

    printf("\033[?2026l");
}

static Julie_Status j_term_exit(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
    Julie_Status status;

    status = JULIE_SUCCESS;

    (void)values;
    if (n_values != 0) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 0, n_values, 0);
        *result = NULL;
        goto out;
    }

    printf(TERM_RESET TERM_CURSOR_HOME TERM_CLEAR_SCREEN);
    restore_term();
    exit(0);

    *result = julie_nil_value(interp);

out:;
    return status;
}

static Julie_Status j_term_clear(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
    Julie_Status status;

    status = JULIE_SUCCESS;

    (void)values;
    if (n_values != 0) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 0, n_values, 0);
        *result = NULL;
        goto out;
    }

    clear_screen(update_screen);

    *result = julie_nil_value(interp);

out:;
    return status;
}

static Julie_Status j_term_flush(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
    Julie_Status status;

    status = JULIE_SUCCESS;

    (void)values;
    if (n_values != 0) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 0, n_values, 0);
        *result = NULL;
        goto out;
    }

    flush_screen();

    *result = julie_nil_value(interp);

out:;
    return status;
}

static Julie_Status j_term_set_cell_bg(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
    Julie_Status  status;
    Julie_Value  *row;
    Julie_Value  *col;
    Julie_Value  *color;

    status = JULIE_SUCCESS;

    if (n_values != 3) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 3, n_values, 0);
        *result = NULL;
        goto out;
    }

    status = julie_eval(interp, values[0], &row);
    if (status != JULIE_SUCCESS) {
        *result = NULL;
        goto out;
    }

    if (!JULIE_TYPE_IS_INTEGER(row->type)) {
        *result = NULL;
        status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[0], _JULIE_INTEGER, row->type);
        goto out_free_row;
    }

    status = julie_eval(interp, values[1], &col);
    if (status != JULIE_SUCCESS) {
        *result = NULL;
        goto out_free_row;
    }

    if (!JULIE_TYPE_IS_INTEGER(col->type)) {
        *result = NULL;
        status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[1], _JULIE_INTEGER, col->type);
        goto out_free_col;
    }

    status = julie_eval(interp, values[2], &color);
    if (status != JULIE_SUCCESS) {
        *result = NULL;
        goto out_free_col;
    }

    if (!JULIE_TYPE_IS_INTEGER(color->type)) {
        *result = NULL;
        status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[2], _JULIE_INTEGER, color->type);
        goto out_free_color;
    }

    set_cell_bg(row->uint, col->uint, color->uint);

    *result = julie_nil_value(interp);

out_free_color:;
    julie_free_value(interp, color);
out_free_col:;
    julie_free_value(interp, col);
out_free_row:;
    julie_free_value(interp, row);

out:;
    return status;
}

static Julie_Status j_term_set_cell_fg(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
    Julie_Status  status;
    Julie_Value  *row;
    Julie_Value  *col;
    Julie_Value  *color;

    status = JULIE_SUCCESS;

    if (n_values != 3) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 3, n_values, 0);
        *result = NULL;
        goto out;
    }

    status = julie_eval(interp, values[0], &row);
    if (status != JULIE_SUCCESS) {
        *result = NULL;
        goto out;
    }

    if (!JULIE_TYPE_IS_INTEGER(row->type)) {
        *result = NULL;
        status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[0], _JULIE_INTEGER, row->type);
        goto out_free_row;
    }

    status = julie_eval(interp, values[1], &col);
    if (status != JULIE_SUCCESS) {
        *result = NULL;
        goto out_free_row;
    }

    if (!JULIE_TYPE_IS_INTEGER(col->type)) {
        *result = NULL;
        status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[1], _JULIE_INTEGER, col->type);
        goto out_free_col;
    }

    status = julie_eval(interp, values[2], &color);
    if (status != JULIE_SUCCESS) {
        *result = NULL;
        goto out_free_col;
    }

    if (!JULIE_TYPE_IS_INTEGER(color->type)) {
        *result = NULL;
        status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[2], _JULIE_INTEGER, color->type);
        goto out_free_color;
    }

    set_cell_fg(row->uint, col->uint, color->uint);

    *result = julie_nil_value(interp);

out_free_color:;
    julie_free_value(interp, color);
out_free_col:;
    julie_free_value(interp, col);
out_free_row:;
    julie_free_value(interp, row);

out:;
    return status;
}

static Julie_Status j_term_set_cell_char(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
    Julie_Status  status;
    Julie_Value  *row;
    Julie_Value  *col;
    Julie_Value  *c;

    status = JULIE_SUCCESS;

    if (n_values != 3) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 3, n_values, 0);
        *result = NULL;
        goto out;
    }

    status = julie_eval(interp, values[0], &row);
    if (status != JULIE_SUCCESS) {
        *result = NULL;
        goto out;
    }

    if (!JULIE_TYPE_IS_INTEGER(row->type)) {
        *result = NULL;
        status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[0], _JULIE_INTEGER, row->type);
        goto out_free_row;
    }

    status = julie_eval(interp, values[1], &col);
    if (status != JULIE_SUCCESS) {
        *result = NULL;
        goto out_free_row;
    }

    if (!JULIE_TYPE_IS_INTEGER(col->type)) {
        *result = NULL;
        status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[1], _JULIE_INTEGER, col->type);
        goto out_free_col;
    }

    status = julie_eval(interp, values[2], &c);
    if (status != JULIE_SUCCESS) {
        *result = NULL;
        goto out_free_col;
    }

    if (c->type != JULIE_STRING) {
        *result = NULL;
        status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[2], JULIE_STRING, c->type);
        goto out_free_c;
    }

    set_cell_glyph(row->uint, col->uint, julie_value_cstring(c));

    *result = julie_nil_value(interp);

out_free_c:;
    julie_free_value(interp, c);
out_free_col:;
    julie_free_value(interp, col);
out_free_row:;
    julie_free_value(interp, row);

out:;
    return status;
}
