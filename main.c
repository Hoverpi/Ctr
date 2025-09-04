#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LENGTH 100

static char to_lower_char(char c) {
    if (c >= 'A' && c <= 'Z') return (char)(c + 32);
    return c;
}

// Replace spaces with '_' and lowercase chars in-place
char *standardize_chars(char *s) {
    if (!s) return NULL;
    for (size_t i = 0; s[i] != '\0'; ++i) {
        if (s[i] == ' ') s[i] = '_';
        s[i] = to_lower_char(s[i]);
    }
    return s;
}

// Small struct to sort key chars and keep original index
typedef struct {
    char ch;
    int idx;
} KeyChar;

int keychar_cmp(const void *a, const void *b) {
    const KeyChar *A = (const KeyChar *)a;
    const KeyChar *B = (const KeyChar *)b;
    if (A->ch < B->ch) return -1;
    if (A->ch > B->ch) return  1;
    return (A->idx - B->idx);
}

// Free matrix allocated as rows of char*
static void free_matrix(char **matrix, size_t rows) {
    if (!matrix) return;
    for (size_t r = 0; r < rows; ++r) {
        free(matrix[r]);
    }
    free(matrix);
}

// Encryption: fill row-wise, read columns in sorted key order
void encryption(char *text, char *key) {
    if (!text || !key) {
        fprintf(stderr, "Missing text or key\n");
        return;
    }

    standardize_chars(text);
    standardize_chars(key);

    size_t text_len = strlen(text);
    size_t cols = strlen(key);
    if (cols == 0) {
        fprintf(stderr, "Key must contain at least one character\n");
        return;
    }

    size_t rows = (text_len + cols - 1) / cols;

    // allocate matrix rows
    char **matrix = malloc(rows * sizeof(char *));
    if (!matrix) { perror("malloc matrix"); return; }

    for (size_t r = 0; r < rows; ++r) {
        matrix[r] = calloc(cols + 1, sizeof(char));
        if (!matrix[r]) {
            perror("calloc row");
            free_matrix(matrix, r); // free only allocated rows
            return;
        }
        for (size_t c = 0; c < cols; ++c) matrix[r][c] = '_';
        matrix[r][cols] = '\0';
    }

    // fill matrix row-wise
    for (size_t i = 0; i < text_len; ++i) {
        size_t r = i / cols;
        size_t c = i % cols;
        matrix[r][c] = text[i];
    }

    // build sortable key array
    KeyChar *karr = malloc(cols * sizeof(KeyChar));
    if (!karr) {
        perror("malloc karr");
        free_matrix(matrix, rows);
        return;
    }
    for (size_t i = 0; i < cols; ++i) { karr[i].ch = key[i]; karr[i].idx = (int)i; }
    qsort(karr, cols, sizeof(KeyChar), keychar_cmp);

    // produce ciphertext by reading columns in sorted-key order
    size_t total = rows * cols;
    char *cipher = malloc(total + 1);
    if (!cipher) {
        perror("malloc cipher");
        free(karr);
        free_matrix(matrix, rows);
        return;
    }
    size_t pos = 0;
    for (size_t k = 0; k < cols; ++k) {
        size_t col = (size_t)karr[k].idx;
        for (size_t r = 0; r < rows; ++r) {
            cipher[pos++] = matrix[r][col];
        }
    }
    cipher[pos] = '\0';

    // print results
    printf("Standardized Plain: %s\n", text);
    printf("Standardized Key  : %s\n", key);
    printf("Matrix (rows x cols = %zu x %zu):\n", rows, cols);
    for (size_t r = 0; r < rows; ++r) {
        printf("Row %zu: %s\n", r + 1, matrix[r]);
    }

    printf("Sorted key chars (char:index): ");
    for (size_t i = 0; i < cols; ++i) printf("%c:%d ", karr[i].ch, karr[i].idx);
    printf("\n");

    printf("Ciphertext: %s\n", cipher);

    // cleanup
    free(cipher);
    free(karr);
    free_matrix(matrix, rows);
}

void decryption(char *cipher, char *key) {
    if (!cipher || !key) {
        fprintf(stderr, "Missing cipher or key\n");
        return;
    }

    standardize_chars(key);

    size_t cipher_len = strlen(cipher);
    size_t cols = strlen(key);
    if (cols == 0) {
        fprintf(stderr, "Key must contain at least one character\n");
        return;
    }

    size_t rows = cipher_len / cols;
    if (cipher_len % cols != 0) {
        rows = (cipher_len + cols - 1) / cols;
        fprintf(stderr, "Warning: cipher length (%zu) not multiple of cols (%zu). Using rows=%zu\n",
                cipher_len, cols, rows);
    }

    // allocate matrix rows
    char **matrix = malloc(rows * sizeof(char *));
    if (!matrix) { perror("malloc matrix"); return; }

    for (size_t r = 0; r < rows; ++r) {
        matrix[r] = calloc(cols + 1, sizeof(char));
        if (!matrix[r]) {
            perror("calloc row");
            free_matrix(matrix, r); // free only allocated rows
            return;
        }
        for (size_t c = 0; c < cols; ++c) matrix[r][c] = '_';
        matrix[r][cols] = '\0';
    }
    
    // build sortable key array
    KeyChar *karr = malloc(cols * sizeof(KeyChar));
    if (!karr) {
        perror("malloc karr");
        free_matrix(matrix, rows);
        return;
    }
    for (size_t i = 0; i < cols; ++i) { karr[i].ch = key[i]; karr[i].idx = (int)i; }
    qsort(karr, cols, sizeof(KeyChar), keychar_cmp);

    // fill matrix using sorted key
    size_t pos = 0;
    for (size_t k = 0; k < cols; ++k) {
        size_t col = (size_t)karr[k].idx;
        for (size_t r = 0; r < rows; ++r) {
            if (pos < cipher_len) matrix[r][col] = cipher[pos++];
            else matrix[r][col] = '_';
        }
    }

    // produce text by building matrix and convert '_' to ' ' 
    char *plain = malloc(rows * cols + 1);
    if (!plain) {
        perror("malloc plain");
        free(karr);
        free_matrix(matrix, rows);
        return;
    }
    
    size_t p = 0;
    for (size_t r = 0; r < rows; ++r) {
        for (size_t c = 0; c < cols; ++c) {
            char ch = matrix[r][c];
            plain[p++] = (ch == '_') ? ' ' : ch;
        }
    }
    plain[p] = '\0';

    // print results
    printf("Standardized Key  : %s\n", key);
    printf("Matrix (rows x cols = %zu x %zu):\n", rows, cols);
    for (size_t r = 0; r < rows; ++r) {
        printf("Row %zu: %s\n", r + 1, matrix[r]);
    }

    printf("Sorted key chars (char:index): ");
    for (size_t i = 0; i < cols; ++i) printf("%c:%d ", karr[i].ch, karr[i].idx);
    printf("\n");

    printf("Plaintext: %s\n", plain);

    // cleanup
    free(plain);
    free(karr);
    free_matrix(matrix, rows);
    
}

int main(int argc, char **argv) {
    char buffer[MAX_LENGTH];
    char *text = NULL;
    char *key = NULL;

    printf("Type the secret (max %d chars): ", MAX_LENGTH - 1);
    if (!fgets(buffer, sizeof(buffer), stdin)) {
        perror("fgets secret");
        return EXIT_FAILURE;
    }
    buffer[strcspn(buffer, "\n")] = '\0';
    text = malloc(strlen(buffer) + 1);
    if (!text) { perror("malloc text"); return EXIT_FAILURE; }
    strcpy(text, buffer);

    printf("Type the key: ");
    if (!fgets(buffer, sizeof(buffer), stdin)) {
        perror("fgets key");
        free(text);
        return EXIT_FAILURE;
    }
    buffer[strcspn(buffer, "\n")] = '\0';
    key = malloc(strlen(buffer) + 1);
    if (!key) { perror("malloc key"); free(text); return EXIT_FAILURE; }
    strcpy(key, buffer);

    if (argc == 1) {
        printf("Usage: %s -e  (encrypt)\n       %s -d  (decrypt)\n", argv[0], argv[0]);
        free(text);
        free(key);
        return 0;
    }

    int opt;
    while ((opt = getopt(argc, argv, "ed")) != -1) {
        switch (opt) {
            case 'e': encryption(text, key); break;
            case 'd': decryption(text, key); break;
            default: fprintf(stderr, "Unknown option\n");
        }
    }

    free(text);
    free(key);
    return 0;
}
