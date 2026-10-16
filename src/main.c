
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 65536
#define BLAKE2B_BLOCK_SIZE 128

typedef struct {
  uint32_t state[8];
  uint64_t bit_length;
  uint8_t buffer[64];
  size_t buffer_length;
} SHA256;

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static uint32_t ror32(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32 - n));
}

static void sha256_transform(SHA256 *ctx, const uint8_t block[64]) {
  uint32_t w[64];

  for (unsigned i = 0; i < 16; ++i) {
    w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
           ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
  }

  for (unsigned i = 16; i < 64; ++i) {
    uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = ctx->state[0], b = ctx->state[1];
  uint32_t c = ctx->state[2], d = ctx->state[3];
  uint32_t e = ctx->state[4], f = ctx->state[5];
  uint32_t g = ctx->state[6], h = ctx->state[7];

  for (unsigned i = 0; i < 64; ++i) {
    uint32_t s1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + s1 + ch + sha256_k[i] + w[i];
    uint32_t s0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void sha256_init(SHA256 *ctx) {
  static const uint32_t initial[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                      0xa54ff53a, 0x510e527f, 0x9b05688c,
                                      0x1f83d9ab, 0x5be0cd19};

  memcpy(ctx->state, initial, sizeof(initial));
  ctx->bit_length = 0;
  ctx->buffer_length = 0;
}

static void sha256_update(SHA256 *ctx, const uint8_t *data, size_t len) {
  while (len > 0) {
    size_t take = 64 - ctx->buffer_length;
    if (take > len)
      take = len;

    memcpy(ctx->buffer + ctx->buffer_length, data, take);
    ctx->buffer_length += take;
    data += take;
    len -= take;

    if (ctx->buffer_length == 64) {
      sha256_transform(ctx, ctx->buffer);
      ctx->bit_length += 512;
      ctx->buffer_length = 0;
    }
  }
}

static void sha256_final(SHA256 *ctx, uint8_t digest[32]) {
  size_t i = ctx->buffer_length;

  ctx->buffer[i++] = 0x80;

  if (i > 56) {
    while (i < 64)
      ctx->buffer[i++] = 0;

    sha256_transform(ctx, ctx->buffer);
    i = 0;
  }

  while (i < 56)
    ctx->buffer[i++] = 0;

  ctx->bit_length += (uint64_t)ctx->buffer_length * 8;

  for (unsigned j = 0; j < 8; ++j)
    ctx->buffer[63 - j] = (uint8_t)(ctx->bit_length >> (j * 8));

  sha256_transform(ctx, ctx->buffer);

  for (unsigned j = 0; j < 8; ++j) {
    digest[j * 4] = (uint8_t)(ctx->state[j] >> 24);
    digest[j * 4 + 1] = (uint8_t)(ctx->state[j] >> 16);
    digest[j * 4 + 2] = (uint8_t)(ctx->state[j] >> 8);
    digest[j * 4 + 3] = (uint8_t)ctx->state[j];
  }
}

typedef struct {
  uint64_t h[8], t[2], f[2];
  uint8_t buffer[128];
  size_t buflen;
} Blake2b;

static const uint64_t blake_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

static const uint8_t blake_sigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

static uint64_t ror64(uint64_t x, unsigned n) {
  return (x >> n) | (x << (64 - n));
}

static uint64_t load64(const uint8_t *p) {
  uint64_t x = 0;
  for (unsigned i = 0; i < 8; ++i)
    x |= (uint64_t)p[i] << (8 * i);
  return x;
}

static void store64(uint8_t *p, uint64_t x) {
  for (unsigned i = 0; i < 8; ++i)
    p[i] = (uint8_t)(x >> (8 * i));
}

#define BG(a, b, c, d, x, y)                                                   \
  do {                                                                         \
    v[a] += v[b] + (x);                                                        \
    v[d] = ror64(v[d] ^ v[a], 32);                                             \
    v[c] += v[d];                                                              \
    v[b] = ror64(v[b] ^ v[c], 24);                                             \
    v[a] += v[b] + (y);                                                        \
    v[d] = ror64(v[d] ^ v[a], 16);                                             \
    v[c] += v[d];                                                              \
    v[b] = ror64(v[b] ^ v[c], 63);                                             \
  } while (0)

static void blake_compress(Blake2b *ctx, const uint8_t block[128]) {
  uint64_t m[16], v[16];

  for (unsigned i = 0; i < 16; ++i)
    m[i] = load64(block + i * 8);

  for (unsigned i = 0; i < 8; ++i) {
    v[i] = ctx->h[i];
    v[i + 8] = blake_iv[i];
  }

  v[12] ^= ctx->t[0];
  v[13] ^= ctx->t[1];
  v[14] ^= ctx->f[0];
  v[15] ^= ctx->f[1];

  for (unsigned r = 0; r < 12; ++r) {
    const uint8_t *s = blake_sigma[r];

    BG(0, 4, 8, 12, m[s[0]], m[s[1]]);
    BG(1, 5, 9, 13, m[s[2]], m[s[3]]);
    BG(2, 6, 10, 14, m[s[4]], m[s[5]]);
    BG(3, 7, 11, 15, m[s[6]], m[s[7]]);
    BG(0, 5, 10, 15, m[s[8]], m[s[9]]);
    BG(1, 6, 11, 12, m[s[10]], m[s[11]]);
    BG(2, 7, 8, 13, m[s[12]], m[s[13]]);
    BG(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }

  for (unsigned i = 0; i < 8; ++i)
    ctx->h[i] ^= v[i] ^ v[i + 8];
}

#undef BG

static void blake_increment(Blake2b *ctx, uint64_t n) {
  ctx->t[0] += n;
  if (ctx->t[0] < n)
    ++ctx->t[1];
}

static void blake_init(Blake2b *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->h, blake_iv, sizeof(blake_iv));
  ctx->h[0] ^= 0x01010040ULL;
}

static void blake_update(Blake2b *ctx, const uint8_t *data, size_t len) {
  if (!len)
    return;

  size_t left = ctx->buflen;
  size_t fill = BLAKE2B_BLOCK_SIZE - left;

  if (len > fill) {
    memcpy(ctx->buffer + left, data, fill);
    blake_increment(ctx, BLAKE2B_BLOCK_SIZE);
    blake_compress(ctx, ctx->buffer);
    ctx->buflen = 0;
    data += fill;
    len -= fill;

    while (len > BLAKE2B_BLOCK_SIZE) {
      blake_increment(ctx, BLAKE2B_BLOCK_SIZE);
      blake_compress(ctx, data);
      data += BLAKE2B_BLOCK_SIZE;
      len -= BLAKE2B_BLOCK_SIZE;
    }
  }

  memcpy(ctx->buffer + ctx->buflen, data, len);
  ctx->buflen += len;
}

static void blake_final(Blake2b *ctx, uint8_t digest[64]) {
  blake_increment(ctx, (uint64_t)ctx->buflen);
  ctx->f[0] = UINT64_MAX;
  memset(ctx->buffer + ctx->buflen, 0, BLAKE2B_BLOCK_SIZE - ctx->buflen);
  blake_compress(ctx, ctx->buffer);

  for (unsigned i = 0; i < 8; ++i)
    store64(digest + i * 8, ctx->h[i]);
}

static int calculate_hash(const char *path, int sha, uint8_t *digest) {
  FILE *file = fopen(path, "rb");

  if (!file) {
    fprintf(stderr, "ERROR: cannot open '%s'.\n", path);
    return 0;
  }

  uint8_t buffer[BUFFER_SIZE];
  size_t n;
  int ok = 1;

  if (sha) {
    SHA256 ctx;
    sha256_init(&ctx);

    while ((n = fread(buffer, 1, sizeof(buffer), file)) > 0)
      sha256_update(&ctx, buffer, n);

    if (ferror(file))
      ok = 0;
    else
      sha256_final(&ctx, digest);
  } else {
    Blake2b ctx;
    blake_init(&ctx);

    while ((n = fread(buffer, 1, sizeof(buffer), file)) > 0)
      blake_update(&ctx, buffer, n);

    if (ferror(file))
      ok = 0;
    else
      blake_final(&ctx, digest);
  }

  if (!ok)
    fprintf(stderr, "ERROR: failed to read '%s'.\n", path);

  fclose(file);
  return ok;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t size) {
  if (strlen(hex) != size * 2)
    return 0;

  for (size_t i = 0; i < size; ++i) {
    unsigned value = 0;

    for (unsigned j = 0; j < 2; ++j) {
      char c = hex[i * 2 + j];
      unsigned d;

      if (c >= '0' && c <= '9')
        d = (unsigned)(c - '0');
      else if (c >= 'a' && c <= 'f')
        d = (unsigned)(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F')
        d = (unsigned)(c - 'A' + 10);
      else
        return 0;

      value = value * 16 + d;
    }

    out[i] = (uint8_t)value;
  }

  return 1;
}

static void print_hex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i)
    printf("%02x", data[i]);
}

static void print_usage(void) {
  puts("hashfile - checksum verifier");
  puts("");
  puts("Usage:");
  puts("  hashfile verify <file> --sha256 <checksum>");
  puts("  hashfile verify <file> --blake2b <checksum>");
  puts("");
  puts("Options:");
  puts("  -h, --help  Show this message");
}

int main(int argc, char *argv[]) {
  if (argc == 1) {
    print_usage();
    return 0;
  }

  if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
    print_usage();
    return 0;
  }

  if (argc != 5 || strcmp(argv[1], "verify") != 0) {
    fprintf(stderr, "ERROR: invalid command or arguments.\n\n");
    print_usage();
    return 2;
  }

  int sha;
  size_t digest_size;

  if (strcmp(argv[3], "--sha256") == 0) {
    sha = 1;
    digest_size = 32;
  } else if (strcmp(argv[3], "--blake2b") == 0) {
    sha = 0;
    digest_size = 64;
  } else {
    fprintf(stderr, "ERROR: unsupported algorithm '%s'.\n", argv[3]);
    print_usage();
    return 2;
  }

  uint8_t expected[64], actual[64];

  if (!hex_to_bytes(argv[4], expected, digest_size)) {
    fprintf(
        stderr,
        "ERROR: checksum must contain exactly %zu hexadecimal characters.\n",
        digest_size * 2);
    return 2;
  }

  if (!calculate_hash(argv[2], sha, actual))
    return 2;

  printf("File: %s\n", argv[2]);
  printf("Algorithm: %s\n", sha ? "SHA-256" : "BLAKE2b-512");
  printf("Expected:   ");
  print_hex(expected, digest_size);
  putchar('\n');
  printf("Calculated: ");
  print_hex(actual, digest_size);
  putchar('\n');

  if (memcmp(expected, actual, digest_size) == 0) {
    puts("Result: PASS");
    return 0;
  }

  puts("Result: FAIL");
  return 1;
}
