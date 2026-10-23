#include <Arduino.h>
#include <Preferences.h>
#include "esp_system.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/bignum.h"
#include "mbedtls/md.h"

#define PIN_BOOT_BTN 0
#define PIN_LED      2
#define TOUCH_TIMEOUT_MS 15000
#define MAX_RK_SLOTS 16

struct ResidentKeySlot {
  uint8_t used;
  uint8_t rp_id_hash[32];
  uint8_t key_handle[48];
  char rp_id[64];
  char user_name[64];
  uint8_t user_id_len;
  uint8_t user_id[64];
};

static Preferences prefs;
static uint8_t g_master_key[32];
static uint8_t g_aaguid[16];
static uint32_t g_counter = 0;

static const uint32_t SHA256_K[64] = {
  0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
  0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
  0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
  0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
  0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
  0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
  0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
  0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

struct Sha256Ctx {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t data[64];
  size_t datalen;
};

static void sha256_transform(Sha256Ctx *ctx, const uint8_t data[64]) {
  uint32_t m[64];
  for (int i = 0, j = 0; i < 16; ++i, j += 4) {
    m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
           ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    uint32_t s0 = rotr32(m[i - 15], 7) ^ rotr32(m[i - 15], 18) ^ (m[i - 15] >> 3);
    uint32_t s1 = rotr32(m[i - 2], 17) ^ rotr32(m[i - 2], 19) ^ (m[i - 2] >> 10);
    m[i] = m[i - 16] + s0 + m[i - 7] + s1;
  }
  uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
  uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + S1 + ch + SHA256_K[i] + m[i];
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = S0 + maj;
    h = g; g = f; f = e; e = d + temp1;
    d = c; c = b; b = a; a = temp1 + temp2;
  }
  ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
  ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256Ctx *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667UL; ctx->state[1] = 0xbb67ae85UL;
  ctx->state[2] = 0x3c6ef372UL; ctx->state[3] = 0xa54ff53aUL;
  ctx->state[4] = 0x510e527fUL; ctx->state[5] = 0x9b05688cUL;
  ctx->state[6] = 0x1f83d9abUL; ctx->state[7] = 0x5be0cd19UL;
}

static void sha256_update(Sha256Ctx *ctx, const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen++] = data[i];
    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

static void sha256_final(Sha256Ctx *ctx, uint8_t hash[32]) {
  size_t i = ctx->datalen;
  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64) ctx->data[i++] = 0x00;
    sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }
  ctx->bitlen += ctx->datalen * 8ULL;
  ctx->data[63] = ctx->bitlen;
  ctx->data[62] = ctx->bitlen >> 8;
  ctx->data[61] = ctx->bitlen >> 16;
  ctx->data[60] = ctx->bitlen >> 24;
  ctx->data[59] = ctx->bitlen >> 32;
  ctx->data[58] = ctx->bitlen >> 40;
  ctx->data[57] = ctx->bitlen >> 48;
  ctx->data[56] = ctx->bitlen >> 56;
  sha256_transform(ctx, ctx->data);
  for (i = 0; i < 4; ++i) {
    for (int j = 0; j < 8; ++j) {
      hash[i + j * 4] = (ctx->state[j] >> (24 - i * 8)) & 0xff;
    }
  }
}

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[32]) {
  uint8_t k_ipad[64];
  uint8_t k_opad[64];
  uint8_t tk[32];
  if (key_len > 64) {
    Sha256Ctx tctx;
    sha256_init(&tctx);
    sha256_update(&tctx, key, key_len);
    sha256_final(&tctx, tk);
    key = tk;
    key_len = 32;
  }
  memset(k_ipad, 0x36, 64);
  memset(k_opad, 0x5c, 64);
  for (size_t i = 0; i < key_len; ++i) {
    k_ipad[i] ^= key[i];
    k_opad[i] ^= key[i];
  }
  uint8_t inner[32];
  Sha256Ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, k_ipad, 64);
  sha256_update(&ctx, msg, msg_len);
  sha256_final(&ctx, inner);

  sha256_init(&ctx);
  sha256_update(&ctx, k_opad, 64);
  sha256_update(&ctx, inner, 32);
  sha256_final(&ctx, out);
}

static int esp_rng_cb(void *ctx, unsigned char *buf, size_t len) {
  (void)ctx;
  esp_fill_random(buf, len);
  return 0;
}

static int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t expected_bytes) {
  if (strlen(hex) != expected_bytes * 2) return false;
  for (size_t i = 0; i < expected_bytes; ++i) {
    int hi = hex_val(hex[i * 2]);
    int lo = hex_val(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

static size_t hex_to_var_bytes(const char *hex, uint8_t *out, size_t max_bytes) {
  size_t len = strlen(hex);
  if (len % 2 != 0 || (len / 2) > max_bytes) return 0;
  size_t bytes = len / 2;
  for (size_t i = 0; i < bytes; ++i) {
    int hi = hex_val(hex[i * 2]);
    int lo = hex_val(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return 0;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return bytes;
}

static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
  static const char *hex = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out[i * 2]     = hex[(in[i] >> 4) & 0x0F];
    out[i * 2 + 1] = hex[in[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

static size_t encode_ecdsa_der(const uint8_t r[32], const uint8_t s[32], uint8_t out[72]) {
  int r_off = 0;
  while (r_off < 31 && r[r_off] == 0) r_off++;
  bool r_pad = (r[r_off] & 0x80) != 0;
  int r_len = 32 - r_off + (r_pad ? 1 : 0);

  int s_off = 0;
  while (s_off < 31 && s[s_off] == 0) s_off++;
  bool s_pad = (s[s_off] & 0x80) != 0;
  int s_len = 32 - s_off + (s_pad ? 1 : 0);

  int seq_len = 2 + r_len + 2 + s_len;
  size_t idx = 0;
  out[idx++] = 0x30;
  out[idx++] = (uint8_t)seq_len;
  out[idx++] = 0x02;
  out[idx++] = (uint8_t)r_len;
  if (r_pad) out[idx++] = 0x00;
  memcpy(&out[idx], &r[r_off], 32 - r_off);
  idx += (32 - r_off);

  out[idx++] = 0x02;
  out[idx++] = (uint8_t)s_len;
  if (s_pad) out[idx++] = 0x00;
  memcpy(&out[idx], &s[s_off], 32 - s_off);
  idx += (32 - s_off);
  return idx;
}

static void compute_kh_mac(const uint8_t rp_id_hash[32], const uint8_t nonce[16], uint8_t mac_out[32]) {
  const char *tag = "YUBIESP-KH-MAC-V1";
  uint8_t buf[17 + 32 + 16];
  memcpy(buf, tag, 17);
  memcpy(buf + 17, rp_id_hash, 32);
  memcpy(buf + 17 + 32, nonce, 16);
  hmac_sha256(g_master_key, 32, buf, sizeof(buf), mac_out);
}

static bool verify_key_handle(const uint8_t rp_id_hash[32], const uint8_t kh[48]) {
  uint8_t expected[32];
  compute_kh_mac(rp_id_hash, kh, expected);
  uint8_t diff = 0;
  for (int i = 0; i < 32; ++i) {
    diff |= (expected[i] ^ kh[16 + i]);
  }
  return diff == 0;
}

static bool derive_p256_keypair(const uint8_t rp_id_hash[32], const uint8_t nonce[16],
                                mbedtls_ecp_group *grp, mbedtls_mpi *d,
                                uint8_t pub_x[32], uint8_t pub_y[32]) {
  const char *tag = "YUBIESP-P256-KEY-V1";
  uint8_t buf[19 + 32 + 16 + 1];
  memcpy(buf, tag, 19);
  memcpy(buf + 19, rp_id_hash, 32);
  memcpy(buf + 19 + 32, nonce, 16);

  uint8_t candidate[32];
  for (uint8_t attempt = 0; attempt < 64; ++attempt) {
    buf[sizeof(buf) - 1] = attempt;
    hmac_sha256(g_master_key, 32, buf, sizeof(buf), candidate);
    if (mbedtls_mpi_read_binary(d, candidate, 32) != 0) continue;
    if (mbedtls_ecp_check_privkey(grp, d) == 0) {
      mbedtls_ecp_point Q;
      mbedtls_ecp_point_init(&Q);
      int rc = mbedtls_ecp_mul(grp, &Q, d, &grp->G, esp_rng_cb, NULL);
      if (rc != 0) {
        mbedtls_ecp_point_free(&Q);
        return false;
      }
      uint8_t raw_pub[65];
      size_t olen = 0;
      rc = mbedtls_ecp_point_write_binary(grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, raw_pub, sizeof(raw_pub));
      mbedtls_ecp_point_free(&Q);
      if (rc != 0 || olen != 65 || raw_pub[0] != 0x04) return false;
      memcpy(pub_x, raw_pub + 1, 32);
      memcpy(pub_y, raw_pub + 33, 32);
      return true;
    }
  }
  return false;
}

static bool sign_p256_digest(mbedtls_ecp_group *grp, const mbedtls_mpi *d,
                             const uint8_t digest[32],
                             uint8_t sig_r[32], uint8_t sig_s[32]) {
  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  int rc = mbedtls_ecdsa_sign_det_ext(grp, &r, &s, d, digest, 32, MBEDTLS_MD_SHA256, esp_rng_cb, NULL);
  if (rc == 0) {
    // Enforce low-S per FIDO2 / CTAP2 / OpenSSH best practice: if s > N/2, s = N - s
    mbedtls_mpi half_n;
    mbedtls_mpi_init(&half_n);
    mbedtls_mpi_copy(&half_n, &grp->N);
    mbedtls_mpi_shift_r(&half_n, 1);
    if (mbedtls_mpi_cmp_mpi(&s, &half_n) > 0) {
      mbedtls_mpi_sub_mpi(&s, &grp->N, &s);
    }
    mbedtls_mpi_free(&half_n);
    rc = mbedtls_mpi_write_binary(&r, sig_r, 32);
    if (rc == 0) rc = mbedtls_mpi_write_binary(&s, sig_s, 32);
  }
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  return rc == 0;
}

static bool wait_for_user_presence(const char *cmd_name) {
  Serial.printf("{\"event\":\"wait_touch\",\"cmd\":\"%s\",\"timeout_ms\":%d}\n", cmd_name, TOUCH_TIMEOUT_MS);
  Serial.flush();

  // If button is already held down before prompt, wait for release first
  uint32_t pre_start = millis();
  while (digitalRead(PIN_BOOT_BTN) == LOW && (millis() - pre_start) < 2000) {
    delay(10);
  }

  uint32_t start = millis();
  uint32_t last_toggle = start;
  bool led_state = true;
  digitalWrite(PIN_LED, HIGH);

  while ((millis() - start) < TOUCH_TIMEOUT_MS) {
    uint32_t now = millis();
    if ((now - last_toggle) >= 100) {
      led_state = !led_state;
      digitalWrite(PIN_LED, led_state ? HIGH : LOW);
      last_toggle = now;
    }
    if (digitalRead(PIN_BOOT_BTN) == LOW) {
      delay(25); // Debounce 25ms
      if (digitalRead(PIN_BOOT_BTN) == LOW) {
        digitalWrite(PIN_LED, HIGH);
        // Wait for button release (up to 1500ms)
        uint32_t rel = millis();
        while (digitalRead(PIN_BOOT_BTN) == LOW && (millis() - rel) < 1500) {
          delay(10);
        }
        delay(120);
        digitalWrite(PIN_LED, LOW);
        return true;
      }
    }
    delay(5);
  }
  digitalWrite(PIN_LED, LOW);
  return false;
}

static int count_resident_keys() {
  int count = 0;
  ResidentKeySlot slot;
  for (int i = 0; i < MAX_RK_SLOTS; ++i) {
    char key[12];
    snprintf(key, sizeof(key), "rk_%d", i);
    if (prefs.getBytes(key, &slot, sizeof(slot)) == sizeof(slot) && slot.used == 1) {
      count++;
    }
  }
  return count;
}

static int store_resident_key(const uint8_t rp_id_hash[32], const uint8_t kh[48],
                              const char *rp_id, const char *user_name,
                              const uint8_t *user_id, uint8_t user_id_len) {
  ResidentKeySlot slot;
  int target_idx = -1;
  int first_free = -1;

  for (int i = 0; i < MAX_RK_SLOTS; ++i) {
    char key[12];
    snprintf(key, sizeof(key), "rk_%d", i);
    if (prefs.getBytes(key, &slot, sizeof(slot)) == sizeof(slot) && slot.used == 1) {
      if (memcmp(slot.rp_id_hash, rp_id_hash, 32) == 0 &&
          slot.user_id_len == user_id_len &&
          memcmp(slot.user_id, user_id, user_id_len) == 0) {
        target_idx = i;
        break;
      }
    } else if (first_free < 0) {
      first_free = i;
    }
  }

  if (target_idx < 0) target_idx = first_free;
  if (target_idx < 0) return -1;

  memset(&slot, 0, sizeof(slot));
  slot.used = 1;
  memcpy(slot.rp_id_hash, rp_id_hash, 32);
  memcpy(slot.key_handle, kh, 48);
  strncpy(slot.rp_id, rp_id ? rp_id : "", sizeof(slot.rp_id) - 1);
  strncpy(slot.user_name, user_name ? user_name : "", sizeof(slot.user_name) - 1);
  slot.user_id_len = user_id_len > 64 ? 64 : user_id_len;
  if (slot.user_id_len > 0 && user_id) {
    memcpy(slot.user_id, user_id, slot.user_id_len);
  }

  char key[12];
  snprintf(key, sizeof(key), "rk_%d", target_idx);
  prefs.putBytes(key, &slot, sizeof(slot));
  return target_idx;
}

static char *next_token(char **cursor) {
  if (!cursor || !*cursor) return NULL;
  char *p = *cursor;
  while (*p == ' ' || *p == '\t') p++;
  if (*p == '\0') {
    *cursor = p;
    return NULL;
  }
  char *start = p;
  while (*p != '\0' && *p != ' ' && *p != '\t') p++;
  if (*p != '\0') {
    *p = '\0';
    *cursor = p + 1;
  } else {
    *cursor = p;
  }
  return start;
}

static void handle_info() {
  char aaguid_hex[33];
  bytes_to_hex(g_aaguid, 16, aaguid_hex);
  Serial.printf("{\"ok\":true,\"cmd\":\"INFO\",\"device\":\"YubiESP-WROOM-32\",\"chip\":\"ESP32-D0WD-V3\",\"version\":\"1.0.0\",\"aaguid\":\"%s\",\"counter\":%lu,\"rk_count\":%d,\"rk_max\":%d}\n",
                aaguid_hex, (unsigned long)g_counter, count_resident_keys(), MAX_RK_SLOTS);
}

static void handle_blink() {
  for (int i = 0; i < 5; ++i) {
    digitalWrite(PIN_LED, HIGH);
    delay(80);
    digitalWrite(PIN_LED, LOW);
    delay(80);
  }
  Serial.println("{\"ok\":true,\"cmd\":\"BLINK\"}");
}

static void handle_enroll(char *args) {
  char *rp_hash_tok = next_token(&args);
  char *cd_hash_tok = next_token(&args);
  char *flags_tok   = next_token(&args);
  char *extra_tok   = next_token(&args);
  char *res_tok     = next_token(&args);
  char *rp_id_tok   = next_token(&args);
  char *user_tok    = next_token(&args);
  char *uid_hex_tok = next_token(&args);

  uint8_t rp_id_hash[32];
  uint8_t client_data_hash[32];
  if (!rp_hash_tok || !cd_hash_tok ||
      !hex_to_bytes(rp_hash_tok, rp_id_hash, 32) ||
      !hex_to_bytes(cd_hash_tok, client_data_hash, 32)) {
    Serial.println("{\"ok\":false,\"cmd\":\"ENROLL\",\"err\":\"BAD_ARGS\"}");
    return;
  }

  uint8_t flags = 0x45; // UP (0x01) | UV (0x04) | AT (0x40)
  if (flags_tok && strcmp(flags_tok, "-") != 0) {
    if (!hex_to_bytes(flags_tok, &flags, 1)) {
      Serial.println("{\"ok\":false,\"cmd\":\"ENROLL\",\"err\":\"BAD_FLAGS\"}");
      return;
    }
  }

  uint8_t extra_data[256];
  size_t extra_len = 0;
  if (extra_tok && strcmp(extra_tok, "-") != 0) {
    extra_len = hex_to_var_bytes(extra_tok, extra_data, sizeof(extra_data));
    if (extra_len == 0) {
      Serial.println("{\"ok\":false,\"cmd\":\"ENROLL\",\"err\":\"BAD_EXTRA_DATA\"}");
      return;
    }
  }

  bool is_resident = (res_tok && strcmp(res_tok, "1") == 0);
  uint8_t user_id[64];
  size_t user_id_len = 0;
  if (uid_hex_tok && strcmp(uid_hex_tok, "-") != 0) {
    user_id_len = hex_to_var_bytes(uid_hex_tok, user_id, sizeof(user_id));
    if (user_id_len == 0) {
      Serial.println("{\"ok\":false,\"cmd\":\"ENROLL\",\"err\":\"BAD_USER_ID\"}");
      return;
    }
  }

  if (!wait_for_user_presence("ENROLL")) {
    Serial.println("{\"ok\":false,\"cmd\":\"ENROLL\",\"err\":\"USER_PRESENCE_TIMEOUT\"}");
    return;
  }

  uint8_t kh[48];
  esp_fill_random(kh, 16);
  compute_kh_mac(rp_id_hash, kh, kh + 16);

  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  uint8_t pub_x[32], pub_y[32];
  if (!derive_p256_keypair(rp_id_hash, kh, &grp, &d, pub_x, pub_y)) {
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    Serial.println("{\"ok\":false,\"cmd\":\"ENROLL\",\"err\":\"KEYGEN_FAILED\"}");
    return;
  }

  int rk_slot = -1;
  if (is_resident) {
    rk_slot = store_resident_key(
      rp_id_hash, kh,
      (rp_id_tok && strcmp(rp_id_tok, "-") != 0) ? rp_id_tok : "",
      (user_tok && strcmp(user_tok, "-") != 0) ? user_tok : "",
      user_id, (uint8_t)user_id_len
    );
    if (rk_slot < 0) {
      mbedtls_mpi_free(&d);
      mbedtls_ecp_group_free(&grp);
      Serial.println("{\"ok\":false,\"cmd\":\"ENROLL\",\"err\":\"KEY_STORE_FULL\"}");
      return;
    }
  }

  g_counter++;
  prefs.putUInt("counter", g_counter);

  // 1) U2F / OpenSSH enrollment signature over:
  //    0x00 || rp_id_hash(32) || client_data_hash(32) || key_handle(48) || 0x04 || pub_x(32) || pub_y(32)
  uint8_t u2f_msg[1 + 32 + 32 + 48 + 1 + 32 + 32];
  size_t u_idx = 0;
  u2f_msg[u_idx++] = 0x00;
  memcpy(&u2f_msg[u_idx], rp_id_hash, 32); u_idx += 32;
  memcpy(&u2f_msg[u_idx], client_data_hash, 32); u_idx += 32;
  memcpy(&u2f_msg[u_idx], kh, 48); u_idx += 48;
  u2f_msg[u_idx++] = 0x04;
  memcpy(&u2f_msg[u_idx], pub_x, 32); u_idx += 32;
  memcpy(&u2f_msg[u_idx], pub_y, 32); u_idx += 32;

  uint8_t u2f_digest[32];
  Sha256Ctx sctx;
  sha256_init(&sctx);
  sha256_update(&sctx, u2f_msg, sizeof(u2f_msg));
  sha256_final(&sctx, u2f_digest);

  uint8_t u2f_r[32], u2f_s[32], u2f_der[72];
  bool u2f_ok = sign_p256_digest(&grp, &d, u2f_digest, u2f_r, u2f_s);
  size_t u2f_der_len = encode_ecdsa_der(u2f_r, u2f_s, u2f_der);

  // 2) CTAP2 / WebAuthn MakeCredential self-attestation signature over:
  //    rp_id_hash(32) || flags(1) || counter_be(4) || attestedCredData || client_data_hash(32)
  //    where attestedCredData defaults to: aaguid(16) || credIdLen(0x0030) || kh(48) || COSE_Key(77)
  //    or uses caller-supplied extra_data if provided.
  uint8_t ctap_digest[32];
  sha256_init(&sctx);
  sha256_update(&sctx, rp_id_hash, 32);
  sha256_update(&sctx, &flags, 1);
  uint8_t cnt_be[4] = {
    (uint8_t)((g_counter >> 24) & 0xFF),
    (uint8_t)((g_counter >> 16) & 0xFF),
    (uint8_t)((g_counter >> 8) & 0xFF),
    (uint8_t)(g_counter & 0xFF)
  };
  sha256_update(&sctx, cnt_be, 4);
  if (extra_len > 0) {
    sha256_update(&sctx, extra_data, extra_len);
  } else {
    // Standard CTAP2 COSE_Key for ES256 (77 bytes):
    // a5 01 02 03 26 20 01 21 58 20 <pub_x 32B> 22 58 20 <pub_y 32B>
    uint8_t cred_hdr[18];
    memcpy(cred_hdr, g_aaguid, 16);
    cred_hdr[16] = 0x00;
    cred_hdr[17] = 48;
    sha256_update(&sctx, cred_hdr, 18);
    sha256_update(&sctx, kh, 48);
    uint8_t cose_prefix[10] = {0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20};
    uint8_t cose_mid[3]     = {0x22, 0x58, 0x20};
    sha256_update(&sctx, cose_prefix, 10);
    sha256_update(&sctx, pub_x, 32);
    sha256_update(&sctx, cose_mid, 3);
    sha256_update(&sctx, pub_y, 32);
  }
  sha256_update(&sctx, client_data_hash, 32);
  sha256_final(&sctx, ctap_digest);

  uint8_t sig_r[32], sig_s[32], sig_der[72];
  bool ctap_ok = sign_p256_digest(&grp, &d, ctap_digest, sig_r, sig_s);
  size_t sig_der_len = encode_ecdsa_der(sig_r, sig_s, sig_der);

  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);

  if (!u2f_ok || !ctap_ok) {
    Serial.println("{\"ok\":false,\"cmd\":\"ENROLL\",\"err\":\"SIGN_FAILED\"}");
    return;
  }

  char kh_hex[97], px_hex[65], py_hex[65];
  char r_hex[65], s_hex[65], der_hex[145], u2f_der_hex[145];
  bytes_to_hex(kh, 48, kh_hex);
  bytes_to_hex(pub_x, 32, px_hex);
  bytes_to_hex(pub_y, 32, py_hex);
  bytes_to_hex(sig_r, 32, r_hex);
  bytes_to_hex(sig_s, 32, s_hex);
  bytes_to_hex(sig_der, sig_der_len, der_hex);
  bytes_to_hex(u2f_der, u2f_der_len, u2f_der_hex);

  Serial.printf("{\"ok\":true,\"cmd\":\"ENROLL\",\"key_handle\":\"%s\",\"pubkey_x\":\"%s\",\"pubkey_y\":\"%s\",\"counter\":%lu,\"flags\":%u,\"rk_slot\":%d,\"sig_r\":\"%s\",\"sig_s\":\"%s\",\"sig_der\":\"%s\",\"u2f_sig_der\":\"%s\"}\n",
                kh_hex, px_hex, py_hex, (unsigned long)g_counter, (unsigned int)flags, rk_slot,
                r_hex, s_hex, der_hex, u2f_der_hex);
}

static void handle_sign(char *args) {
  char *rp_hash_tok = next_token(&args);
  char *kh_tok      = next_token(&args);
  char *cd_hash_tok = next_token(&args);
  char *flags_tok   = next_token(&args);

  uint8_t rp_id_hash[32];
  uint8_t kh[48];
  uint8_t client_data_hash[32];
  if (!rp_hash_tok || !kh_tok || !cd_hash_tok ||
      !hex_to_bytes(rp_hash_tok, rp_id_hash, 32) ||
      !hex_to_bytes(kh_tok, kh, 48) ||
      !hex_to_bytes(cd_hash_tok, client_data_hash, 32)) {
    Serial.println("{\"ok\":false,\"cmd\":\"SIGN\",\"err\":\"BAD_ARGS\"}");
    return;
  }

  uint8_t flags = 0x05; // UP (0x01) | UV (0x04)
  if (flags_tok && strcmp(flags_tok, "-") != 0) {
    if (!hex_to_bytes(flags_tok, &flags, 1)) {
      Serial.println("{\"ok\":false,\"cmd\":\"SIGN\",\"err\":\"BAD_FLAGS\"}");
      return;
    }
  }

  if (!verify_key_handle(rp_id_hash, kh)) {
    Serial.println("{\"ok\":false,\"cmd\":\"SIGN\",\"err\":\"INVALID_KEY_HANDLE\"}");
    return;
  }

  if (!wait_for_user_presence("SIGN")) {
    Serial.println("{\"ok\":false,\"cmd\":\"SIGN\",\"err\":\"USER_PRESENCE_TIMEOUT\"}");
    return;
  }

  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  uint8_t pub_x[32], pub_y[32];
  if (!derive_p256_keypair(rp_id_hash, kh, &grp, &d, pub_x, pub_y)) {
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    Serial.println("{\"ok\":false,\"cmd\":\"SIGN\",\"err\":\"KEY_DERIVE_FAILED\"}");
    return;
  }

  g_counter++;
  prefs.putUInt("counter", g_counter);

  uint8_t signed_blob[32 + 1 + 4 + 32];
  memcpy(signed_blob, rp_id_hash, 32);
  signed_blob[32] = flags;
  signed_blob[33] = (uint8_t)((g_counter >> 24) & 0xFF);
  signed_blob[34] = (uint8_t)((g_counter >> 16) & 0xFF);
  signed_blob[35] = (uint8_t)((g_counter >> 8) & 0xFF);
  signed_blob[36] = (uint8_t)(g_counter & 0xFF);
  memcpy(signed_blob + 37, client_data_hash, 32);

  uint8_t digest[32];
  Sha256Ctx sctx;
  sha256_init(&sctx);
  sha256_update(&sctx, signed_blob, sizeof(signed_blob));
  sha256_final(&sctx, digest);

  uint8_t sig_r[32], sig_s[32], sig_der[72];
  bool ok = sign_p256_digest(&grp, &d, digest, sig_r, sig_s);
  size_t der_len = encode_ecdsa_der(sig_r, sig_s, sig_der);

  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);

  if (!ok) {
    Serial.println("{\"ok\":false,\"cmd\":\"SIGN\",\"err\":\"SIGN_FAILED\"}");
    return;
  }

  char px_hex[65], py_hex[65], r_hex[65], s_hex[65], der_hex[145];
  bytes_to_hex(pub_x, 32, px_hex);
  bytes_to_hex(pub_y, 32, py_hex);
  bytes_to_hex(sig_r, 32, r_hex);
  bytes_to_hex(sig_s, 32, s_hex);
  bytes_to_hex(sig_der, der_len, der_hex);

  Serial.printf("{\"ok\":true,\"cmd\":\"SIGN\",\"flags\":%u,\"counter\":%lu,\"pubkey_x\":\"%s\",\"pubkey_y\":\"%s\",\"sig_r\":\"%s\",\"sig_s\":\"%s\",\"sig_der\":\"%s\"}\n",
                (unsigned int)flags, (unsigned long)g_counter, px_hex, py_hex, r_hex, s_hex, der_hex);
}

static void handle_list_rk(char *args) {
  char *filter_tok = next_token(&args);
  uint8_t filter_hash[32];
  bool has_filter = false;
  if (filter_tok && strcmp(filter_tok, "-") != 0) {
    if (!hex_to_bytes(filter_tok, filter_hash, 32)) {
      Serial.println("{\"ok\":false,\"cmd\":\"LIST_RK\",\"err\":\"BAD_FILTER\"}");
      return;
    }
    has_filter = true;
  }

  if (!wait_for_user_presence("LIST_RK")) {
    Serial.println("{\"ok\":false,\"cmd\":\"LIST_RK\",\"err\":\"USER_PRESENCE_TIMEOUT\"}");
    return;
  }

  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  Serial.print("{\"ok\":true,\"cmd\":\"LIST_RK\",\"credentials\":[");
  bool first = true;
  ResidentKeySlot slot;
  for (int i = 0; i < MAX_RK_SLOTS; ++i) {
    char key[12];
    snprintf(key, sizeof(key), "rk_%d", i);
    if (prefs.getBytes(key, &slot, sizeof(slot)) == sizeof(slot) && slot.used == 1) {
      if (has_filter && memcmp(slot.rp_id_hash, filter_hash, 32) != 0) continue;
      uint8_t pub_x[32], pub_y[32];
      if (!derive_p256_keypair(slot.rp_id_hash, slot.key_handle, &grp, &d, pub_x, pub_y)) continue;

      char rph_hex[65], kh_hex[97], px_hex[65], py_hex[65], uid_hex[129];
      bytes_to_hex(slot.rp_id_hash, 32, rph_hex);
      bytes_to_hex(slot.key_handle, 48, kh_hex);
      bytes_to_hex(pub_x, 32, px_hex);
      bytes_to_hex(pub_y, 32, py_hex);
      bytes_to_hex(slot.user_id, slot.user_id_len, uid_hex);

      if (!first) Serial.print(",");
      first = false;
      Serial.printf("{\"slot\":%d,\"rp_id\":\"%s\",\"rp_id_hash\":\"%s\",\"user_name\":\"%s\",\"user_id\":\"%s\",\"key_handle\":\"%s\",\"pubkey_x\":\"%s\",\"pubkey_y\":\"%s\"}",
                    i, slot.rp_id, rph_hex, slot.user_name, uid_hex, kh_hex, px_hex, py_hex);
    }
  }
  Serial.println("]}");
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
}

static void handle_delete_rk(char *args) {
  char *slot_tok = next_token(&args);
  if (!slot_tok || *slot_tok == '\0') {
    Serial.println("{\"ok\":false,\"cmd\":\"DELETE_RK\",\"err\":\"BAD_ARGS\"}");
    return;
  }
  char *endptr = NULL;
  long slot_idx = strtol(slot_tok, &endptr, 10);
  if (*endptr != '\0' || slot_idx < 0 || slot_idx >= MAX_RK_SLOTS) {
    Serial.println("{\"ok\":false,\"cmd\":\"DELETE_RK\",\"err\":\"BAD_SLOT\"}");
    return;
  }
  if (!wait_for_user_presence("DELETE_RK")) {
    Serial.println("{\"ok\":false,\"cmd\":\"DELETE_RK\",\"err\":\"USER_PRESENCE_TIMEOUT\"}");
    return;
  }
  char key[12];
  snprintf(key, sizeof(key), "rk_%ld", slot_idx);
  prefs.remove(key);
  Serial.printf("{\"ok\":true,\"cmd\":\"DELETE_RK\",\"slot\":%ld}\n", slot_idx);
}

static char g_line_buf[1024];
static size_t g_line_len = 0;
static bool g_line_overflow = false;

void setup() {
  pinMode(PIN_BOOT_BTN, INPUT_PULLUP);
  pinMode(PIN_LED, OUTPUT);
  digitalWrite(PIN_LED, LOW);

  Serial.setRxBufferSize(1024);
  Serial.begin(115200);

  prefs.begin("yubiesp", false);
  if (prefs.getBytes("master_key", g_master_key, 32) != 32) {
    esp_fill_random(g_master_key, 32);
    prefs.putBytes("master_key", g_master_key, 32);
  }
  if (prefs.getBytes("aaguid", g_aaguid, 16) != 16) {
    const uint8_t default_aaguid[16] = {
      0x59, 0x55, 0x42, 0x49, 0x45, 0x53, 0x50, 0x33,
      0x32, 0x57, 0x52, 0x4f, 0x4f, 0x4d, 0x00, 0x01
    };
    memcpy(g_aaguid, default_aaguid, 16);
    prefs.putBytes("aaguid", g_aaguid, 16);
  }
  g_counter = prefs.getUInt("counter", 0);

  // Two short blinks on boot
  for (int i = 0; i < 2; ++i) {
    digitalWrite(PIN_LED, HIGH);
    delay(60);
    digitalWrite(PIN_LED, LOW);
    delay(60);
  }
}

void loop() {
  while (Serial.available() > 0) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      if (g_line_overflow) {
        g_line_len = 0;
        g_line_overflow = false;
        Serial.println("{\"ok\":false,\"err\":\"LINE_TOO_LONG\"}");
        continue;
      }
      g_line_buf[g_line_len] = '\0';
      g_line_len = 0;

      char *cursor = g_line_buf;
      char *cmd = next_token(&cursor);
      if (!cmd) continue;

      if (strcmp(cmd, "PING") == 0 || strcmp(cmd, "INFO") == 0) {
        handle_info();
      } else if (strcmp(cmd, "BLINK") == 0) {
        handle_blink();
      } else if (strcmp(cmd, "ENROLL") == 0) {
        handle_enroll(cursor);
      } else if (strcmp(cmd, "SIGN") == 0) {
        handle_sign(cursor);
      } else if (strcmp(cmd, "LIST_RK") == 0) {
        handle_list_rk(cursor);
      } else if (strcmp(cmd, "DELETE_RK") == 0) {
        handle_delete_rk(cursor);
      } else {
        Serial.println("{\"ok\":false,\"err\":\"UNKNOWN_CMD\"}");
      }
    } else if (g_line_len < sizeof(g_line_buf) - 1) {
      g_line_buf[g_line_len++] = c;
    } else {
      g_line_overflow = true;
    }
  }
}
