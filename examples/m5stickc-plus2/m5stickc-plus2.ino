/*
 * ML-KEM (FIPS 203) live demo for the M5StickC PLUS2
 * (ESP32-PICO-V3-02, 1.14" 135x240 ST7789V2 display).
 *
 * Runs one complete post-quantum key exchange per second and shows the
 * timing of every step, the running averages and a fingerprint of the
 * agreed 32-byte shared secret.
 *
 *   Button A (front, "M5"):  tamper test -- flips one ciphertext bit and
 *                            shows that decapsulation implicitly rejects it
 *   Button B (right side):   switch parameter set 512 -> 768 -> 1024
 *
 * Every exchange is also logged on the serial port (115200 baud).
 *
 * Requires the M5Unified library (Library Manager: "M5Unified"), which also
 * keeps the PLUS2 powered on battery (HOLD pin G4).
 * Board: "M5StickCPlus2" (esp32:esp32:m5stack_stickc_plus2).
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <M5Unified.h>
#include <MLKEM.h>

// Colors (RGB565)
#define COL_BG       0x0000
#define COL_HEADER   0x04B4  // teal (same in all three demos)
#define COL_CARD     0x2124
#define COL_LABEL    0xBDF7
#define COL_OK       0x07E0
#define COL_ERR      0xF800
#define COL_WARN     0xFD20

// Buffers sized for the largest parameter set
static uint8_t pk[MLKEM1024::PUBLIC_KEY_SIZE];
static uint8_t sk[MLKEM1024::SECRET_KEY_SIZE];
static uint8_t ct[MLKEM1024::CIPHERTEXT_SIZE];
static uint8_t ssBob[32], ssAlice[32];

static const unsigned LEVELS[] = {512, 768, 1024};
static int levelIdx = 1;  // start with ML-KEM-768 (NIST's recommended default)

struct Stats {
  uint32_t runs, failures;
  uint64_t sumUs[3];
  uint32_t lastUs[3];
} stats;

static const char *OP_LABEL[3] = {"KeyGen", "Encaps", "Decaps"};

// ---- ML-KEM dispatch for the selected parameter set ----------------------
template <class KEM>
int exchange(uint32_t us[3]) {
  uint32_t t0 = micros();
  int r = KEM::generateKeypair(pk, sk);         // Alice
  uint32_t t1 = micros();
  if (r == 0) r = KEM::encapsulate(ct, ssBob, pk);  // Bob
  uint32_t t2 = micros();
  if (r == 0) r = KEM::decapsulate(ssAlice, ct, sk);  // Alice
  uint32_t t3 = micros();
  us[0] = t1 - t0;
  us[1] = t2 - t1;
  us[2] = t3 - t2;
  return r;
}

static int runExchange(uint32_t us[3]) {
  switch (LEVELS[levelIdx]) {
    case 512:  return exchange<MLKEM512>(us);
    case 768:  return exchange<MLKEM768>(us);
    default:   return exchange<MLKEM1024>(us);
  }
}

static int decapsulateOnly() {
  switch (LEVELS[levelIdx]) {
    case 512:  return MLKEM512::decapsulate(ssAlice, ct, sk);
    case 768:  return MLKEM768::decapsulate(ssAlice, ct, sk);
    default:   return MLKEM1024::decapsulate(ssAlice, ct, sk);
  }
}

static size_t ciphertextSize() {
  switch (LEVELS[levelIdx]) {
    case 512:  return MLKEM512::CIPHERTEXT_SIZE;
    case 768:  return MLKEM768::CIPHERTEXT_SIZE;
    default:   return MLKEM1024::CIPHERTEXT_SIZE;
  }
}

// ---- UI ------------------------------------------------------------------
static M5Canvas canvas(&M5.Display);  // off-screen buffer: flicker-free

// Times: "6.15 ms" below 100 ms, "123.4 ms" below 10 s, "54.27 s" above
// (same format in the ML-KEM, ML-DSA and SLH-DSA demos)
static void fmtTime(char *buf, size_t n, double ms) {
  if (ms < 100) {
    snprintf(buf, n, "%.2f ms", ms);
  } else if (ms < 10000) {
    snprintf(buf, n, "%.1f ms", ms);
  } else {
    snprintf(buf, n, "%.2f s", ms / 1000.0);
  }
}

// Header: small algorithm name + bold parameter set (same in all demos)
static void drawTitle(const char *alg, const char *variant) {
  canvas.setTextColor(TFT_WHITE, COL_HEADER);
  canvas.setTextDatum(middle_left);
  canvas.setFont(&fonts::Font2);
  canvas.drawString(alg, 6, 12);
  const int x = 6 + canvas.textWidth(alg) + 6;
  canvas.setFont(&fonts::FreeSansBold9pt7b);
  canvas.drawString(variant, x, 11);
  canvas.setFont(&fonts::Font2);
}

static void drawScreen(const char *status, uint16_t statusColor) {
  const int W = canvas.width();
  canvas.fillScreen(COL_BG);

  // Header
  canvas.fillRect(0, 0, W, 22, COL_HEADER);
  drawTitle("ML-KEM", String(LEVELS[levelIdx]).c_str());
  canvas.setTextDatum(middle_right);
  canvas.drawString(String(M5.Power.getBatteryLevel()) + "%", W - 5, 11);

  // Timing rows: last run and average
  canvas.setFont(&fonts::Font2);
  canvas.setTextDatum(middle_left);
  for (int i = 0; i < 3; i++) {
    int y = 26 + i * 21;
    canvas.fillRoundRect(3, y, W - 6, 19, 4, COL_CARD);
    canvas.setTextColor(COL_LABEL, COL_CARD);
    canvas.drawString(OP_LABEL[i], 9, y + 10);
    canvas.setTextColor(TFT_WHITE, COL_CARD);
    char last[16], avg[16], buf[40];
    if (stats.runs == 0) {
      snprintf(buf, sizeof(buf), "-");
    } else {
      fmtTime(last, sizeof(last), stats.lastUs[i] / 1000.0);
      fmtTime(avg, sizeof(avg), stats.sumUs[i] / 1000.0 / stats.runs);
      snprintf(buf, sizeof(buf), "%s  avg %s", last, avg);
    }
    canvas.setTextDatum(middle_right);
    canvas.drawString(buf, W - 9, y + 10);
    canvas.setTextDatum(middle_left);
  }

  // Shared secret fingerprint + status
  canvas.setTextColor(COL_LABEL, COL_BG);
  char fp[40];
  if (stats.runs) {
    snprintf(fp, sizeof(fp), "K: %02X%02X%02X%02X..", ssAlice[0], ssAlice[1],
             ssAlice[2], ssAlice[3]);
  } else {
    snprintf(fp, sizeof(fp), "K: -");
  }
  canvas.drawString(fp, 6, 99);
  canvas.setTextColor(statusColor, COL_BG);
  canvas.setTextDatum(middle_right);
  canvas.drawString(status, W - 6, 99);

  // Footer
  canvas.setTextColor(COL_LABEL, COL_BG);
  canvas.setTextDatum(middle_left);
  char foot[48];
  snprintf(foot, sizeof(foot), "#%lu  fail %lu", (unsigned long)stats.runs,
           (unsigned long)stats.failures);
  canvas.drawString(foot, 6, 122);
  canvas.setTextDatum(middle_right);
  canvas.drawString("A:tamper B:level", W - 6, 122);

  canvas.pushSprite(0, 0);
}

static void resetStats() {
  memset(&stats, 0, sizeof(stats));
  memset(ssAlice, 0, sizeof(ssAlice));
}

// ---- Arduino ---------------------------------------------------------------
void setup() {
  auto cfg = M5.config();
  M5.begin(cfg);
  Serial.begin(115200);
  M5.Display.setRotation(1);  // landscape, 240 x 135
  M5.Display.setBrightness(96);
  canvas.createSprite(M5.Display.width(), M5.Display.height());
  resetStats();
  drawScreen("ready", COL_LABEL);
  Serial.println("\nML-KEM live demo (M5StickC PLUS2)");
}

void loop() {
  static uint32_t lastRun = 0;
  M5.update();

  if (M5.BtnB.wasPressed()) {
    levelIdx = (levelIdx + 1) % 3;
    resetStats();
    Serial.printf("Switched to ML-KEM-%u\n", LEVELS[levelIdx]);
    lastRun = 0;
  }

  if (M5.BtnA.wasPressed() && stats.runs > 0) {
    // Tamper test on the last exchange: flip one ciphertext bit
    size_t pos = esp_random() % ciphertextSize();
    ct[pos] ^= 1u << (esp_random() & 7);
    int r = decapsulateOnly();
    bool rejected = (r == 0) && memcmp(ssAlice, ssBob, 32) != 0;
    Serial.printf("Tamper test (ct byte %u flipped): %s\n", (unsigned)pos,
                  rejected ? "implicitly REJECTED" : "NOT rejected!");
    drawScreen(rejected ? "tamper REJECTED" : "tamper ACCEPTED!",
               rejected ? COL_WARN : COL_ERR);
    delay(2500);
    lastRun = millis();
    return;
  }

  if (lastRun == 0 || millis() - lastRun >= 1000) {
    lastRun = millis();
    uint32_t us[3];
    int r = runExchange(us);
    bool ok = (r == 0) && memcmp(ssAlice, ssBob, 32) == 0;
    stats.runs++;
    if (!ok) stats.failures++;
    for (int i = 0; i < 3; i++) {
      stats.lastUs[i] = us[i];
      stats.sumUs[i] += us[i];
    }
    Serial.printf("ML-KEM-%u #%lu keygen=%.2fms encaps=%.2fms decaps=%.2fms %s\n",
                  LEVELS[levelIdx], (unsigned long)stats.runs, us[0] / 1000.0,
                  us[1] / 1000.0, us[2] / 1000.0, ok ? "MATCH" : "MISMATCH");
    drawScreen(ok ? "secrets MATCH" : "MISMATCH", ok ? COL_OK : COL_ERR);
  }
  delay(10);
}
