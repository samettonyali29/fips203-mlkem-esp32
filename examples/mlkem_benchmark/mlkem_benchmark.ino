/*
 * ML-KEM benchmark for ESP32
 *
 * Measures, for ML-KEM-512, ML-KEM-768 and ML-KEM-1024:
 *   - execution time of KeyGen, Encaps and Decaps (min / median / mean / max
 *     over ITERATIONS runs, in milliseconds and CPU cycles)
 *   - peak stack and peak (transient) heap usage of each operation, bytes.
 *     By default the library keeps large temporaries on the internal heap;
 *     build with -DMLKEM_ESP32_USE_STACK to move them to the stack.
 *
 * Every operation's result is checked (shared secrets must match), so the
 * benchmark doubles as a stress test.
 *
 * Results are printed as a table and as CSV lines (prefix "CSV,") that can
 * be grepped from the serial log:
 *   CSV,parameter_set,operation,iterations,min_us,median_us,mean_us,max_us,min_cycles,stack_bytes,heap_bytes
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <MLKEM.h>
#include <esp_heap_caps.h>
#include <esp_idf_version.h>

/* Per-operation heap peaks need heap_caps_monitor_local_minimum_free_size_*
 * (ESP-IDF >= 5.3, i.e. Arduino-ESP32 >= 3.1). Older cores report 0. */
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 3, 0)
#define HAVE_HEAP_MONITOR 1
#endif
#ifndef ESP_ARDUINO_VERSION_STR
#define ESP_ARDUINO_VERSION_STR "2.x"
#endif

static const int ITERATIONS = 100;
static const uint32_t TASK_STACK = 32768;  // plenty for every parameter set

enum Op { OP_KEYGEN, OP_ENCAPS, OP_DECAPS };
static const char *OP_NAME[] = {"KeyGen", "Encaps", "Decaps"};

static uint32_t cyclesBuf[ITERATIONS];

/* ---- peak memory measurement ------------------------------------------
 * Each operation runs once in a fresh task; the task's stack high-water mark
 * then gives the peak stack depth of the operation (plus a small, constant
 * task/call overhead that is measured with an empty job and subtracted).
 * The heap peak is the drop of the minimum free internal heap during the
 * operation. */
struct MemJob {
  unsigned level;
  Op op;
  volatile uint32_t freeStack;
  volatile uint32_t heapPeak;
  TaskHandle_t notify;
};
struct MemUsage {
  uint32_t stack, heap;
};

static int cmpU32(const void *a, const void *b) {
  uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
  return (x > y) - (x < y);
}

template <class KEM>
void runOnce(Op op) {
  static uint8_t pk[KEM::PUBLIC_KEY_SIZE], sk[KEM::SECRET_KEY_SIZE];
  static uint8_t ct[KEM::CIPHERTEXT_SIZE], ss[KEM::SHARED_SECRET_SIZE];
  int ret = 0;
  switch (op) {
    case OP_KEYGEN: ret = KEM::generateKeypair(pk, sk); break;
    case OP_ENCAPS: ret = KEM::encapsulate(ct, ss, pk); break;
    case OP_DECAPS: ret = KEM::decapsulate(ss, ct, sk); break;
  }
  if (ret != 0) Serial.printf("  error %d in %s\n", ret, OP_NAME[op]);
}

static void memTask(void *arg) {
  MemJob *job = (MemJob *)arg;
#ifdef HAVE_HEAP_MONITOR
  const size_t heapBefore = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
  heap_caps_monitor_local_minimum_free_size_start();
#endif
  switch (job->level) {
    case 512:  runOnce<MLKEM512>(job->op); break;
    case 768:  runOnce<MLKEM768>(job->op); break;
    case 1024: runOnce<MLKEM1024>(job->op); break;
    default: break;  // level 0: empty job, measures the overhead
  }
#ifdef HAVE_HEAP_MONITOR
  job->heapPeak = heapBefore - heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
  heap_caps_monitor_local_minimum_free_size_stop();
#endif
  job->freeStack = uxTaskGetStackHighWaterMark(NULL);
  xTaskNotifyGive(job->notify);
  vTaskDelete(NULL);
}

static MemUsage measureMemory(unsigned level, Op op) {
  MemJob job = {level, op, 0, 0, xTaskGetCurrentTaskHandle()};
  xTaskCreate(memTask, "mem", TASK_STACK, &job, 1, NULL);
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
  vTaskDelay(2);  // let the idle task free the deleted task
  MemUsage m = {TASK_STACK - job.freeStack, job.heapPeak};
  return m;
}

/* ---- timing ------------------------------------------------------------ */
template <class KEM>
void benchLevel() {
  static uint8_t pk[KEM::PUBLIC_KEY_SIZE], sk[KEM::SECRET_KEY_SIZE];
  static uint8_t ct[KEM::CIPHERTEXT_SIZE];
  static uint8_t ssA[KEM::SHARED_SECRET_SIZE], ssB[KEM::SHARED_SECRET_SIZE];
  const uint32_t mhz = getCpuFrequencyMhz();
  const MemUsage overhead = measureMemory(0, OP_KEYGEN);
  int errors = 0;

  Serial.printf("\n--- ML-KEM-%u (NIST category %u): pk=%u sk=%u ct=%u ss=%u bytes ---\n",
                KEM::PARAMETER_SET, KEM::SECURITY_CATEGORY,
                (unsigned)KEM::PUBLIC_KEY_SIZE, (unsigned)KEM::SECRET_KEY_SIZE,
                (unsigned)KEM::CIPHERTEXT_SIZE, (unsigned)KEM::SHARED_SECRET_SIZE);
  Serial.println("  Operation      min ms   median ms     mean ms      max ms   min kcycles   stack B    heap B");

  for (int o = OP_KEYGEN; o <= OP_DECAPS; o++) {
    Op op = (Op)o;
    uint64_t sum = 0;
    for (int i = 0; i < ITERATIONS; i++) {
      /* Encaps/Decaps need a fresh key/ciphertext; prepare outside timing. */
      if (op != OP_KEYGEN && (i == 0 || op == OP_DECAPS)) {
        if (i == 0) errors += KEM::generateKeypair(pk, sk) != 0;
        if (op == OP_DECAPS) errors += KEM::encapsulate(ct, ssA, pk) != 0;
      }
      int ret = 0;
      uint32_t t0 = ESP.getCycleCount();
      switch (op) {
        case OP_KEYGEN: ret = KEM::generateKeypair(pk, sk); break;
        case OP_ENCAPS: ret = KEM::encapsulate(ct, ssA, pk); break;
        case OP_DECAPS: ret = KEM::decapsulate(ssB, ct, sk); break;
      }
      uint32_t t1 = ESP.getCycleCount();
      cyclesBuf[i] = t1 - t0;
      sum += cyclesBuf[i];
      if (ret != 0) errors++;
      if (op == OP_ENCAPS) errors += KEM::decapsulate(ssB, ct, sk) != 0 ||
                                     memcmp(ssA, ssB, sizeof ssA) != 0;
      if (op == OP_DECAPS) errors += memcmp(ssA, ssB, sizeof ssA) != 0;
      if ((i & 7) == 7) vTaskDelay(1);  // keep the idle task / watchdog happy
    }
    qsort(cyclesBuf, ITERATIONS, sizeof(uint32_t), cmpU32);
    const uint32_t cmin = cyclesBuf[0], cmax = cyclesBuf[ITERATIONS - 1];
    const uint32_t cmed = cyclesBuf[ITERATIONS / 2];
    const double cmean = (double)sum / ITERATIONS;
    const MemUsage mem = measureMemory(KEM::PARAMETER_SET, op);
    const unsigned stack = mem.stack - overhead.stack;
    const unsigned heap = mem.heap > overhead.heap ? mem.heap - overhead.heap : 0;

    Serial.printf("  %-8s %11.3f %11.3f %11.3f %11.3f %13.1f %9u %9u\n", OP_NAME[op],
                  cmin / (mhz * 1000.0), cmed / (mhz * 1000.0),
                  cmean / (mhz * 1000.0), cmax / (mhz * 1000.0), cmin / 1000.0,
                  stack, heap);
    Serial.printf("CSV,ML-KEM-%u,%s,%d,%.1f,%.1f,%.1f,%.1f,%u,%u,%u\n",
                  KEM::PARAMETER_SET, OP_NAME[op], ITERATIONS, (double)cmin / mhz,
                  (double)cmed / mhz, cmean / mhz, (double)cmax / mhz,
                  (unsigned)cmin, stack, heap);
  }
  Serial.printf("  Correctness: %s (%d errors in %d runs)\n",
                errors ? "FAILED" : "OK", errors, 3 * ITERATIONS);
  memset(sk, 0, sizeof sk);
}

static void benchTask(void *) {
  Serial.println();
  Serial.println("==============================================");
  Serial.println("  ML-KEM (FIPS 203) benchmark");
  Serial.println("==============================================");
  Serial.printf("Chip: %s rev %u, %u cores @ %u MHz, flash %u MB, PSRAM %u KB\n",
                ESP.getChipModel(), ESP.getChipRevision(), ESP.getChipCores(),
                (unsigned)getCpuFrequencyMhz(), (unsigned)(ESP.getFlashChipSize() >> 20),
                (unsigned)(ESP.getPsramSize() >> 10));
  Serial.printf("Arduino-ESP32 %s, ESP-IDF %s, %d iterations per operation\n",
                ESP_ARDUINO_VERSION_STR, esp_get_idf_version(), ITERATIONS);
  const uint32_t heapBefore = ESP.getFreeHeap();

  benchLevel<MLKEM512>();
  benchLevel<MLKEM768>();
  benchLevel<MLKEM1024>();

  Serial.printf("\nFree heap: before %u, after %u bytes, minimum ever %u bytes\n",
                (unsigned)heapBefore, (unsigned)ESP.getFreeHeap(),
                (unsigned)ESP.getMinFreeHeap());
  Serial.println("Benchmark complete.");
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  xTaskCreate(benchTask, "bench", TASK_STACK, NULL, 1, NULL);
}

void loop() {
  delay(1000);
}
