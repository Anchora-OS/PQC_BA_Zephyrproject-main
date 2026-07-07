#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/printk.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/device.h>
#include <zephyr/sys/atomic.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// Own Header Files
#include "FiPS204_implementation.h"
#include "USBcommunication.h"
#include "ECDSA_implementation.h"

#define SLEEP_TIME_MS     1000
#define PERF_MAX_RUNS     64
#define BASE_MESSAGE_TEXT "Hello from Zephyr ECDSA & Fips204 Implementation"

// Get LED, switches and button from the devicetree alias.
#define LED0_NODE    DT_ALIAS(led0)
#define BUTTON_NODE  DT_ALIAS(t3)
#define SWITCH_NODE0 DT_ALIAS(sw0)
#define SWITCH_NODE1 DT_ALIAS(sw1)

#if !DT_NODE_HAS_STATUS(LED0_NODE, okay)
#error "No led0 alias found in devicetree"
#endif

#if !DT_NODE_HAS_STATUS(BUTTON_NODE, okay)
#error "No button (sw0) alias found"
#endif

#if !DT_NODE_HAS_STATUS(SWITCH_NODE0, okay)
#error "No switch (sw0) alias found"
#endif

#if !DT_NODE_HAS_STATUS(SWITCH_NODE1, okay)
#error "No switch (sw1) alias found"
#endif

static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
static const struct gpio_dt_spec button = GPIO_DT_SPEC_GET(BUTTON_NODE, gpios);
static const struct gpio_dt_spec switch_gpio0 = GPIO_DT_SPEC_GET(SWITCH_NODE0, gpios);
static const struct gpio_dt_spec switch_gpio1 = GPIO_DT_SPEC_GET(SWITCH_NODE1, gpios);
static struct gpio_callback button_cb_data; // Button callback structure vor ISR

// global variables
static struct gpio_dt_spec OSZI_GPIO_toggle;
static mbedtls_ecdsa_context ecdsa;
unsigned char signature[64];
size_t sig_len = 0;
static char message_to_sign[128] = BASE_MESSAGE_TEXT; // Active message used for sign/verify/export
int ret;
static atomic_t test_requested = ATOMIC_INIT(0);
bool run_once_at_start = true; // Flag to run the test once at startup without button press
static int number_of_test_runs = 33;

enum perf_algo
{
    PERF_ALGO_ECDSA = 0,
    PERF_ALGO_FIPS204,
    PERF_ALGO_COUNT
};

enum perf_stage
{
    PERF_STAGE_KEYGEN = 0,
    PERF_STAGE_SIGN,
    PERF_STAGE_VERIFY,
    PERF_STAGE_COUNT
};

static uint64_t perf_time_us[PERF_ALGO_COUNT][PERF_STAGE_COUNT][PERF_MAX_RUNS];
static size_t perf_stack_before_bytes[PERF_ALGO_COUNT][PERF_STAGE_COUNT][PERF_MAX_RUNS];
static size_t perf_stack_after_bytes[PERF_ALGO_COUNT][PERF_STAGE_COUNT][PERF_MAX_RUNS];
static bool perf_stack_measurement_ok[PERF_ALGO_COUNT][PERF_STAGE_COUNT][PERF_MAX_RUNS];
static int perf_current_run_index[PERF_ALGO_COUNT] = {0};
static int perf_recorded_runs[PERF_ALGO_COUNT] = {0};

void send_ECDSA_Key_and_signature(void);

void send_FIPS204_key_and_signature(void);

static void OSZI_GPIO_set(bool active);

int init_Devices(void);

void button_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins);

bool switch_state0(void);

bool switch_state1(void);

int start_ECDSA_Test(void);

int start_FIPS204_Test(void);

static size_t base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_size);

static bool get_stack_used_bytes(size_t *used_bytes);

static bool get_heap_used_bytes(size_t *used_bytes);

static void print_performance_result(const char *label, uint64_t cycle_delta, size_t stack_before,
                                     size_t stack_after, bool stack_ok, size_t heap_before,
                                     size_t heap_after, bool heap_ok);

static int execute_test(bool use_fips204);

static int run_automatic_tests(bool use_fips204);

static int run_manual_test(bool use_fips204);

static int calc_test_results(bool use_fips204);

static int send_structured_test_results(bool use_fips204);

static void performance_tests_reset(bool use_fips204);

static void performance_set_run_index(bool use_fips204, int run_index);

static void performance_record(bool use_fips204, enum perf_stage stage, uint64_t cycle_delta,
                               size_t stack_before, size_t stack_after, bool stack_ok);

static void update_message_for_run(int run_index);

/**
 * @brief Initialize the board and dispatch the selected test mode.
 *
 * Waits for a test request, reads the board switches, and runs either the
 * manual or automatic test flow.
 *
 * @return int Returns 0 for normal operation and 1 on fatal test errors.
 */
int main(void)
{
    USB_print("\n\nStarting Main\n");
    if (init_Devices())
    {
        USB_print("LED initialization failed\n");
        return 0;
    }
    while (true)
    {
        if (atomic_cas(&test_requested, 1, 0) ||
            run_once_at_start) // ren tests on button press or once at startup
        {
            if (!run_once_at_start)
            {
                USB_print("\n\nButton pressed, continue testing...\n");
            }
            run_once_at_start = false;
            atomic_set(&test_requested, 0);

            // Read the mode selection switch to determine which algorithm to test.
            bool use_fips204 = switch_state0();

            // Read the second switch to determine whether to run the multi-pass
            // benchmark or just a single test.
            if (switch_state1())
            {
                if (run_automatic_tests(use_fips204) != 0)
                {
                    USB_print("Automatic test run failed\n");
                    return 1;
                }
            }
            else
            {
                if (run_manual_test(use_fips204) != 0)
                {
                    USB_print("Manual test run failed\n");
                    return 1;
                }
            }
        }
        gpio_pin_toggle_dt(&led); // Toggle LED to indicate program is running and
        // responsive, also while waiting for button press
        k_msleep(50);
    }
    return 0;
}

/**
 * @brief Run the selected signature implementation.
 *
 * Dispatches to the ECDSA or ML-DSA test flow based on the active mode flag.
 *
 * @param [in] use_fips204 True selects ML-DSA, false selects ECDSA.
 * @return int Returns 0 when the selected flow completes successfully.
 */
static int execute_test(bool use_fips204)
{
    if (use_fips204)
    {
        USB_print("Testing Fips204 implementation...\n");
        return start_FIPS204_Test();
    }

    USB_print("Testing ECDSA implementation...\n");
    return start_ECDSA_Test();
}

/**
 * @brief Run one manual test pass
 *
 * Keeps the base message unchanged and executes a single selected algorithm
 * run without collecting summary output.
 *
 * @param [in] use_fips204 True selects ML-DSA, false selects ECDSA.
 * @return int Returns 0 on success and 1 on failure.
 */
static int run_manual_test(bool use_fips204)
{
    // Single-run mode keeps the original unchanged base message.
    snprintf(message_to_sign, sizeof(message_to_sign), "%s", BASE_MESSAGE_TEXT);

    performance_tests_reset(use_fips204);
    performance_set_run_index(use_fips204, 0);

    if (execute_test(use_fips204) != 0)
    {
        USB_print("Test failed\n");
        return 1;
    }

    // uncomment these lines to send results for the single run  as structured data to the host
    // too
    /*if (calc_test_results(use_fips204) != 0) {
        USB_print("Result calculation failed\n");
        return 1;
    }*/

    return 0;
}

/**
 * @brief Run the configured multi-pass benchmark mode.
 *
 * Updates the signed message per run, collects measurements, and exports the
 * summary data after the loop finishes.
 *
 * @param [in] use_fips204 True selects ML-DSA, false selects ECDSA.
 * @return int Returns 0 on success and 1 on failure.
 */
static int run_automatic_tests(bool use_fips204)
{
    performance_tests_reset(use_fips204);

    if (number_of_test_runs > PERF_MAX_RUNS)
    {
        char warning_msg[120];
        snprintf(warning_msg, sizeof(warning_msg),
                "Warning: only first %d test runs are stored for averaging calculations\n",
                PERF_MAX_RUNS);
        USB_print(warning_msg);
    }

    for (int test_run = 1; test_run <= number_of_test_runs; test_run++)
    {
        char run_msg[96];
        USB_print("-----------------------------------------------------\n");
        snprintf(run_msg, sizeof(run_msg), "\n\n--- Test Run %d of %d ---\n", test_run,
                number_of_test_runs);
        USB_print(run_msg);

        update_message_for_run(test_run); // Update the message to sign for each run to
        // ensure distinct signatures

        performance_set_run_index(use_fips204, test_run - 1);

        if (execute_test(use_fips204) != 0)
        {
            USB_print("Test failed\n");
            return 1;
        }
    }

    if (calc_test_results(use_fips204) != 0)
    {
        USB_print("Result calculation failed\n");
        return 1;
    }

    if (send_structured_test_results(use_fips204) != 0)
    {
        USB_print("Structured CSV export failed\n");
        return 1;
    }

    USB_print("\n\nAll test runs completed successfully on Board \n");
    return 0;
}

/**
 * @brief Summarize the collected benchmark results on the console.
 *
 * Prints stack usage per stage and timing statistics for the active
 * algorithm.
 *
 * @param [in] use_fips204 True selects ML-DSA, false selects ECDSA.
 * @return int Returns 0 when statistics were printed successfully.
 */
static int calc_test_results(bool use_fips204)
{
    enum perf_algo algo = use_fips204 ? PERF_ALGO_FIPS204 : PERF_ALGO_ECDSA;
    const char *algo_name =
            use_fips204
            ? "FIPS204"
            : "ECDSA"; // Check if any runs were recorded for the selected algorithm.

    if (perf_recorded_runs[algo] <= 0)
    {
        char no_data_msg[80];
        snprintf(no_data_msg, sizeof(no_data_msg), "No %s performance samples recorded\n",
                algo_name);
        USB_print(no_data_msg);
        return 1;
    }

    const char *stage_label[PERF_STAGE_COUNT] = {"key generation", "signing", "verify"};
    char msg[220];

    USB_print("\n===== Stack Usage Per Test Run =====\n");

    // Print stack usage for each recorded run and stage
    for (int run = 0; run < perf_recorded_runs[algo]; run++)
    {
        snprintf(msg, sizeof(msg), "\nTest Run %d:\n", run + 1);
        USB_print(msg);

        for (int stage = 0; stage < PERF_STAGE_COUNT; stage++)
        {
            if (perf_stack_measurement_ok[algo][stage][run])
            {
                snprintf(msg, sizeof(msg), "-    %s: %u bytes\n",
                        stage_label[stage],
                        (unsigned int) perf_stack_after_bytes[algo][stage][run]);
            }
            else
            {
                snprintf(msg, sizeof(msg), "-    %s: n/a\n", stage_label[stage]);
            }
            USB_print(msg);
        }
    }

    USB_print("\n===== Performance Statistics (Time) =====\n");

    // Calculate and print mean, min, and max timing for each stage across all recorded runs
    for (int stage = 0; stage < PERF_STAGE_COUNT; stage++)
    {
        uint64_t sum_us = 0;
        uint64_t min_us = UINT64_MAX;
        uint64_t max_us = 0;

        for (int run = 0; run < perf_recorded_runs[algo]; run++)
        {
            uint64_t time_us = perf_time_us[algo][stage][run];
            sum_us += time_us;
            if (time_us < min_us)
            {
                min_us = time_us;
            }
            if (time_us > max_us)
            {
                max_us = time_us;
            }
        }

        uint64_t mean_us = sum_us / (uint64_t) perf_recorded_runs[algo];

        snprintf(msg, sizeof(msg),
                "\n-  %s:\n  Mean: %llu us | Min: %llu us | Max: %llu us\n",
                stage_label[stage], (unsigned long long) mean_us,
                (unsigned long long) min_us, (unsigned long long) max_us);
        USB_print(msg);
    }

    return 0;
}

/**
 * @brief Send the collected benchmark results as structured CSV data.
 *
 * Builds the host-facing CSV payload and transfers it over USB.
 *
 * @param [in] use_fips204 True selects ML-DSA, false selects ECDSA.
 * @return int Returns 0 when the payload was generated and sent.
 */
static int send_structured_test_results(bool use_fips204)
{
    enum perf_algo algo = use_fips204 ? PERF_ALGO_FIPS204 : PERF_ALGO_ECDSA;
    const char *algo_name =
            use_fips204
            ? "FIPS204"
            : "ECDSA"; // Check if any runs were recorded for the selected algorithm.

    if (perf_recorded_runs[algo] <= 0)
    {
        return 1;
    }

    const char *stage_label[PERF_STAGE_COUNT] = {"key_generation", "signing", "verify"};

    static char csv_buffer[16384];
    int buffer_pos = 0;
    int buffer_max = sizeof(csv_buffer);

    int written = snprintf(
            csv_buffer + buffer_pos, buffer_max - buffer_pos,
            "algorithm,stage,run,time_us,stack_before,stack_after,stack_used_bytes,stack_ok\n");
    if (written < 0 || written >= (buffer_max - buffer_pos))
    {
        USB_print("CSV buffer too small at header\n");
        return 1;
    }
    buffer_pos += written;

    // Write a CSV line for each recorded run and stage with the format:
    // algorithm,stage,run,time_us,stack_before,stack_after,stack_used_bytes,stack_ok
    for (int run = 0; run < perf_recorded_runs[algo]; run++)
    {
        for (int stage = 0; stage < PERF_STAGE_COUNT; stage++)
        {
            uint64_t time_us = perf_time_us[algo][stage][run];
            size_t stack_before = perf_stack_before_bytes[algo][stage][run];
            size_t stack_after = perf_stack_after_bytes[algo][stage][run];
            bool stack_ok = perf_stack_measurement_ok[algo][stage][run];
            long stack_used = stack_ok ? (long) stack_after - (long) stack_before : 0;

            written = snprintf(csv_buffer + buffer_pos, buffer_max - buffer_pos,
                    "%s,%s,%d,%llu,%u,%u,%ld,%s\n", algo_name,
                    stage_label[stage], run + 1, (unsigned long long) time_us,
                    (unsigned int) stack_before, (unsigned int) stack_after,
                    stack_used, stack_ok ? "true" : "false");

            if (written < 0 || written >= (buffer_max - buffer_pos))
            {
                USB_print("CSV buffer too small, truncating results\n");
                USB_send_structured_data(csv_buffer);
                return 0;
            }

            buffer_pos += written;
        }
    }

    USB_send_structured_data(csv_buffer); // Send the CSV data over USB to the host for analysis
    return 0;
}

/**
 * @brief Clear all stored benchmark samples for the selected algorithm.
 *
 * Resets timing, stack, and run counters for the chosen test path.
 *
 * @param [in] use_fips204 True selects ML-DSA, false selects ECDSA.
 * @return None.
 */
static void performance_tests_reset(bool use_fips204)
{
    enum perf_algo algo = use_fips204 ? PERF_ALGO_FIPS204 : PERF_ALGO_ECDSA;

    memset(perf_time_us[algo], 0, sizeof(perf_time_us[algo]));
    memset(perf_stack_before_bytes[algo], 0, sizeof(perf_stack_before_bytes[algo]));
    memset(perf_stack_after_bytes[algo], 0, sizeof(perf_stack_after_bytes[algo]));
    memset(perf_stack_measurement_ok[algo], 0, sizeof(perf_stack_measurement_ok[algo]));
    perf_current_run_index[algo] = 0;
    perf_recorded_runs[algo] = 0;
}

/**
 * @brief Select the result slot for the next recorded benchmark sample.
 *
 * Stores the zero-based run index used by the measurement recorder.
 *
 * @param [in] use_fips204 True selects ML-DSA, false selects ECDSA.
 * @param [in] run_index Zero-based test run index.
 * @return None.
 */
static void performance_set_run_index(bool use_fips204, int run_index)
{
    enum perf_algo algo = use_fips204 ? PERF_ALGO_FIPS204 : PERF_ALGO_ECDSA;
    perf_current_run_index[algo] = run_index;
}

/**
 * @brief Store one benchmark measurement in the active slot.
 *
 * Records timing and stack usage for the current algorithm and stage.
 *
 * @param [in] use_fips204 True selects ML-DSA, false selects ECDSA.
 * @param [in] stage Benchmark stage being recorded.
 * @param [in] cycle_delta Measured cycle delta for the stage.
 * @param [in] stack_before Stack usage before the stage.
 * @param [in] stack_after Stack usage after the stage.
 * @param [in] stack_ok True when stack information was collected successfully.
 * @return None.
 */
static void performance_record(bool use_fips204, enum perf_stage stage, uint64_t cycle_delta,
                               size_t stack_before, size_t stack_after, bool stack_ok)
{
    enum perf_algo algo = use_fips204 ? PERF_ALGO_FIPS204 : PERF_ALGO_ECDSA;

    // stage and run index validation to prevent out-of-bounds access
    if (stage < 0 || stage >= PERF_STAGE_COUNT)
    {
        return;
    }

    // perf_current_run_index is set externally before the test run starts
    if (perf_current_run_index[algo] < 0 || perf_current_run_index[algo] >= PERF_MAX_RUNS)
    {
        return;
    }

    perf_time_us[algo][stage][perf_current_run_index[algo]] = k_cyc_to_us_floor64(cycle_delta);
    perf_stack_before_bytes[algo][stage][perf_current_run_index[algo]] = stack_before;
    perf_stack_after_bytes[algo][stage][perf_current_run_index[algo]] = stack_after;
    perf_stack_measurement_ok[algo][stage][perf_current_run_index[algo]] = stack_ok;

    if ((perf_current_run_index[algo] + 1) > perf_recorded_runs[algo])
    {
        perf_recorded_runs[algo] = perf_current_run_index[algo] + 1;
    }
}

/**
 * @brief Refresh the message string for the next benchmark run.
 *
 * Appends the run number so each automatic pass signs distinct data.
 *
 * @param [in] run_index One-based test run index.
 * @return None.
 */
static void update_message_for_run(int run_index)
{
    snprintf(message_to_sign, sizeof(message_to_sign), "%s [Run %d]", BASE_MESSAGE_TEXT,
            run_index);
}

/**
 * @brief Execute the ECDSA key generation, signing, and verification flow.
 *
 * Starts from a clean ECDSA state, measures each stage, and sends the result
 * payload over USB.
 *
 * @return int Returns 0 on success and 1 when any ECDSA step fails.
 */
int start_ECDSA_Test(void)
{
    size_t stack_before = 0;
    size_t stack_after = 0;
    size_t heap_before = 0;
    size_t heap_after = 0;
    bool stack_ok;
    bool heap_ok;
    uint64_t t0;
    uint64_t t1;
    int rc;

    // Start each run from a clean ECDSA/signature state.
    ecdsa_free(&ecdsa);
    sig_len = 0;
    memset(signature, 0, sizeof(signature));

    USB_print("Generating ECDSA keypair...\n");
    stack_ok = get_stack_used_bytes(&stack_before);
    heap_ok = get_heap_used_bytes(&heap_before);
    OSZI_GPIO_set(true);   // Set GPIO high to indicate start of key generation for oscilloscope
    // measurement
    t0 = k_cycle_get_64(); // start time measurement for key generation
    rc = ecdsa_generate_keys(&ecdsa);
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (rc != 0)
    {
        USB_print("Key generation failed\n");
        return 1;
    }
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    if (heap_ok)
    {
        heap_ok = get_heap_used_bytes(&heap_after);
    }
    print_performance_result("ECDSA keygen", t1 - t0, stack_before, stack_after, stack_ok, heap_before, heap_after, heap_ok);
    performance_record(false, PERF_STAGE_KEYGEN, t1 - t0, stack_before, stack_after, stack_ok);
    USB_print("Key generation successful\n");

    USB_print("Signing message...\n");
    stack_ok = get_stack_used_bytes(&stack_before);
    heap_ok = get_heap_used_bytes(&heap_before);
    OSZI_GPIO_set(
            true); // Set GPIO high to indicate start of signing for oscilloscope measurement
    t0 = k_cycle_get_64(); // start time measurement for signing
    rc = ecdsa_sign(&ecdsa, (const unsigned char *) message_to_sign, strlen(message_to_sign),
            signature, &sig_len);
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (rc != 0)
    {
        USB_print("Signing failed\n");
        return 1;
    }
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    if (heap_ok)
    {
        heap_ok = get_heap_used_bytes(&heap_after);
    }
    print_performance_result("ECDSA sign", t1 - t0, stack_before, stack_after, stack_ok, heap_before, heap_after, heap_ok);
    performance_record(false, PERF_STAGE_SIGN, t1 - t0, stack_before, stack_after, stack_ok);
    USB_print("Signing successful\n");

    USB_print("Verifying signature...\n");
    stack_ok = get_stack_used_bytes(&stack_before);
    heap_ok = get_heap_used_bytes(&heap_before);
    OSZI_GPIO_set(true);   // Set GPIO high to indicate start of verification for oscilloscope
    // measurement
    t0 = k_cycle_get_64(); // start time measurement for verification
    rc = ecdsa_verify(&ecdsa, (const unsigned char *) message_to_sign, strlen(message_to_sign),
            signature, sig_len);
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (rc != 0)
    {
        USB_print("Verification failed\n");
        return 1;
    }
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    if (heap_ok)
    {
        heap_ok = get_heap_used_bytes(&heap_after);
    }
    print_performance_result("ECDSA verify", t1 - t0, stack_before, stack_after, stack_ok, heap_before, heap_after, heap_ok);
    performance_record(false, PERF_STAGE_VERIFY, t1 - t0, stack_before, stack_after, stack_ok);
    USB_print("Verification successful\n");

    USB_print("Sending signature and Key\n");
    send_ECDSA_Key_and_signature(); // Send the generated key and signature over USB to the host
    // for verification
    return 0;
}

/**
 * @brief Execute the ML-DSA key generation, signing, and verification flow.
 *
 * Starts from a clean ML-DSA state, measures each stage, and sends the result
 * payload over USB.
 *
 * @return int Returns 0 on success and 1 when any ML-DSA step fails.
 */
int start_FIPS204_Test(void)
{
    size_t stack_before = 0;
    size_t stack_after = 0;
    size_t heap_before = 0;
    size_t heap_after = 0;
    bool stack_ok;
    bool heap_ok;
    uint64_t t0;
    uint64_t t1;
    int rc;

    // Start each run from a clean ML-DSA state.
    fips204_reset_state();

    USB_print("Generating ML-DSA keypair...\n");
    stack_ok = get_stack_used_bytes(&stack_before);
    heap_ok = get_heap_used_bytes(&heap_before);
    OSZI_GPIO_set(true);   // Set GPIO high to indicate start of key generation for oscilloscope
    // measurement
    t0 = k_cycle_get_64(); // start time measurement for key generation
    rc = fips204_generate_keys();
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (rc != 0)
    {
        USB_print("ML-DSA key generation failed\n");
        return 1;
    }
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    if (heap_ok)
    {
        heap_ok = get_heap_used_bytes(&heap_after);
    }
    print_performance_result("ML-DSA keygen", t1 - t0, stack_before, stack_after, stack_ok, heap_before, heap_after, heap_ok);
    performance_record(true, PERF_STAGE_KEYGEN, t1 - t0, stack_before, stack_after, stack_ok);
    USB_print("ML-DSA key generation successful\n");

    USB_print("Signing ML-DSA message...\n");
    stack_ok = get_stack_used_bytes(&stack_before);
    heap_ok = get_heap_used_bytes(&heap_before);
    OSZI_GPIO_set(
            true); // Set GPIO high to indicate start of signing for oscilloscope measurement
    t0 = k_cycle_get_64(); // start time measurement for signing
    rc = fips204_sign();
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (rc != 0)
    {
        USB_print("ML-DSA signing failed\n");
        return 1;
    }
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    if (heap_ok)
    {
        heap_ok = get_heap_used_bytes(&heap_after);
    }
    print_performance_result("ML-DSA sign", t1 - t0, stack_before, stack_after, stack_ok, heap_before, heap_after, heap_ok);
    performance_record(true, PERF_STAGE_SIGN, t1 - t0, stack_before, stack_after, stack_ok);
    USB_print("ML-DSA signing successful\n");

    USB_print("Verifying ML-DSA signature...\n");
    stack_ok = get_stack_used_bytes(&stack_before);
    heap_ok = get_heap_used_bytes(&heap_before);
    OSZI_GPIO_set(true);   // Set GPIO high to indicate start of verification for oscilloscope
    // measurement
    t0 = k_cycle_get_64(); // start time measurement for verification
    rc = fips204_verify();
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (rc != 0)
    {
        USB_print("ML-DSA verification failed\n");
        return 1;
    }
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    if (heap_ok)
    {
        heap_ok = get_heap_used_bytes(&heap_after);
    }
    print_performance_result("ML-DSA verify", t1 - t0, stack_before, stack_after, stack_ok, heap_before, heap_after, heap_ok);
    performance_record(true, PERF_STAGE_VERIFY, t1 - t0, stack_before, stack_after, stack_ok);
    USB_print("ML-DSA verification successful\n");

    USB_print("Sending ML-DSA signature and key\n");
    send_FIPS204_key_and_signature(); // Send the generated key and signature over USB to the
    // host for verification
    return 0;
}

/**
 * @brief Record the button interrupt as a pending test request.
 *
 * Latches the request flag so the main loop can start the next test in
 * thread context.
 *
 * @param [in] dev Button device that triggered the callback.
 * @param [in] cb GPIO callback object registered for the button.
 * @param [in] pins Active pin mask supplied by Zephyr.
 * @return None.
 */
void button_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
    ARG_UNUSED(dev);
    ARG_UNUSED(cb);
    ARG_UNUSED(pins);

    atomic_set(&test_requested, 1);
}

/**
 * @brief Drive the oscilloscope GPIO marker pin.
 *
 * Uses the configured probe pin only when the port is ready.
 *
 * @param [in] active True drives the marker high, false drives it low.
 * @return None.
 */
static void OSZI_GPIO_set(bool active)
{
    if (!gpio_is_ready_dt(&OSZI_GPIO_toggle))
    {
        return;
    }

    gpio_pin_set_dt(&OSZI_GPIO_toggle, active ? 1 : 0);
}

/**
 * @brief Read the first mode switch from the board.
 *
 * Returns the current logic level from the selected GPIO line.
 *
 * @return bool True when the switch is active, false otherwise.
 */
bool switch_state0(void)
{
    int val = gpio_pin_get_dt(&switch_gpio0);
    if (val < 0)
    {
        return false;
    }
    return val > 0;
}

/**
 * @brief Read the second mode switch from the board.
 *
 * Returns the current logic level from the selected GPIO line.
 *
 * @return bool True when the switch is active, false otherwise.
 */
bool switch_state1(void)
{
    int val = gpio_pin_get_dt(&switch_gpio1);
    if (val < 0)
    {
        return false;
    }
    return val > 0;
}

/**
 * @brief Encode raw bytes as base64.
 *
 * Writes a null-terminated base64 string when the output buffer is large
 * enough.
 *
 * @param [in] in Source buffer.
 * @param [in] in_len Source length in bytes.
 * @param [out] out Destination buffer.
 * @param [in] out_size Destination buffer size in bytes.
 * @return size_t Number of written characters, or 0 on failure.
 */
static size_t base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_size)
{
    static const char b64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // static base64
    // character set
    size_t required = 4 * ((in_len + 2) / 3);
    size_t i = 0;
    size_t j = 0;

    if (out_size < required + 1)
    {
        return 0;
    }

    // Process input in 3-byte blocks and convert to 4 base64 characters
    while (i < in_len)
    {
        uint32_t octet_a = in[i++];
        uint32_t octet_b = (i < in_len) ? in[i++] : 0;
        uint32_t octet_c = (i < in_len) ? in[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = b64[(triple >> 18) & 0x3F];
        out[j++] = b64[(triple >> 12) & 0x3F];
        out[j++] = b64[(triple >> 6) & 0x3F];
        out[j++] = b64[triple & 0x3F];
    }

    // Add padding characters if input length is not a multiple of 3
    if (in_len % 3 == 1)
    {
        out[j - 2] = '=';
        out[j - 1] = '=';
    }
    else if (in_len % 3 == 2)
    {
        out[j - 1] = '=';
    }

    // Null-terminate the output string
    out[j] = '\0';
    return j;
}

/**
 * @brief Measure the current thread stack usage.
 *
 * Uses Zephyr stack-info support when available and reports the current
 * high-water mark in bytes.
 *
 * @param [out] used_bytes Receives the current stack usage in bytes.
 * @return bool True when stack information is available.
 */
static bool get_stack_used_bytes(size_t *used_bytes)
/*
 * Stack usage here is a high-watermark metric from Zephyr stack initialization.
 * It reports the maximum stack depth reached so far by this thread, not a
 * per-call "live" stack value. Because of that, later test runs can show a
 * "new peak delta" of 0 bytes when they stay within the already observed peak.
 */
{
#if defined(CONFIG_THREAD_STACK_INFO) && \
    defined(CONFIG_INIT_STACKS) // Zephyr must be configured to track stack usage and initialize
    // stack memory for this to work
size_t unused = 0;
if (k_thread_stack_space_get(k_current_get(), &unused) != 0) {
return false;
}

*used_bytes = CONFIG_MAIN_STACK_SIZE - unused;
return true;
#else
    ARG_UNUSED(used_bytes);
    return false;
#endif
}

#include <stdlib.h>
#include <new>

// Global variable to track allocations across the runtime
static size_t total_heap_allocated = 0;
static size_t peak_heap_allocated = 0;

// Override C++ global 'new'
void* operator new(size_t size) {
    total_heap_allocated += size;
    if (total_heap_allocated > peak_heap_allocated) {
        peak_heap_allocated = total_heap_allocated;
    }
    return malloc(size);
}

// Override C++ global 'delete' 
void operator delete(void* p, size_t size) noexcept {
    if (p) {
        total_heap_allocated -= size;
        free(p);
    }
}

// For older C++ configurations that don't pass size to delete
void operator delete(void* p) noexcept {
    if (p) {
        free(p);
    }
}

// Override arrays
void* operator new[](size_t size) {
    total_heap_allocated += size;
    if (total_heap_allocated > peak_heap_allocated) {
        peak_heap_allocated = total_heap_allocated;
    }
    return malloc(size);
}

void operator delete[](void* p, size_t size) noexcept {
    if (p) {
        total_heap_allocated -= size;
        free(p);
    }
}

void operator delete[](void* p) noexcept {
    if (p) {
        free(p);
    }
}

static bool get_heap_used_bytes(size_t *used_bytes)
{
    // Return the peak count of bytes requested by C++ 'new' commands
    // We return the peak instead of the current, because by the time
    // this function is called, the algorithm might have already freed
    // its intermediate vectors.
    *used_bytes = peak_heap_allocated;
    return true;
}

/**
 * @brief Print a single timing and stack-usage measurement.
 *
 * Formats the measured duration and stack change into a compact USB log line.
 *
 * @param [in] label Short label for the benchmarked step.
 * @param [in] cycle_delta Measured cycle delta for the step.
 * @param [in] stack_before Stack usage before the step.
 * @param [in] stack_after Stack usage after the step.
 * @param [in] stack_ok True when stack information was collected successfully.
 * @param [in] heap_before Heap usage before the step.
 * @param [in] heap_after Heap usage after the step.
 * @param [in] heap_ok True when heap information was collected successfully.
 * @return None.
 */
static void print_performance_result(const char *label, uint64_t cycle_delta, size_t stack_before,
                                     size_t stack_after, bool stack_ok, size_t heap_before,
                                     size_t heap_after, bool heap_ok)
{
    char msg[256];
    uint64_t us = k_cyc_to_us_floor64(cycle_delta);
    int pos = 0;

    if (stack_ok)
    {
        long delta = (long) stack_after - (long) stack_before;
        pos += snprintf(
                msg + pos, sizeof(msg) - pos,
                "PERF %s: %llu us | stack used: %u -> %u bytes (new peak delta %+ld bytes)",
                label, (unsigned long long) us, (unsigned int) stack_before,
                (unsigned int) stack_after, delta);
    }
    else
    {
        pos += snprintf(msg + pos, sizeof(msg) - pos,
                "PERF %s: %llu us | stack used: n/a (enable CONFIG_THREAD_STACK_INFO)",
                label, (unsigned long long) us);
    }

    if (pos < (int)sizeof(msg))
    {
        if (heap_ok)
        {
            long heap_delta = (long) heap_after - (long) heap_before;
            snprintf(msg + pos, sizeof(msg) - pos,
                    " | heap used: %u -> %u bytes (delta %+ld bytes)",
                    (unsigned int) heap_before, (unsigned int) heap_after, heap_delta);
        }
        else
        {
            snprintf(msg + pos, sizeof(msg) - pos, " | heap used: n/a");
        }
    }

    USB_print(msg);
}

/**
 * @brief Initialize the board peripherals and callbacks used by the tests.
 *
 * Configures the USB console, LED, button, switches, and the oscilloscope pin.
 *
 * @return int Returns 0 on success and 1 when a device setup step fails.
 */
int init_Devices(void)
{
    const struct device *cdc_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));
    if (!device_is_ready(cdc_dev))
    {
        USB_print("CDC ACM device not ready\n");
        return 1;
    }

    if (!gpio_is_ready_dt(&led))
    {
        USB_print("Error: LED device not ready\n");
        return 1;
    }

    ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
    if (ret < 0)
    {
        USB_print("Error: cannot configure LED\n");
        return 1;
    }

    // Configure the button input.
    ret = gpio_pin_configure_dt(&button, GPIO_INPUT);
    if (ret < 0)
    {
        printk("Error: button config failed\n");
        return 1;
    }

    // Enable the edge-triggered button interrupt.
    ret = gpio_pin_interrupt_configure_dt(&button, GPIO_INT_EDGE_TO_ACTIVE);
    if (ret < 0)
    {
        printk("Error: interrupt config failed\n");
        return 1;
    }

    // Configure both mode switches as inputs.
    ret = gpio_pin_configure_dt(&switch_gpio0, GPIO_INPUT);
    if (ret < 0)
    {
        printk("Error: switch0 config failed\n");
        return 1;
    }

    ret = gpio_pin_configure_dt(&switch_gpio1, GPIO_INPUT);
    if (ret < 0)
    {
        printk("Error: switch1 config failed\n");
        return 1;
    }

    OSZI_GPIO_toggle.port = DEVICE_DT_GET(DT_NODELABEL(gpiod));
    if (!device_is_ready(OSZI_GPIO_toggle.port))
    {
        printk("Error: OSZI GPIO port device not ready\n");
        return 1;
    }
    OSZI_GPIO_toggle.pin = 3;
    OSZI_GPIO_toggle.dt_flags = GPIO_ACTIVE_HIGH;

    ret = gpio_pin_configure_dt(&OSZI_GPIO_toggle, GPIO_OUTPUT_INACTIVE);
    if (ret < 0)
    {
        printk("Error: OSZI GPIO config failed\n");
        return 1;
    }

    gpio_init_callback(&button_cb_data, button_pressed, BIT(button.pin));
    gpio_add_callback(button.port, &button_cb_data);

    return 0; // Return 0 when initialization succeeds and 1 on a fatal setup error.
}

/**
 * @brief Send the ECDSA public key, signature, and message as one USB payload.
 *
 * Serializes the EC public key, signature, and message into the host's
 * delimiter-based payload format.
 *
 * @return None.
 */
void send_ECDSA_Key_and_signature(void)
{
    unsigned char pub_raw[2 + 32 + 2 + 32]; // len(Qx) + Qx + len(Qy) + Qy
    size_t qx_len = 32;
    size_t qy_len = 32;
    size_t pub_raw_len;

    char pub_b64[200];
    char sig_b64[200];
    char msg_b64[256];
    char payload[800];

    int rc;

    if (sig_len == 0)
    {
        USB_print("send_USB: signature is empty");
        return;
    }

    // Extract public key (Qx, Qy)
    unsigned char pubkey_uncompressed[65];
    size_t pubkey_len = 0;

    // Export public key in uncompressed format: 0x04 || X || Y
    rc = mbedtls_ecp_point_write_binary(&ecdsa.MBEDTLS_PRIVATE(grp), &ecdsa.MBEDTLS_PRIVATE(Q),
            MBEDTLS_ECP_PF_UNCOMPRESSED, &pubkey_len,
            pubkey_uncompressed, sizeof(pubkey_uncompressed));

    if (rc != 0)
    {
        USB_print("send_USB: failed to export EC public key");
        return;
    }

    if (pubkey_len != sizeof(pubkey_uncompressed) || pubkey_uncompressed[0] != 0x04)
    {
        USB_print("send_USB: invalid uncompressed EC public key format");
        return;
    }

    // Build raw public key buffer.
    unsigned char *qx_ptr = &pubkey_uncompressed[1]; // Skip the 0x04 prefix before Qx.
    unsigned char *qy_ptr = &pubkey_uncompressed[33];

    // Build the raw public-key payload format used by the host.
    pub_raw[0] = (unsigned char) ((qx_len >> 8) & 0xFF);
    pub_raw[1] = (unsigned char) (qx_len & 0xFF);
    memcpy(&pub_raw[2], qx_ptr, qx_len);

    pub_raw[2 + qx_len] = (unsigned char) ((qy_len >> 8) & 0xFF);
    pub_raw[3 + qx_len] = (unsigned char) (qy_len & 0xFF);
    memcpy(&pub_raw[4 + qx_len], qy_ptr, qy_len);

    pub_raw_len = 4 + qx_len + qy_len;

    // Keep each field separate so the host can validate them independently and
    // detect which part failed before the final payload is assembled.
    // The public key is packed binary data, while signature and message are
    // already raw buffers from the current test run.
    if (base64_encode(pub_raw, pub_raw_len, pub_b64, sizeof(pub_b64)) == 0)
    {
        USB_print("send_USB: pubkey base64 failed");
        return;
    }

    if (base64_encode(signature, sig_len, sig_b64, sizeof(sig_b64)) == 0)
    {
        USB_print("send_USB: signature base64 failed");
        return;
    }

    if (base64_encode((unsigned char *) message_to_sign, strlen(message_to_sign), msg_b64,
            sizeof(msg_b64)) == 0)
    {
        USB_print("send_USB: message base64 failed");
        return;
    }

    // Join the three encoded fields using the host parser's fixed delimiter.
    // If the payload does not fit, the host would only receive a truncated
    // record, so the send is aborted instead.
    if (snprintf(payload, sizeof(payload), "%s@%s@%s", pub_b64, sig_b64, msg_b64) >=
        (int) sizeof(payload))
    {
        USB_print("send_USB: payload buffer too small");
        return;
    }

    // Send public key, signature and message over USB in format
    // "base64(pubkey)@base64(signature)@base64(message)" so the host can split it
    // correctly and verify the result.
    USB_send_key_and_signature(payload);
}

/**
 * @brief Send the ML-DSA public key, signature, and message as one USB payload.
 *
 * Serializes the ML-DSA artifacts into the host's delimiter-based payload
 * format.
 *
 * @return None.
 */
void send_FIPS204_key_and_signature(void)
{
    const uint8_t *pub = fips204_get_public_key();
    const uint8_t *sig = fips204_get_signature();
    const uint8_t *msg = fips204_get_message();
    size_t pub_len = fips204_get_public_key_len();
    size_t sig_len_local = fips204_get_signature_len();
    size_t msg_len = fips204_get_message_len();

    char pub_b64[3000];
    char sig_b64[5000];
    char msg_b64[256];
    char payload[8000];

    // Reject the send if any field is missing, because the host needs all
    // three parts to verify the result and compare the captured run data.
    if (!pub || !sig || !msg || pub_len == 0 || sig_len_local == 0 || msg_len == 0)
    {
        USB_print("send_USB: FIPS204 data missing\n");
        return;
    }

    // FIPS204 already provides raw key/signature/message buffers, so the only
    // extra step here is converting each one to a transport-safe text form.
    if (base64_encode(pub, pub_len, pub_b64, sizeof(pub_b64)) == 0)
    {
        USB_print("send_USB: FIPS204 pubkey base64 failed\n");
        return;
    }

    if (base64_encode(sig, sig_len_local, sig_b64, sizeof(sig_b64)) == 0)
    {
        USB_print("send_USB: FIPS204 signature base64 failed\n");
        return;
    }

    if (base64_encode(msg, msg_len, msg_b64, sizeof(msg_b64)) == 0)
    {
        USB_print("send_USB: FIPS204 message base64 failed\n");
        return;
    }

    // Keep the same delimiter contract as the ECDSA path so the host can
    // parse both algorithms with the same receiver logic.
    if (snprintf(payload, sizeof(payload), "%s@%s@%s", pub_b64, sig_b64, msg_b64) >=
        (int) sizeof(payload))
    {
        USB_print("send_USB: FIPS204 payload buffer too small\n");
        return;
    }

    // Send public key, signature and message over USB in format
    // "base64(pubkey)@base64(signature)@base64(message)" so the host can split it
    // correctly and verify the result.
    USB_send_key_and_signature(
            payload); // Payload format: base64(pubkey)@base64(signature)@base64(message).
}
