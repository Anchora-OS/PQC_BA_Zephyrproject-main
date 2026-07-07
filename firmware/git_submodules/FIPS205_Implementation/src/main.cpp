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
#include "Fips205_implementation.h"
#include "USBcommunication.h"
#include "RSAPSS_implementation.h"

#define SLEEP_TIME_MS 1000
#define BASE_MESSAGE  "Hello from Zephyr RSA-PSS and Fips205 implementation"

/* Get Nodes from devicetree alias */
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
static mbedtls_rsa_context rsa;
unsigned char signature[256];
size_t sig_len = 0;
char message_to_sign[128] =
        BASE_MESSAGE; // Msg that will be signed in RSA test, can be changed to any string of
// choice, but should be less than 128 bytes for this test setup
int ret;
static atomic_t test_requested = ATOMIC_INIT(0);
static bool run_once_at_start = true;
static int number_of_test_Runs =
        33; // 33 is max test runs that fit (their results) in the sending buffer
static void OSZI_GPIO_set(bool active); // OSZI GPIO for oscilloscope power measurement probe on PD3
static int send_structured_test_results(bool use_fips205);

#define PERF_MAX_RUNS 64
enum perf_algo
{
    PERF_ALGO_RSA = 0,
    PERF_ALGO_FIPS205,
    PERF_ALGO_COUNT
};

enum perf_stage
{
    RSA_PERF_KEYGEN = 0,
    RSA_PERF_SIGN,
    RSA_PERF_VERIFY,
    RSA_PERF_STAGE_COUNT
};

static uint64_t perf_time_us[PERF_ALGO_COUNT][RSA_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static size_t perf_stack_before_bytes[PERF_ALGO_COUNT][RSA_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static size_t perf_stack_after_bytes[PERF_ALGO_COUNT][RSA_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static bool perf_stack_measurement_ok[PERF_ALGO_COUNT][RSA_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static int perf_current_run_index[PERF_ALGO_COUNT] = {0};
static int perf_recorded_runs[PERF_ALGO_COUNT] = {0};

static char fips205_pub_b64[512];
static char fips205_sig_b64[14000];
static char fips205_msg_b64[256];
static char fips205_payload[15000];

int start_signing(void);

void sendRSAPSS_Key_and_signature(void);

void send_FIPS205_key_and_signature(void);

bool switch_state0(void);

bool switch_state1(void);

int init_Devices(void);

void button_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins);

int start_rsa_test(void);

int start_fips205_test(void);

static size_t base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_size);

static bool get_stack_used_bytes(size_t *used_bytes);

static void print_performance_result(const char *label, uint64_t cycle_delta, size_t stack_before,
                                     size_t stack_after, bool stack_ok);

static int execute_test(bool use_fips205);

static int run_automatic_tests(bool use_fips205);

static int run_manual_test(bool use_fips205);

static int calc_test_results(bool use_fips205);

static void performance_tests_reset(bool use_fips205);

static void performance_set_run_index(bool use_fips205, int run_index);

static void performance_record(bool use_fips205, enum perf_stage stage, uint64_t cycle_delta,
                               size_t stack_before, size_t stack_after, bool stack_ok);

static void update_message_for_run(int run_number);

// ---------------------Main Function---------------------

/**
 * @brief Main entry point for the firmware application.
 *
 * Initializes devices and enters the main loop which waits for test
 * requests (button or automatic) and executes chosen tests.
 *
 * @return int Returns 0 on normal exit (should not normally return), 1 on error
 */
int main(void)
{
    USB_print("\n\nStarting Main (RSA-PSS + FIPS205)\n");
    if (init_Devices())
    {
        USB_print("LED initialization failed\n");
        return 0;
    }

    while (true)
    {
        if (run_once_at_start ||
            atomic_cas(&test_requested, 1,
                    0)) // Start test if Button Pressed or once automatically at start
        {
            if (!run_once_at_start)
            {
                USB_print("\n\nButton pressed, continue testing...\n");
            }
            run_once_at_start = false;
            atomic_set(&test_requested, 0);

            // Check if switch 1 is active for automatic multiple test runs or single
            // runs
            bool use_fips205 = switch_state0();

            if (switch_state1())
            {
                // Automatic multiple test runs (switch_state0 is locked at entry)
                if (run_automatic_tests(use_fips205) != 0)
                {
                    USB_print("Automatic test run failed\n");
                    return 1;
                }
            }
            else
            {
                // Manual single test run
                if (run_manual_test(use_fips205) != 0)
                {
                    USB_print("Manual test run failed\n");
                    return 1;
                }
            }
        }

        gpio_pin_toggle_dt(
                &led); // Toggle LED to indicate program is running and responsive
        k_msleep(50);
    }
    return 0;
}

/**
 * @brief Execute a single test using the selected algorithm.
 *
 * Calls either the FIPS205 or RSA-PSS test routine based on flag.
 *
 * @param[in] use_fips205 True to run FIPS205 tests, false to run RSA-PSS tests
 * @return int 0 on success, non-zero on failure
 */
static int execute_test(bool use_fips205)
{
    if (use_fips205)
    {
        USB_print("Testing Fips205 implementation...\n");
        return start_fips205_test();
    }
    else
    {
        USB_print("Testing RSA PSS implementation...\n");
        return start_rsa_test();
    }
}

/**
 * @brief Run a single manual test.
 *
 * Resets performance tracking, runs one execution and does not summarize or export
 * results.
 *
 * @param[in] use_fips205 Selects algorithm to test
 * @return int 0 on success, 1 on failure
 */
static int run_manual_test(bool use_fips205)
{
    performance_tests_reset(use_fips205);
    performance_set_run_index(use_fips205, 0);

    if (execute_test(use_fips205) != 0)
    {
        USB_print("Test failed\n");
        return 1;
    }

    // decomment this if you want to calculate and export results for single runs too
    /*if (calc_test_results(use_fips205) != 0)
    {
        USB_print("Result calculation failed\n");
        return 1;
    }*/

    return 0;
}

/**
 * @brief Run multiple automatic test runs.
 *
 * Iterates `number_of_test_Runs` times, updating message and executing tests
 * while collecting performance data.
 *
 * @param[in] use_fips205 Selects algorithm to test across all runs
 * @return int 0 on success, 1 on failure
 */
static int run_automatic_tests(bool use_fips205)
{
    performance_tests_reset(use_fips205);

    if (number_of_test_Runs > PERF_MAX_RUNS)
    {
        char warning_msg[120];
        snprintf(warning_msg, // warning about exceeding max runs that can be stored in
                // performance buffers
                sizeof(warning_msg),
                "Warning: only first %d test runs are stored for averaging calculations\n",
                PERF_MAX_RUNS);
        USB_print(warning_msg);
    }

    // Loop through test runs, updating message and executing tests
    for (int test_run = 1; test_run <= number_of_test_Runs; test_run++)
    {
        USB_print("-----------------------------------------------------\n");
        char run_msg[100];
        snprintf(run_msg, sizeof(run_msg), "\n\n--- Test Run %d of %d ---\n", test_run,
                number_of_test_Runs);
        USB_print(run_msg);

        update_message_for_run(test_run); // Update message to include run number (ensures
        // different data per run, not cached)

        performance_set_run_index(
                use_fips205,
                test_run - 1); // Set current run index for performance recording

        if (execute_test(use_fips205) != 0)
        {
            USB_print("Test failed\n");
            return 1;
        }
    }

    // summarize results after all runs are complete
    if (calc_test_results(use_fips205) != 0)
    {
        USB_print("Result calculation failed\n");
        return 1;
    }

    send_structured_test_results(
            use_fips205); // Send structured test results as CSV with delimiters

    USB_print("    "); // create newline
    USB_print("\n\nAll test runs completed successfully on Board \n");
    USB_print("    ");
    return 0;
}

/**
 * @brief Calculate aggregated test results and print statistics.
 *
 * Computes mean/min/max timing and prints stack usage and timing statistics
 * for recorded runs.
 *
 * @param[in] use_fips205 Selects which algorithm's results to process
 * @return int 0 on success, 1 if no samples are available
 */
static int calc_test_results(bool use_fips205)
{
    enum perf_algo algo =
            use_fips205
            ? PERF_ALGO_FIPS205
            : PERF_ALGO_RSA; // Select algorithm index for accessing performance data
    const char *algo_name = use_fips205 ? "FIPS205" : "RSA";

    // Check if any performance samples were recorded for this algorithm
    if (perf_recorded_runs[algo] <= 0)
    {
        char no_data_msg[80];
        snprintf(no_data_msg, sizeof(no_data_msg), "No %s performance samples recorded\n",
                algo_name);
        USB_print(no_data_msg);
        return 1;
    }

    const char *stage_label[RSA_PERF_STAGE_COUNT] = {"key generation", "signing", "verify"};
    char msg[220];

    // Print stack usage per test run
    USB_print("\n===== Stack Usage Per Test Run =====\n");

    for (int run = 0; run < perf_recorded_runs[algo]; run++)
    {
        snprintf(msg, sizeof(msg), "\nTest Run %d:\n", run + 1);
        USB_print(msg);

        for (int stage = 0; stage < RSA_PERF_STAGE_COUNT; stage++)
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

    // Print timing statistics (mean, min, max)
    USB_print("\n===== Performance Statistics (Time) =====\n");

    for (int stage = 0; stage < RSA_PERF_STAGE_COUNT; stage++)
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

        // Print all results for this stage
        snprintf(msg, sizeof(msg),
                "\n-  %s:\n  Mean: %llu us | Min: %llu us | Max: %llu us\n",
                stage_label[stage], (unsigned long long) mean_us,
                (unsigned long long) min_us, (unsigned long long) max_us);
        USB_print(msg);
    }

    return 0;
}

/**
 * @brief Prepare and send structured (CSV) test results over USB.
 *
 * Builds a CSV buffer containing algorithm, stage, run, timing and stack
 * information and sends it via USB.
 *
 * @param[in] use_fips205 Selects which algorithm's recorded data to send
 * @return int 0 on success, 1 on failure or if no data
 */
static int send_structured_test_results(bool use_fips205)
{
    enum perf_algo algo =
            use_fips205
            ? PERF_ALGO_FIPS205
            : PERF_ALGO_RSA; // Select algorithm index for accessing performance data
    const char *algo_name = use_fips205 ? "FIPS205" : "RSA";

    // Check if any performance samples were recorded for this algorithm
    if (perf_recorded_runs[algo] <= 0)
    {
        return 1;
    }

    const char *stage_label[RSA_PERF_STAGE_COUNT] = {"key_generation", "signing", "verify"};

    // Build CSV buffer with header and all data rows
    static char csv_buffer[4096];
    int buffer_pos = 0;
    int buffer_max = sizeof(csv_buffer);

    // CSV Header
    buffer_pos += snprintf(
            csv_buffer + buffer_pos, buffer_max - buffer_pos,
            "algorithm,stage,run,time_us,stack_before,stack_after,stack_used_bytes,stack_ok\n");

    // Data rows for each run and stage
    for (int run = 0; run < perf_recorded_runs[algo]; run++)
    {
        for (int stage = 0; stage < RSA_PERF_STAGE_COUNT; stage++)
        {
            uint64_t time_us = perf_time_us[algo][stage][run];
            size_t stack_before = perf_stack_before_bytes[algo][stage][run];
            size_t stack_after = perf_stack_after_bytes[algo][stage][run];
            bool stack_ok = perf_stack_measurement_ok[algo][stage][run];

            long stack_used = stack_ok ? (long) stack_after - (long) stack_before : 0;

            buffer_pos += snprintf(
                    csv_buffer + buffer_pos, buffer_max - buffer_pos,
                    "%s,%s,%d,%llu,%u,%u,%ld,%s\n", algo_name, stage_label[stage],
                    run + 1, (unsigned long long) time_us, (unsigned int) stack_before,
                    (unsigned int) stack_after, stack_used, stack_ok ? "true" : "false");

            if (buffer_pos >= buffer_max - 100)
            {
                USB_print("CSV buffer too small, truncating results\n");
                break;
            }
        }
    }

    USB_send_structured_data(csv_buffer);
    return 0;
}

/**
 * @brief Reset performance measurement buffers for the selected algorithm.
 *
 * Clears timing and stack arrays and resets counters.
 *
 * @param[in] use_fips205 Selects which algorithm's buffers to reset
 */
static void performance_tests_reset(bool use_fips205)
{
    enum perf_algo algo = use_fips205 ? PERF_ALGO_FIPS205 : PERF_ALGO_RSA;

    memset(perf_time_us[algo], 0, sizeof(perf_time_us[algo]));
    memset(perf_stack_before_bytes[algo], 0, sizeof(perf_stack_before_bytes[algo]));
    memset(perf_stack_after_bytes[algo], 0, sizeof(perf_stack_after_bytes[algo]));
    memset(perf_stack_measurement_ok[algo], 0, sizeof(perf_stack_measurement_ok[algo]));
    perf_current_run_index[algo] = 0;
    perf_recorded_runs[algo] = 0;
}

/**
 * @brief Set the current run index for recording performance samples.
 *
 * Updates internal index used by `performance_record`.
 *
 * @param[in] use_fips205 Algorithm selector
 * @param[in] run_index Zero-based run id
 */
static void performance_set_run_index(bool use_fips205, int run_index)
{
    enum perf_algo algo = use_fips205 ? PERF_ALGO_FIPS205 : PERF_ALGO_RSA;
    perf_current_run_index[algo] = run_index;
}

/**
 * @brief Record a single performance sample for the selected algorithm/stage.
 *
 * Stores timing and stack usage into the internal arrays and updates the count
 * of recorded runs.
 *
 * @param[in] use_fips205 Algorithm selector
 * @param[in] stage Which stage (keygen/sign/verify)
 * @param[in] cycle_delta Cycle count delta measured
 * @param[in] stack_before Stack usage snapshot before operation
 * @param[in] stack_after Stack usage snapshot after operation
 * @param[in] stack_ok Whether stack measurement was available
 */
static void performance_record(bool use_fips205, enum perf_stage stage, uint64_t cycle_delta,
                               size_t stack_before, size_t stack_after, bool stack_ok)
{
    enum perf_algo algo = use_fips205 ? PERF_ALGO_FIPS205 : PERF_ALGO_RSA;

    // stage neglect and run index bounds check to avoid out-of-bounds writes in case of logic
    // errors
    if (stage < 0 || stage >= RSA_PERF_STAGE_COUNT)
    {
        return;
    }

    // performance_set_run_index should have been called before to set the correct run index
    if (perf_current_run_index[algo] < 0 || perf_current_run_index[algo] >= PERF_MAX_RUNS)
    {
        return;
    }

    // Store the performance data for this run and stage
    perf_time_us[algo][stage][perf_current_run_index[algo]] = k_cyc_to_us_floor64(cycle_delta);
    perf_stack_before_bytes[algo][stage][perf_current_run_index[algo]] = stack_before;
    perf_stack_after_bytes[algo][stage][perf_current_run_index[algo]] = stack_after;
    perf_stack_measurement_ok[algo][stage][perf_current_run_index[algo]] = stack_ok;

    // Update the count of recorded runs if this is a new run index
    if ((perf_current_run_index[algo] + 1) > perf_recorded_runs[algo])
    {
        perf_recorded_runs[algo] = perf_current_run_index[algo] + 1;
    }
}

/**
 * @brief Run the RSA-PSS test sequence: keygen, sign, verify and send results.
 *
 * Generates RSA keypair, signs `message_to_sign`, verifies signature and sends
 * public key + signature over USB.
 *
 * @return int 0 on success, 1 on failure
 */
int start_rsa_test(void)
{
    size_t stack_before = 0;
    size_t stack_after = 0;
    bool stack_ok;
    uint64_t t0;
    uint64_t t1;

    rsa_free(&rsa);
    sig_len = 0;
    memset(signature, 0, sizeof(signature));

    USB_print("Generating RSA-2048 keypair...\n");

    stack_ok = get_stack_used_bytes(&stack_before);
    OSZI_GPIO_set(
            true); // Set GPIO high to mark start of key generation for oscilloscope measurement
    t0 = k_cycle_get_64(); // start time measurement for RSA key generation
    if (rsa_pss_generate_keys(&rsa) != 0)
    {
        OSZI_GPIO_set(false);
        USB_print("RSA key generation failed\n");
        return 1;
    }
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    USB_print("RSA-2048 keypair generation successful\n");
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    print_performance_result("RSA key generation", t1 - t0, stack_before, stack_after,
            stack_ok);
    performance_record(false, RSA_PERF_KEYGEN, t1 - t0, stack_before, stack_after, stack_ok);

    USB_print("Signing message (RSA-PSS)...\n");

    stack_ok = get_stack_used_bytes(&stack_before);
    OSZI_GPIO_set(true); // Set GPIO high to mark start of signing for oscilloscope measurement
    t0 = k_cycle_get_64(); // start time measurement for RSA signing
    if (start_signing() != 0)
    {
        t1 = k_cycle_get_64();
        OSZI_GPIO_set(false);
        USB_print("RSA signing failed\n");
        return 1;
    }
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    print_performance_result("RSA signing", t1 - t0, stack_before, stack_after, stack_ok);
    performance_record(false, RSA_PERF_SIGN, t1 - t0, stack_before, stack_after, stack_ok);

    if (sig_len == 0)
    {
        return 1;
    }
    USB_print("RSA signing successful\n");

    USB_print("Verifying signature (RSA-PSS)...\n");
    stack_ok = get_stack_used_bytes(&stack_before);
    OSZI_GPIO_set(
            true); // Set GPIO high to mark start of verification for oscilloscope measurement
    t0 = k_cycle_get_64(); // start time measurement for RSA verification
    if (rsa_pss_verify(&rsa, (const unsigned char *) message_to_sign, strlen(message_to_sign),
            signature, sig_len) != 0)
    {
        OSZI_GPIO_set(false);
        USB_print("RSA verification failed\n");
        return 1;
    }
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    USB_print("RSA verification successful\n");
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    print_performance_result("RSA verify", t1 - t0, stack_before, stack_after, stack_ok);
    performance_record(false, RSA_PERF_VERIFY, t1 - t0, stack_before, stack_after, stack_ok);

    USB_print("Sending RSA signature and key\n");
    sendRSAPSS_Key_and_signature(); // test run completed, snend results over USB for host side
    // validation
    return 0;
}

/**
 * @brief Run the FIPS205 (SLH-DSA) test sequence: keygen, sign, verify and send.
 *
 * Generates SLH-DSA keypair, signs message, verifies signature and sends
 * public key + signature over USB.
 *
 * @return int 0 on success, 1 on failure
 */
int start_fips205_test(void)
{
    size_t stack_before = 0;
    size_t stack_after = 0;
    bool stack_ok;
    uint64_t t0;
    uint64_t t1;

    USB_print("Generating SLH-DSA keypair...\n");

    stack_ok = get_stack_used_bytes(&stack_before);
    OSZI_GPIO_set(
            true); // Set GPIO high to mark start of key generation for oscilloscope measurement
    t0 = k_cycle_get_64(); // start time measurement for FIPS205 key generation
    if (fips205_generate_keys() != 0)
    {
        OSZI_GPIO_set(false);
        USB_print("FIPS205 key generation failed\n");
        return 1;
    }
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    USB_print("SLH-DSA keypair generation successful\n");
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    print_performance_result("FIPS205 key generation", t1 - t0, stack_before, stack_after,
            stack_ok);
    performance_record(true, RSA_PERF_KEYGEN, t1 - t0, stack_before, stack_after, stack_ok);

    USB_print("Signing message (FIPS205)...\n");
    stack_ok = get_stack_used_bytes(&stack_before);
    OSZI_GPIO_set(true); // Set GPIO high to mark start of signing for oscilloscope measurement
    t0 = k_cycle_get_64(); // start time measurement for FIPS205 signing
    if (fips205_sign() != 0)
    {
        OSZI_GPIO_set(false);
        USB_print("FIPS205 signing failed\n");
        return 1;
    }
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    USB_print("FIPS205 signing successful\n");
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    print_performance_result("FIPS205 signing", t1 - t0, stack_before, stack_after, stack_ok);
    performance_record(true, RSA_PERF_SIGN, t1 - t0, stack_before, stack_after, stack_ok);

    USB_print("Verifying signature (FIPS205)...\n");
    stack_ok = get_stack_used_bytes(&stack_before);
    OSZI_GPIO_set(
            true); // Set GPIO high to mark start of verification for oscilloscope measurement
    t0 = k_cycle_get_64(); // start time measurement for FIPS205 verification
    if (fips205_verify() == 0)
    {
        OSZI_GPIO_set(false);
        USB_print("FIPS205 verification failed\n");
        return 1;
    }
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    USB_print("FIPS205 verification successful\n");
    if (stack_ok)
    {
        stack_ok = get_stack_used_bytes(&stack_after);
    }
    print_performance_result("FIPS205 verify", t1 - t0, stack_before, stack_after, stack_ok);
    performance_record(true, RSA_PERF_VERIFY, t1 - t0, stack_before, stack_after, stack_ok);

    USB_print("Sending FIPS205 signature and key\n");
    send_FIPS205_key_and_signature(); // test run completed, send results over USB for host side
    // validation
    return 0;
}

/**
 * @brief GPIO interrupt handler for the button.
 *
 * Marks that a test has been requested by setting `test_requested`.
 *
 * @param dev Unused device pointer
 * @param cb Unused callback pointer
 * @param pins Unused pin mask
 */
void button_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
    ARG_UNUSED(dev);
    ARG_UNUSED(cb);
    ARG_UNUSED(pins);

    atomic_set(&test_requested, 1);
}

/**
 * @brief Minimal base64 encoder.
 *
 * Encodes `in` into base64 and writes a null-terminated string.
 *
 * @param[in] in Input bytes
 * @param[in] in_len Input length
 * @param[out] out Output buffer
 * @param[in] out_size Size of output buffer
 * @return size_t Number of bytes written (excluding terminating NUL), or 0 on error
 */
static size_t base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_size)
{
    static const char b64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // Base64
    // character set
    size_t required = 4 * ((in_len + 2) / 3);
    size_t i = 0;
    size_t j = 0;

    if (out_size < required + 1)
    {
        return 0;
    }

    // Process input in 3-byte chunks and convert to 4 base64 characters
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

    // Add padding if input length is not a multiple of 3
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
 * @brief Get approximate stack usage (high-water-mark) for current thread.
 *
 * Fills `used_bytes` with estimated stack used when enabled by Zephyr config
 * options; otherwise returns false.
 *
 * @param[out] used_bytes Pointer to size_t to receive value
 * @return bool true if value filled, false if stack info not available
 */
static bool get_stack_used_bytes(size_t *used_bytes)
{

/*
 * Stack usage here is a high-watermark metric from Zephyr stack initialization.
 * It reports the maximum stack depth reached so far by this thread, not a
 * per-call live stack value. Later runs may therefore show 0 new-peak bytes.
 */
#if defined(CONFIG_THREAD_STACK_INFO) && \
    defined(CONFIG_INIT_STACKS) // Zephyr must be configured to track stack usage for this to
    // work
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

/**
 * @brief Print a concise performance result line.
 *
 * Formats timing and stack usage into a readable message sent over USB for
 * logging or host collection.
 *
 * @param[in] label Stage label
 * @param[in] cycle_delta Cycles elapsed
 * @param[in] stack_before Stack usage snapshot before operation
 * @param[in] stack_after Stack usage snapshot after operation
 * @param[in] stack_ok Whether stack measurement was valid
 */
static void print_performance_result(const char *label, uint64_t cycle_delta, size_t stack_before,
                                     size_t stack_after, bool stack_ok)
{
    char msg[180];
    uint64_t us = k_cyc_to_us_floor64(cycle_delta);

    if (stack_ok)
    {
        long delta = (long) stack_after - (long) stack_before;
        snprintf(
                msg, sizeof(msg),
                "PERF %s: %llu us | stack used: %u -> %u bytes (new peak delta %+ld bytes)",
                label, (unsigned long long) us, (unsigned int) stack_before,
                (unsigned int) stack_after, delta);
    }
    else
    {
        snprintf(msg, sizeof(msg),
                "PERF %s: %llu us | stack used: n/a (enable CONFIG_THREAD_STACK_INFO + "
                "CONFIG_INIT_STACKS)",
                label, (unsigned long long) us);
    }

    USB_print(msg);
}

/**
 * @brief Toggle the OSZI GPIO pin used for external timing/probing.
 *
 * Sets the configured `OSZI_GPIO_toggle` pin high or low if ready.
 *
 * @param[in] active true to set pin active/high, false to deactivate
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
 * @brief Update the global `message_to_sign` to include run number metadata.
 *
 * Embeds the run index into the message so each test run varies.
 *
 * @param[in] run_number 1-based run index
 */
static void update_message_for_run(int run_number)
{
    // ensures each run has different data to sign, avoiding caching effects
    snprintf(message_to_sign, sizeof(message_to_sign), "%s [Run %d]", BASE_MESSAGE, run_number);
}

/**
 * @brief Initialize hardware peripherals used by the firmware and LEDs.
 *
 * Prepares USB CDC device, configures LED, button, switches and initializes
 * OSZI GPIO for external probing.
 *
 * @return int 0 on success, 1 on failure
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

    ret = gpio_pin_configure_dt(&button, GPIO_INPUT);
    if (ret < 0)
    {
        printk("Error: button config failed\n");
        return 1;
    }

    // Enable interrupt on button
    ret = gpio_pin_interrupt_configure_dt(&button, GPIO_INT_EDGE_TO_ACTIVE);
    if (ret < 0)
    {
        printk("Error: interrupt config failed\n");
        return 1;
    }
    gpio_init_callback(&button_cb_data, button_pressed, BIT(button.pin));
    gpio_add_callback(button.port, &button_cb_data);

    ret = gpio_pin_configure_dt(&switch_gpio0, GPIO_INPUT);
    if (ret < 0)
    {
        printk("Error: switch config failed\n");
        return 1;
    }

    ret = gpio_pin_configure_dt(&switch_gpio1, GPIO_INPUT);
    if (ret < 0)
    {
        printk("Error: switch config failed\n");
        return 1;
    }

    // Initialize OSZI GPIO for oscilloscope probe on PD3
    OSZI_GPIO_toggle.port = DEVICE_DT_GET(DT_NODELABEL(gpiod));
    if (!OSZI_GPIO_toggle.port)
    {
        printk("Error: OSZI GPIO port device not found\n");
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

    return 0;
}

/**
 * @brief Read logical state of switch 0.
 *
 * Returns true if the switch reads active/high.
 *
 * @return bool true if switch is active, false on error or inactive
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
 * @brief Read logical state of switch 1.
 *
 * Returns true if the switch reads active/high.
 *
 * @return bool true if switch is active, false on error or inactive
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
 * @brief Perform RSA-PSS signing of the global `message_to_sign`.
 *
 * Uses `rsa_pss_sign` to produce a signature in `signature`.
 *
 * @return int 0 on success, 1 on failure
 */
int start_signing(void)
{
    sig_len = 0;
    if (rsa_pss_sign(&rsa, (unsigned char *) message_to_sign, strlen(message_to_sign), signature,
            &sig_len) != 0)
    {
        return 1;
    }

    return 0;
}

/**
 * @brief Export RSA public key, encode data in base64 and send over USB.
 *
 * Builds a payload of base64(pubkey)@base64(signature)@base64(msg).
 */
void sendRSAPSS_Key_and_signature(void)
{
    unsigned char n_bin[256];
    unsigned char e_bin[8];
    unsigned char pub_raw[2 + sizeof(n_bin) + 2 + sizeof(e_bin)];
    size_t n_len = mbedtls_rsa_get_len(&rsa);
    size_t e_len = sizeof(e_bin);
    size_t e_start = 0;
    size_t e_effective_len;
    size_t pub_raw_len;
    int rc;

    char pub_b64[380];
    char sig_b64[380];
    char msg_b64[256];
    char payload[1200];

    if (sig_len == 0)
    {
        USB_print("send_RSA: signature is empty");
        return;
    }

    // Export the RSA public key as raw binary first.
    // The signature and message are already byte buffers, but the key needs
    // modulus/exponent packing before it can be base64-encoded.
    rc = mbedtls_rsa_export_raw(&rsa, n_bin, sizeof(n_bin), NULL, 0, NULL, 0, NULL, 0, e_bin,
            sizeof(e_bin));
    if (rc != 0)
    {
        USB_print("send_RSA: failed to export RSA public key");
        return;
    }

    while (e_start + 1 < e_len && e_bin[e_start] == 0)
    {
        e_start++;
    }
    e_effective_len = e_len - e_start;

    pub_raw[0] = (unsigned char) ((n_len >> 8) & 0xFF);
    pub_raw[1] = (unsigned char) (n_len & 0xFF);
    memcpy(&pub_raw[2], n_bin, n_len);
    pub_raw[2 + n_len] = (unsigned char) ((e_effective_len >> 8) & 0xFF);
    pub_raw[3 + n_len] = (unsigned char) (e_effective_len & 0xFF);
    memcpy(&pub_raw[4 + n_len], &e_bin[e_start], e_effective_len);
    pub_raw_len = 4 + n_len + e_effective_len;

    // Encode each field separately so the host can split them back out later.
    // Public key uses packed RSA bytes, signature uses the generated signature,
    // and message uses the plaintext that was signed.
    if (base64_encode(pub_raw, pub_raw_len, pub_b64, sizeof(pub_b64)) == 0)
    {
        USB_print("send_RSA: public key base64 buffer too small");
        return;
    }

    if (base64_encode(signature, sig_len, sig_b64, sizeof(sig_b64)) == 0)
    {
        USB_print("send_RSA: signature base64 buffer too small");
        return;
    }

    if (base64_encode((unsigned char *) message_to_sign, strlen(message_to_sign), msg_b64,
            sizeof(msg_b64)) == 0)
    {
        USB_print("send_RSA: message base64 buffer too small");
        return;
    }

    if (snprintf(payload, sizeof(payload), "%s@%s@%s", pub_b64, sig_b64, msg_b64) >=
        (int) sizeof(payload))
    {
        USB_print("send_RSA: payload buffer too small");
        return;
    }

    // Send public key, signature and message over USB in format
    // "base64(pubkey)@base64(signature)@base64(message)" so the host can split it
    // correctly and verify the result.
    USB_send_key_and_signature(payload);
}

/**
 * @brief Export FIPS205 public key, signature and message, base64-encode and send.
 *
 * Collects key/sig/msg from the FIPS205 module, encodes and sends.
 */
void send_FIPS205_key_and_signature(void)
{
    const uint8_t *pubkey = fips205_get_public_key();
    const uint8_t *sig = fips205_get_signature();
    const uint8_t *msg = fips205_get_message();
    size_t pub_len = fips205_get_public_key_len();
    size_t sig_len_local = fips205_get_signature_len();
    size_t msg_len = fips205_get_message_len();

    if (pubkey == nullptr || sig == nullptr || msg == nullptr || pub_len == 0 ||
        sig_len_local == 0 || msg_len == 0)
    {
        USB_print("send_FIPS205: crypto output is empty");
        return;
    }

    // encode each field separately so the host can split them back out later.
    // Public key uses raw bytes from FIPS205, signature uses generated signature,
    // and message uses the plaintext that was signed.
    if (base64_encode(pubkey, pub_len, fips205_pub_b64, sizeof(fips205_pub_b64)) == 0)
    {
        USB_print("send_FIPS205: public key base64 buffer too small");
        return;
    }

    if (base64_encode(sig, sig_len_local, fips205_sig_b64, sizeof(fips205_sig_b64)) == 0)
    {
        USB_print("send_FIPS205: signature base64 buffer too small");
        return;
    }

    if (base64_encode(msg, msg_len, fips205_msg_b64, sizeof(fips205_msg_b64)) == 0)
    {
        USB_print("send_FIPS205: message base64 buffer too small");
        return;
    }

    if (snprintf(fips205_payload, sizeof(fips205_payload), "%s@%s@%s", fips205_pub_b64,
            fips205_sig_b64, fips205_msg_b64) >= (int) sizeof(fips205_payload))
    {
        USB_print("send_FIPS205: payload buffer too small");
        return;
    }

    // Send public key, signature and message over USB in format
    // "base64(pubkey)@base64(signature)@base64(message)" so the host can split it
    // correctly and verify the result.
    USB_send_key_and_signature(fips205_payload);
}