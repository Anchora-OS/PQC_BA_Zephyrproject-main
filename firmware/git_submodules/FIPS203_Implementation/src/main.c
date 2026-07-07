#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/device.h>

// Own Header Files
#include "ECDHA_implementation.h"
#include "Fips203_implementation.h"
#include "user_usb.h"

#define USB_RX_TIMEOUT K_SECONDS(5) // Time to wait for USB responses from Host during test execution
#define USB_MESSAGE_SIZE 4200
#define FIPS203_BASE64_CHUNK_SIZE 96
#define PERF_MAX_RUNS 64

enum ecdh_perf_stage
{
    ECDH_PERF_KEYGEN = 0,
    ECDH_PERF_KEY_EXCHANGE,
    ECDH_PERF_COMPUTE_SECRET,
    ECDH_PERF_STAGE_COUNT
};

enum fips203_perf_stage
{
    FIPS203_PERF_KEYGEN = 0,
    FIPS203_PERF_KEY_EXCHANGE,
    FIPS203_PERF_COMPUTE_SECRET,
    FIPS203_PERF_STAGE_COUNT
};

enum test_algorithm
{
    TEST_ALGO_ECDH = 0,
    TEST_ALGO_FIPS203 = 1,
};

enum test_mode
{
    TEST_MODE_MANUAL = 0,
    TEST_MODE_BATCH = 1,
};

/* Get Nodes from devicetree alias */
#define BUTTON_NODE DT_ALIAS(t3)
#define SWITCH_NODE0 DT_ALIAS(sw0)
#define SWITCH_NODE1 DT_ALIAS(sw1)

#if !DT_NODE_HAS_STATUS(BUTTON_NODE, okay)
#error "No button (sw0) alias found"
#endif

#if !DT_NODE_HAS_STATUS(SWITCH_NODE0, okay)
#error "No switch (sw0) alias found"
#endif

#if !DT_NODE_HAS_STATUS(SWITCH_NODE1, okay)
#error "No switch (sw1) alias found"
#endif

void button_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins);

bool switch_state0(void);

bool switch_state1(void);

static int run_ecdh_test_execution(void);

static int run_fips203_test_execution(void);

static bool ecdh_get_stack_used_bytes(size_t *used_bytes);

static void ecdh_print_performance_result(const char *label, uint64_t cycle_delta,
                                          size_t stack_before, size_t stack_after, bool stack_ok);

static void ecdh_performance_tests_reset(void);

static void ecdh_performance_set_run_index(int run_index);

static bool fips203_get_stack_used_bytes(size_t *used_bytes);

static void fips203_print_performance_result(const char *label, uint64_t cycle_delta,
                                             size_t stack_before, size_t stack_after, bool stack_ok);

static void fips203_performance_tests_reset(void);

static void fips203_performance_set_run_index(int run_index);

static void fips203_performance_record(enum fips203_perf_stage stage, uint64_t cycle_delta,
                                       size_t stack_before, size_t stack_after, bool stack_ok);

static void OSZI_GPIO_set(bool active);

static int calc_test_results(enum test_algorithm algorithm);

static int send_shared_secret_as_data(const ecdha_shared_secret_t *shared_secret);


static const struct gpio_dt_spec button = GPIO_DT_SPEC_GET(BUTTON_NODE, gpios);
static const struct gpio_dt_spec switch_gpio0 = GPIO_DT_SPEC_GET(SWITCH_NODE0, gpios);
static const struct gpio_dt_spec switch_gpio1 = GPIO_DT_SPEC_GET(SWITCH_NODE1, gpios);
static struct gpio_callback button_cb_data;  // Button callback structure vor ISR
static struct gpio_dt_spec OSZI_GPIO_toggle;

// Global Vars
static atomic_t test_requested = ATOMIC_INIT(0);
static bool run_once_at_start = true;
static int number_of_batch_tests = 33;

// Performance measurement arrays for ECDH
static uint64_t ecdh_perf_time_us[ECDH_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static size_t ecdh_perf_stack_before_bytes[ECDH_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static size_t ecdh_perf_stack_after_bytes[ECDH_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static bool ecdh_perf_stack_measurement_ok[ECDH_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static int ecdh_perf_current_run_index = 0;
static int ecdh_perf_recorded_runs = 0;

// Performance measurement arrays for FIPS203
static uint64_t fips203_perf_time_us[FIPS203_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static size_t fips203_perf_stack_before_bytes[FIPS203_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static size_t fips203_perf_stack_after_bytes[FIPS203_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static bool fips203_perf_stack_measurement_ok[FIPS203_PERF_STAGE_COUNT][PERF_MAX_RUNS];
static int fips203_perf_current_run_index = 0;
static int fips203_perf_recorded_runs = 0;

// FIPS203 Key Storage 
static fips203_public_key_t fips203_pubkey;
static fips203_secret_key_t fips203_seckey;
static fips203_cipher_text_t fips203_cipher;
static fips203_shared_secret_t fips203_receiver_secret;

/**
 * @brief Send a tagged log message over USB.
 *
 * Formats a short application log record and forwards it to the USB logging
 * backend used by the board test flow.
 *
 * @param [in] tag Message category prefix; defaults to "APP" when NULL.
 * @param [in] message Log text to transmit; defaults to an empty string when NULL.
 * @return 0 on success or a negative errno value on failure.
 */
static int log_usb_message(const char *tag, const char *message)
{
    char buffer[USB_MESSAGE_SIZE];
    int ret;

    if (tag == NULL)
    {
        tag = "APP";
    }

    if (message == NULL)
    {
        message = "";
    }

    // Format the message with a simple "TAG: message" structure. Ensure the entire message fits within the buffer, including the null terminator.
    if (snprintf(buffer, sizeof(buffer), "%s: %s", tag, message) >= (int) sizeof(buffer))
    {
        return -ENOSPC;
    }

    ret = usb_send_log(buffer);
    return (ret < 0) ? ret : 0;
}

/**
 * @brief Send an ECDH point as a log record.
 *
 * Converts a point to text and writes it to the USB log stream so host-side
 * tooling can inspect the current key material.
 *
 * @param [in] label Name used for the emitted record.
 * @param [in] point Point to serialize and transmit.
 * @return 0 on success or a negative errno value on failure.
 */
static int send_point_as_log(const char *label, const ecdha_point_t *point)
{
    char point_text[ECDHA_POINT_TEXT_SIZE];
    char buffer[USB_MESSAGE_SIZE];
    int ret;

    // Convert the point to a human-readable string. 
    ret = ecdha_public_key_to_string(point, point_text, sizeof(point_text));
    if (ret != 0)
    {
        return ret;
    }

    // Format the log message as "LABEL=POINT_TEXT". 
    if (snprintf(buffer, sizeof(buffer), "%s=%s", label, point_text) >= (int) sizeof(buffer))
    {
        return -ENOSPC;
    }

    ret = usb_send_log(buffer);
    return (ret < 0) ? ret : 0;
}

/**
 * @brief Send a 32-bit value as USB data.
 *
 * Emits a single key-value record that the host can parse during test runs.
 *
 * @param [in] label Name used for the emitted data field.
 * @param [in] value Unsigned 32-bit value to transmit.
 * @return 0 on success or a negative errno value on failure.
 */
static int send_u32_as_data(const char *label, uint32_t value)
{
    char buffer[USB_MESSAGE_SIZE];
    int ret;

    if (label == NULL)
    {
        label = "VALUE";
    }

    // Format the data as "LABEL=VALUE"
    if (snprintf(buffer, sizeof(buffer), "%s=%lu", label, (unsigned long) value) >= (int) sizeof(buffer))
    {
        return -ENOSPC;
    }

    ret = usb_send_data(buffer);
    return (ret < 0) ? ret : 0;
}

/**
 * @brief Send the individual coordinates of an ECDH point as USB data.
 *
 * This keeps host parsing simple by separating the X and Y coordinates into
 * dedicated records, or by marking the point as infinity.
 *
 * @param [in] prefix Base name used for the generated data fields.
 * @param [in] point Point to serialize.
 * @return 0 on success or a negative errno value on failure.
 */
static int send_point_components_as_data(const char *prefix, const ecdha_point_t *point)
{
    int ret;
    char label[USB_MESSAGE_SIZE];

    if (prefix == NULL || point == NULL)
    {
        return -EINVAL;
    }

    // If the point is at infinity, send a single record indicating that instead of coordinates.
    if (point->infinity)
    {
        char buffer[USB_MESSAGE_SIZE];

        if (snprintf(buffer, sizeof(buffer), "%s=INF", prefix) >= (int) sizeof(buffer))
        {
            return -ENOSPC;
        }

        ret = usb_send_data(buffer);
        return (ret < 0) ? ret : 0;
    }

    // For finite points, send the X and Y coordinates as separate records with appropriate labels.
    if (snprintf(label, sizeof(label), "%s_QX", prefix) >= (int) sizeof(label))
    {
        return -ENOSPC;
    }

    ret = send_u32_as_data(label, point->x);
    if (ret != 0)
    {
        return ret;
    }

    // Send the Y coordinate with a label derived from the prefix.
    if (snprintf(label, sizeof(label), "%s_QY", prefix) >= (int) sizeof(label))
    {
        return -ENOSPC;
    }

    return send_u32_as_data(label, point->y);
}

/**
 * @brief Send an ECDH shared secret as a log record.
 *
 * Serializes the derived secret for debug and verification output on the host.
 *
 * @param [in] shared_secret Shared secret to transmit.
 * @return 0 on success or a negative errno value on failure.
 */
static int send_shared_secret(const ecdha_shared_secret_t *shared_secret)
{
    char secret_text[ECDHA_SHARED_SECRET_TEXT_SIZE];
    char buffer[USB_MESSAGE_SIZE];
    int ret;

    // Convert the shared secret to a human-readable string.
    ret = ecdha_shared_secret_to_string(shared_secret, secret_text, sizeof(secret_text));
    if (ret != 0)
    {
        return ret;
    }

    // Format the log message as "COMMON_SECRET=SECRET_TEXT".
    if (snprintf(buffer, sizeof(buffer), "COMMON_SECRET=%s", secret_text) >= (int) sizeof(buffer))
    {
        return -ENOSPC;
    }

    ret = usb_send_data(buffer);
    return (ret < 0) ? ret : 0;
}


/**
 * @brief Send a FIPS203 shared secret as USB data.
 *
 * Converts the derived secret to hexadecimal text so the host can compare the
 * board output against the expected decapsulation result.
 *
 * @param [in] label Name used for the emitted record.
 * @param [in] secret Shared secret to serialize.
 * @return 0 on success or a negative errno value on failure.
 */
static int send_fips203_shared_secret_as_data(
        const char *label,
        const fips203_shared_secret_t *secret)
{
    char hex_buffer[FIPS203_SHARED_SECRET_BYTE_LEN * 2 + 1];
    char usb_buffer[USB_MESSAGE_SIZE];
    int ret;

    if (label == NULL || secret == NULL)
    {
        return -EINVAL;
    }

    // Convert the shared secret bytes to a hexadecimal string representation.
    for (size_t i = 0; i < FIPS203_SHARED_SECRET_BYTE_LEN; i++)
    {
        snprintf(&hex_buffer[i * 2], 3, "%02X", secret->data[i]);
    }

    hex_buffer[FIPS203_SHARED_SECRET_BYTE_LEN * 2] = '\0';

    // Format the data as "LABEL=HEX_STRING".
    if (snprintf(usb_buffer,
            sizeof(usb_buffer),
            "%s=%s",
            label,
            hex_buffer) >= (int) sizeof(usb_buffer))
    {
        return -ENOSPC;
    }

    ret = usb_send_data(usb_buffer);
    return (ret < 0) ? ret : 0;
}

/**
 * @brief Convert one Base64 character to its numeric value.
 *
 * Supports the standard Base64 alphabet and rejects invalid characters.
 *
 * @param [in] c Input character.
 * @return Base64 value in the range 0..63 or a negative errno value.
 */
static int base64_value(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return c - 'A';
    }

    if (c >= 'a' && c <= 'z')
    {
        return c - 'a' + 26;
    }

    if (c >= '0' && c <= '9')
    {
        return c - '0' + 52;
    }

    if (c == '+')
    {
        return 62;
    }

    if (c == '/')
    {
        return 63;
    }

    return -EINVAL;
}

/**
 * @brief Encode a byte buffer as Base64.
 *
 * Produces a null-terminated Base64 string suitable for USB chunking.
 *
 * @param [in] in Source buffer.
 * @param [in] in_len Source buffer length in bytes.
 * @param [out] out Destination string buffer.
 * @param [in] out_size Destination buffer size in bytes.
 * @return Encoded length on success or a negative errno value on failure.
 */
static int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_size)
{
    static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // Standard Base64 alphabet
    size_t required = 4U * ((in_len + 2U) / 3U) + 1U;
    size_t i = 0;
    size_t o = 0;

    if (in == NULL || out == NULL)
    {
        return -EINVAL;
    }

    if (out_size < required)
    {
        return -ENOSPC;
    }

    // Process input in 3-byte blocks and convert to 4 Base64 characters.
    while (i < in_len)
    {
        uint32_t octet_a = in[i++];
        uint32_t octet_b = (i < in_len) ? in[i++] : 0U;
        uint32_t octet_c = (i < in_len) ? in[i++] : 0U;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[o++] = b64_table[(triple >> 18) & 0x3FU];
        out[o++] = b64_table[(triple >> 12) & 0x3FU];
        out[o++] = b64_table[(triple >> 6) & 0x3FU];
        out[o++] = b64_table[triple & 0x3FU];
    }

    // Add padding '=' characters if the input length was not a multiple of 3.
    switch (in_len % 3U)
    {
        case 1U:out[o - 1U] = '=';
            out[o - 2U] = '=';
            break;
        case 2U:out[o - 1U] = '=';
            break;
        default:break;
    }

    // Null-terminate the output string.
    out[o] = '\0';
    return (int) o;
}


/**
 * @brief Decode a Base64 string into raw bytes.
 *
 * Used to recover the host ciphertext before FIPS203 decapsulation.
 *
 * @param [in] in Base64 input string.
 * @param [in] in_len Length of the Base64 input in bytes.
 * @param [out] out Output byte buffer.
 * @param [in] out_size Output buffer size in bytes.
 * @param [out] out_len Number of decoded bytes written.
 * @return 0 on success or a negative errno value on failure.
 */
static int base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_size, size_t *out_len)
{
    size_t i = 0U;
    size_t o = 0U;

    if (in == NULL || out == NULL || out_len == NULL)
    {
        return -EINVAL;
    }

    if ((in_len % 4U) != 0U)
    {
        return -EINVAL;
    }

    // Process input in 4-character blocks and convert to 3 bytes. Handle padding and invalid characters.
    while (i < in_len)
    {
        int a = (in[i] == '=') ? -2 : base64_value(in[i]);
        int b = (in[i + 1U] == '=') ? -2 : base64_value(in[i + 1U]);
        int c = (in[i + 2U] == '=') ? -2 : base64_value(in[i + 2U]);
        int d = (in[i + 3U] == '=') ? -2 : base64_value(in[i + 3U]);
        uint32_t triple;

        // Validate the decoded values. Negative values indicate invalid characters or padding.
        if (a < 0 || b < 0)
        {
            return -EINVAL;
        }

        if (c == -2 && d != -2)
        {
            return -EINVAL;
        }

        if (c < -2 || d < -2)
        {
            return -EINVAL;
        }

        // Combine the 6-bit values into a 24-bit triple. Treat padding as zero.
        triple = ((uint32_t) a << 18) |
                 ((uint32_t) b << 12) |
                 ((uint32_t)((c < 0) ? 0U : (uint32_t) c) << 6) |
                 ((uint32_t)((d < 0) ? 0U : (uint32_t) d));

        if (o + 1U > out_size)
        {
            return -ENOSPC;
        }

        // Extract the original bytes from the triple and write to output. Only write bytes that correspond to non-padding characters.
        out[o++] = (uint8_t)((triple >> 16) & 0xFFU);

        // If the third character is padding, we only have one byte of output. If the fourth character is padding, we have two bytes of output. Otherwise, we have three bytes.
        if (c != -2)
        {
            if (o + 1U > out_size)
            {
                return -ENOSPC;
            }
            out[o++] = (uint8_t)((triple >> 8) & 0xFFU);
        }

        if (d != -2)
        {
            if (o + 1U > out_size)
            {
                return -ENOSPC;
            }
            out[o++] = (uint8_t)(triple & 0xFFU);
        }

        i += 4U;
    }

    *out_len = o;
    return 0;
}

/**
 * @brief Send a Base64 payload as fixed-size USB chunks.
 *
 * Splits the encoded data into host-friendly records so large keys can travel
 * through the CDC transport without buffer overruns.
 *
 * @param [in] command Command name used in the chunk header.
 * @param [in] base64_text Encoded payload to transmit.
 * @param [in] base64_len Length of the encoded payload.
 * @return 0 on success or a negative errno value on failure.
 */
static int send_chunked_base64_message(const char *command,
                                       const char *base64_text,
                                       size_t base64_len)
{
    char line[USB_MESSAGE_SIZE];
    size_t total_chunks;

    if (command == NULL || base64_text == NULL)
    {
        return -EINVAL;
    }

    if (base64_len == 0U)
    {
        return -EINVAL;
    }

    // Calculate the total number of chunks needed to send the entire Base64 payload. 
    total_chunks = (base64_len + FIPS203_BASE64_CHUNK_SIZE - 1U) / FIPS203_BASE64_CHUNK_SIZE;

    for (size_t chunk_index = 0U; chunk_index < total_chunks; chunk_index++)
    {
        size_t chunk_offset = chunk_index * FIPS203_BASE64_CHUNK_SIZE;
        size_t chunk_len = base64_len - chunk_offset;
        int written;
        int ret;

        if (chunk_len > FIPS203_BASE64_CHUNK_SIZE)
        {
            chunk_len = FIPS203_BASE64_CHUNK_SIZE;
        }

        /* Build explicit, terminated chunk line with leading '@' so the
         * host receives a clean, CRLF-terminated record. Use usb_send_str
         * to avoid double-prefixing by usb_send_data. */
        written = snprintf(line,
                sizeof(line),
                "@%s@%zu/%zu@%.*s\r\n",
                command,
                chunk_index,
                total_chunks,
                (int) chunk_len,
                base64_text + chunk_offset);
        if (written < 0 || written >= (int) sizeof(line))
        {
            return -ENOSPC;
        }

        ret = usb_send_str(line);
        if (ret < 0)
        {
            return ret;
        }

        /* Small delay to prevent CDC coalescing / interleaving of log/data
         * on the host. Performance is not critical here; 100ms is safe. */
        k_sleep(K_MSEC(100));

        // UNCOMMENT the following if you want to have more log msg for each chunk sent

        /* Log the chunk we just sent so host-side traces can verify all
         * indices 0..N-1 actually left the board. */
        {
            /*
            char logbuf[64];
            int lw = snprintf(logbuf, sizeof(logbuf), "%s chunk %zu/%zu sent",
                              command, chunk_index, total_chunks);
            if (lw > 0 && lw < (int)sizeof(logbuf)) {
                (void)log_usb_message("INFO", logbuf);
            }
            */
        }
    }

    // Log the completion of the entire message after all chunks are sent.
    char logbuf[64];
    int lw = snprintf(logbuf, sizeof(logbuf), "%s chunk %zu sent",
            command, total_chunks);
    if (lw > 0 && lw < (int) sizeof(logbuf))
    {
        (void) log_usb_message("INFO", logbuf);
    }

    return 0;
}

/**
 * @brief Send the generated FIPS203 public key to the host.
 *
 * Encodes the key material and transmits it in chunked Base64 form for the
 * host-side encapsulation step.
 *
 * @return 0 on success or a negative errno value on failure.
 */
static int send_fips203_public_key(void)
{
    char b64_pubkey[4096];
    int out_len;
    int ret;

    out_len = base64_encode(fips203_pubkey.data,
            FIPS203_PKEY_BYTE_LEN,
            b64_pubkey,
            sizeof(b64_pubkey));
    if (out_len <= 0)
    {
        return -EINVAL;
    }

    b64_pubkey[out_len] = '\0';

    ret = send_chunked_base64_message("INIT", b64_pubkey, (size_t) out_len);
    return (ret < 0) ? ret : 0;
}

/**
 * @brief Receive and decode the host ciphertext for FIPS203.
 *
 * Collects chunked Base64 records from USB, assembles them, and converts the
 * payload back into the binary ciphertext buffer.
 *
 * @return 0 on success or a negative errno value on failure.
 */
static int receive_ciphertext_from_host(void)
{
    uint8_t rx_buf[128];
    char acc[USB_MESSAGE_SIZE];
    size_t acc_len = 0U;
    char cipher_b64[4096];
    size_t cipher_b64_len = 0U;
    size_t decoded_len = 0U;
    size_t expected_total_chunks = 0U;
    size_t expected_chunk_index = 0U;
    int ret;

    // Line-buffered receiver: accumulate bytes and extract complete lines 
    while (1)
    {
        size_t rx_len = 0U;
        char *line_end;

        ret = usb_receive_wait(rx_buf, sizeof(rx_buf) - 1U, &rx_len, USB_RX_TIMEOUT);
        if (ret != 0)
        {
            return (ret == -EAGAIN) ? -ETIMEDOUT : ret;
        }

        if (rx_len == 0U)
        {
            continue;
        }

        // Ensure we have room in accumulator 
        if (acc_len + rx_len >= sizeof(acc))
        {
            return -ENOSPC;
        }

        memcpy(acc + acc_len, rx_buf, rx_len);
        acc_len += rx_len;

        // Process all complete lines (terminated by '\n') 
        while ((line_end = (char *) memchr(acc, '\n', acc_len)) != NULL)
        {
            size_t line_len = (size_t)(line_end - acc);
            // Trim trailing CR if present
            if (line_len > 0 && acc[line_len - 1] == '\r')
            {
                line_len--;
            }

            // Null-terminate the extracted line temporarily 
            char saved = acc[line_len];
            acc[line_len] = '\0';

            // Skip leading whitespace 
            char *line = acc;
            while (*line == ' ' || *line == '\t')
            {
                line++;
            }

            // Only handle lines beginning with '@' and command VERIFY. Ignore others. 
            if (*line == '@')
            {
                char *command = line + 1;
                char *chunk_info = strchr(command, '@');
                if (chunk_info != NULL)
                {
                    *chunk_info = '\0';
                    char *payload = strchr(chunk_info + 1, '@');
                    if (payload != NULL)
                    {
                        *payload = '\0';
                        payload++;

                        if (strcmp(command, "VERIFY") == 0)
                        {
                            char *slash = strchr(chunk_info + 1, '/');
                            char *endptr;
                            unsigned long chunk_index_ul;
                            unsigned long total_chunks_ul;
                            size_t payload_len;

                            if (slash == NULL)
                            {
                                // restore and continue 
                                acc[line_len] = saved;
                                goto next_line;
                            }

                            *slash = '\0';
                            errno = 0;
                            chunk_index_ul = strtoul(chunk_info + 1, &endptr, 10);
                            if (errno != 0 || endptr == chunk_info + 1 || *endptr != '\0')
                            {
                                return -EINVAL;
                            }

                            errno = 0;
                            total_chunks_ul = strtoul(slash + 1, &endptr, 10);
                            if (errno != 0 || endptr == slash + 1 || *endptr != '\0')
                            {
                                return -EINVAL;
                            }

                            if (total_chunks_ul == 0UL || chunk_index_ul >= total_chunks_ul)
                            {
                                return -EINVAL;
                            }

                            if (expected_total_chunks == 0U)
                            {
                                expected_total_chunks = (size_t) total_chunks_ul;
                            }
                            else if (expected_total_chunks != (size_t) total_chunks_ul)
                            {
                                return -EINVAL;
                            }

                            if (chunk_index_ul != expected_chunk_index)
                            {
                                return -EINVAL;
                            }

                            payload_len = strlen(payload);
                            if (cipher_b64_len + payload_len >= sizeof(cipher_b64))
                            {
                                return -ENOSPC;
                            }

                            memcpy(cipher_b64 + cipher_b64_len, payload, payload_len);
                            cipher_b64_len += payload_len;
                            expected_chunk_index++;

                            if (expected_chunk_index == expected_total_chunks)
                            {
                                // restore buffer before exiting
                                acc[line_len] = saved;
                                goto assembled;
                            }
                        }
                    }
                }
            }

            next_line:
            // restore and remove consumed line including the '\n' 
            acc[line_len] = saved;
            size_t remove_len = (size_t)(line_end - acc) + 1U; // include '\n' 
            if (acc_len > remove_len)
            {
                memmove(acc, acc + remove_len, acc_len - remove_len);
                acc_len -= remove_len;
            }
            else
            {
                acc_len = 0U;
            }
        }
    }

    assembled:

    ret = base64_decode(cipher_b64,
            cipher_b64_len,
            fips203_cipher.data,
            sizeof(fips203_cipher.data),
            &decoded_len);
    if (ret != 0)
    {
        return ret;
    }

    if (decoded_len != FIPS203_CIPHER_TEXT_BYTE_LEN)
    {
        return -EINVAL;
    }

    return 0;
}

/**
 * @brief Send the ECDH shared secret as USB data.
 *
 * Mirrors the log variant but emits the value in the structured data stream so
 * host scripts can capture it directly.
 *
 * @param [in] shared_secret Shared secret to transmit.
 * @return 0 on success or a negative errno value on failure.
 */
static int send_shared_secret_as_data(const ecdha_shared_secret_t *shared_secret)
{
    char secret_text[ECDHA_SHARED_SECRET_TEXT_SIZE];
    char buffer[USB_MESSAGE_SIZE];
    int ret;

    ret = ecdha_shared_secret_to_string(shared_secret, secret_text, sizeof(secret_text));
    if (ret != 0)
    {
        return ret;
    }

    if (snprintf(buffer, sizeof(buffer), "COMMON_SECRET=%s", secret_text) >= (int) sizeof(buffer))
    {
        return -ENOSPC;
    }

    ret = usb_send_data(buffer);
    return (ret < 0) ? ret : 0;
}

/**
 * @brief Read the algorithm selection switches.
 *
 * Uses the configured GPIO input to choose between ECDH and FIPS203 runs.
 *
 * @return Selected test algorithm.
 */
static enum test_algorithm get_selected_algorithm(void)
{
    return switch_state0() ? TEST_ALGO_FIPS203 : TEST_ALGO_ECDH;
}

/**
 * @brief Read the test mode selection switch.
 *
 * Uses the second GPIO input to choose between manual and batch execution.
 *
 * @return Selected test mode.
 */
static enum test_mode get_selected_mode(void)
{
    return switch_state1() ? TEST_MODE_BATCH : TEST_MODE_MANUAL;
}

/**
 * @brief Convert the selected algorithm to a short display name.
 *
 * The returned label is used in status messages and summary output.
 *
 * @param [in] algorithm Algorithm identifier.
 * @return Human-readable algorithm name.
 */
static const char *algorithm_name(enum test_algorithm algorithm)
{
    switch (algorithm)
    {
        case TEST_ALGO_ECDH:return "ECDH";
        case TEST_ALGO_FIPS203:return "FIPS203";
        default:return "UNKNOWN";
    }
}


/**
 * @brief Fill a buffer with the deterministic FIPS203 test seed.
 *
 * The seed is intentionally repeatable so test runs are easier to compare.
 *
 * @param [out] seed Destination buffer.
 * @param [in] seed_len Number of bytes to populate.
 * @return None.
 */
static void fips203_generate_random_seed(uint8_t *seed, size_t seed_len)
{
    // Deterministic seed keeps the test flow repeatable on the board. 
    for (size_t i = 0; i < seed_len; i++)
    {
        seed[i] = (uint8_t)((i * 73 + 42) % 256);
    }
}

/* FIPS203 Key Exchange - Calls wrapped via Fips203_implementation */

/**
 * @brief Run the full FIPS203 test flow.
 *
 * Handles key generation, key exchange, decapsulation, and result reporting
 * for a single FIPS203 run.
 *
 * @return 0 on success or a negative errno value on failure.
 */
static int run_fips203_test_execution(void)
{
    uint8_t seed_d[FIPS203_SEED_D_BYTE_LEN];
    uint8_t seed_z[FIPS203_SEED_Z_BYTE_LEN];
    size_t stack_before = 0;
    size_t stack_after = 0;
    bool stack_ok;
    uint64_t t0;
    uint64_t t1;
    int ret;

    // Stage 1: Key Generation 
    (void) log_usb_message("INFO", "Generating FIPS203 keypair...");

    // Generate random seeds 
    fips203_generate_random_seed(seed_d, FIPS203_SEED_D_BYTE_LEN);
    fips203_generate_random_seed(seed_z, FIPS203_SEED_Z_BYTE_LEN);

    stack_ok = fips203_get_stack_used_bytes(&stack_before);
    OSZI_GPIO_set(true);    // Toggle GPIO to mark the start of the key generation phase for oscilloscope measurement.
    t0 = k_cycle_get_64();  // start time measurement
    ret = fips203_keygen(seed_d, seed_z, &fips203_pubkey, &fips203_seckey);
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (stack_ok)
    {
        stack_ok = fips203_get_stack_used_bytes(&stack_after);
    }

    if (ret != 0)
    {
        fips203_print_performance_result("FIPS203 keypair generation", t1 - t0, stack_before, stack_after, stack_ok);
        fips203_performance_record(FIPS203_PERF_KEYGEN, t1 - t0, stack_before, stack_after, stack_ok);
        (void) log_usb_message("ERR", "FIPS203 keypair generation failed");
        return ret;
    }
    k_sleep(K_MSEC(100));
    fips203_print_performance_result("FIPS203 keypair generation", t1 - t0, stack_before, stack_after, stack_ok);
    fips203_performance_record(FIPS203_PERF_KEYGEN, t1 - t0, stack_before, stack_after, stack_ok);
    (void) log_usb_message("INFO", "FIPS203 keypair generation succeeded");
    k_sleep(K_MSEC(100));

    // Stage 2: Public key exchange and host encapsulation 
    (void) log_usb_message("INFO", "Starting FIPS203 key exchange (send public key, receive ciphertext)...");

    k_sleep(K_MSEC(100));
    stack_ok = fips203_get_stack_used_bytes(&stack_before);
    OSZI_GPIO_set(true);    // Toggle GPIO to mark the start of the key exchange phase for oscilloscope measurement.
    t0 = k_cycle_get_64();  //  start time measurement

    ret = send_fips203_public_key();


    if (ret != 0)
    {
        t1 = k_cycle_get_64();
        if (stack_ok)
        {
            stack_ok = fips203_get_stack_used_bytes(&stack_after);
        }
        fips203_print_performance_result("FIPS203 key exchange", t1 - t0, stack_before, stack_after, stack_ok);
        k_sleep(K_MSEC(100));
        fips203_performance_record(FIPS203_PERF_KEY_EXCHANGE, t1 - t0, stack_before, stack_after, stack_ok);
        k_sleep(K_MSEC(100));
        (void) log_usb_message("ERR", "Failed to send FIPS203 public key");
        return ret;
    }


    (void) log_usb_message("INFO", "Waiting for host ciphertext...");
    ret = receive_ciphertext_from_host();
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (stack_ok)
    {
        stack_ok = fips203_get_stack_used_bytes(&stack_after);
    }
    k_sleep(K_MSEC(200));

    if (ret != 0)
    {
        fips203_print_performance_result("FIPS203 key exchange", t1 - t0, stack_before, stack_after, stack_ok);
        k_sleep(K_MSEC(100));
        fips203_performance_record(FIPS203_PERF_KEY_EXCHANGE, t1 - t0, stack_before, stack_after, stack_ok);
        if (ret == -ETIMEDOUT)
        {
            (void) log_usb_message("ERR", "Timed out waiting for host ciphertext");
        }
        else
        {
            (void) log_usb_message("ERR", "Received invalid host ciphertext");
        }
        return ret;
    }
    k_sleep(K_MSEC(100));

    fips203_print_performance_result("FIPS203 key exchange", t1 - t0, stack_before, stack_after, stack_ok);
    fips203_performance_record(FIPS203_PERF_KEY_EXCHANGE, t1 - t0, stack_before, stack_after, stack_ok);
    (void) log_usb_message("INFO", "FIPS203 key exchange succeeded");

    k_sleep(K_MSEC(100));
    /* Stage 3: Compute Shared Secret (Decapsulation) */
    (void) log_usb_message("INFO", "Computing FIPS203 shared secret...");
    stack_ok = fips203_get_stack_used_bytes(&stack_before);
    OSZI_GPIO_set(true);    // Toggle GPIO to mark the start of the decapsulation phase for oscilloscope measurement.
    t0 = k_cycle_get_64();  // start time measurement
    ret = fips203_decapsulate(&fips203_seckey, &fips203_cipher, &fips203_receiver_secret);
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (stack_ok)
    {
        stack_ok = fips203_get_stack_used_bytes(&stack_after);
    }
    k_sleep(K_MSEC(100));

    if (ret != 0)
    {
        fips203_print_performance_result("FIPS203 shared secret computation", t1 - t0, stack_before, stack_after, stack_ok);
        fips203_performance_record(FIPS203_PERF_COMPUTE_SECRET, t1 - t0, stack_before, stack_after, stack_ok);
        (void) log_usb_message("ERR", "FIPS203 decapsulation failed");
        return ret;
    }
    k_sleep(K_MSEC(100));
    fips203_print_performance_result("FIPS203 shared secret computation", t1 - t0, stack_before, stack_after, stack_ok);
    fips203_performance_record(FIPS203_PERF_COMPUTE_SECRET, t1 - t0, stack_before, stack_after, stack_ok);
    (void) log_usb_message("INFO", "FIPS203 shared secret computation succeeded");

    (void) log_usb_message("INFO", "sent common secret");

    (void) log_usb_message("INFO", "FIPS203 test execution complete");

    ret = send_fips203_shared_secret_as_data(   // send the derived shared secret back to the host for verification
            "COMMON_SECRET",
            &fips203_receiver_secret);

    if (ret != 0)
    {
        (void) log_usb_message("ERR", "Failed to send common secret");
        return ret;
    }
    k_sleep(K_MSEC(100));

    return 0;
}

/**
 * @brief Run the selected algorithm's test path.
 *
 * Dispatches to either the ECDH or FIPS203 execution routine and logs the
 * selected mode for host-side traceability.
 *
 * @param [in] algorithm Selected algorithm.
 * @return 0 on success or a negative errno value on failure.
 */
static int run_selected_test(enum test_algorithm algorithm)
{
    char status[USB_MESSAGE_SIZE];

    if (snprintf(status, sizeof(status), "Testing %s implementation", algorithm_name(algorithm)) >= (int) sizeof(status))
    {
        return -ENOSPC;
    }

    (void) log_usb_message("INFO", status);

    switch (algorithm)
    {
        case TEST_ALGO_ECDH:return run_ecdh_test_execution();
        case TEST_ALGO_FIPS203:return run_fips203_test_execution();
        default:return -EINVAL;
    }
}

/**
 * @brief Run a single manual test iteration.
 *
 * Resets the relevant performance state before executing one selected test.
 *
 * @param [in] algorithm Selected algorithm.
 * @return 0 on success or a negative errno value on failure.
 */
static int run_manual_test(enum test_algorithm algorithm)
{
    if (algorithm == TEST_ALGO_ECDH)
    {
        ecdh_performance_tests_reset();
        ecdh_performance_set_run_index(0);
    }
    else if (algorithm == TEST_ALGO_FIPS203)
    {
        fips203_performance_tests_reset();
        fips203_performance_set_run_index(0);
    }

    int ret = run_selected_test(algorithm);

    return ret;
}

/**
 * @brief Run the selected algorithm multiple times for benchmarking.
 *
 * Clears the performance buffers, runs the selected test repeatedly, and then
 * prints the aggregated timing and stack results.
 *
 * @param [in] algorithm Selected algorithm.
 * @return 0 on success or a negative errno value on failure.
 */
static int run_batch_test(enum test_algorithm algorithm)
{
    k_sleep(K_SECONDS(0.5));
    int ret;
    char message[USB_MESSAGE_SIZE];

    if (algorithm == TEST_ALGO_ECDH)
    {
        ecdh_performance_tests_reset();
    }
    else if (algorithm == TEST_ALGO_FIPS203)
    {
        fips203_performance_tests_reset();
    }

    if (number_of_batch_tests <= 0)
    {
        return -EINVAL;
    }

    if (number_of_batch_tests > PERF_MAX_RUNS)
    {
        char warning_msg[120];
        snprintf(warning_msg,
                sizeof(warning_msg),
                "Warning: only first %d test runs are stored for averaging calculations",
                PERF_MAX_RUNS);
        (void) log_usb_message("WARN", warning_msg);
    }
    k_sleep(K_MSEC(100));
    for (int test_run = 1; test_run <= number_of_batch_tests; test_run++)
    {
        if (snprintf(message, sizeof(message), "===== Batch run %d of %d =====", test_run, number_of_batch_tests) >= (int) sizeof(message))
        {
            return -ENOSPC;
        }

        (void) log_usb_message("INFO", message);

        if (algorithm == TEST_ALGO_ECDH)
        {
            ecdh_performance_set_run_index(test_run - 1);
        }
        else if (algorithm == TEST_ALGO_FIPS203)
        {
            fips203_performance_set_run_index(test_run - 1);
        }

        ret = run_selected_test(algorithm);
        if (ret != 0)
        {
            return ret;
        }
    }

    // Display aggregated results for selected algorithm 
    if (calc_test_results(algorithm) != 0)
    {
        (void) log_usb_message("WARN", "Result calculation incomplete");
    }

    if (algorithm == TEST_ALGO_ECDH)
    {
        (void) log_usb_message("INFO", "All ECDH batch test runs completed successfully");
    }
    else if (algorithm == TEST_ALGO_FIPS203)
    {
        (void) log_usb_message("INFO", "All FIPS203 batch test runs completed successfully");
    }

    return 0;
}

/**
 * @brief Measure the current ECDH stack usage.
 *
 * Uses Zephyr stack introspection when it is available and reports the amount
 * of stack already consumed by the current thread.
 *
 * @param [out] used_bytes Number of bytes already used on the stack.
 * @return True when stack measurement succeeded, otherwise false.
 */
static bool ecdh_get_stack_used_bytes(size_t *used_bytes)
{
#if defined(CONFIG_THREAD_STACK_INFO) && defined(CONFIG_INIT_STACKS)    // Zephyr provides a convenient API to get the remaining stack space for the current thread. We can use this to calculate how much stack has been used so far.
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
 * @brief Print an ECDH performance summary.
 *
 * Formats timing and stack data into a single log line for the host.
 *
 * @param [in] label Performance stage name.
 * @param [in] cycle_delta Measured cycle count for the stage.
 * @param [in] stack_before Stack usage before the stage.
 * @param [in] stack_after Stack usage after the stage.
 * @param [in] stack_ok True when stack measurement is valid.
 * @return None.
 */
static void ecdh_print_performance_result(const char *label, uint64_t cycle_delta,
                                          size_t stack_before, size_t stack_after,
                                          bool stack_ok)
{
    char msg[100];
    uint64_t us = k_cyc_to_us_floor64(cycle_delta);

    //send time measurements and stack usage to host
    if (stack_ok)
    {
        long delta = (long) stack_after - (long) stack_before;
        snprintf(msg,
                sizeof(msg),
                "PERF %s: %llu us | stack: %u -> %u bytes (delta %+ld bytes)",
                label,
                (unsigned long long) us,
                (unsigned int) stack_before,
                (unsigned int) stack_after,
                delta);
    }
    else
    {
        snprintf(msg,
                sizeof(msg),
                "PERF %s: %llu us | stack: n/a (enable CONFIG_THREAD_STACK_INFO + CONFIG_INIT_STACKS)",
                label,
                (unsigned long long) us);
    }

    (void) log_usb_message("PERF", msg);
}

/**
 * @brief Clear the recorded ECDH benchmark history.
 *
 * Resets the per-stage buffers before a new batch test run starts.
 *
 * @return None.
 */
static void ecdh_performance_tests_reset(void)
{
    memset(ecdh_perf_time_us, 0, sizeof(ecdh_perf_time_us));
    memset(ecdh_perf_stack_before_bytes, 0, sizeof(ecdh_perf_stack_before_bytes));
    memset(ecdh_perf_stack_after_bytes, 0, sizeof(ecdh_perf_stack_after_bytes));
    memset(ecdh_perf_stack_measurement_ok, 0, sizeof(ecdh_perf_stack_measurement_ok));
    ecdh_perf_current_run_index = 0;
    ecdh_perf_recorded_runs = 0;
}

/**
 * @brief Set the active ECDH performance slot.
 *
 * The index determines where the next benchmark sample will be stored.
 *
 * @param [in] run_index Zero-based run index.
 * @return None.
 */
static void ecdh_performance_set_run_index(int run_index)
{
    ecdh_perf_current_run_index = run_index;
}

/**
 * @brief Store one ECDH performance sample.
 *
 * Saves timing and stack data for the currently selected run index.
 *
 * @param [in] stage Performance stage being recorded.
 * @param [in] cycle_delta Measured cycle count for the stage.
 * @param [in] stack_before Stack usage before the stage.
 * @param [in] stack_after Stack usage after the stage.
 * @param [in] stack_ok True when stack measurement is valid.
 * @return None.
 */
static void ecdh_performance_record(enum ecdh_perf_stage stage,
                                    uint64_t cycle_delta, size_t stack_before,
                                    size_t stack_after, bool stack_ok)
{
    if (stage < 0 || stage >= ECDH_PERF_STAGE_COUNT)
    {
        return;
    }

    if (ecdh_perf_current_run_index < 0 || ecdh_perf_current_run_index >= PERF_MAX_RUNS)
    {
        return;
    }

    // Store the measured performance data in the corresponding buffers for later aggregation.
    ecdh_perf_time_us[stage][ecdh_perf_current_run_index] = k_cyc_to_us_floor64(cycle_delta);
    ecdh_perf_stack_before_bytes[stage][ecdh_perf_current_run_index] = stack_before;
    ecdh_perf_stack_after_bytes[stage][ecdh_perf_current_run_index] = stack_after;
    ecdh_perf_stack_measurement_ok[stage][ecdh_perf_current_run_index] = stack_ok;

    if ((ecdh_perf_current_run_index + 1) > ecdh_perf_recorded_runs)
    {
        ecdh_perf_recorded_runs = ecdh_perf_current_run_index + 1;
    }
}

// FIPS203 Performance Measurement Functions (mirroring ECDH pattern) 

/**
 * @brief Measure the current FIPS203 stack usage.
 *
 * Uses the same stack inspection path as the ECDH benchmark helpers.
 *
 * @param [out] used_bytes Number of bytes already used on the stack.
 * @return True when stack measurement succeeded, otherwise false.
 */
static bool fips203_get_stack_used_bytes(size_t *used_bytes)
{
#if defined(CONFIG_THREAD_STACK_INFO) && defined(CONFIG_INIT_STACKS)    // Zephyr provides a convenient API to get the remaining stack space for the current thread. We can use this to calculate how much stack has been used so far.
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
 * @brief Print a FIPS203 performance summary.
 *
 * Formats the measured cycles and stack usage for host-side reporting.
 *
 * @param [in] label Performance stage name.
 * @param [in] cycle_delta Measured cycle count for the stage.
 * @param [in] stack_before Stack usage before the stage.
 * @param [in] stack_after Stack usage after the stage.
 * @param [in] stack_ok True when stack measurement is valid.
 * @return None.
 */
static void fips203_print_performance_result(const char *label, uint64_t cycle_delta,
                                             size_t stack_before, size_t stack_after,
                                             bool stack_ok)
{
    k_sleep(K_MSEC(100));
    char msg[100];
    uint64_t us = k_cyc_to_us_floor64(cycle_delta);

    //send time measurements and stack usage to host
    if (stack_ok)
    {
        long delta = (long) stack_after - (long) stack_before;
        snprintf(msg,
                sizeof(msg),
                "PERF %s: %llu us | stack: %u -> %u bytes (delta %+ld bytes)",
                label,
                (unsigned long long) us,
                (unsigned int) stack_before,
                (unsigned int) stack_after,
                delta);
    }
    else
    {
        snprintf(msg,
                sizeof(msg),
                "PERF %s: %llu us | stack: n/a (enable CONFIG_THREAD_STACK_INFO + CONFIG_INIT_STACKS)",
                label,
                (unsigned long long) us);
    }

    (void) log_usb_message("PERF", msg);
}

/**
 * @brief Set the oscilloscope probe GPIO state.
 *
 * Marks the active timing window on the external measurement pin when the
 * configured GPIO is available.
 *
 * @param [in] active True to assert the probe line, false to clear it.
 * @return None.
 */
static void OSZI_GPIO_set(bool active)
{
    if (!gpio_is_ready_dt(&OSZI_GPIO_toggle))
    {
        return;
    }

    (void) gpio_pin_set_dt(&OSZI_GPIO_toggle, active ? 1 : 0);
}

/**
 * @brief Clear the recorded FIPS203 benchmark history.
 *
 * Resets the per-stage buffers before a new batch test run starts.
 *
 * @return None.
 */
static void fips203_performance_tests_reset(void)
{
    memset(fips203_perf_time_us, 0, sizeof(fips203_perf_time_us));
    memset(fips203_perf_stack_before_bytes, 0, sizeof(fips203_perf_stack_before_bytes));
    memset(fips203_perf_stack_after_bytes, 0, sizeof(fips203_perf_stack_after_bytes));
    memset(fips203_perf_stack_measurement_ok, 0, sizeof(fips203_perf_stack_measurement_ok));
    fips203_perf_current_run_index = 0;
    fips203_perf_recorded_runs = 0;
}

/**
 * @brief Set the active FIPS203 performance slot.
 *
 * The index determines where the next benchmark sample will be stored.
 *
 * @param [in] run_index Zero-based run index.
 * @return None.
 */
static void fips203_performance_set_run_index(int run_index)
{
    fips203_perf_current_run_index = run_index;
}

/**
 * @brief Store one FIPS203 performance sample.
 *
 * Saves timing and stack data for the currently selected run index.
 *
 * @param [in] stage Performance stage being recorded.
 * @param [in] cycle_delta Measured cycle count for the stage.
 * @param [in] stack_before Stack usage before the stage.
 * @param [in] stack_after Stack usage after the stage.
 * @param [in] stack_ok True when stack measurement is valid.
 * @return None.
 */
static void fips203_performance_record(enum fips203_perf_stage stage,
                                       uint64_t cycle_delta, size_t stack_before,
                                       size_t stack_after, bool stack_ok)
{
    if (stage < 0 || stage >= FIPS203_PERF_STAGE_COUNT)
    {
        return;
    }

    if (fips203_perf_current_run_index < 0 || fips203_perf_current_run_index >= PERF_MAX_RUNS)
    {
        return;
    }

    // Store the measured performance data in the corresponding buffers for later aggregation.
    fips203_perf_time_us[stage][fips203_perf_current_run_index] = k_cyc_to_us_floor64(cycle_delta);
    fips203_perf_stack_before_bytes[stage][fips203_perf_current_run_index] = stack_before;
    fips203_perf_stack_after_bytes[stage][fips203_perf_current_run_index] = stack_after;
    fips203_perf_stack_measurement_ok[stage][fips203_perf_current_run_index] = stack_ok;

    if ((fips203_perf_current_run_index + 1) > fips203_perf_recorded_runs)
    {
        fips203_perf_recorded_runs = fips203_perf_current_run_index + 1;
    }
}

/**
 * @brief Print aggregate results for the selected algorithm.
 *
 * Summarizes timing and stack measurements across all recorded batch runs and
 * streams the CSV block expected by the host tooling.
 *
 * @param [in] algorithm Selected algorithm.
 * @return 0 on success, 1 when no samples were recorded, or a negative errno value.
 */
static int calc_test_results(enum test_algorithm algorithm)
{
    int recorded_runs;
    uint64_t(*perf_time_us)[PERF_MAX_RUNS];
    size_t(*perf_stack_after_bytes)[PERF_MAX_RUNS];
    bool (*perf_stack_measurement_ok)[PERF_MAX_RUNS];
    int stage_count;
    const char *stage_labels[3];
    char algo_name[32];
    char msg[220];


    if (algorithm == TEST_ALGO_ECDH)
    {
        recorded_runs = ecdh_perf_recorded_runs;
        perf_time_us = ecdh_perf_time_us;
        perf_stack_after_bytes = ecdh_perf_stack_after_bytes;
        perf_stack_measurement_ok = ecdh_perf_stack_measurement_ok;
        stage_count = ECDH_PERF_STAGE_COUNT;
        stage_labels[0] = "keypair generation";
        stage_labels[1] = "key exchange (send+receive)";
        stage_labels[2] = "shared secret computation";
        snprintf(algo_name, sizeof(algo_name), "ECDH");
    }
    else if (algorithm == TEST_ALGO_FIPS203)
    {
        recorded_runs = fips203_perf_recorded_runs;
        perf_time_us = fips203_perf_time_us;
        perf_stack_after_bytes = fips203_perf_stack_after_bytes;
        perf_stack_measurement_ok = fips203_perf_stack_measurement_ok;
        stage_count = FIPS203_PERF_STAGE_COUNT;
        stage_labels[0] = "keypair generation";
        stage_labels[1] = "key exchange (encapsulation/exchange handshake)";
        stage_labels[2] = "shared secret computation";
        snprintf(algo_name, sizeof(algo_name), "FIPS203");
    }
    else
    {
        return -EINVAL;
    }

    if (recorded_runs <= 0)
    {
        snprintf(msg, sizeof(msg), "No %s performance samples recorded", algo_name);
        (void) log_usb_message("WARN", msg);
        return 1;
    }

    (void) log_usb_message("INFO", "===== Stack Usage Per Test Run =====");

    // Print stack usage for each run and stage
    for (int run = 0; run < recorded_runs; run++)
    {
        snprintf(msg, sizeof(msg), "Test Run %d:", run + 1);
        (void) log_usb_message("INFO", msg);
        k_sleep(K_MSEC(100));

        for (int stage = 0; stage < stage_count; stage++)
        {
            if (perf_stack_measurement_ok[stage][run])
            {
                snprintf(msg,
                        sizeof(msg),
                        "  %s: %u bytes",
                        stage_labels[stage],
                        (unsigned int) perf_stack_after_bytes[stage][run]);
            }
            else
            {
                snprintf(msg,
                        sizeof(msg),
                        "  %s: n/a",
                        stage_labels[stage]);
            }
            (void) log_usb_message("INFO", msg);
            k_sleep(K_MSEC(100));
        }
    }

    (void) log_usb_message("INFO", "===== Performance Statistics (Time) =====");

    // Calculate and print mean, min, and max times for each stage across all runs
    for (int stage = 0; stage < stage_count; stage++)
    {
        uint64_t sum_us = 0;
        uint64_t min_us = UINT64_MAX;
        uint64_t max_us = 0;

        for (int run = 0; run < recorded_runs; run++)
        {
            uint64_t time_us = perf_time_us[stage][run];
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

        uint64_t mean_us = sum_us / (uint64_t) recorded_runs;

        snprintf(msg,
                sizeof(msg),
                "%s: Mean=%llu us | Min=%llu us | Max=%llu us",
                stage_labels[stage],
                (unsigned long long) mean_us,
                (unsigned long long) min_us,
                (unsigned long long) max_us);
        (void) log_usb_message("INFO", msg);
        k_sleep(K_MSEC(50));
    }

    /*
     * Send CSV measurement data wrapped in #start# / #stop# block.
     * Host script looks for these markers to identify and parse CSV data.
     * Format: 
     * #start#
     * algorithm,stage,run,time_us,stack_before,stack_after,stack_used_bytes,stack_ok
     * [data rows...]
     * #stop#
     */
    if (recorded_runs > 0)
    {
        static char csv_buffer[2048];
        int buf_pos;
        const int buf_max = (int) sizeof(csv_buffer);

        // Send start marker
        (void) usb_send_str("#start#\r\n");
        k_sleep(K_MSEC(20));

        // Send CSV header
        (void) usb_send_str("algorithm,stage,run,time_us,stack_before,stack_after,stack_used_bytes,stack_ok\r\n");
        k_sleep(K_MSEC(20));

        // Send data rows grouped by run (all 3 stages for run N, then all 3 for run N+1) 
        for (int run = 0; run < recorded_runs; run++)
        {
            buf_pos = 0;

            for (int stage = 0; stage < stage_count; stage++)
            {
                uint64_t time_us = perf_time_us[stage][run];
                size_t stack_before = 0;
                size_t stack_after = 0;
                bool stack_ok = false;

                // Select correct arrays based on algorithm
                if (algorithm == TEST_ALGO_ECDH)
                {
                    stack_before = ecdh_perf_stack_before_bytes[stage][run];
                    stack_after = ecdh_perf_stack_after_bytes[stage][run];
                    stack_ok = ecdh_perf_stack_measurement_ok[stage][run];
                }
                else
                {
                    stack_before = fips203_perf_stack_before_bytes[stage][run];
                    stack_after = fips203_perf_stack_after_bytes[stage][run];
                    stack_ok = fips203_perf_stack_measurement_ok[stage][run];
                }

                long stack_used = stack_ok ? (long) stack_after - (long) stack_before : 0;

                buf_pos += snprintf(csv_buffer + buf_pos, buf_max - buf_pos,
                        "%s,%s,%d,%llu,%u,%u,%ld,%s\r\n",
                        algo_name,
                        stage_labels[stage],
                        run + 1,
                        (unsigned long long) time_us,
                        (unsigned int) stack_before,
                        (unsigned int) stack_after,
                        stack_used,
                        stack_ok ? "true" : "false");
            }

            // Send this run's batch (all 3 stages as one message) 
            (void) usb_send_str(csv_buffer);
            k_sleep(K_MSEC(20));
        }

        // Send stop marker
        (void) usb_send_str("#stop#\r\n");
        k_sleep(K_MSEC(20));
    }

    return 0;
}

/**
 * @brief Receive the peer public key for the ECDH exchange.
 *
 * Reads a single text line from USB and converts it into the internal point
 * representation used by the shared-secret calculation.
 *
 * @param [out] peer_public_key Parsed peer point.
 * @return 0 on success or a negative errno value on failure.
 */
static int receive_peer_public_key(ecdha_point_t *peer_public_key)
{
    uint8_t rx_buf[ECDHA_POINT_TEXT_SIZE];
    size_t rx_len = 0;
    int ret;

    // Read the peer public key as a single line of text from USB. The host is expected to send the point in uncompressed hex format, followed by a newline. We trim any trailing newlines before parsing.
    ret = usb_receive_wait(rx_buf, sizeof(rx_buf) - 1U, &rx_len, USB_RX_TIMEOUT);
    if (ret != 0)
    {
        return (ret == -EAGAIN) ? -ETIMEDOUT : ret;
    }

    while (rx_len > 0U && (rx_buf[rx_len - 1U] == '\n' || rx_buf[rx_len - 1U] == '\r'))
    {
        rx_len--;
    }

    rx_buf[rx_len] = '\0';
    return ecdha_public_key_from_string((char *) rx_buf, peer_public_key);
}

/**
 * @brief Run the full ECDH test flow.
 *
 * Handles key generation, key exchange, shared-secret computation, and result
 * reporting for a single ECDH run.
 *
 * @return 0 on success or a negative errno value on failure.
 */
static int run_ecdh_test_execution(void)
{
    ecdha_keypair_t local_keypair;
    ecdha_point_t peer_public_key;
    ecdha_shared_secret_t shared_secret;
    char status[USB_MESSAGE_SIZE];
    int ret;
    size_t stack_before = 0;
    size_t stack_after = 0;
    bool stack_ok;
    uint64_t t0;
    uint64_t t1;

    // Stage 1: Keypair Generation 
    (void) log_usb_message("INFO", "Generating ECDH keypair...");
    stack_ok = ecdh_get_stack_used_bytes(&stack_before);
    OSZI_GPIO_set(true);    // Toggle GPIO to mark the start of the key generation phase for oscilloscope measurement.
    t0 = k_cycle_get_64();  //  start time measurement
    ret = ecdha_generate_keypair(&local_keypair);
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (stack_ok)
    {
        stack_ok = ecdh_get_stack_used_bytes(&stack_after);
    }

    if (ret != 0)
    {
        (void) log_usb_message("ERR", "ECDH keypair generation failed");
        return ret;
    }
    ecdh_print_performance_result("ECDH keypair generation", t1 - t0, stack_before, stack_after, stack_ok);
    ecdh_performance_record(ECDH_PERF_KEYGEN, t1 - t0, stack_before, stack_after, stack_ok);
    (void) log_usb_message("INFO", "ECDH keypair generation succeeded");

    if (snprintf(status, sizeof(status), "ECDH test using %s", ecdha_curve_name()) >= (int) sizeof(status))
    {
        return -ENOSPC;
    }

    ret = send_point_as_log("LOCAL_PUBLIC_KEY", &local_keypair.public_key);
    if (ret != 0)
    {
        (void) log_usb_message("ERR", "Failed to send local public key");
        return ret;
    }


    ret = send_point_components_as_data("LOCAL_PUBLIC_KEY", &local_keypair.public_key);
    if (ret != 0)
    {
        (void) log_usb_message("ERR", "Failed to send local public key components");
        return ret;
    }
    (void) log_usb_message("INFO", "Sent board public key");

    ret = send_u32_as_data("LOCAL_PRIVATE_SCALAR", local_keypair.private_scalar);
    if (ret != 0)
    {
        (void) log_usb_message("ERR", "Failed to send local private scalar");
        return ret;
    }
    (void) log_usb_message("INFO", "Sent board private scalar");

    // Stage 2: Key Exchange (send and receive)
    (void) log_usb_message("INFO", "Starting key exchange (send + receive)...");
    stack_ok = ecdh_get_stack_used_bytes(&stack_before);

    ret = log_usb_message("INFO", "Waiting for host public key");
    if (ret != 0)
    {
        return ret;
    }

    OSZI_GPIO_set(true);    // Toggle GPIO to mark the start of the key exchange phase for oscilloscope measurement.
    t0 = k_cycle_get_64();  // start time measurement for the key exchange phase
    ret = receive_peer_public_key(&peer_public_key);
    if (ret != 0)
    {
        if (ret == -ETIMEDOUT)
        {
            (void) log_usb_message("ERR", "Timed out waiting for host public key");
        }
        else
        {
            (void) log_usb_message("ERR", "Received invalid host public key");
        }
        return ret;
    }

    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (stack_ok)
    {
        stack_ok = ecdh_get_stack_used_bytes(&stack_after);
    }
    ecdh_print_performance_result("ECDH key exchange", t1 - t0, stack_before, stack_after, stack_ok);
    ecdh_performance_record(ECDH_PERF_KEY_EXCHANGE, t1 - t0, stack_before, stack_after, stack_ok);
    (void) log_usb_message("INFO", "Received host public key");

    ret = send_point_as_log("HOST_PUBLIC_KEY", &peer_public_key);
    if (ret != 0)
    {
        (void) log_usb_message("ERR", "Failed to echo host public key");
        return ret;
    }

    ret = send_u32_as_data("HOST_QX", peer_public_key.x);
    if (ret != 0)
    {
        (void) log_usb_message("ERR", "Failed to send host Qx");
        return ret;
    }
    (void) log_usb_message("INFO", "Sent host Qx");

    ret = send_u32_as_data("HOST_QY", peer_public_key.y);
    if (ret != 0)
    {
        (void) log_usb_message("ERR", "Failed to send host Qy");
        return ret;
    }
    (void) log_usb_message("INFO", "Sent host Qy");

    // Stage 3: Compute Shared Secret 
    (void) log_usb_message("INFO", "Computing shared secret...");
    stack_ok = ecdh_get_stack_used_bytes(&stack_before);
    OSZI_GPIO_set(true);    // Toggle GPIO to mark the start of the shared secret computation phase for oscilloscope measurement.
    t0 = k_cycle_get_64();  // start time measurement for the shared secret computation phase
    ret = ecdha_compute_shared_secret(&local_keypair, &peer_public_key, &shared_secret);
    t1 = k_cycle_get_64();
    OSZI_GPIO_set(false);
    if (stack_ok)
    {
        stack_ok = ecdh_get_stack_used_bytes(&stack_after);
    }

    if (ret != 0)
    {
        (void) log_usb_message("ERR", "Shared secret computation failed");
        return ret;
    }
    ecdh_print_performance_result("ECDH shared secret computation", t1 - t0, stack_before, stack_after, stack_ok);
    ecdh_performance_record(ECDH_PERF_COMPUTE_SECRET, t1 - t0, stack_before, stack_after, stack_ok);
    (void) log_usb_message("INFO", "Shared secret computation succeeded");

    (void) log_usb_message("INFO", "sent common secret");
    (void) log_usb_message("INFO", "ECDH test execution complete");

    ret = send_shared_secret(&shared_secret);
    if (ret != 0)
    {
        (void) log_usb_message("ERR", "Failed to send common secret");
        return ret;
    }


    ret = send_shared_secret_as_data(&shared_secret);
    if (ret != 0)
    {
        (void) log_usb_message("ERR", "Failed to send common secret as data");
        return ret;
    }

    return 0;
}


/**
 * @brief Configure the board devices used by the test application. (HW and LED Initialization)
 *
 * Initializes the USB console, button, switches, and oscilloscope probe GPIOs
 * required by the main test loop.
 *
 * @return 0 on success or 1 when initialization fails.
 */
int init_Devices(void)
{
    const struct device *cdc_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));
    if (!device_is_ready(cdc_dev))
    {
        log_usb_message("ERR", "CDC ACM device not ready\n");
        return 1;
    }

    // Configure button
    int ret = gpio_pin_configure_dt(&button, GPIO_INPUT);
    if (ret < 0)
    {
        log_usb_message("ERR", "Error: button config failed\n");
        return 1;
    }

    // Enable interrupt on button
    ret = gpio_pin_interrupt_configure_dt(&button, GPIO_INT_EDGE_TO_ACTIVE);
    if (ret < 0)
    {
        log_usb_message("ERR", "Error: interrupt config failed\n");
        return 1;
    }
    gpio_init_callback(&button_cb_data, button_pressed, BIT(button.pin));
    gpio_add_callback(button.port, &button_cb_data);

    ret = gpio_pin_configure_dt(&switch_gpio0, GPIO_INPUT);
    if (ret < 0)
    {
        log_usb_message("ERR", "Error: switch config failed\n");
        return 1;
    }

    ret = gpio_pin_configure_dt(&switch_gpio1, GPIO_INPUT);
    if (ret < 0)
    {
        log_usb_message("ERR", "Error: switch config failed\n");
        return 1;
    }

    // Initialize OSZI GPIO for oscilloscope probe on PD3
    OSZI_GPIO_toggle.port = DEVICE_DT_GET(DT_NODELABEL(gpiod));
    if (!OSZI_GPIO_toggle.port)
    {
        (void) log_usb_message("ERR", "OSZI GPIO port device not found");
        return 1;
    }
    OSZI_GPIO_toggle.pin = 3;
    OSZI_GPIO_toggle.dt_flags = GPIO_ACTIVE_HIGH;

    ret = gpio_pin_configure_dt(&OSZI_GPIO_toggle, GPIO_OUTPUT_INACTIVE);
    if (ret < 0)
    {
        (void) log_usb_message("ERR", "OSZI GPIO config failed");
        return 1;
    }

    return 0;       // return 0 if initialization was successful and 1 if main needs to be stopped due to an error
}

/**
 * @brief Read the algorithm selection switch.
 *
 * @return True when the switch is asserted, otherwise false.
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
 * @brief Read the mode selection switch.
 *
 * @return True when the switch is asserted, otherwise false.
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
 * @brief Mark the test flow as requested from the button interrupt. (runs when button was pressed)
 *
 * The callback only sets the request flag; the main loop performs the actual
 * test work outside interrupt context.
 *
 * @param [in] dev GPIO device that triggered the callback.
 * @param [in] cb Registered GPIO callback context.
 * @param [in] pins Active pin mask.
 * @return None.
 */
void button_pressed(const struct device *dev,
                    struct gpio_callback *cb,
                    uint32_t pins)
{
    ARG_UNUSED(dev);
    ARG_UNUSED(cb);
    ARG_UNUSED(pins);

    atomic_set(&test_requested, 1);
}

/**
 * @brief Application entry point.
 *
 * Initializes the USB path and board devices, then waits for a button press or
 * startup trigger to run the selected test mode.
 *
 * @return 0 on normal exit or a negative errno value on failure.
 */
int main(void)
{
    int ret;
    char status[USB_MESSAGE_SIZE];
    enum test_algorithm algorithm;
    enum test_mode mode;

    ret = usb_init();
    if (ret != 0)
    {
        return ret;
    }

    ret = init_Devices();
    if (ret != 0)
    {
        log_usb_message("ERR", "Device initialization failed");
        return ret;
    }

    (void) log_usb_message("INFO", "BOARD_Test_START");

    while (true)
    {
        if (run_once_at_start || atomic_cas(&test_requested, 1, 0)) // Test runs when button is pressed or once at startup
        {
            if (!run_once_at_start)
            {
                log_usb_message("INFO", "Button pressed, continue testing...\n");
            }
            k_sleep(K_SECONDS(0.5));


            run_once_at_start = false;

            algorithm = get_selected_algorithm();   // read the switch states to determine which algorithm and test mode to run
            mode = get_selected_mode();

            if (snprintf(status, sizeof(status),
                    "SW0=%s, SW1=%s",
                    algorithm_name(algorithm),
                    (mode == TEST_MODE_BATCH) ? "BATCH" : "MANUAL") >= (int) sizeof(status))
            {
                return -ENOSPC;
            }

            (void) log_usb_message("INFO", status);

            if (mode == TEST_MODE_BATCH)
            {  // depending on the switch state, run either batch or manual test
                ret = run_batch_test(algorithm);
            }
            else
            {
                ret = run_manual_test(algorithm);
            }

            if (ret != 0)
            {
                char message[USB_MESSAGE_SIZE];

                if (snprintf(message, sizeof(message),
                        "Test execution failed (%d)", ret) >= (int) sizeof(message))
                {
                    return -ENOSPC;
                }

                (void) log_usb_message("ERR", message);
            }
        }

        k_sleep(K_SECONDS(1));
    }

    return 0;
}
