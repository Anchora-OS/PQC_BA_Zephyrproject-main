#include <stddef.h>
#include <zephyr/kernel.h>
#include <stdint.h>
#include <zephyr/sys/printk.h>
#include "USBcommunication.h"
#include <string.h>

// Small delay to keep USB prints stable on the host side.
#define SLEEP_TIME_MS 100

/**
 * @brief Send key, signature, and message payload over USB.
 *
 * Splits the formatted payload into labeled sections and streams them.
 *
 * @param[in] str Payload in the form pub@sig@msg
 */
void USB_send_key_and_signature(const char *str)
{
    k_msleep(SLEEP_TIME_MS);
    const size_t CHUNK_SIZE = 256;
    k_msleep(SLEEP_TIME_MS);

    if (str == NULL)
    {
        return;
    }

    // Find the field separators in the payload: pub@sig@msg.
    const char *sep1 = strchr(str, '@');
    if (!sep1)
    {
        // Fallback: send the whole line with a prefix.
        printk("@%s\n", str);
        return;
    }
    const char *sep2 = strchr(sep1 + 1, '@');
    if (!sep2)
    {
        // Malformed payload: send the whole line with a prefix.
        printk("@%s\n", str);
        return;
    }

    const char *pub_start = str;
    size_t pub_len = (size_t) (sep1 - pub_start);
    const char *sig_start = sep1 + 1;
    size_t sig_len = (size_t) (sep2 - sig_start);
    const char *msg_start = sep2 + 1;
    size_t msg_len = strlen(msg_start);

    // Stream each section with a label so the host can parse the payload.
    auto send_labeled = [&](const char *label, const char *data, size_t len)
    {
        size_t offset = 0;
        // Start marker for this field.
        printk("@%s\n", label);
        while (offset < len)
        {
            size_t to_send = (len - offset) > CHUNK_SIZE ? CHUNK_SIZE : (len - offset);
            printk("%.*s", (int) to_send, data + offset);
            offset += to_send;
            k_msleep(20);
        }
        // Ensure a clean end marker after each field.
        printk("\n@END_%s\n", label);
        k_msleep(10);
    };

    // Send public key, signature, and message separately with labels.
    send_labeled("PUB", pub_start, pub_len);
    send_labeled("SIG", sig_start, sig_len);
    send_labeled("MSG", msg_start, msg_len);

    // Final marker so the host knows the transfer is complete.
    printk("@END_ALL\n");


}

/**
 * @brief Send a plain text line over USB.
 *
 * Waits briefly and prints (sends) the provided string.
 *
 * @param[in] str Null-terminated text to send
 */
void USB_print(const char *str)
{
    k_msleep(SLEEP_TIME_MS);
    printk("%s\n", str);
}

/**
 * @brief Send structured CSV data over USB.
 *
 * Wraps the payload in start/stop markers and streams it in chunks.
 *
 * @param[in] str CSV text with embedded newlines
 */
void USB_send_structured_data(const char *str)
{
    const size_t CHUNK_SIZE = 256;
    size_t len = strlen(str);
    size_t offset = 0;

    // Send start delimiter.
    k_msleep(SLEEP_TIME_MS);
    printk("#start#\n");

    // Stream the CSV payload in chunks to avoid long single USB transfers.
    while (offset < len)
    {
        size_t to_send = (len - offset) > CHUNK_SIZE ? CHUNK_SIZE : (len - offset);
        printk("%.*s", (int) to_send, str + offset);
        offset += to_send;
        k_msleep(20); // Short pause between chunks for stability
    }

    // Ensure newline before stop delimiter and send stop.
    printk("\n#stop#\n");
}