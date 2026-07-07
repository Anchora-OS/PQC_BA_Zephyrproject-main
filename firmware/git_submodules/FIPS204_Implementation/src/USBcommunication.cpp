#include <stddef.h>
#include <zephyr/kernel.h>
#include <stdint.h>
#include <zephyr/sys/printk.h>
#include "USBcommunication.h"

#define SLEEP_TIME_MS 100 // to make usb communication more stable


/**
 * @brief Send the key/signature/message payload over USB.
 *
 * Splits the combined payload into labeled sections so the host can parse and
 * verify each field separately while keeping the transfer text-based.
 * start and end markers for each field for hostside delimitation and parsing.
 *
 * @param [in] str Combined payload in the form pub@sig@msg.
 * @return None.
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

    // Locate the field separators so the payload can be split into labeled
    // chunks without changing the underlying content.
    const char *sep1 = strchr(str, '@');
    if (!sep1)
    {
        // Fallback path: send the whole payload with a single prefix.
        printk("@%s\n", str);
        return;
    }
    const char *sep2 = strchr(sep1 + 1, '@');
    if (!sep2)
    {
        // Same fallback when the payload is malformed and only contains one separator.
        printk("@%s\n", str);
        return;
    }

    const char *pub_start = str;
    size_t pub_len = (size_t) (sep1 - pub_start);
    const char *sig_start = sep1 + 1;
    size_t sig_len = (size_t) (sep2 - sig_start);
    const char *msg_start = sep2 + 1;
    size_t msg_len = strlen(msg_start);

    auto send_labeled = [&](const char *label, const char *data, size_t len)
    {
        size_t offset = 0;
        // Emit a start marker so the receiver knows which logical field follows.
        printk("@%s\n", label);
        while (offset < len)
        {
            size_t to_send = (len - offset) > CHUNK_SIZE ? CHUNK_SIZE : (len - offset);
            printk("%.*s", (int) to_send, data + offset);
            offset += to_send;
            k_msleep(20);
        }
        // Close each field with an explicit end marker to keep parsing simple.
        printk("\n@END_%s\n", label);
        k_msleep(10);
    };

    // Send the three logical fields in a fixed order so the host can map them
    // back to the correct verification inputs.
    send_labeled("PUB", pub_start, pub_len);
    send_labeled("SIG", sig_start, sig_len);
    send_labeled("MSG", msg_start, msg_len);

    // Final marker for the end of the combined payload.
    printk("@END_ALL\n");
}

/**
 * @brief Send a text line (Char array) to the USB host.
 *
 * Adds a small delay before the send so short log bursts do not overrun the
 * host-side capture rate.
 *
 * @param [in] str Null-terminated string to print.
 * @return None.
 */
void USB_print(const char *str)
{
    k_msleep(SLEEP_TIME_MS);
    printk("%s\n", str);
}


/**
 * @brief Send structured CSV test results over USB.
 *
 * Delimits the payload so the host can capture the full CSV block without
 * mixing it with normal log output.
 * uses #start# and #stop# markers to indicate the beginning and end of the structured payload
 *
 * @param [in] str Null-terminated CSV text with embedded newlines preserved.
 * @return None.
 */
void USB_send_structured_data(const char *str)
{
    const size_t CHUNK_SIZE = 256;
    size_t len = strlen(str);
    size_t offset = 0;

    // Mark the beginning of the structured payload.
    k_msleep(SLEEP_TIME_MS);
    printk("#start#\n");

    // Stream in chunks so the transport stays responsive on slower links.
    while (offset < len)
    {
        size_t to_send = (len - offset) > CHUNK_SIZE ? CHUNK_SIZE : (len - offset);
        printk("%.*s", (int) to_send, str + offset);
        offset += to_send;
        k_msleep(20); // Short pause between chunks for stability
    }

    // Close the payload cleanly so the receiver can stop reading at once.
    printk("\n#stop#\n");
}