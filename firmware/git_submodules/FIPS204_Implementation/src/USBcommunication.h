#ifndef USBCOMMUNICATION_H
#define USBCOMMUNICATION_H

/**
 * @brief Send a combined payload containing public key, signature and message.
 *
 * The expected format is: base64(pub)@base64(sig)@base64(message). The
 * implementation splits and transmits labeled chunks so the host can parse
 * and verify each part independently.
 *
 * @param [in] str Null-terminated combined payload string.
 */
void USB_send_key_and_signature(const char *str);

/**
 * @brief Print a log line to the USB console.
 *
 * Adds a small delay for transport stability; intended for human-readable
 * diagnostic messages.
 *
 * @param [in] str Null-terminated string to print.
 */
void USB_print(const char *str);

/**
 * @brief Send structured CSV data over USB.
 *
 * The function wraps the provided CSV payload with start/stop markers so the
 * receiver can capture the block atomically.
 *
 * @param [in] str Null-terminated CSV text (may contain newlines).
 */
void USB_send_structured_data(const char *str);

#endif
