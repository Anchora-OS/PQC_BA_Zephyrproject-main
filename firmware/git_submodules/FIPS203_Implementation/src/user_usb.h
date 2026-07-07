#ifndef USER_USB_H_
#define USER_USB_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <zephyr/kernel.h>

/**
 * @brief Initialize the USB transport layer.
 *
 * Sets up the CDC/ACM path and prepares the helper layer for later sends and
 * receives.
 *
 * @return 0 on success or a negative errno value on failure.
 */
int usb_init(void);

/**
 * @brief Check whether the host connection is active.
 *
 * @return True when the USB DTR state is asserted, otherwise false.
 */
bool usb_is_connected(void);

/**
 * @brief Send a raw byte buffer through USB.
 *
 * @param [in] data Byte buffer to transmit.
 * @param [in] len Number of bytes to send.
 * @return Number of bytes written on success or a negative errno value.
 */
int user_usb_send(const uint8_t *data, size_t len);

/**
 * @brief Send a null-terminated string through USB.
 *
 * @param [in] str Text to transmit.
 * @return 0 or a positive byte count on success, negative errno on failure.
 */
int usb_send_str(const char *str);

/**
 * @brief Send a human-readable tagged line.
 *
 * @param [in] tag Short category prefix.
 * @param [in] message Message body to transmit.
 * @return 0 on success or a negative errno value on failure.
 */
int usb_send_text_line(const char *tag, const char *message);

/**
 * @brief Send a labeled 32-bit unsigned integer as a key/value pair.
 *
 * The helper formats the label and value in a stable textual representation
 * suitable for logging over the USB transport.
 *
 * @param [in] label Short textual key identifying the value.
 * @param [in] value 32-bit unsigned integer to transmit.
 * @return 0 on success or a negative errno value on failure.
 */
int usb_send_kv_u32(const char *label, uint32_t value);

/**
 * @brief Send a raw C-string as data over USB.
 *
 * Convenience wrapper that transmits the nul-terminated `data` buffer.
 *
 * @param [in] data NUL-terminated string to send.
 * @return 0 on success or a negative errno value on failure.
 */
int usb_send_data(const char *data);

/**
 * @brief Send a log record with the standard USB log prefix.
 *
 * @param [in] log Log message text.
 * @return 0 on success or a negative errno value on failure.
 */
int usb_send_log(const char *log);

/**
 * @brief Send comma-separated values (CSV) text over USB.
 *
 * Used for machine-parsable measurements and bench output.
 *
 * @param [in] csv_data CSV line to transmit (NUL-terminated).
 * @return 0 on success or a negative errno value on failure.
 */
int usb_send_csv(const char *csv_data);

/**
 * @brief Try to read available bytes from the USB receive buffer without blocking.
 *
 * Copies up to `out_size` bytes into `out`. If no data is available the
 * function returns immediately with an appropriate status code.
 *
 * @param [out] out Destination buffer for received bytes.
 * @param [in] out_size Size of the destination buffer in bytes.
 * @param [out] out_len Number of bytes written into `out` on success.
 * @return 0 on success, 0 with `out_len==0` if no data available, or a negative
 * errno value on error.
 */
int usb_receive_try(uint8_t *out, size_t out_size, size_t *out_len);

/**
 * @brief Wait for one buffered USB line.
 *
 * @param [out] out Destination buffer.
 * @param [in] out_size Destination buffer size in bytes.
 * @param [out] out_len Number of bytes copied into out.
 * @param [in] timeout Maximum wait duration.
 * @return 0 on success or a negative errno value on failure / timeout.
 */
int usb_receive_wait(uint8_t *out,
                     size_t out_size,
                     size_t *out_len,
                     k_timeout_t timeout);

/**
 * @brief Entry point for the USB worker thread.
 *
 * This function conforms to the Zephyr thread entry prototype and is used to
 * run the USB processing loop when the worker thread is started.
 *
 * @param p1 Unused; reserved for Zephyr thread API.
 * @param p2 Unused; reserved for Zephyr thread API.
 * @param p3 Unused; reserved for Zephyr thread API.
 */
void usb_entry(void *p1, void *p2, void *p3);

#endif /* USER_USB_H_ */
