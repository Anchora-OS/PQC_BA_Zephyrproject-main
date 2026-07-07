#ifndef USBCOMMUNICATION_H
#define USBCOMMUNICATION_H

/**
 * @brief Send a packed payload containing public key, signature and message.
 *
 * The payload format is "base64(pub)@base64(sig)@base64(msg)"; the
 * receiver splits on '@' and decodes each field.
 *
 * @param[in] str Payload string in the described format
 */
void USB_send_key_and_signature(const char *str);

/**
 * @brief Send a single line of text over USB.
 *
 * @param[in] str Null-terminated string to send
 */
void USB_print(const char *str);

/**
 * @brief Send structured CSV data over USB wrapped with start/stop markers.
 *
 * @param[in] str CSV text with embedded newlines
 */
void USB_send_structured_data(const char *str);

#endif
