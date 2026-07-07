/*------------------------------------------------------------------------------------
Parts of the USB communication and device support implementation (mainly this file) 
used in this implmentation are based on software originally developed by the Institute 
of Embedded Systems (InES) at ZHAW. The original copyright notices and disclaimer 
statements have been preserved below. The incorporated code has been modified and 
extended within the scope of this work and now serves as 
the foundation for the CDC ACM USB communication.

Hofer Levin & Wyss Julien 29.05.2026
------------------------------------------------------------------------------------*/





/********************************************************************************
 *  _____       ______   ____
 * |_   _|     |  ____|/ ____|  Institute of Embedded Systems
 *   | |  _ __ | |__  | (___    Zurich University of Applied Sciences
 *   | | | '_ \|  __|  \___ \   8401 Winterthur, Switzerland
 *  _| |_| | | | |____ ____) |
 * |_____|_| |_|______|_____/
 *  
 *******************************************************************************
 *
 * Copyright (c) 2022, Institute Of Embedded Systems at Zurich University
 * of Applied Sciences. All rights reserved.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *******************************************************************************
 * Zephyr application to test the user USB.
 * - 
 * 
 * 17.04.2026, frtt@zhaw.ch
 ******************************************************************************/

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/usb/usbd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <zephyr/logging/log.h>
#include "zephyr/usb/usbd_msg.h"

#include "user_usb.h"




/*******************************************************************************
 * Logging
 ******************************************************************************/
LOG_MODULE_REGISTER( user_usb, CONFIG_LOG_DEFAULT_LEVEL );


/*******************************************************************************
 * Defines
 ******************************************************************************/
#define ZEPHYR_PROJECT_USB_VID  0x2fe3
#define BUF_SIZE 512
#define RX_LINE_BUFFER_SIZE 512

#define USBD_PID            0x0001
#define USBD_MANUFACTURER   "Zephyr Project"
#define USBD_PRODUCT        "USBD"
#define USBD_MAX_POWER      125
#define USBD_CLASS_CDC_ACM  "cdc_acm_0"

/*******************************************************************************
 * struct
 ******************************************************************************/
typedef struct
{
    struct ring_buf rb;
    uint8_t ring_buffer[BUF_SIZE];
} ring_buf_t;

static ring_buf_t rx;

const struct device *const uart_dev = DEVICE_DT_GET(DT_NODELABEL(cdc_acm_uart0));


/*******************************************************************************
 * local var
 ******************************************************************************/
static bool rx_throttled;
static atomic_t usb_initialized;

static atomic_t usb_connected;

K_SEM_DEFINE( dtr_sem, 0, 1 );


/*******************************************************************************
 * instantiation
 ******************************************************************************/
USBD_DEVICE_DEFINE( usbd,
                    DEVICE_DT_GET( DT_NODELABEL( zephyr_udc0 ) ),
                    ZEPHYR_PROJECT_USB_VID,
                    USBD_PID );

USBD_DESC_LANG_DEFINE( sample_lang );
USBD_DESC_MANUFACTURER_DEFINE( sample_mfr, USBD_MANUFACTURER );
USBD_DESC_PRODUCT_DEFINE( sample_product, USBD_PRODUCT );
IF_ENABLED( CONFIG_HWINFO, ( USBD_DESC_SERIAL_NUMBER_DEFINE( sample_sn ) ) );

USBD_DESC_CONFIG_DEFINE( fs_cfg_desc, "FS Configuration" );
USBD_DESC_CONFIG_DEFINE( hs_cfg_desc, "HS Configuration" );

static const uint8_t attributes = USB_SCD_SELF_POWERED;

static K_MUTEX_DEFINE( rx_mutex );
static K_MUTEX_DEFINE( tx_mutex );

static int user_usb_setup( const struct device* uart_dev );

/* Full speed configuration */
USBD_CONFIGURATION_DEFINE( fs_config,
                           attributes,
                           USBD_MAX_POWER,
                           &fs_cfg_desc);

/* High speed configuration */
USBD_CONFIGURATION_DEFINE( hs_config,
                           attributes,
                           USBD_MAX_POWER,
                           &hs_cfg_desc );


/*******************************************************************************
 * print baudrate
 ******************************************************************************/
static int add_config_and_classes( struct usbd_context *ctx,
                                   enum usbd_speed speed,
                                   struct usbd_config_node* cfg )
{
    int err;

    err = usbd_add_configuration( ctx, speed, cfg );
    if( err )
    {
        (void)usb_send_text_line("ERR", "Failed to add Speed configuration");
        return err;
    }

    err = usbd_register_class( ctx, USBD_CLASS_CDC_ACM, speed, 1 );
    if( err )
    {
        (void)usb_send_text_line("ERR", "Failed to add register classes");
        return err;
    }

    return 0;
}


/*******************************************************************************
 * print baudrate
 ******************************************************************************/
struct usbd_context* usbd_setup_device( usbd_msg_cb_t msg_cb  )
{
	int err;

	/* doc add string descriptor start */
	err = usbd_add_descriptor( &usbd, &sample_lang );
    if( err )
    {
        char buf[128];
        (void)snprintf(buf, sizeof(buf), "Failed to initialize language descriptor (%d)", err);
        (void)usb_send_text_line("ERR", buf);
        return NULL;
    }

	err = usbd_add_descriptor( &usbd, &sample_mfr );
    if( err )
    {
        char buf[128];
        (void)snprintf(buf, sizeof(buf), "Failed to initialize manufacturer descriptor (%d)", err);
        (void)usb_send_text_line("ERR", buf);
        return NULL;
    }

	err = usbd_add_descriptor( &usbd, &sample_product );
    if( err )
    {
        char buf[128];
        (void)snprintf(buf, sizeof(buf), "Failed to initialize product descriptor (%d)", err);
        (void)usb_send_text_line("ERR", buf);
        return NULL;
    }

	IF_ENABLED( CONFIG_HWINFO, (
		        err = usbd_add_descriptor( &usbd, &sample_sn );
	))
    if( err )
    {
        char buf[128];
        (void)snprintf(buf, sizeof(buf), "Failed to initialize SN descriptor (%d)", err);
        (void)usb_send_text_line("ERR", buf);
        return NULL;
    }
	/* doc add string descriptor end */

	if( USBD_SUPPORTS_HIGH_SPEED &&
	    usbd_caps_speed( &usbd ) == USBD_SPEED_HS )
    {
        add_config_and_classes( &usbd, USBD_SPEED_HS, &hs_config );

        usbd_device_set_code_triple( &usbd, USBD_SPEED_HS,
		                             USB_BCC_MISCELLANEOUS,
                                     0x02,
                                     0x01 );

	}

    add_config_and_classes( &usbd, USBD_SPEED_FS, &fs_config );

    usbd_device_set_code_triple( &usbd, USBD_SPEED_FS,
		                             USB_BCC_MISCELLANEOUS,
                                     0x02,
                                     0x01 );

	usbd_self_powered( &usbd, attributes & USB_SCD_SELF_POWERED );

	if( msg_cb != NULL )
    {
		/* doc device init-and-msg start */
		err = usbd_msg_register_cb(&usbd, msg_cb);
        if (err) {
            (void)usb_send_text_line("ERR", "Failed to register message callback");
            return NULL;
        }
		/* doc device init-and-msg end */
	}

	return &usbd;
}


/*******************************************************************************
 * usb init device
 ******************************************************************************/
struct usbd_context *usbd_init_device( usbd_msg_cb_t msg_cb )
{
	int err;

	if( usbd_setup_device( msg_cb ) == NULL )
    {
		return NULL;
	}

	/* doc device init start */
	err = usbd_init( &usbd );
    if( err )
    {
        (void)usb_send_text_line("ERR", "Failed to initialize device support");
        return NULL;
    }
	/* doc device init end */

	return &usbd;
}


/**
 * @brief Report the current UART baudrate over USB.
 *
 * @param [in] dev UART device used for the query.
 * @return None.
 */
static inline void print_baudrate( const struct device *dev )
{
	uint32_t baudrate;
	int ret;

	ret = uart_line_ctrl_get( dev, UART_LINE_CTRL_BAUD_RATE, &baudrate );
    if (ret) {
        char buf[128];
        (void)snprintf(buf, sizeof(buf), "Failed to get baudrate, ret code %d", ret);
        (void)usb_send_text_line("WARN", buf);
    } else {
        char buf[64];
        (void)snprintf(buf, sizeof(buf), "Baudrate %u", baudrate);
        (void)usb_send_text_line("INFO", buf);
    }
}


/**
 * @brief Handle USB device and connection state changes.
 *
 * Tracks bus power, DTR state, and line coding updates so the helper layer
 * can expose a simple connection state to the application.
 *
 * @param [in] ctx USB device context.
 * @param [in] msg USB message event.
 * @return None.
 */
static void msg_cb( struct usbd_context *const ctx, const struct usbd_msg* msg )
{
    {
        char buf[128];
        (void)snprintf(buf, sizeof(buf), "USBD message: %s", usbd_msg_type_string( msg->type ));
        (void)usb_send_text_line("INFO", buf);
    }

    if( usbd_can_detect_vbus( ctx ) )
    {
        if( msg->type == USBD_MSG_VBUS_READY )
        {
                        if( usbd_enable( ctx ) )
                        {
                            (void)usb_send_text_line("ERR", "Failed to enable device support");
                        }
        }

        if( msg->type == USBD_MSG_VBUS_REMOVED )
        {
                        if( usbd_disable( ctx ) )
                        {
                            (void)usb_send_text_line("ERR", "Failed to disable device support");
                        }
        }
    }

    if( msg->type == USBD_MSG_CDC_ACM_CONTROL_LINE_STATE )
    {
        uint32_t dtr = 0U;

        uart_line_ctrl_get( msg->dev, UART_LINE_CTRL_DTR, &dtr );
        if(dtr)
        {
            atomic_set( &usb_connected, 1 );
            (void)usb_send_text_line("INFO", "USB connected (DTR set)");
            k_sem_give( &dtr_sem );
        }
        else
        {
            atomic_set( &usb_connected, 0 );
            (void)usb_send_text_line("INFO", "USB disconnected (DTR cleared)");
        }
    }

    if( msg->type == USBD_MSG_CDC_ACM_LINE_CODING )
    {
        print_baudrate( msg->dev );
    }
}


/**
 * @brief Move UART data into the USB receive buffer.
 *
 * The handler keeps the circular buffer fed and throttles RX when the buffer
 * becomes full.
 *
 * @param [in] dev UART device instance.
 * @param [in] user_data Unused callback context.
 * @return None.
 */
static void interrupt_handler( const struct device* dev, void* user_data )
{
    ARG_UNUSED( user_data );

    while( uart_irq_update( dev ) && uart_irq_is_pending( dev ) )
    {
        if( !rx_throttled && uart_irq_rx_ready( dev ) )
        {
            int recv_len, rb_len;
            uint8_t buffer[BUF_SIZE];

            size_t len = MIN( ring_buf_space_get( &rx.rb ), BUF_SIZE );

            if( len == 0 )
            {
                /* Throttle because ring buffer is full */
                uart_irq_rx_disable( dev );
                rx_throttled = true;
                continue;
            }

            recv_len = uart_fifo_read( dev, buffer, len );
            if( recv_len < 0 )
            {
                (void)usb_send_text_line("ERR", "Failed to read UART_FIFO");
                recv_len = 0;
            }

            rb_len = ring_buf_put( &rx.rb, buffer, recv_len );
            if( rb_len < recv_len )
            {
                char buf[64];
                (void)snprintf(buf, sizeof(buf), "Drop %u bytes", recv_len - rb_len);
                (void)usb_send_text_line("WARN", buf);
            }

            {
                char buf[64];
                (void)snprintf(buf, sizeof(buf), "tty_fifo -> ringbuf %d bytes", rb_len);
                (void)usb_send_text_line("DBG", buf);
            }
        }

        if( uart_irq_tx_ready( dev ) )
        {
            if( rx_throttled )
            {
                uart_irq_rx_enable( dev );
                rx_throttled = false;
            }
            uart_irq_tx_disable(dev);
            break;
        }
    }
}


/**
 * @brief Initialize the USB helper state.
 *
 * Sets up the transport once and marks it ready for later send and receive
 * operations.
 *
 * @return 0 on success or a negative errno value on failure.
 */
int usb_init(void)
{
    int ret;

    if (atomic_get(&usb_initialized))
    {
        return 0;
    }

    ret = user_usb_setup(uart_dev);
    if (ret == 0)
    {
        atomic_set(&usb_initialized, 1);
    }

    return ret;
}


/**
 * @brief Send raw bytes over the active USB connection.
 *
 * @param [in] data Byte buffer to transmit.
 * @param [in] len Number of bytes to send.
 * @return Number of bytes written on success or a negative errno value.
 */
int user_usb_send(const uint8_t *data, size_t len)
{
    if (data == NULL || len == 0)
    {
        return -EINVAL;
    }

    if (!atomic_get(&usb_initialized))
    {
        return -EACCES;
    }

    if (!usb_is_connected())
    {
        return -ENOTCONN;
    }

    /* Small delay to stabilize USB CDC output before sending data. */
    k_sleep(K_MSEC(10));

    k_mutex_lock(&tx_mutex, K_FOREVER);

    for (size_t i = 0; i < len; i++)
    {
        uart_poll_out(uart_dev, data[i]);
    }

    k_mutex_unlock(&tx_mutex);
    return (int)len;
}


/**
 * @brief Send a null-terminated string over USB.
 *
 * @param [in] str Text to transmit.
 * @return 0 or a positive byte count on success, negative errno on failure.
 */
int usb_send_str(const char *str)
{
    size_t len;

    if (str == NULL)
    {
        return -EINVAL;
    }

    len = strlen(str);
    return user_usb_send((const uint8_t *)str, len);
}

/**
 * @brief Send a tagged human-readable USB line.
 *
 * @param [in] tag Log prefix used by the caller.
 * @param [in] message Message text to transmit.
 * @return 0 on success or a negative errno value on failure.
 */
int usb_send_text_line(const char *tag, const char *message)
{
    char buffer[128];

    if (tag == NULL) {
        tag = "APP";
    }

    if (message == NULL) {
        message = "";
    }

    if (snprintf(buffer, sizeof(buffer), "%s: %s", tag, message) >= (int)sizeof(buffer)) {
        return -ENOSPC;
    }

    return usb_send_log(buffer);
}

int usb_send_kv_u32(const char *label, uint32_t value)
{
    char buffer[128];

    if (label == NULL) {
        label = "VALUE";
    }

    if (snprintf(buffer, sizeof(buffer), "%s=%lu", label, (unsigned long)value) >= (int)sizeof(buffer)) {
        return -ENOSPC;
    }

    return usb_send_data(buffer);
}


int usb_send_data(const char *data)
{
    const char prefix[] = "@";
    int ret;

    if (data == NULL)
    {
        return -EINVAL;
    }

    ret = usb_send_str(prefix);
    if (ret < 0)
    {
        return ret;
    }

    ret = usb_send_str(data);
    if (ret < 0)
    {
        return ret;
    }

    return usb_send_str("\r\n");
}


/**
 * @brief Send a log record over USB.
 *
 * @param [in] log Log message text.
 * @return 0 on success or a negative errno value on failure.
 */
int usb_send_log(const char *log)
{
    const char prefix[] = "[log] ";
    int ret;

    if (log == NULL)
    {
        return -EINVAL;
    }

    ret = usb_send_str(prefix);
    if (ret < 0)
    {
        return ret;
    }

    ret = usb_send_str(log);
    if (ret < 0)
    {
        return ret;
    }

    return usb_send_str("\r\n");
}


/**
 * usb_send_csv - Send CSV data wrapped in #start# and #stop# markers
 * 
 * Streams the CSV payload in chunks to avoid long single USB transfers
 * and prevent buffer overflow. Each chunk has a delay to allow USB flushing.
 * 
 * Format:
 *   #start#
 *   [csv_data in chunks]
 *   #stop#
 */
int usb_send_csv(const char *csv_data)
{
    const size_t CHUNK_SIZE = 256;
    int ret;

    if (csv_data == NULL)
    {
        return -EINVAL;
    }

    /* Send start delimiter */
    k_sleep(K_MSEC(20));
    ret = usb_send_str("#start#\r\n");
    if (ret < 0)
    {
        return ret;
    }

    /* Stream the CSV payload in chunks to avoid long transfers */
    size_t len = strlen(csv_data);
    size_t offset = 0;

    while (offset < len) {
        size_t to_send = (len - offset) > CHUNK_SIZE ? CHUNK_SIZE : (len - offset);
        ret = user_usb_send((const uint8_t *)(csv_data + offset), to_send);
        if (ret < 0) {
            return ret;
        }
        offset += to_send;
        k_sleep(K_MSEC(20)); /* short pause between chunks */
    }

    /* Send stop delimiter */
    ret = usb_send_str("\r\n#stop#\r\n");
    if (ret < 0)
    {
        return ret;
    }

    k_sleep(K_MSEC(20));
    return 0;
}


int usb_receive_try(uint8_t *out, size_t out_size, size_t *out_len)
{
    uint8_t tmp[RX_LINE_BUFFER_SIZE];
    uint32_t available;
    uint32_t pulled;
    size_t copy_len = 0;
    bool found_line = false;

    if (out == NULL || out_len == NULL || out_size == 0)
    {
        return -EINVAL;
    }

    *out_len = 0;

    if (!atomic_get(&usb_initialized))
    {
        return -EACCES;
    }

    available = ring_buf_size_get(&rx.rb);
    if (available == 0)
    {
        return -EAGAIN;
    }

    pulled = ring_buf_get(&rx.rb, tmp, MIN(available, (uint32_t)sizeof(tmp)));
    for (uint32_t i = 0; i < pulled; i++)
    {
        if (tmp[i] == '\n')
        {
            copy_len = i + 1;
            found_line = true;
            break;
        }
    }

    if (!found_line)
    {
        copy_len = pulled;
    }

    if (copy_len > out_size)
    {
        copy_len = out_size;
    }

    memcpy(out, tmp, copy_len);
    *out_len = copy_len;

    if (pulled > copy_len)
    {
        (void)ring_buf_put(&rx.rb, &tmp[copy_len], pulled - copy_len);
    }

    if (rx_throttled && ring_buf_space_get(&rx.rb) > 0U)
    {
        uart_irq_rx_enable(uart_dev);
        rx_throttled = false;
    }
    return 0;
}


/**
 * @brief Wait for one buffered USB line.
 *
 * @param [out] out Destination buffer.
 * @param [in] out_size Destination buffer size in bytes.
 * @param [out] out_len Number of bytes copied into out.
 * @param [in] timeout Maximum wait duration.
 * @return 0 on success or a negative errno value on timeout / failure.
 */
int usb_receive_wait(uint8_t *out,
                     size_t out_size,
                     size_t *out_len,
                     k_timeout_t timeout)
{
    int64_t end_ms = k_uptime_get() + k_ticks_to_ms_floor64(timeout.ticks);

    while (1)
    {
        int ret = usb_receive_try(out, out_size, out_len);
        if (ret == 0)
        {
            return 0;
        }

        if (ret != -EAGAIN)
        {
            return ret;
        }

        if (K_TIMEOUT_EQ(timeout, K_NO_WAIT))
        {
            return -EAGAIN;
        }

        if (K_TIMEOUT_EQ(timeout, K_FOREVER))
        {
            k_msleep(10);
            continue;
        }

        if (k_uptime_get() >= end_ms)
        {
            return -EAGAIN;
        }

        k_msleep(10);
    }
}


/******************************************************************************
 * setup
 ******************************************************************************/
static int user_usb_setup( const struct device* uart_dev )
{
    int ret;

    if( !device_is_ready( uart_dev ) )
    {
        (void)usb_send_text_line("ERR", "CDC ACM device not ready");
        return -ENODEV;
    }

    struct usbd_context* ctx = usbd_init_device( msg_cb );
    if( ctx == NULL )
    {
        (void)usb_send_text_line("ERR", "Failed to initialize USB device");
        return -ENODEV;
    }

    if( !usbd_can_detect_vbus( ctx ) )
    {
        ret = usbd_enable( ctx );
        if( ret )
        {
            (void)usb_send_text_line("ERR", "Failed to enable device support");
            return ret;
        }
    }

    (void)usb_send_text_line("WARN", "USB device support enabled");

    ring_buf_init( &rx.rb, BUF_SIZE, rx.ring_buffer );

    uart_irq_callback_set( uart_dev, interrupt_handler );
    uart_irq_rx_enable( uart_dev );

    (void)usb_send_text_line("WARN", "Wait for DTR");
    k_sem_take( &dtr_sem, K_FOREVER );
    (void)usb_send_text_line("INFO", "DTR set");

    k_msleep( 100 );

    return 0;
}


/******************************************************************************
 * USER USB Thread
 ******************************************************************************/
void user_usb_thread( void )
{
    int ret;

    ret = usb_init();
    if (ret != 0)
    {
        char buf[64];
        (void)snprintf(buf, sizeof(buf), "USB init failed (%d)", ret);
        (void)usb_send_text_line("ERR", buf);
        return;
    }

    while( 1 )
    {
        k_msleep( 1000 );
    }
}


/******************************************************************************
 * Thread entry functions
 ******************************************************************************/
bool usb_is_connected(void)
{
    return atomic_get(&usb_connected) != 0;
}


/**
 * @brief Thread entry wrapper for the USB service thread.
 *
 * @param [in] p1 Unused thread parameter.
 * @param [in] p2 Unused thread parameter.
 * @param [in] p3 Unused thread parameter.
 * @return None.
 */
void usb_entry( void* p1, void* p2, void* p3 )
{
    ARG_UNUSED( p1 );
    ARG_UNUSED( p2 );
    ARG_UNUSED( p3 );

    user_usb_thread();
}
