/*******    Disclaimer *******************************

Parts of the GPIO initialization and interrupt
handling implementation are based on and adapted 
from the Zephyr Project GPIO sample applications 
and documentation, including the “Blinky” and 
“Button Interrupt” examples. The code has been 
modified and extended for the purposes of this project.
Source:
https://docs.zephyrproject.org/latest/samples/index.html

******************************************************/

#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/printk.h>

#define SLEEP_TIME_MS 1000

/* Devicetree aliases */
#define LED0_NODE DT_ALIAS(led0)
#define LED1_NODE DT_ALIAS(led1)
#define BUTTON_NODE DT_ALIAS(t3)

/* Safety checks */
#if !DT_NODE_HAS_STATUS(LED0_NODE, okay)
#error "No led0 alias found"
#endif

#if !DT_NODE_HAS_STATUS(LED1_NODE, okay)
#error "No led1 alias found"
#endif

#if !DT_NODE_HAS_STATUS(BUTTON_NODE, okay)
#error "No button (sw0) alias found"
#endif

/* GPIO specs */
static const struct gpio_dt_spec led0 = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
static const struct gpio_dt_spec led1 = GPIO_DT_SPEC_GET(LED1_NODE, gpios);
static const struct gpio_dt_spec button = GPIO_DT_SPEC_GET(BUTTON_NODE, gpios);

static struct gpio_callback button_cb_data;

/* Button interrupt handler */
void button_pressed(const struct device *dev,
                    struct gpio_callback *cb,
                    uint32_t pins)
{
    /* Read button state and mirror it to LED1 */
    int val = gpio_pin_get_dt(&button);
    gpio_pin_set_dt(&led1, val);
}

int main(void)
{
    int ret;

    /* Check devices */
    if (!gpio_is_ready_dt(&led0) ||
        !gpio_is_ready_dt(&led1) ||
        !gpio_is_ready_dt(&button)) {
        printk("Error: device not ready\n");
        return 0;
    }

    /* Configure LED0 (blinking) */
    gpio_pin_configure_dt(&led0, GPIO_OUTPUT_ACTIVE);

    /* Configure LED1 (controlled by button) */
    gpio_pin_configure_dt(&led1, GPIO_OUTPUT_INACTIVE);

    /* Configure button */
    ret = gpio_pin_configure_dt(&button, GPIO_INPUT);
    if (ret < 0) {
        printk("Error: button config failed\n");
        return 0;
    }

    /* Enable interrupt on button */
    ret = gpio_pin_interrupt_configure_dt(&button, GPIO_INT_EDGE_BOTH);
    if (ret < 0) {
        printk("Error: interrupt config failed\n");
        return 0;
    }

    gpio_init_callback(&button_cb_data, button_pressed, BIT(button.pin));
    gpio_add_callback(button.port, &button_cb_data);

    printk("Blinky + button control started!\n");

    while (1) {
        gpio_pin_toggle_dt(&led0);
        k_msleep(SLEEP_TIME_MS);
    }

    return 0;
}
