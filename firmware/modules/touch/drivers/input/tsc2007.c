#define DT_DRV_COMPAT ti_tsc2007

#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/input/input.h>
#include <zephyr/input/input_touch.h>

#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(tsc2007, CONFIG_INPUT_LOG_LEVEL);

#define TS_POLL_PERIOD      10 /* ms */

/* converter function */
#define TSC2007_MEASURE_TEMP_0          (0x0 << 4)
#define TSC2007_MEASURE_AUX             (0x2 << 4)
#define TSC2007_MEASURE_TEMP_1          (0x4 << 4)
#define TSC2007_ACTIVATE_X_DRIVERS      (0x8 << 4)
#define TSC2007_ACTIVATE_Y_DRIVERS      (0x9 << 4)
#define TSC2007_ACTIVATE_YP_XN_DRIVERS  (0xa << 4)
#define TSC2007_SETUP_COMMAND           (0xb << 4)
#define TSC2007_MEASURE_X_POSITION      (0xc << 4)
#define TSC2007_MEASURE_Y_POSITION      (0xd << 4)
#define TSC2007_MEASURE_Z1_POSITION     (0xe << 4)
#define TSC2007_MEASURE_Z2_POSITION     (0xf << 4)

/* power modes */
#define TSC2007_POWER_DOWN_IRQ_EN       (0x0 << 2)
#define TSC2007_ADC_ON_IRQ_DISABLED0    (0x1 << 2)
#define TSC2007_ADC_OFF_IRQ_ENABLED     (0x2 << 2)
#define TSC2007_ADC_ON_IRQ_DISABLED1    (0x3 << 2)

/* resolution */
#define TSC2007_12BIT                   (0x0 << 1)
#define TSC2007_8BIT                    (0x1 << 1)

#define MAX_12BIT                       ((1 << 12) - 1)

#define ADC_ON_12BIT    (TSC2007_12BIT | TSC2007_ADC_ON_IRQ_DISABLED0)

static const uint8_t read_x = (ADC_ON_12BIT | TSC2007_MEASURE_X_POSITION);
static const uint8_t read_y = (ADC_ON_12BIT | TSC2007_MEASURE_Y_POSITION);
static const uint8_t read_z1 = (ADC_ON_12BIT | TSC2007_MEASURE_Z1_POSITION);
static const uint8_t read_z2 = (ADC_ON_12BIT | TSC2007_MEASURE_Z2_POSITION);

static const uint8_t pwrdown = (TSC2007_12BIT | TSC2007_POWER_DOWN_IRQ_EN);
static const uint8_t setup_command = (TSC2007_SETUP_COMMAND |
                                      TSC2007_POWER_DOWN_IRQ_EN |
                                      TSC2007_12BIT);

/* Touch Event */
struct ts_event {
    uint16_t x;
    uint16_t y;
    uint16_t z1;
    uint16_t z2;
};

struct tsc2007_config 
{
    struct input_touchscreen_common_config common;
    struct i2c_dt_spec bus;
    struct gpio_dt_spec int_gpio;
    int raw_x_min;
    int raw_y_min;
    uint16_t raw_x_max;
    uint16_t raw_y_max;
};

struct tsc2007_data 
{
    const struct device *dev;
    struct k_work_delayable work;
    struct gpio_callback int_gpio_cb;
    uint16_t touch_x;
    uint16_t touch_y;
    bool pendown;
};

INPUT_TOUCH_STRUCT_CHECK(struct tsc2007_config);

static int tsc2007_setup(const struct device *dev)
{
    int ret;
    uint8_t rx[2];
    
    const struct tsc2007_config *config = dev->config;

    ret = i2c_write_read_dt(&config->bus, &setup_command, 1, rx, sizeof(rx));
    if (ret < 0) 
    {
        return ret;
    }

    return 0;
}

static int tsc2007_powerdown(const struct device *dev)
{
    int ret;

    const struct tsc2007_config *config = dev->config;

    ret = i2c_write_dt(&config->bus, &pwrdown, 1);
    if (ret < 0) 
    {
        return ret;
    }

    return 0;
}

static void tsc2007_report_touch(const struct device *dev)
{
    const struct tsc2007_config *config = dev->config;
    const struct input_touchscreen_common_config *common = &config->common;
    struct tsc2007_data *data = dev->data;
    int x = data->touch_x;
    int y = data->touch_y;

    if (common->screen_width > 0 &&
        common->screen_height > 0)
    {
        x = (((int)data->touch_x - config->raw_x_min) * common->screen_width) /
            (config->raw_x_max - config->raw_x_min);
        y = (((int)data->touch_y - config->raw_y_min) * common->screen_height) /
            (config->raw_y_max - config->raw_y_min);

        x = clamp(x, 0, common->screen_width);
        y = clamp(y, 0, common->screen_height);
    }

    input_touchscreen_report_pos(dev, x, y, K_NO_WAIT);
    //input_report_key(dev, INPUT_BTN_TOUCH, 1, true, K_NO_WAIT);
}

static int tsc2007_read_adc(const struct device *dev,
                            uint8_t cmd,
                            uint16_t *value)
{
    const struct tsc2007_config *config = dev->config;
    uint8_t rx[2];
    int ret;

    ret = i2c_write_read_dt(&config->bus, &cmd, 1, rx, sizeof(rx));
    if (ret < 0)
    {
        return ret;
    }

    *value = ((rx[0] << 8) | rx[1]) >> 4;

    return 0;
}

static int tsc2007_read_values(const struct device *dev,
                              struct ts_event *tc)
{
    int ret;

    /* y- still on; turn on only y+ (and ADC) */
    ret = tsc2007_read_adc(dev, read_y, &tc->y);

    if (ret < 0)
    {
        LOG_ERR("Could not read y value (%d)", ret);
        return ret;
    }

    /* turn y- off; x+ on, then leave in lowpower */
    ret = tsc2007_read_adc(dev, read_x, &tc->x);
    if (ret < 0)
    {
        LOG_ERR("Could not read x value (%d)", ret);
        return ret;
    }

    /* turn y+ off, x- on, we'll use formula #1 */

    ret = tsc2007_read_adc(dev, read_z1, &tc->z1);
    if (ret < 0) 
    {
        LOG_ERR("Could not read z1 values (%d)", ret);
        return ret;
    }

    ret = tsc2007_read_adc(dev, read_z2, &tc->z2);
    if (ret < 0) 
    {
        LOG_ERR("Could not read z2 values (%d)", ret);
        return ret;
    }

    ret = tsc2007_powerdown(dev);
    if (ret < 0)
    {
        LOG_ERR("Could not read power (%d)", ret);
        return ret;
    }

    return 0;
}

static uint32_t tsc2007_calculate_pressure(struct ts_event *tc)
{
    uint32_t ret = 0;

    if (tc->x == MAX_12BIT)
    {
        tc->x = 0;
    }

    if (tc->x && tc->z1) {
        ret = tc->z2 - tc->z1;
        ret *= tc->x;
        ret *= 400; // x_plate_ohms
        ret /= tc->z1;
        ret = (ret + 2047) >> 12;
    }

    return ret;
}

static void tsc2007_work_handler(struct k_work *work)
{
    struct tsc2007_data *data =
        CONTAINER_OF(work, struct tsc2007_data, work.work);
    const struct tsc2007_config *config = data->dev->config;

    struct ts_event tc;
    uint32_t pressure;
    int ret;

    if (data->pendown)
    {
        if (!gpio_pin_get_dt(&config->int_gpio))
        {
            input_report_key(data->dev, INPUT_BTN_TOUCH, 0, true, K_NO_WAIT);
            data->pendown = false;
            goto out;
        }
    }

    ret = tsc2007_read_values(data->dev, &tc);
    if (ret < 0)
    {
        LOG_ERR("touch read error %d", ret);
        return;
    }

    data->touch_x = tc.x;
    data->touch_y = tc.y;

    pressure = tsc2007_calculate_pressure(&tc);

    if (pressure > MAX_12BIT)
    {
        goto out;
    }

    if (pressure) {
        if (!data->pendown)
        {
            input_report_key(data->dev, INPUT_BTN_TOUCH, 1, true, K_NO_WAIT);
            data->pendown = true;
        }

        tsc2007_report_touch(data->dev);
    }
    else if (!gpio_pin_get_dt(&config->int_gpio) && data->pendown)
    {
        input_report_key(data->dev, INPUT_BTN_TOUCH, 0, true, K_NO_WAIT);
        data->pendown = false;
    }

out:
    if (data->pendown)
    {
        k_work_schedule(&data->work, K_MSEC(TS_POLL_PERIOD));
    }
    else
    {
        gpio_pin_interrupt_configure_dt(&config->int_gpio, GPIO_INT_EDGE_TO_ACTIVE);
    }
}

static void tsc2007_interrupt_handler(const struct device *dev, 
                                      struct gpio_callback *cb,
                                      uint32_t pins)
{
    struct tsc2007_data *data =
        CONTAINER_OF(cb, struct tsc2007_data, int_gpio_cb);

    const struct tsc2007_config *config = data->dev->config;

    gpio_pin_interrupt_configure_dt(&config->int_gpio, GPIO_INT_DISABLE);

    k_work_schedule(&data->work, K_MSEC(TS_POLL_PERIOD));
}

static int tsc2007_init(const struct device *dev)
{
    const struct tsc2007_config *config = dev->config;
    struct tsc2007_data *data = dev->data;
    int ret;

    data->dev = dev;

    if (!i2c_is_ready_dt(&config->bus)) 
    {
        LOG_ERR("I2C controller device not ready");
        return -ENODEV;
    }

    k_work_init_delayable(&data->work, tsc2007_work_handler);

    if (!gpio_is_ready_dt(&config->int_gpio)) 
    {
        LOG_ERR("Interrupt GPIO controller device not ready");
        return -ENODEV;
    }

    ret = gpio_pin_configure_dt(&config->int_gpio, GPIO_INPUT);
    if (ret < 0)
    {
        LOG_ERR("Could not configure interrupt GPIO pin (%d)", ret);
        return ret;
    }

    ret = gpio_pin_interrupt_configure_dt(&config->int_gpio, GPIO_INT_EDGE_TO_ACTIVE);
    if (ret < 0)
    {
        LOG_ERR("Could not configure GPIO interrupt (%d)", ret);
        return ret;
    }

    gpio_init_callback(&data->int_gpio_cb, tsc2007_interrupt_handler,
                       BIT(config->int_gpio.pin));

    ret = gpio_add_callback_dt(&config->int_gpio, &data->int_gpio_cb);
    if (ret < 0) 
    {
        LOG_ERR("Could not set GPIO callback (%d)", ret);
        return ret;
    }

    k_msleep(2);

    tsc2007_setup(dev);
    tsc2007_powerdown(dev);

    return 0;
}

#define TSC2007_DEFINE(index)                                               \
	BUILD_ASSERT(DT_INST_PROP_OR(index, raw_x_max, 4096) >                  \
		     DT_INST_PROP_OR(index, raw_x_min, 0),                          \
		     "raw-x-max should be larger than raw-x-min");                  \
	BUILD_ASSERT(DT_INST_PROP_OR(index, raw_y_max, 4096) >                  \
		     DT_INST_PROP_OR(index, raw_y_min, 0),                          \
		     "raw-y-max should be larger than raw-y-min");                  \
    static const struct tsc2007_config tsc2007_config_##index =             \
    {                                                                       \
        .common = INPUT_TOUCH_DT_INST_COMMON_CONFIG_INIT(index),            \
        .bus = I2C_DT_SPEC_INST_GET(index),                                 \
        .int_gpio = GPIO_DT_SPEC_INST_GET(index, int_gpios),                \
        .raw_x_min = DT_INST_PROP_OR(index, raw_x_min, 0),                  \
        .raw_x_max = DT_INST_PROP_OR(index, raw_x_max, 4096),               \
        .raw_y_min = DT_INST_PROP_OR(index, raw_y_min, 0),                  \
        .raw_y_max = DT_INST_PROP_OR(index, raw_y_max, 4096),               \
    };                                                                      \
    static struct tsc2007_data tsc2007_data_##index;                        \
    DEVICE_DT_INST_DEFINE(index,                                            \
                          tsc2007_init,                                     \
                          NULL,                                             \
                          &tsc2007_data_##index,                            \
                          &tsc2007_config_##index,                          \
                          POST_KERNEL,                                      \
                          CONFIG_INPUT_INIT_PRIORITY,                       \
                          NULL);

DT_INST_FOREACH_STATUS_OKAY(TSC2007_DEFINE)
