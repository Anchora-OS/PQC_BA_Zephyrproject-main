# Hardware Test & Project Template

This workspace serves as a baseline template and hardware verification test for subsequent project implementations. It features a basic routine where LED0 blinks continuously and LED1 illuminates upon pressing Button T3.

## Configuration Profiles

The workspace contains two distinct `prj.conf` configuration files:

- **Hardware Testing Profile** (`prj.conf (With full board functionality)`): Activates all board features, facilitating comprehensive hardware testing and validation.
- **Minimal Baseline Profile** (`prj.conf`): Intentionally kept minimal to provide an accurate baseline for Flash and RAM utilization measurements during the build process. This establishes a reference footprint of an almost empty project for comparison against other implementations.

## Acknowledgments & Disclaimer

The codebase within this project is heavily inspired by and derived from the following sources:
- **Zephyr RTOS Tutorial**: [Getting Started Guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html)
- **Zephyr Code Samples**: [Blinky Program](https://docs.zephyrproject.org/latest/samples/basic/blinky/README.html)
- **InES Institute (ZHAW)**: The code is inspired by and partially based directly on software originally developed by the Institute of Embedded Systems (InES) at ZHAW. The [InES/MC1_STM32H573](https://github.zhaw.ch/InES/MC1_STM32H573.git) repository was provided alongside the MC1 hardware board for this project.

*21.03.2026 Hofer levin*



