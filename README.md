# mbed TLS Examples on mbedOS

This repository contains a collection of mbed TLS example applications based on mbed OS. Each subdirectory contains a separate example meant for building as an executable.

# Getting started

## Required hardware
* An [FRDM-K64F](http://developer.mbed.org/platforms/FRDM-K64F/) development board.
* A micro-USB cable.

## Required software
* [mbed CLI](https://github.com/ARMmbed/mbed-cli) - to build the example program. To learn how to build mbed OS applications with mbed CLI, see the [user guide](https://github.com/ARMmbed/mbed-cli/blob/master/README.md)
* [Serial port monitor](https://developer.mbed.org/handbook/SerialPC#host-interface-and-terminal-applications).

## Building and running the examples

1. Clone the repository containing the collection of examples:
    ```
    $ git clone https://github.com/ARMmbed/mbed-os-example-tls
    ```

1. Open a command line tool and navigate to one of the project’s subdirectories.

1. Update `mbed-os` sources using the `mbed deploy` command.

1. Build the application by selecting the board and build toolchain using the command `mbed compile -m K64F -t GCC_ARM`. mbed-cli builds a binary file under the project’s `.build` directory.

1. Connect the FRDM-K64F to the computer with the micro-USB cable, being careful to use the **OpenSDA** connector on the target board. The board is listed as a mass-storage device.

1. Drag the binary `.build/K64F/GCC_ARM/<EXAMPLE>.bin` to the board to flash the application.

1. The board is automatically programmed with the new binary. A flashing LED on it indicates that it is still working. When the LED stops blinking, the board is ready to work.

1. Press the **RESET** button on the board to run the program.

## Monitoring the application

Please browse the subdirectories for specific documentation.
* [Benchmark](./benchmark/README.md)

The application prints debug messages over the serial port, so you can monitor its activity with a serial terminal emulator. Start the [serial terminal emulator](https://developer.mbed.org/handbook/Terminals) and connect to the [virtual serial port](https://developer.mbed.org/handbook/SerialPC#host-interface-and-terminal-applications) presented by FRDM-K64F. Use the following settings:

* 115200 baud (not 9600).
* 8N1.
* No flow control.

After pressing the **RESET** button on the board, you should be able to observe the application's output.

## Debugging mbed TLS

To optionally print out more debug information, edit the `main.cpp` for the sample and change the definition of `DEBUG_LEVEL` (near the top of the file) from 0 to a positive number between 1 and 4.
