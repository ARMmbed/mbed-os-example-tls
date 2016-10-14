# mbed TLS Examples on mbedOS

This repository contains a collection of mbed TLS example applications based on mbed OS. Each subdirectory contains a separate example meant for building as an executable.

# Getting started

## Required hardware
* An [FRDM-K64F](http://developer.mbed.org/platforms/FRDM-K64F/) development board.
* A micro-USB cable.

### Other hardware

Although the only board supported by these examples is K64F, they should work on any mbed enabled hardware, if it has a hardware entropy source, and this entropy source is integrated with mbed TLS. The single example that does not need an entropy source is `hashing`.

If your board has no hardware entropy source or its entropy source is not integrated with mbed TLS, but you want to try these examples anyway, then you may want to consider compiling mbed TLS without real entropy sources.

*Warning!* Without entropy sources mbed TLS does not provide any security whatsoever. If you still want to compile mbed TLS without entropy sources, then consult the section "How to test without entropy sources" in the mbed TLS Porting Guide.

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

1. Build the application by selecting the board and build toolchain using the command `mbed compile -m K64F -t GCC_ARM`. mbed-cli builds a binary file under the project’s `BUILD` directory.

1. Connect the FRDM-K64F to the computer with the micro-USB cable, being careful to use the **OpenSDA** connector on the target board. The board is listed as a mass-storage device.

1. Drag the binary `BUILD/K64F/GCC_ARM/<EXAMPLE>.bin` to the board to flash the application.

1. The board is automatically programmed with the new binary. A flashing LED on it indicates that it is still working. When the LED stops blinking, the board is ready to work.

1. Press the **RESET** button on the board to run the program.

## Monitoring the application

Please browse the subdirectories for specific documentation.
* [authcrypt](./authcrypt/README.md): performs authenticated encryption and authenticated decryption of a buffer.
* [benchmark](./benchmark/README.md): benchmarks the various cryptographic primitives offered by mbed TLS.
* [hashing](./hashing/README.md): performs hashing of a buffer with SHA-256 using various APIs.
* [tls-client](./tls-client/README.md): downloads a file from an HTTPS server (developer.mbed.org) and looks for a specific string in that file.

The application prints debug messages over the serial port, so you can monitor its activity with a serial terminal emulator. Start the [serial terminal emulator](https://developer.mbed.org/handbook/Terminals) and connect to the [virtual serial port](https://developer.mbed.org/handbook/SerialPC#host-interface-and-terminal-applications) presented by FRDM-K64F. Use the following settings:

* 9600 baud.
* 8N1.
* No flow control.

After pressing the **RESET** button on the board, you should be able to observe the application's output.

## Debugging mbed TLS

To optionally print out more debug information, edit the `main.cpp` for the sample and change the definition of `DEBUG_LEVEL` (near the top of the file) from 0 to a positive number between 1 and 4.
