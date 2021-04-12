![](./resources/official_armmbed_example_badge.png)
# Mbed TLS Examples on Mbed OS

The example project is part of the [Arm Mbed OS Official Examples](https://os.mbed.com/code/). This repository contains a collection of Mbed TLS example applications based on Mbed OS. Each subdirectory contains a separate example meant for building as an executable.

# Getting started

## Required hardware
* Any Mbed OS capable development board such as those listed [here](https://os.mbed.com/platforms/), which have an entropy source integrated into Mbed TLS. The single example that does not need an entropy source is `hashing`. To use the `tls-client` example you should also have a network interface supported on your board.

If your board has no hardware entropy source or its entropy source is not integrated with Mbed TLS, but you want to try these examples anyway, then you may want to consider compiling Mbed TLS without real entropy sources.

*Warning!* Without entropy sources Mbed TLS does not provide any security whatsoever. If you still want to compile Mbed TLS without entropy sources, then consult the section "How to test without entropy sources" in the Mbed TLS Porting Guide.

## Required software

* [Mbed CLI](https://github.com/ARMmbed/mbed-cli) or [Mbed CLI 2](https://github.com/ARMmbed/mbed-tools). This will be used to configure and build the project.

An alternative to Mbed CLI is to use the [Mbed Online Compiler](https://os.mbed.com/compiler/). In this case, you need to import the example projects from [Mbed developer](https://os.mbed.com/) to your Mbed Online Compiler session using the links below:
* [authcrypt](https://os.mbed.com/teams/mbed-os-examples/code/mbed-os-example-tls-authcrypt)
* [benchmark](https://os.mbed.com/teams/mbed-os-examples/code/mbed-os-example-tls-benchmark)
* [hashing](https://os.mbed.com/teams/mbed-os-examples/code/mbed-os-example-tls-hashing)
* [tls-client](https://os.mbed.com/teams/mbed-os-examples/code/mbed-os-example-tls-tls-client)

## Mbed OS build tools

### Mbed CLI 2
Starting with version 6.5, Mbed OS uses Mbed CLI 2. It uses Ninja as a build system, and CMake to generate the build environment and manage the build process in a compiler-independent manner. If you are working with Mbed OS version prior to 6.5 then check the section [Mbed CLI 1](#mbed-cli-1).

[Install Mbed CLI 2](https://os.mbed.com/docs/mbed-os/latest/build-tools/install-or-upgrade.html)

### Mbed CLI 1
[Install Mbed CLI 1](https://os.mbed.com/docs/mbed-os/latest/quick-start/offline-with-mbed-cli.html)

## Building and running the examples

1. Clone the repository containing the collection of examples:
    ```bash
    $ git clone https://github.com/ARMmbed/mbed-os-example-tls
    ```

1. Open a command line tool and navigate to one of the project’s subdirectories.

1. Update the source tree:

    * Mbed CLI 2
    ```bash
    $ mbed-tools deploy
    ```

    * Mbed CLI 1
    ```bash
    $ mbed deploy
    ```

1. Connect a USB cable between the USB port on the board and the host computer.
1. Run the following command to build the example project, program the microcontroller flash memory, and open a serial terminal to the device:

    * Mbed CLI 2

    ```bash
    $ mbed-tools compile -m <TARGET> -t <TOOLCHAIN> --flash --sterm
    ```

    * Mbed CLI 1

    ```bash
    $ mbed compile -m <TARGET> -t <TOOLCHAIN> --flash --sterm
    ```

1. Press the **RESET** button on the board to run the program.


Your PC may take a few minutes to compile your code.

The binary will be located in the following directory:
* **Mbed CLI 2** - `./cmake_build/<TARGET>/develop/<TOOLCHAIN>/`
* **Mbed CLI 1** - `./BUILD/<TARGET>/<TOOLCHAIN>/`

You can manually copy the binary to the target, which gets mounted on the host computer through USB, rather than using the `--flash` option.

You can also open a serial terminal separately, as explained below, rather than using the `--sterm` option.

## Monitoring the application

Please browse the subdirectories for specific documentation.
* [authcrypt](./authcrypt/README.md): performs authenticated encryption and authenticated decryption of a buffer.
* [benchmark](./benchmark/README.md): benchmarks the various cryptographic primitives offered by Mbed TLS.
* [hashing](./hashing/README.md): performs hashing of a buffer with SHA-256 using various APIs.
* [tls-client](./tls-client/README.md): downloads a file from an HTTPS server (os.mbed.com) and looks for a specific string in that file.

The application prints debug messages over the serial port, so you can monitor its activity with a
serial terminal emulator. The default serial baudrate has been set to 9600 for these examples.
If not using the `--sterm` option when flashing, have a client open and connected to board. You may use:

- Mbed CLI 2 
    ```bash
    $ mbed-tools sterm
    ```

- Mbed CLI 1
    ```bash
    $ mbed sterm
    ```

- [Tera Term](https://ttssh2.osdn.jp/index.html.en) for Windows

- screen or minicom for Linux
    ```bash
    $ screen /dev/serial/<your board> 9600
    ```

After pressing the **RESET** button on the board, you should be able to observe the application's output.

## Debugging Mbed TLS

To optionally print out more debug information, edit the `main.cpp` for the sample and change the definition of `DEBUG_LEVEL` (near the top of the file) from 0 to a positive number between 1 and 4.

## License and contributions

The software is provided under Apache-2.0 license. Contributions to this project are accepted under the same license. Please see [contributing.md](CONTRIBUTING.md) for more info.

This project contains code from other projects. The original license text is included in those source files. They must comply with our license guide.
