# Binary Ninja SVD Loader

This library will parse out structure definitions for the memory-mapped peripherals in a CMSIS-SVD file and apply them to a binary view.

## Installation

Use the Binary Ninja plugin manager to install the plugin.

## Usage

Once your firmware is loaded into Binary Ninja, navigate to Tools and select
`Load SVD`. Choose the SVD file to load from the file picker that shows up and
you're all set.

For STM32 targets, the stm32-rs project is a great place to look for SVD files.
https://stm32.agg.io/rs/ Since they do code generation to create hardware APIs,
the project has a bunch of bugfixes from upstream. For other ARM parts,
https://github.com/posborne/cmsis-svd is a nice repository.

Should both those sources fail you, SVDs can commonly be found in a number of
embedded IDE board support packages - chances are, you can find one floating
around for any chip you want to look at, even for chips you can't buy on the
open market.

As a concrete starting point, pretty much every device pack in the Keil device
support list will have an SVD to get you going. It's a lot of devices.
https://keil.com/dd2/


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
This project is dual-licensed under the MIT and Apache 2.0 licenses. You may
use the project under the terms of the license that you prefer.
[MIT](https://choosealicense.com/licenses/mit/)
[Apache 2.0](https://choosealicense.com/licenses/apache-2.0/)
