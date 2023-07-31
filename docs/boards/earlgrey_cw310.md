# <img alt="OpenSK logo" src="../img/OpenSK.svg" width="200px">

## OpenTitan Earl Grey on the CW310

### Flashing using OpenTitanTool

Flashing Earl Grey requires [OpenTitanTool](https://github.com/lowRISC/opentitan/tree/master/sw/host/opentitantool):

Build OpenTitanTool from the OpenTitan repository and add it to your path:

```sh
git clone 'https://github.com/lowRISC/opentitan'
cd opentitan
./bazelisk.sh build //sw/host/opentitantool
bin_path="$(./ci/scripts/target-location.sh //sw/host/opentitantool)"
PATH="$(dirname "$bin_path"):${PATH}"

To flash the firmware, run:

```shell
./deploy.py --board=earlgrey-cw310-opensk --opensk --programmer=opentitantool
```

This should run OpenTitanTool to bootstrap OpenSK onto OpenTitan.

If OpenTitanTool complains about an incorrect SFDP signature, this probably
means the FPGA hasn't been properly programmed with Earl Grey.

Reprogram the FPGA and check it by running a test:

```sh
./bazelisk.sh test \
    --test_output=streamed \
    --cache_test_results=no \
    //sw/device/tests:uart_smoketest_fpga_cw310_test_rom
```
