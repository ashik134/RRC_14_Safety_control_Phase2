// GPIO4 switches the shared VSPI bus between the SD card and the W5500.
//
// Measured on this PLC: LOW = SD card answers, W5500 reads 0xFF. HIGH = W5500
// answers, SD card stops. Neither chip loses anything across a switch (the
// W5500 keeps its address and link, the card needs no re-init), and the board
// file only calls the pin CS1. GPIO4 boots pulled LOW, which is why the SD card
// worked until something raised it.
//
// Both chips already serialise every access through SPI.beginTransaction(), so
// that is where the switch happens: linked in place of the real function with
// -Wl,--wrap (see platformio.ini), once it holds the bus lock. The SD and
// Ethernet libraries and every caller of them stay as they are, and the two
// chips can take turns one transaction at a time. The clock tells them apart.
//
// One SD call does not go through there: the driver's ff_sd_status() sends its
// command with no transaction at all, so it would miss the switch and talk over
// live Ethernet traffic. FatFs calls it on nearly every file operation. It is
// given a transaction here, as the driver registers itself with FatFs.
#include "spi_bus_switch.h"

#include <Arduino.h>
#include <SPI.h>
#include <driver/gpio.h>
#include "ff.h"
#include "diskio_impl.h"

static const gpio_num_t BUS_SELECT_PIN = GPIO_NUM_4;

// sd_diskio talks at these rates: SD.begin()'s default, and its card-init rate.
static const uint32_t SD_SPI_HZ      = 4000000;
static const uint32_t SD_SPI_INIT_HZ = 400000;

extern "C" void __real__ZN8SPIClass16beginTransactionE11SPISettings(SPIClass *spi, SPISettings settings);

extern "C" void __wrap__ZN8SPIClass16beginTransactionE11SPISettings(SPIClass *spi, SPISettings settings) {
  __real__ZN8SPIClass16beginTransactionE11SPISettings(spi, settings);   // takes the bus lock
  bool forSd = settings._clock == SD_SPI_HZ || settings._clock == SD_SPI_INIT_HZ;
  gpio_set_level(BUS_SELECT_PIN, forSd ? 0 : 1);
}

static DSTATUS (*sdStatus)(BYTE pdrv) = nullptr;

static DSTATUS lockedSdStatus(BYTE pdrv) {
  SPI.beginTransaction(SPISettings(SD_SPI_HZ, MSBFIRST, SPI_MODE0));
  DSTATUS status = sdStatus(pdrv);
  SPI.endTransaction();
  return status;
}

extern "C" void __real_ff_diskio_register(BYTE pdrv, const ff_diskio_impl_t *impl);

extern "C" void __wrap_ff_diskio_register(BYTE pdrv, const ff_diskio_impl_t *impl) {
  if (!impl) {
    __real_ff_diskio_register(pdrv, impl);
    return;
  }
  static ff_diskio_impl_t locked;
  locked = *impl;
  sdStatus = impl->status;
  locked.status = &lockedSdStatus;
  __real_ff_diskio_register(pdrv, &locked);
}

void spiBusSwitchBegin() {
  gpio_set_level(BUS_SELECT_PIN, 0);
  gpio_set_direction(BUS_SELECT_PIN, GPIO_MODE_OUTPUT);
}
