// See spi_bus_switch.cpp: GPIO4 picks the SD card or the W5500 on the shared bus.
#pragma once

void spiBusSwitchBegin();   // once, before the first SPI access
