idf_component_register(
  SRCS "main.cpp"
  INCLUDE_DIRS "."
  REQUIRES espressif__arduino-esp32 spiffs
)

spiffs_create_partition_image(storage ../spiffs FLASH_IN_PROJECT)
