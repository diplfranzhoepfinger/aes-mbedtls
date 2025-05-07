#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include "mbedtls/aes.h"
#include "hal/cpu_hal.h"

#include "esp_log.h"

uint8_t key[32] =  { 0x79, 0x24, 0x42, 0x26, 0x45, 0x28, 0x48, 0x2B, 0x4D, 0x62, 0x51, 0x65, 0x54, 0x68, 0x57, 0x6D, 0x5A, 0x71, 0x34, 0x74, 0x37, 0x77, 0x21, 0x7A, 0x25, 0x43, 0x2A, 0x46, 0x2D, 0x4A, 0x40, 0x4E};
uint8_t data_in[16] = "HELLO ESP32-C3!";
uint8_t ciphertext[16];
uint8_t plaintext[16];


static const char* TAG = "aes-mbedtls";

void app_main() {
    // Initialize AES with context
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    // Set key
    assert(mbedtls_aes_setkey_enc(&ctx, key, 256) == 0);
    // Encrypt
    for (int i = 0; i < 5; i++) {
        // Five loops to eliminate instruction cache effects and observe general timing range
        esp_cpu_set_cycle_count(0); // Start cycle counting
        assert(mbedtls_aes_crypt_ecb( &ctx, MBEDTLS_AES_ENCRYPT, data_in, ciphertext ) == 0);
        ESP_LOGI(TAG, "perfcount: %ld", esp_cpu_get_cycle_count()); // End cycle counting and print "perfcount"
    }
    
    ESP_LOG_BUFFER_HEX_LEVEL("ciphertext:", ciphertext, 16, ESP_LOG_INFO); // expect: 4d 9f f1 e6 2e a4 ca 39 9f 4e 73 67 51 51 6b 24

    // Decrypt
    
    assert(mbedtls_aes_setkey_dec(&ctx, key, 256) == 0);
    assert(mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, ciphertext, plaintext) == 0);

    ESP_LOGI(TAG, "plaintext: %s", plaintext);
    
#ifdef CONFIG_MBEDTLS_HARDWARE_AES
    ESP_LOGI(TAG, "CONFIG_MBEDTLS_HARDWARE_AES=y\n");
#else
    ESP_LOGI(TAG, "CONFIG_MBEDTLS_HARDWARE_AES=n\n");
#endif

    mbedtls_aes_free(&ctx);
    
}
