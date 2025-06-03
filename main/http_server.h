#pragma once
#include "esp_http_server.h"

/**
 * @brief Starts the HTTP server (listening on port 80).
 * @return Handle to the server or NULL on failure.
 */
httpd_handle_t start_webserver(void);

/**
 * @brief Stops the running HTTP server.
 */
void stop_webserver(httpd_handle_t server);
