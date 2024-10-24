#pragma once

#ifdef __cplusplus
#include <cstdlib>
#else
#include <stdlib.h>
#endif

#define WS_EVENT_OPEN "open"
#define WS_EVENT_CLOSE "close"
#define WS_EVENT_FRAME "frame"
#define WS_EVENT_ERROR "error"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @enum e_ws_status
 * @brief Defines the status codes for WebSocket operations.
 *
 * This enum represents different status codes that can be returned by
 * WebSocket operations to indicate success, error, or a busy state.
 */
enum e_ws_status : unsigned char
{
    status_ok = 0x0, /**< @brief Operation was successful. */
    status_error = 0x1, /**< @brief An error occurred during the operation. */
    status_busy = 0x2 /**< @brief The socket is currently busy. */
};

/**
 * @enum e_ws_mode
 * @brief Defines the security mode for WebSocket communication.
 *
 * This enum is used to set or indicate whether the WebSocket communication
 * is secured (SSL/TLS) or unsecured.
 */
enum e_ws_mode : unsigned char
{
    mode_unsecured = 0x0, /**< @brief Unsecured mode. */
    mode_secured = 0x1 /**< @brief Secured mode (SSL). */
};

/**
 * @enum e_ws_endpoint_type
 * @brief Defines the type of WebSocket endpoint.
 *
 * This enum is used to specify whether the WebSocket endpoint is acting
 * as a server or a client.
 */
enum e_ws_endpoint_type : unsigned char
{
    endpoint_server = 0x0, /**< @brief The endpoint is a server. */
    endpoint_client = 0x1 /**< @brief The endpoint is a client. */
};

/**
 * @struct ws_settings_t
 * @brief WebSocket settings
 *
 * This structure holds various configuration settings for a WebSocket
 * connection, including endpoint type, security options, timeouts, and
 * SSL/TLS credentials.
 */
typedef struct
{
    e_ws_endpoint_type endpoint; /**< @brief Type of the WebSocket endpoint (client or server). */

    e_ws_mode mode; /**< @brief Operation mode (secured or unsecured). */

    unsigned int read_timeout; /**< @brief Read timeout in milliseconds. Defines how long to wait for reading data. */
    unsigned int poll_timeout; /**< @brief Poll timeout in milliseconds. Defines how long to wait during polling operations. */

    char *ssl_seed; /**< @brief Seed for the SSL/TLS random number generator. */
    char *ssl_ca_cert; /**< @brief CA certificate used for SSL/TLS verification. */
    char *ssl_own_cert; /**< @brief Own certificate for the WebSocket connection, used by clients or servers. */
    char *ssl_private_key; /**< @brief Private key associated with the own certificate, used for SSL/TLS encryption. */

    size_t fd_limit; /**< @brief Maximum number of file descriptors that the WebSocket should manage. */

    char *host; /**< @brief Hostname or IP address of the WebSocket server. This field must be filled. */
    char *allowed_origin; /**< @brief Allowed origin for WebSocket connections (used in CORS scenarios). This field can be NULL. */

    unsigned int ping_interval; /**< @brief Interval in milliseconds between WebSocket ping messages to maintain connection. */
    unsigned int ping_timeout; /**< @brief Timeout in milliseconds to wait for a pong message after sending a ping. */
} ws_settings_t;

/**
 * @brief Initializes the WebSocket settings structure with default values.
 *
 * This function sets the default values for the WebSocket settings, ensuring
 * that the structure is properly initialized before use. The default values
 * include:
 * - `endpoint` is set to `endpoint_server`.
 * - `mode` is set to `mode_unsecured`.
 * - Timeouts (read and poll) are set to 0.
 * - SSL/TLS fields (seed, certificates, private key) are set to NULL.
 * - `fd_limit` is set to 0.
 * - `host` and `allowed_origin` are set to NULL.
 * - `ping_interval` is set to 60 seconds (60000 ms).
 * - `ping_timeout` is set to 30 seconds (30000 ms).
 *
 * @param[in,out] settings Pointer to the WebSocket settings structure to initialize.
 */
void inline ws_settings_init( ws_settings_t *settings )
{
    settings->endpoint = e_ws_endpoint_type::endpoint_server;

    settings->mode = e_ws_mode::mode_unsecured;

    settings->read_timeout = 0;
    settings->poll_timeout = 0;

    settings->ssl_seed = NULL;
    settings->ssl_ca_cert = NULL;
    settings->ssl_own_cert = NULL;
    settings->ssl_private_key = NULL;

    settings->fd_limit = 0;

    settings->host = NULL;
    settings->allowed_origin = NULL;

    settings->ping_interval = 60 * 1000;
    settings->ping_timeout = 30 * 1000;
}

/**
 * @brief Frees the dynamically allocated memory in the WebSocket settings structure.
 *
 * This function safely frees any memory that was allocated for the WebSocket
 * settings structure, specifically for the SSL/TLS fields (`ssl_seed`, `ssl_ca_cert`,
 * `ssl_own_cert`, `ssl_private_key`), the `host`, and `allowed_origin` fields.
 * After freeing the memory, the respective pointers are set to NULL to prevent
 * dangling pointers.
 *
 * @param[in,out] settings Pointer to the WebSocket settings structure to destroy.
 */
void inline ws_settings_destroy( ws_settings_t *settings )
{
    if ( settings->ssl_seed )
    {
#ifdef __cplusplus
        std::free( settings->ssl_seed );
#else
        free( settings->ssl_seed );
#endif
        settings->ssl_seed = NULL;
    }

    if ( settings->ssl_ca_cert )
    {
#ifdef __cplusplus
        std::free( settings->ssl_ca_cert );
#else
        free( settings->ssl_ca_cert );
#endif
        settings->ssl_ca_cert = NULL;
    }

    if ( settings->ssl_own_cert )
    {
#ifdef __cplusplus
        std::free( settings->ssl_own_cert );
#else
        free( settings->ssl_own_cert );
#endif
        settings->ssl_own_cert = NULL;
    }

    if ( settings->ssl_private_key )
    {
#ifdef __cplusplus
        std::free( settings->ssl_private_key );
#else
        free( settings->ssl_private_key );
#endif
        settings->ssl_private_key = NULL;
    }

    if ( settings->host )
    {
#ifdef __cplusplus
        std::free( settings->host );
#else
        free( settings->host );
#endif
        settings->host = NULL;
    }

    if ( settings->allowed_origin )
    {
#ifdef __cplusplus
        std::free( settings->allowed_origin );
#else
        free( settings->allowed_origin );
#endif
        settings->allowed_origin = NULL;
    }
}

#ifdef __cplusplus
}
#endif
