#ifndef __KAFKA_HELPERS_H
#define __KAFKA_HELPERS_H

#include "kafka-types.h"

static __inline int32_t read_big_endian_int32(const char* buf) {
  const int32_t length = *((int32_t*)buf);
  return bpf_ntohl(length);
}

//#define MINIMUM_API_VERSION_FOR_CLIENT_ID 1
//#define MAX_LENGTH_FOR_CLIENT_ID_STRING 50

static __inline int16_t read_big_endian_int16(const char* buf) {
//    log_debug("read_big_endian_int16: %d %d", buf[0], buf[1]);
    const int16_t length = *((int16_t*)buf);
//    log_debug("read_big_endian_int16 ---: %d", length);
//    log_debug("read_big_endian_int16 --2: %d", bpf_ntohs(length));
    return bpf_ntohs(length);
}

// Checking if the buffer represents kafka message
//static __always_inline bool is_kafka(const char* buf, __u32 buf_size) {
static __always_inline bool try_parse_request_header(kafka_transaction_t *kafka_transaction) {
    char *request_fragment = kafka_transaction->request_fragment;
//    const uint32_t request_fragment_size = sizeof(kafka_transaction->request_fragment);
//    if (buf_size < KAFKA_MIN_SIZE) {
//        log_debug("buffer size is less than KAFKA_MIN_SIZE");
//        return false;
//    }

    if (request_fragment == NULL) {
        log_debug("request_fragment == NULL");
        return false;
    }

    // Kafka size field is 4 bytes
//    const int32_t message_size = read_big_endian_int32(buf) + 4;
    const int32_t message_size = read_big_endian_int32(request_fragment);
    //log_debug("message_size = %d", message_size);
    //log_debug("buf_size = %d", buf_size);

    // Enforcing count to be exactly message_size + 4 to mitigate mis-classification.
    // However, this will miss long messages broken into multiple reads.
//    if (message_size < 0 || buf_size != (__u32)message_size) {
    if (message_size <= 0) {
//        log_debug("message_size < 0 || buf_size != (__u32)message_size");
        //log_debug("message_size <= 0");
        return false;
    }

    const int16_t request_api_key = read_big_endian_int16(request_fragment + 4);
    log_debug("request_api_key: %d", request_api_key);
    if (request_api_key < 0 || request_api_key > KAFKA_MAX_VERSION) {
        log_debug("request_api_key < 0 || request_api_key > KAFKA_MAX_VERSION");
        return false;
    }

    const int16_t request_api_version = read_big_endian_int16(request_fragment + 6);
    log_debug("request_api_version: %d", request_api_version);
    if (request_api_version < 0 || request_api_version > KAFKA_MAX_API) {
        log_debug("request_api_version < 0 || request_api_version > KAFKA_MAX_API");
        return false;
    }
    kafka_transaction->request_api_version = request_api_version;

    const int32_t correlation_id = read_big_endian_int32(request_fragment + 8);
    log_debug("correlation_id: %d", correlation_id);
    if (correlation_id < 0) {
        log_debug("correlation_id < 0");
        return false;
    }
     kafka_transaction->correlation_id = correlation_id;

    const int16_t MINIMUM_API_VERSION_FOR_CLIENT_ID = 1;
//    const uint32_t MAX_LENGTH_FOR_CLIENT_ID_STRING = 50;
    //char client_id[MAX_LENGTH_FOR_CLIENT_ID_STRING] = {0};
    __builtin_memset(kafka_transaction->client_id, 0, sizeof(kafka_transaction->client_id));
    if (request_api_version >= MINIMUM_API_VERSION_FOR_CLIENT_ID) {
        const int16_t client_id_size = read_big_endian_int16(request_fragment + 12);
        log_debug("client_id_size: %d", client_id_size);
        uint32_t max_size_of_client_id_string = sizeof(kafka_transaction->client_id);
        if (client_id_size <= 0 || client_id_size > max_size_of_client_id_string) {
            log_debug("client_id <=0 || client_id_size > MAX_LENGTH_FOR_CLIENT_ID_STRING");
        }
        else
        {
            const char* client_id_in_buf = request_fragment + 14;
            const uint16_t client_id_size_final = client_id_size < max_size_of_client_id_string ? client_id_size : max_size_of_client_id_string;
            bpf_probe_read_kernel_with_telemetry(kafka_transaction->client_id, client_id_size_final, (void*)client_id_in_buf);
            log_debug("client_id: %s", kafka_transaction->client_id);
        }
    }

    return true;
}

#endif
