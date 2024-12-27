#include <sys/socket.h>
#include <zlib.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <errno.h>

#define PACKET_MAX_LEN 1024
#define PACKET_MAX_SIZE (1024 - 2 * sizeof(uint32_t) - sizeof(bool) - sizeof(uint16_t))
#define SERVER_PORT 12345
#define SUCCESS 0
#define RECEIVE_ERROR 201
#define FILE_ERROR 202
#define HASH_ERROR 203

typedef struct {
    uint32_t packet_number;
    bool termination;
    uint16_t data_size;
    char data[PACKET_MAX_LEN - sizeof(uint32_t)];
    uint32_t crc;
} Packet;

static int sockfd;
static struct sockaddr_in server_addr, client_addr;
static socklen_t client_len;

int calculate_md5(const char *filename, unsigned char *hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file for MD5 calculation");
        return FILE_ERROR;
    }
 
    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);

    char buffer[PACKET_MAX_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, PACKET_MAX_SIZE, file)) > 0) {
        MD5_Update(&md5_ctx, buffer, bytes_read);
    }

    if (ferror(file)) {
        perror("Error reading file for MD5 calculation");
        fclose(file);
        return FILE_ERROR;
    }

    MD5_Final(hash, &md5_ctx);
    fclose(file);
    return SUCCESS;
}

int init_socket() {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return -1;
    }

    return SUCCESS;
}

int send_ack() {
    if (sendto(sockfd, "ACK", 3, 0, (struct sockaddr *)&client_addr, client_len) < 0) {
        perror("Failed to send ACK");
        return -1;
    }
    return SUCCESS;
}

int receive_packet(Packet *packet) {
    ssize_t received = recvfrom(sockfd, packet, sizeof(*packet), 0,
                               (struct sockaddr *)&client_addr, &client_len);
    if (received < 0) {
        perror("Error receiving packet");
        return RECEIVE_ERROR;
    }

    // Validate CRC
    uint32_t calculated_crc = crc32(0L, (const Bytef *)&packet->packet_number, 
    sizeof(packet->packet_number) + 
    sizeof(packet->termination) + 
    packet->data_size);
    if (calculated_crc != packet->crc) {
        fprintf(stderr, "CRC mismatch in packet %u. Dropping packet.\n", packet->packet_number);
        return RECEIVE_ERROR;
    }

    return SUCCESS;
}

int receive_filename(char *filename, size_t filename_size) {
    Packet packet;
    int result = receive_packet(&packet);
    if (result != SUCCESS) return result;

    if (packet.packet_number != 0) {
        fprintf(stderr, "Expected filename packet, got packet number %u\n", packet.packet_number);
        return RECEIVE_ERROR;
    }

    strncpy(filename, packet.data, filename_size - 1);
    filename[filename_size - 1] = '\0';
    printf("Receiving file: %s\n", filename);
    return send_ack();
}

int receive_md5_hash(unsigned char *received_md5) {
    Packet packet;
    int result = receive_packet(&packet);
    if (result != SUCCESS) return result;

    if (packet.packet_number != 1) {
        fprintf(stderr, "Expected MD5 hash packet, got packet number %u\n", packet.packet_number);
        return RECEIVE_ERROR;
    }

    memcpy(received_md5, packet.data, MD5_DIGEST_LENGTH);
    return send_ack();
}

int receive_file_data(FILE *file, uint32_t expected_packet) {
    Packet packet;
    while (1) {
        int result = receive_packet(&packet);
        if (result != SUCCESS) return result;

        printf("Received packet %u, packet size %u bytes, termination: %u\n", 
               packet.packet_number, packet.data_size, packet.termination);

        if (packet.packet_number != expected_packet) {
            printf("Expected packet %u, got %u. Requesting retransmission.\n",
                   expected_packet, packet.packet_number);
            continue;
        }

        // Write data to file regardless of termination flag
        if (fwrite(packet.data, 1, packet.data_size, file) != packet.data_size) {
            perror("Error writing to file");
            return FILE_ERROR;
        }
        fflush(file);

        send_ack();
        expected_packet++;

        // Handle termination after writing data
        if (packet.termination) {
            printf("Received termination packet.\n");
            break;
        }
    }
    return SUCCESS;
}

int verify_file_hash(const char *filename, const unsigned char *received_md5) {
    unsigned char calculated_md5[MD5_DIGEST_LENGTH];
    int result = calculate_md5(filename, calculated_md5);
    if (result != SUCCESS) return result;

    if (memcmp(received_md5, calculated_md5, MD5_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "MD5 hash mismatch\n");
        return HASH_ERROR;
    }

    printf("File received successfully with matching MD5 hash.\n");
    return SUCCESS;
}

int receive_file() {
    client_len = sizeof(client_addr);
    char filename[256];
    unsigned char received_md5[MD5_DIGEST_LENGTH];
    uint32_t expected_packet = 2;
    int result;

    if ((result = receive_filename(filename, sizeof(filename))) != SUCCESS) return result;
    if ((result = receive_md5_hash(received_md5)) != SUCCESS) return result;

    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening file for writing");
        return FILE_ERROR;
    }

    result = receive_file_data(file, expected_packet);
    fclose(file);
    if (result != SUCCESS) return result;

    return verify_file_hash(filename, received_md5);
}

int main() {
    if (init_socket() < 0) {
        return 1;
    }

    printf("Server started on port %d\n", SERVER_PORT);
    
    int result = receive_file();
    printf("File reception completed with result: %d\n", result);
    
    close(sockfd);
    return result;
}