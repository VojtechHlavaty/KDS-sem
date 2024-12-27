#include <sys/socket.h>
#include <zlib.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>

#define PACKET_MAX_LEN 1024
#define PACKET_MAX_SIZE (1024 - 2 * sizeof(uint32_t) - sizeof(bool) - sizeof(uint16_t))
#define SERVER_PORT 12345
#define SUCCESS 0
#define FOPEN_ERROR 101
#define SOCKET_INIT_ERROR 102
#define SOCKET_SEND_ERROR 103
#define HASH_ERROR 104
#define TIMEOUT_SECONDS 2

typedef struct {
    uint32_t packet_number;
    bool termination;
    uint16_t data_size;
    char data[PACKET_MAX_LEN - sizeof(uint32_t)];
    uint32_t crc;
} Packet;

// Function prototypes
int calculate_md5(const char *filename, unsigned char *hash);
int init_socket(const char *server_ip, struct sockaddr_in *server_addr);
int send_packet_with_ack(int sockfd, Packet *packet, struct sockaddr_in *server_addr);
int send_filename_packet(int sockfd, const char *fname, struct sockaddr_in *server_addr);
int send_md5_packet(int sockfd, const unsigned char *md5_hash, struct sockaddr_in *server_addr);
int send_file_data(int sockfd, FILE *file, struct sockaddr_in *server_addr);

int calculate_md5(const char *filename, unsigned char *hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file for MD5 calculation");
        return FOPEN_ERROR;
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
        return FOPEN_ERROR;
    }

    MD5_Final(hash, &md5_ctx);
    fclose(file);
    return SUCCESS;
}

int init_socket(const char *server_ip, struct sockaddr_in *server_addr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket initialization failed");
        return SOCKET_INIT_ERROR;
    }

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, server_ip, &server_addr->sin_addr) <= 0) {
        perror("Invalid server IP address");
        close(sockfd);
        return SOCKET_INIT_ERROR;
    }

    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SECONDS;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    return sockfd;
}

int send_packet_with_ack(int sockfd, Packet *packet, struct sockaddr_in *server_addr) {
    while (1) {
        if (sendto(sockfd, packet, sizeof(*packet), 0, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
            perror("Failed to send packet");
            return SOCKET_SEND_ERROR;
        }

        char ack_buffer[16];
        ssize_t ack_len = recvfrom(sockfd, ack_buffer, sizeof(ack_buffer), 0, NULL, NULL);
        if (ack_len > 0 && strncmp(ack_buffer, "ACK", 3) == 0) {
            return SUCCESS;
        }
        printf("Resending packet %d\n", packet->packet_number);
    }
}

int send_filename_packet(int sockfd, const char *fname, struct sockaddr_in *server_addr) {
    Packet packet = {0};
    strncpy(packet.data, fname, PACKET_MAX_SIZE - 1);
    packet.data[PACKET_MAX_SIZE - 1] = '\0';
    packet.packet_number = 0;
    packet.data_size = strlen(fname) + 1;
    packet.termination = false;
    packet.crc = crc32(0L, (const Bytef *)&packet.packet_number, 
    sizeof(packet.packet_number) + 
    sizeof(packet.termination) + 
    packet.data_size);

    int result = send_packet_with_ack(sockfd, &packet, server_addr);
    if (result == SUCCESS) {
        printf("File name sent: %s\n", fname);
    }
    return result;
}

int send_md5_packet(int sockfd, const unsigned char *md5_hash, struct sockaddr_in *server_addr) {
    Packet packet = {0};
    memcpy(packet.data, md5_hash, MD5_DIGEST_LENGTH);
    packet.packet_number = 1;
    packet.data_size = MD5_DIGEST_LENGTH;
    packet.termination = false;
    packet.crc = crc32(0L, (const Bytef *)&packet.packet_number, 
    sizeof(packet.packet_number) + 
    sizeof(packet.termination) + 
    packet.data_size);

    int result = send_packet_with_ack(sockfd, &packet, server_addr);
    if (result == SUCCESS) {
        printf("MD5 hash sent successfully.\n");
    }
    return result;
}

int send_file_data(int sockfd, FILE *file, struct sockaddr_in *server_addr) {
    Packet packet = {0};
    uint32_t packet_number = 2;
    size_t bytes_read;

    while (1) {
        bytes_read = fread(packet.data, 1, PACKET_MAX_SIZE, file);
        packet.packet_number = packet_number++;
        packet.data_size = bytes_read;
        packet.termination = false;

        if (bytes_read < PACKET_MAX_SIZE) {
            if (feof(file)) {
                packet.termination = true;
            } else if (ferror(file)) {
                perror("Error reading file");
                return FOPEN_ERROR;
            }
        }

        packet.crc = crc32(0L, (const Bytef *)&packet.packet_number, 
            sizeof(packet.packet_number) +
            sizeof(packet.termination) +
            packet.data_size);

        int result = send_packet_with_ack(sockfd, &packet, server_addr);
        if (result != SUCCESS) {
            return result;
        }

        printf("Sent packet %d with %zu bytes%s\n", packet.packet_number, bytes_read,
               packet.termination ? " (termination)" : "");

        if (packet.termination) {
            printf("Termination packet sent. Ending communication.\n");
            break;
        }
    }

    return SUCCESS;
}

int send_file(const char *fname, const char *server_ip) {
    printf("File name: %s | Server IP: %s\n", fname, server_ip);

    FILE *file = fopen(fname, "rb");
    if (!file) {
        perror("Error opening file");
        return FOPEN_ERROR;
    }

    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    if (calculate_md5(fname, md5_hash) != SUCCESS) {
        fclose(file);
        return HASH_ERROR;
    }

    struct sockaddr_in server_addr;
    int sockfd = init_socket(server_ip, &server_addr);
    if (sockfd < 0) {
        fclose(file);
        return sockfd;
    }

    int result;
    
    // Send filename
    if ((result = send_filename_packet(sockfd, fname, &server_addr)) != SUCCESS) {
        goto cleanup;
    }

    // Send MD5 hash
    if ((result = send_md5_packet(sockfd, md5_hash, &server_addr)) != SUCCESS) {
        goto cleanup;
    }

    // Send file data
    if ((result = send_file_data(sockfd, file, &server_addr)) != SUCCESS) {
        goto cleanup;
    }

    printf("File sent successfully.\n");

cleanup:
    fclose(file);
    close(sockfd);
    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <file> <server_ip>\n", argv[0]);
        return 1;
    }

    const char *fname = argv[1];
    const char *server_ip = argv[2];

    int ret = send_file(fname, server_ip);
    printf("Result: %d\n", ret);
    return ret;
}