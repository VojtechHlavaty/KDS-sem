#include <sys/socket.h>
#include <zlib.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>

#define PACKET_MAX_LEN 1024
#define PACKET_MAX_SIZE (1024 - 2 * sizeof(uint32_t) - sizeof(bool) - sizeof(uint16_t))
#define RECEIVING_PORT 15000
#define SENDING_PORT 14001

typedef struct {
    uint32_t packet_number;
    bool termination;
    uint16_t data_size;
    char data[PACKET_MAX_LEN - sizeof(uint32_t)];
    uint32_t crc;
} Packet;

typedef struct {
    uint32_t crc;
    char message[16];
} ControlMessage;

static int data_sockfd, ack_sockfd;
static struct sockaddr_in client_addr;
static socklen_t client_len = sizeof(client_addr);
static uint32_t expected_packet = 0;

uint32_t calculate_crc(const char *data, size_t length) {
    return crc32(0L, (const Bytef *)data, length);
}

int calculate_md5(const char *filename, unsigned char *hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file for MD5 calculation");
        return -1;
    }

    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);

    char buffer[PACKET_MAX_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, PACKET_MAX_SIZE, file)) > 0) {
        MD5_Update(&md5_ctx, buffer, bytes_read);
    }

    fclose(file);
    MD5_Final(hash, &md5_ctx);
    return 0;
}

void print_md5(const unsigned char *hash) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int init_sockets() {
    data_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (data_sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in receiver_addr;
    memset(&receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_addr.s_addr = INADDR_ANY;
    receiver_addr.sin_port = htons(RECEIVING_PORT);
    if (bind(data_sockfd, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr)) < 0) {
        perror("Receiver socket bind failed");
        return -1;
    }

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(SENDING_PORT);

    return 0;
}

int send_ack(uint32_t packet_num) {
    ControlMessage ack;
    strncpy(ack.message, "ACK", sizeof(ack.message));
    ack.crc = calculate_crc(ack.message, strlen(ack.message));

    client_addr.sin_port = htons(SENDING_PORT);
    if (sendto(data_sockfd, &ack, sizeof(ack), 0, (struct sockaddr *)&client_addr, client_len) < 0) {
        perror("Failed to send ACK");
        return -1;
    }
    printf("Sent ACK for packet %u with CRC: %u\n", packet_num, ack.crc);
    return 0;
}

int send_nack(uint32_t packet_num) {
    ControlMessage nack;
    strncpy(nack.message, "NACK", sizeof(nack.message));
    nack.crc = calculate_crc(nack.message, strlen(nack.message));

    if (sendto(data_sockfd, &nack, sizeof(nack), 0, (struct sockaddr *)&client_addr, client_len) < 0) {
        perror("Failed to send NACK");
        return -1;
    }
    printf("Sent NACK for packet %u with CRC: %u\n", packet_num, nack.crc);
    return -1;
}

int receive_packet(Packet *packet) {
    while (1) {
        ssize_t received = recvfrom(data_sockfd, packet, sizeof(*packet), 0,
                                    (struct sockaddr *)&client_addr, &client_len);
        if (received < 0) {
            perror("Error receiving packet");
            return -1;
        }

        size_t total_length_for_crc = sizeof(packet->packet_number)
                                    + sizeof(packet->termination)
                                    + sizeof(packet->data_size)
                                    + packet->data_size;

        uint32_t calculated_crc = crc32(0L, (const Bytef *)&packet->packet_number, total_length_for_crc);

        if (calculated_crc != packet->crc) {
            fprintf(stderr, "CRC mismatch for packet %u\n", packet->packet_number);
            send_nack(packet->packet_number);
            continue;
        }

        // Handle out-of-order packets
        if (packet->packet_number != expected_packet) {
            printf("Out-of-order packet received: got %u, expected %u\n", 
                   packet->packet_number, expected_packet);
            send_ack(packet->packet_number);  // Still ACK to prevent sender retransmission
            continue;
        }

        // Send ACK for the correct packet
        if (send_ack(packet->packet_number) < 0) {
            return -1;
        }

        return 0;
    }
}

int main() {
    if (init_sockets() < 0) {
        return 1;
    }

    printf("Receiver started: Data Port %d, ACK Port %d\n", RECEIVING_PORT, SENDING_PORT);

    Packet packet;
    FILE *file = NULL;
    char filename[256];
    unsigned char received_md5[MD5_DIGEST_LENGTH];
    expected_packet = 0;

    while (1) {
        if (receive_packet(&packet) == 0) {
            if (packet.packet_number == 0) {
                strncpy(filename, packet.data, sizeof(filename) - 1);
                file = fopen(filename, "wb");
                printf("Receiving file: %s\n", filename);
                expected_packet++;
            } else if (packet.packet_number == 1) {
                memcpy(received_md5, packet.data, MD5_DIGEST_LENGTH);
                printf("MD5 hash received: ");
                print_md5(received_md5);
                expected_packet++;
            } else {
                fwrite(packet.data, 1, packet.data_size, file);
                expected_packet++;
                
                if (packet.termination) {
                    fclose(file);
                    printf("File received successfully\n");
                    break;
                }
            }
        }
    }

    unsigned char calculated_md5[MD5_DIGEST_LENGTH];
    calculate_md5(filename, calculated_md5);

    printf("Calculated MD5 hash: ");
    print_md5(calculated_md5);

    if (memcmp(received_md5, calculated_md5, MD5_DIGEST_LENGTH) == 0) {
        printf("File integrity verified with MD5\n");
    } else {
        fprintf(stderr, "MD5 mismatch\n");
    }

    close(data_sockfd);
    close(ack_sockfd);
    return 0;
}