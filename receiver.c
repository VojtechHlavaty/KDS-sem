
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
#define RECEIVER_PORT 15001
#define SENDER_PORT 14000

typedef struct {
    uint32_t packet_number;
    bool termination;
    uint16_t data_size;
    char data[PACKET_MAX_LEN - sizeof(uint32_t)];
    uint32_t crc;
} Packet;

static int data_sockfd, ack_sockfd;
static struct sockaddr_in client_addr;
static socklen_t client_len = sizeof(client_addr);
float corruption_probability = 0.0; // 10% chance of corruption
float loss_probability = 0.0;       // 10% chance of packet loss

void introduce_bit_error(Packet *packet) {
    if ((float)rand() / RAND_MAX < corruption_probability) {
        size_t byte_to_corrupt = rand() % packet->data_size;
        packet->data[byte_to_corrupt] ^= 1 << (rand() % 8); // Flip a random bit
        printf("Simulated bit error in packet %u\n", packet->packet_number);
    }
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
    receiver_addr.sin_port = htons(RECEIVER_PORT);
    if (bind(data_sockfd, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr)) < 0) {
        perror("Receiver socket bind failed");
        return -1;
    }

    return 0;
}

int send_ack() {
    client_addr.sin_port = htons(SENDER_PORT);
    if (sendto(data_sockfd, "ACK", 3, 0, (struct sockaddr *)&client_addr, client_len) < 0) {
        perror("Failed to send ACK");
        return -1;
    }
    printf("Sent ACK\n");
    return 0;
}

int send_nack() {
    if (sendto(data_sockfd, "NACK", 4, 0, (struct sockaddr *)&client_addr, client_len) < 0) {
        perror("Failed to send NACK");
        return -1;
    }
    printf("Sent NACK\n");
    return 0;
}

int receive_packet(Packet *packet) {
    while (1) {
        ssize_t received = recvfrom(data_sockfd, packet, sizeof(*packet), 0,
                                    (struct sockaddr *)&client_addr, &client_len);
        if (received < 0) {
            perror("Error receiving packet");
            return -1;
        }

        introduce_bit_error(packet);

        if ((float)rand() / RAND_MAX < loss_probability) {
            printf("Simulating packet loss for PACKET %u\n", packet->packet_number);
            continue; // Pretend this packet was lost
        }

        uint32_t calculated_crc = crc32(0L, (const Bytef *)&packet->packet_number,
                                        sizeof(packet->packet_number) +
                                        sizeof(packet->termination) +
                                        packet->data_size);
        if (calculated_crc != packet->crc) {
            fprintf(stderr, "CRC mismatch for packet %u\n", packet->packet_number);
            if (send_nack() < 0) return -1;
            continue;
        }

        send_ack();
        return 0;
    }
}

int main() {
    if (init_sockets() < 0) {
        return 1;
    }

    printf("Receiver started: Data Port %d, ACK Port %d\n", RECEIVER_PORT, SENDER_PORT);

    Packet packet;
    FILE *file = NULL;
    char filename[256];
    unsigned char received_md5[MD5_DIGEST_LENGTH];

    while (1) {
        if (receive_packet(&packet) == 0) {
            if (packet.packet_number == 0) {
                strncpy(filename, packet.data, sizeof(filename) - 1);
                file = fopen(filename, "wb");
                printf("Receiving file: %s\n", filename);
            } else if (packet.packet_number == 1) {
                memcpy(received_md5, packet.data, MD5_DIGEST_LENGTH);
                printf("MD5 hash received\n");
            } else {
                fwrite(packet.data, 1, packet.data_size, file);
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

    if (memcmp(received_md5, calculated_md5, MD5_DIGEST_LENGTH) == 0) {
        printf("File integrity verified with MD5\n");
    } else {
        fprintf(stderr, "MD5 mismatch\n");
    }

    close(data_sockfd);
    close(ack_sockfd);
    return 0;
}