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
#define WINDOW_SIZE 10

typedef struct {
    uint32_t sequence_number;  // Sn in the algorithm
    bool termination;
    uint16_t data_size;
    char data[PACKET_MAX_LEN - sizeof(uint32_t)];
    uint32_t crc;
} Packet;

typedef struct {
    uint32_t request_number;  // Rn in the algorithm
    uint32_t crc;
} ControlMessage;

typedef struct {
    Packet packet;
    bool is_occupied;
} PacketBuffer;

static int data_sockfd;
static struct sockaddr_in client_addr;
static socklen_t client_len = sizeof(client_addr);

uint32_t calculate_crc(const void *data, size_t length) {
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
    ControlMessage req;
    req.request_number = packet_num;
    req.crc = calculate_crc(&req.request_number, sizeof(req.request_number));

    client_addr.sin_port = htons(SENDING_PORT);
    if (sendto(data_sockfd, &req, sizeof(req), 0, (struct sockaddr *)&client_addr, client_len) < 0) {
        perror("Failed to send request");
        return -1;
    }
    printf("Sent ACK for packet %u\n", packet_num);
    return 0;
}

bool verify_packet_crc(const Packet *packet) {
    size_t total_length_for_crc = sizeof(packet->sequence_number)
                                 + sizeof(packet->termination)
                                 + sizeof(packet->data_size)
                                 + packet->data_size;
    
    uint32_t calculated_crc = crc32(0L, (const Bytef *)&packet->sequence_number, total_length_for_crc);
    return calculated_crc == packet->crc;
}

int receive_file() {
    char filename[256] = {0};
    unsigned char received_md5[MD5_DIGEST_LENGTH];
    FILE *file = NULL;

    uint32_t Rn = 0;
    uint32_t Sb = 0;
    PacketBuffer buffer[WINDOW_SIZE] = {0};
    Packet packet;

    while (1) {
        ssize_t received = recvfrom(data_sockfd, &packet, sizeof(packet), 0,
                                  (struct sockaddr *)&client_addr, &client_len);

        if (received < 0) {
            perror("ERROR at receiving packet");
        }

        size_t crc_size = sizeof(packet.sequence_number) +
                          sizeof(packet.termination) +
                          sizeof(packet.data_size) +
                          packet.data_size;
        uint32_t computed_crc = crc32(0L, (const Bytef *)&packet.sequence_number, crc_size);

        if (computed_crc != packet.crc) {
            continue;
        }

        printf("Received packet %u (termination: %u)\n", packet.sequence_number, packet.termination);

        if (packet.termination) {
            send_ack(packet.sequence_number);

            while (buffer[Rn % WINDOW_SIZE].is_occupied) {
                fwrite(buffer[Rn % WINDOW_SIZE].packet.data, 1, buffer[Rn % WINDOW_SIZE].packet.data_size, file);
                buffer[Rn % WINDOW_SIZE].is_occupied = false;
                Sb = ++Rn;
            }

            fclose(file);
            break;
        }

        if ((Sb <= packet.sequence_number) && (packet.sequence_number < Sb + WINDOW_SIZE)) {
            if (buffer[packet.sequence_number % WINDOW_SIZE].is_occupied) {
                send_ack(packet.sequence_number);
            }

            buffer[packet.sequence_number % WINDOW_SIZE].packet = packet;
            buffer[packet.sequence_number % WINDOW_SIZE].is_occupied = true;

            send_ack(packet.sequence_number);

            while(buffer[Rn % WINDOW_SIZE].is_occupied) {
                // Receive file name from first packet
                if (buffer[Rn % WINDOW_SIZE].packet.sequence_number == 0)
                {
                    strncpy(filename, buffer[Rn % WINDOW_SIZE].packet.data, buffer[Rn % WINDOW_SIZE].packet.data_size);
                    printf("Receiving file %s\n", filename);
                    file = fopen(filename, "wb");
                }
                // Receive file hash from second packet
                else if (buffer[Rn % WINDOW_SIZE].packet.sequence_number == 1)
                {
                    memcpy(received_md5, buffer[Rn % WINDOW_SIZE].packet.data, MD5_DIGEST_LENGTH);
                    printf("Received file hash: ");
                    print_md5(received_md5);
                }
                // Write other packets into file itself
                else
                {
                    size_t bytes_written = fwrite(buffer[Rn % WINDOW_SIZE].packet.data, 1, buffer[Rn % WINDOW_SIZE].packet.data_size, file);
                    if (bytes_written != buffer[Rn % WINDOW_SIZE].packet.data_size) {
                        perror("ERROR while writing into file");
                    }
                }

                //Empty written packets from buffer
                buffer[Rn % WINDOW_SIZE].is_occupied = false;
                Sb = ++Rn;
            }
        }
        // Received packet which is not in window
        else {
            if (packet.sequence_number < Sb) {
                send_ack(packet.sequence_number);
            }
        }
    }

    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    if (calculate_md5(filename, md5_hash) < 0) {
        return -1;
    }
    printf("Calculated MD5 hash: ");
    print_md5(md5_hash);

    if (memcmp(received_md5, md5_hash, MD5_DIGEST_LENGTH) != 0) {
        printf("Mismatched hashes\n");
    } else {
        printf("Matching hashes! File transfer successfull\n");
    }

    return 0;
}

int main() {
    if (init_sockets() < 0) {
        return 1;
    }

    printf("Receiver started: Data Port %d, ACK Port %d, Window Size: %u\n", RECEIVING_PORT, SENDING_PORT, WINDOW_SIZE);

    if (receive_file() < 0) {
        return 1;
    }

    close(data_sockfd);
    return 0;
}