
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
#include <sys/time.h>

#define PACKET_MAX_LEN 1024
#define PACKET_MAX_SIZE (1024 - 2 * sizeof(uint32_t) - sizeof(bool) - sizeof(uint16_t))
#define SENDER_PORT 14000
#define RECEIVER_PORT 15001 

typedef struct {
    uint32_t packet_number;
    bool termination;
    uint16_t data_size;
    char data[PACKET_MAX_LEN - sizeof(uint32_t)];
    uint32_t crc;
} Packet;

static int data_sockfd, ack_sockfd;
static struct sockaddr_in receiver_data_addr, receiver_ack_addr;

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

int init_sockets(const char *receiver_ip) {
    data_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (data_sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Bind the sender's socket to SENDER_PORT for receiving ACKs
    struct sockaddr_in sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin_family = AF_INET;
    sender_addr.sin_addr.s_addr = INADDR_ANY;
    sender_addr.sin_port = htons(SENDER_PORT);
    if (bind(data_sockfd, (struct sockaddr *)&sender_addr, sizeof(sender_addr)) < 0) {
        perror("Sender socket bind failed");
        return -1;
    }

    // Configure the receiver's address
    memset(&receiver_data_addr, 0, sizeof(receiver_data_addr));
    receiver_data_addr.sin_family = AF_INET;
    receiver_data_addr.sin_port = htons(RECEIVER_PORT);
    inet_pton(AF_INET, receiver_ip, &receiver_data_addr.sin_addr);

    return 0;
}

int send_packet(Packet *packet) {
    packet->crc = crc32(0L, (const Bytef *)&packet->packet_number,
                        sizeof(packet->packet_number) +
                        sizeof(packet->termination) +
                        packet->data_size);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    int retries = 5;

    if (setsockopt(data_sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Failed to set socket timeout");
        return -1;
    }

    while(retries > 0) {

        if (sendto(data_sockfd, packet, sizeof(*packet), 0,
               (struct sockaddr *)&receiver_data_addr, sizeof(receiver_data_addr)) < 0) {
        perror("Failed to send packet");
        return -1;
        } 

        printf("Sent PACKET %u, PACKET SIZE: %u bytes (TERMINATION: %u)\n", packet->packet_number, packet->data_size, packet->termination);

        char ack_buffer[16];
        struct sockaddr_in ack_from;
        socklen_t ack_len = sizeof(ack_from);
        ssize_t response_size = recvfrom(data_sockfd, ack_buffer, sizeof(ack_buffer), 0,
                    (struct sockaddr *)&ack_from, &ack_len);

        if (response_size < 0) {
            printf("Timeout or error receiving response, remaning retries: %u\n", retries);
            retries--;
            continue; // Retry sending the packet
        }

        if (strncmp(ack_buffer, "ACK", 3) == 0) {
            printf("Received ACK for PACKET %u\n", packet->packet_number);
            return 0; // Successfully acknowledged
        } else if (strncmp(ack_buffer, "NACK", 4) == 0) {
            printf("Received NACK for PACKET %u, resending...\n", packet->packet_number);
            continue; // Resend the packet
        } else {
            printf("Unexpected response: %.*s\n", (int)response_size, ack_buffer);
        }
    }
    printf("Failed to send PACKET %u after %u tries, ending\n", packet->packet_number, retries);
    return -1;
}


int main(int argc, char *argv[]) {

    struct timeval start_time, end_time;
    size_t total_data_sent = 0;
    gettimeofday(&start_time, NULL);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <file> <receiver_ip>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *receiver_ip = argv[2];
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    init_sockets(receiver_ip);

    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    calculate_md5(filename, md5_hash);

    Packet packet = {0};
    strncpy(packet.data, filename, PACKET_MAX_SIZE - 1);
    packet.packet_number = 0;
    packet.data_size = strlen(filename) + 1;
    send_packet(&packet);

    packet.packet_number = 1;
    memcpy(packet.data, md5_hash, MD5_DIGEST_LENGTH);
    packet.data_size = MD5_DIGEST_LENGTH;
    send_packet(&packet);

    size_t bytes_read;
    uint32_t packet_number = 2;
    while ((bytes_read = fread(packet.data, 1, PACKET_MAX_SIZE, file)) > 0) {
        packet.packet_number = packet_number++;
        packet.data_size = bytes_read;
        packet.termination = feof(file);

        if (send_packet(&packet) < 0) {
            fclose(file);
            return 1;
        }

        total_data_sent += sizeof(packet);

        if (packet.termination) {
            printf("Final packet sent, terminating sender.\n");
            break;
        }
    }

    gettimeofday(&end_time, NULL);

    double elapsed_time = (end_time.tv_sec - start_time.tv_sec) +
                          (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

    double transmission_speed = (total_data_sent * 8) / elapsed_time;

    printf("Total Data Sent: %zu bytes\n", total_data_sent);
    printf("Elapsed Time: %.2f seconds\n", elapsed_time);
    printf("Transmission Speed: %.2f bps\n", transmission_speed);

    fclose(file);
    return 0;
}