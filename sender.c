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
#include <errno.h>

#define PACKET_MAX_LEN 1024
#define PACKET_MAX_SIZE (1024 - 2 * sizeof(uint32_t) - sizeof(bool) - sizeof(uint16_t))
#define SENDING_PORT 14000
#define RECEIVING_PORT 15001
#define WINDOW_SIZE 10
#define TIMEOUT_SEC 1
#define TIMEOUT_USEC 0

typedef struct {
    uint32_t sequence_number;
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
    bool is_acked;
    struct timeval sent_time;
} PacketBuffer;

static int data_sockfd;
static struct sockaddr_in receiver_data_addr;

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

int init_sockets(const char *receiver_ip) {
    data_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (data_sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin_family = AF_INET;
    sender_addr.sin_addr.s_addr = INADDR_ANY;
    sender_addr.sin_port = htons(RECEIVING_PORT);
    
    if (bind(data_sockfd, (struct sockaddr *)&sender_addr, sizeof(sender_addr)) < 0) {
        perror("Sender socket bind failed");
        return -1;
    }

    memset(&receiver_data_addr, 0, sizeof(receiver_data_addr));
    receiver_data_addr.sin_family = AF_INET;
    receiver_data_addr.sin_port = htons(SENDING_PORT);
    inet_pton(AF_INET, receiver_ip, &receiver_data_addr.sin_addr);

    return 0;
}

int send_packet(Packet *packet) {
    if (sendto(data_sockfd, packet, sizeof(*packet), 0,
               (struct sockaddr *)&receiver_data_addr, sizeof(receiver_data_addr)) < 0) {
        perror("Failed to send packet");
        return -1;
    }

    printf("Sent packet %u (size: %u bytes) (termination: %u)\n", packet->sequence_number, packet->data_size, packet->termination);
    return 0;
}

bool is_timeout(struct timeval *sent_time) {
    struct timeval now, diff;
    gettimeofday(&now, NULL);
    timersub(&now, sent_time, &diff);
    return (diff.tv_sec > TIMEOUT_SEC) || 
           (diff.tv_sec == TIMEOUT_SEC && diff.tv_usec >= TIMEOUT_USEC);
}

int receive_ack(ControlMessage *control_msg) {
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    
    if (setsockopt(data_sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Failed to set socket timeout");
        return -1;
    }

    ssize_t received = recvfrom(data_sockfd, control_msg, sizeof(*control_msg), 0,
                               (struct sockaddr *)&from_addr, &from_len);
    
    return received;
}

int send_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return -1;
    }

    // Calculate MD5 hash first
    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    if (calculate_md5(filename, md5_hash) < 0) {
        fclose(file);
        return -1;
    }
    printf("File MD5 hash: ");
    print_md5(md5_hash);

    PacketBuffer buffer[WINDOW_SIZE] = {0};
    uint32_t Sb = 0;
    uint32_t Sm = 0;

    //Send file name

    Packet packet;
    packet.sequence_number = Sm;
    packet.termination = false;
    packet.data_size = strlen(filename);
    strncpy(packet.data, filename, PACKET_MAX_SIZE - 1);
    size_t crc_size = sizeof(packet.sequence_number) + 
                    sizeof(packet.termination) + 
                    sizeof(packet.data_size) +
                    packet.data_size;
    packet.crc = crc32(0L, (const Bytef *)&packet.sequence_number, crc_size);

    buffer[0].packet = packet;
    buffer[0].is_occupied = true;
    buffer[0].is_acked = false;
    gettimeofday(&buffer[0].sent_time, NULL);
    send_packet(&buffer[0].packet);

    // Wait for filename acknowledgment
    ControlMessage control_msg;
    while (!buffer[0].is_acked) {
        if (receive_ack(&control_msg) > 0) {
            uint32_t computed_crc = crc32(0L, (const Bytef *)&control_msg.request_number, sizeof(control_msg.request_number));
            if (computed_crc == control_msg.crc && control_msg.request_number == Sm) {
                buffer[0].is_acked = true;
                Sb = ++Sm;
            }
        }
        
        // Resend if timeout
        if (!buffer[0].is_acked && is_timeout(&buffer[0].sent_time)) {
            send_packet(&buffer[0].packet);
            gettimeofday(&buffer[0].sent_time, NULL);
        }
    }

    // Now send hash using the same buffer slot
    packet.sequence_number = Sm;
    packet.termination = false;
    packet.data_size = MD5_DIGEST_LENGTH;
    memcpy(packet.data, md5_hash, MD5_DIGEST_LENGTH);
    crc_size = sizeof(packet.sequence_number) +
            sizeof(packet.termination) + 
            sizeof(packet.data_size) +
            packet.data_size;
    packet.crc = crc32(0L, (const Bytef *)&packet.sequence_number, crc_size);

    buffer[0].packet = packet;
    buffer[0].is_occupied = true;
    buffer[0].is_acked = false;
    gettimeofday(&buffer[0].sent_time, NULL);
    send_packet(&buffer[0].packet);

    // Wait for hash acknowledgment
    while (!buffer[0].is_acked) {
        if (receive_ack(&control_msg) > 0) {
            uint32_t computed_crc = crc32(0L, (const Bytef *)&control_msg.request_number, sizeof(control_msg.request_number));
            if (computed_crc == control_msg.crc && control_msg.request_number == Sm) {
                buffer[0].is_acked = true;
                Sb = ++Sm;
            }
        }
        
        // Resend if timeout
        if (!buffer[0].is_acked && is_timeout(&buffer[0].sent_time)) {
            send_packet(&buffer[0].packet);
            gettimeofday(&buffer[0].sent_time, NULL);
        }
    }

    while (1) {
        // Send all packets in window
        while (Sm - Sb < WINDOW_SIZE && !feof(file)) {
            size_t bytes_read = fread(packet.data, 1, PACKET_MAX_SIZE, file);

            if (bytes_read > 0) {
                packet.sequence_number = Sm;
                packet.termination = false;
                packet.data_size = bytes_read;
                crc_size = sizeof(packet.sequence_number) + 
                                    sizeof(packet.termination) + 
                                    sizeof(packet.data_size) +
                                    packet.data_size;
                packet.crc = crc32(0L, (const Bytef *)&packet.sequence_number, crc_size);

                buffer[Sm % WINDOW_SIZE].packet = packet;
                buffer[Sm % WINDOW_SIZE].is_occupied = true;
                buffer[Sm % WINDOW_SIZE].is_acked = false;
                gettimeofday(&buffer[Sm % WINDOW_SIZE].sent_time, NULL);

                send_packet(&buffer[Sm % WINDOW_SIZE].packet);
                Sm ++;
            }
        }

        while (1) {
            if (receive_ack(&control_msg) <= 0){
                break;
            }

            uint32_t computed_crc = crc32(0L, (const Bytef *)&control_msg.request_number, sizeof(control_msg.request_number));

            if (computed_crc == control_msg.crc) {
                printf("Received ACK for packet %u\n", control_msg.request_number);
                buffer[control_msg.request_number % WINDOW_SIZE].is_acked = true;
                while (buffer[Sb % WINDOW_SIZE].is_acked) {
                    buffer[Sb % WINDOW_SIZE].is_occupied = false;
                    buffer[Sb % WINDOW_SIZE].is_acked = false;
                    Sb++;
                }
            }
        }

        for (uint32_t i = Sb; i < Sm; i++) {
            if (buffer[i % WINDOW_SIZE].is_occupied && !buffer[i % WINDOW_SIZE].is_acked) {
                struct timeval now;
                gettimeofday(&now, NULL);
                if (is_timeout(&buffer[i % WINDOW_SIZE].sent_time)) {
                    send_packet(&buffer[i % WINDOW_SIZE].packet);
                    gettimeofday(&buffer[i % WINDOW_SIZE].sent_time, NULL);
                }
            }
        }

        if (Sb == Sm && feof(file)) {
            break;
        }
    }

    bool acked = 0;
    int retries = 0;

    while (!acked && retries < 50){
        printf("Retries: %u\n", retries);
        packet.termination = 1;
        packet.sequence_number = Sm;
        crc_size = sizeof(packet.sequence_number) + 
                            sizeof(packet.termination) + 
                            sizeof(packet.data_size) +
                            packet.data_size;
        packet.crc = crc32(0L, (const Bytef *)&packet.sequence_number, crc_size);
        send_packet(&packet);

        if (receive_ack(&control_msg) <= 0){
            retries ++;
            continue;
        }

        uint32_t computed_crc = crc32(0L, (const Bytef *)&control_msg.request_number, sizeof(control_msg.request_number));
        if (computed_crc == control_msg.crc && control_msg.request_number == Sm + 1) {
            printf("Received ACK for termination packet %u\n", control_msg.request_number);
            acked = true;
        }
    }

    printf("File transmission complete\n");
    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <file> <receiver_ip>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *receiver_ip = argv[2];

    if (init_sockets(receiver_ip) < 0) {
        return 1;
    }

    printf("Sender started: Data Port %d, ACK Port %d, Window Size: %u\n", SENDING_PORT, RECEIVING_PORT, WINDOW_SIZE);
    
    if (send_file(filename) < 0) {
        return 1;
    }

    close(data_sockfd);
    return 0;
}