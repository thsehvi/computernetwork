
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

int sock;
FILE *logfile;

void cleanup(int sig)
{
    printf("\nStopping packet capture...\n");

    if (sock >= 0)
        close(sock);

    if (logfile != NULL)
        fclose(logfile);

    printf("Log file saved successfully.\n");
    exit(0);
}

int main()
{
    unsigned char buffer[65536];
    int tcp = 0, udp = 0, icmp = 0;
    ssize_t size;

    struct ethhdr *eth;
    struct iphdr *iph;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // Open log file
    logfile = fopen("packet_log.txt", "w");

    if (logfile == NULL)
    {
        perror("File opening failed");
        return 1;
    }

    // Create raw socket
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock < 0)
    {
        perror("Socket creation failed (Use sudo)");
        fclose(logfile);
        return 1;
    }

    // Handle Ctrl+C
    signal(SIGINT, cleanup);

    printf("Capturing TCP, UDP and ICMP packets...\n");
    printf("Results are saved in packet_log.txt\n");
    printf("Press Ctrl+C to stop.\n\n");

    while (1)
    {
        size = recvfrom(sock, buffer, sizeof(buffer),
                        0, NULL, NULL);

        if (size < 0)
            continue;

        // Check Ethernet header
        if (size < (ssize_t)sizeof(struct ethhdr))
            continue;

        eth = (struct ethhdr *)buffer;

        // Capture IPv4 packets only
        if (ntohs(eth->h_proto) != ETH_P_IP)
            continue;

        // Locate IP header
        iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

        int ip_len = iph->ihl * 4;

        // Validate IP header
        if (ip_len < 20 ||
            size < (ssize_t)(sizeof(struct ethhdr) + ip_len))
            continue;

        inet_ntop(AF_INET, &iph->saddr,
                  src_ip, sizeof(src_ip));

        inet_ntop(AF_INET, &iph->daddr,
                  dst_ip, sizeof(dst_ip));

        // Locate transport header
        unsigned char *transport =
            buffer + sizeof(struct ethhdr) + ip_len;

        int remaining = size - sizeof(struct ethhdr) - ip_len;

        // TCP packets
        if (iph->protocol == IPPROTO_TCP)
        {
            if (remaining < (int)sizeof(struct tcphdr))
                continue;

            struct tcphdr *tcph =
                (struct tcphdr *)transport;

            fprintf(logfile,
                    "[TCP #%d] %s:%u -> %s:%u | Length: %zd bytes\n",
                    ++tcp, src_ip, ntohs(tcph->source),
                    dst_ip, ntohs(tcph->dest), size);
        }

        // UDP packets
        else if (iph->protocol == IPPROTO_UDP)
        {
            if (remaining < (int)sizeof(struct udphdr))
                continue;

            struct udphdr *udph =
                (struct udphdr *)transport;

            fprintf(logfile,
                    "[UDP #%d] %s:%u -> %s:%u | Length: %zd bytes\n",
                    ++udp, src_ip, ntohs(udph->source),
                    dst_ip, ntohs(udph->dest), size);
        }

        // ICMP packets
        else if (iph->protocol == IPPROTO_ICMP)
        {
            if (remaining < (int)sizeof(struct icmphdr))
                continue;

            struct icmphdr *icmph =
                (struct icmphdr *)transport;

            fprintf(logfile,
                    "[ICMP #%d] %s -> %s | Type: %d, Code: %d\n",
                    ++icmp, src_ip, dst_ip,
                    icmph->type, icmph->code);
        }
        else
        {
            continue;
        }

        // Save data immediately
        fflush(logfile);
    }

    cleanup(0);

    return 0;
}
