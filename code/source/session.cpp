#include "session.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <numeric>
#include <span>
#include <utility>
using namespace std;

extern bool running;

Session::Session(const string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  addr_ll.sll_family = AF_PACKET;
  addr_ll.sll_protocol = htons(ETH_P_ALL); // receive all packets
  addr_ll.sll_ifindex = if_nametoindex(iface.c_str());
  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}

void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  string secret;
  cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        getline(cin, secret);
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) encapsulate("");
        if (!secret.empty() && state.recvPacket) {
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

void Session::dissect(ssize_t rdcnt) {
  auto payload = span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  dissectIPv4(payload);
}

void Session::dissectIPv4(span<uint8_t> buffer) {
  auto&& hdr = *(iphdr*)(buffer.data());
  // TODO:
  // Set `recvPacket = true` if we are receiving packet from remote (server)
  struct in_addr remoteIP;
  inet_pton(AF_INET, "172.18.100.254", &remoteIP.s_addr); // server address
  state.recvPacket = (hdr.saddr == remoteIP.s_addr);

  // Track current IP id
  if (!state.recvPacket) 
    state.ipId = ntohs(hdr.id); // client's ip id

  // Call dissectESP(payload) if next protocol is ESP
  if (hdr.protocol == IPPROTO_ESP) {
    // remove header from buffer, header is in 4-byte words
    auto payload = buffer.last(buffer.size() - hdr.ihl * 4);
    dissectESP(payload);
  }
}

void Session::dissectESP(span<uint8_t> buffer) {
  auto&& hdr = *(ESPHeader*)(buffer.data());
  int hashLength = config.aalg->hashLength();
  // remove header and hash from buffer
  buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength);
  vector<uint8_t> data;
  // Decrypt payload (we don't need this in this project)
  if (!config.ealg->empty()) {
    data = config.ealg->decrypt(buffer);
    buffer = span{data.data(), data.size()};
  }

  // TODO:
  // Track ESP sequence number
  if (state.recvPacket == false) { // client
    state.espseq = ntohl(hdr.seq);
    config.spi = ntohl(hdr.spi);
  }

  // Call dissectTCP(payload) if next protocol is TCP
  auto buffer_trailer = buffer.last(sizeof(ESPTrailer));
  auto&& trailer = *(ESPTrailer*)(buffer_trailer.data());
  if (trailer.next == IPPROTO_TCP) { 
    // remove trailer and padding from buffer
    auto payload = buffer.first(buffer.size() - (int)trailer.padlen - sizeof(ESPTrailer));
    dissectTCP(payload);
  }
}

void Session::dissectTCP(span<uint8_t> buffer) {
  auto&& hdr = *(tcphdr*)(buffer.data());
  auto tcphdr_length = hdr.doff << 2;  // word -(*4)-> byte
  auto payload = buffer.last(buffer.size() - tcphdr_length);

  // TODO:
  // Track tcp parameters
  state.tcpseq = ntohl(hdr.seq) + payload.size();
  state.tcpackseq = ntohl(hdr.ack_seq);
  state.srcPort = ntohs(hdr.source);
  state.dstPort = ntohs(hdr.dest);

  // Is ACK message?
  if (payload.empty()) return;
  // We only get non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    cout << "Secret: " << string(payload.begin(), payload.end()) << endl;
    state.ipId++;
    state.espseq++;
    state.sendAck = true;
  }
}

void Session::encapsulate(const string& payload) {
  auto buffer = span{sendBuffer};
  fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  sendto(sock, sendBuffer, totalLength, 0, (sockaddr*)(&addr), addrLen);
}

uint16_t ipv4_checksum(struct iphdr ip_hdr) {
  uint32_t sum = 0;
  uint16_t* ip = (uint16_t*)(&ip_hdr);
  size_t hdr_len = ip_hdr.ihl * 4;  // in bytes
  for (int i = 0; i < hdr_len / 2; i++) {
    sum += ip[i];
  }

  if (hdr_len & 1) {
    uint16_t last_word = ((uint8_t*)(&ip_hdr))[hdr_len - 1];
    sum += (last_word << 8) & htons(0xFF00);
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return static_cast<uint16_t>(~sum);
}

int Session::encapsulateIPv4(span<uint8_t> buffer, const string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());

  // TODO: Fill IP header
  hdr.version = 4;  // IPv4
  hdr.ihl = 5;      // internet header length 5 bytes
  hdr.ttl = 64;     // time to live
  hdr.id = ntohs(state.ipId) + 1;
  hdr.protocol = IPPROTO_ESP;
  hdr.frag_off = htons(0x4000);             // no fragmentation
  hdr.saddr = inet_addr("172.18.1.1");      // source address
  hdr.daddr = inet_addr("172.18.100.254");  // destination address

  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);

  hdr.tot_len = htons(payloadLength);
  hdr.check = ipv4_checksum(hdr);

  return payloadLength;
}

int Session::encapsulateESP(span<uint8_t> buffer, const string& payload) {
  auto&& hdr = *(ESPHeader*)(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));  

  // TODO: Fill ESP header
  hdr.spi = htonl(config.spi);
  hdr.seq = htonl(state.espseq + 1);

  int payloadLength = encapsulateTCP(nextBuffer, payload);              // tcp header + payload
  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);  // padding + trailer + auth

  // TODO: Calculate padding size and do padding in `endBuffer`
  uint8_t padSize = 4 - ((payloadLength + sizeof(ESPTrailer)) % 4);  // 4-byte alignment
  iota(endBuffer.begin(), endBuffer.begin() + padSize, 1);  // add padding with sequence number starting from 1
  payloadLength += padSize + sizeof(ESPTrailer);  // tcp header + payload + padding + trailer

  // ESP trailer
  endBuffer[padSize] = padSize;          // pad length
  endBuffer[padSize + 1] = IPPROTO_TCP;  // next header

  // Do encryption
  if (!config.ealg->empty()) {  // we don't need this in this project
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }

  payloadLength += sizeof(ESPHeader);  // esp header + tcp header + payload + padding + trailer
  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    auto result = config.aalg->hash(buffer.first(payloadLength));
    copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }
  return payloadLength;
}

uint16_t tcp_checksum(struct tcphdr tcp_hdr, const string& payload) {
  // Calculate the TCP pseudo-header checksum
  uint32_t src_addr = inet_addr("172.18.1.1");
  uint32_t dst_addr = inet_addr("172.18.100.254");
  uint32_t sum = 0;

  sum += (dst_addr >> 16) & 0xFFFF;
  sum += dst_addr & 0xFFFF;
  sum += (src_addr >> 16) & 0xFFFF;
  sum += src_addr & 0xFFFF;
  sum += htons(IPPROTO_TCP);

  uint16_t tcphdr_len = tcp_hdr.th_off * 4;
  uint16_t payload_len = tcphdr_len + payload.size();
  sum += htons(payload_len);

  // allocate a pseudo-header buffer
  uint8_t* buf = (uint8_t*)malloc(payload_len);
  memcpy(buf, &tcp_hdr, tcphdr_len);
  memcpy(buf + tcphdr_len, payload.c_str(), payload.size());
  uint16_t* pshdr = (uint16_t*)buf;

  while (payload_len > 1) {
    sum += *pshdr++;
    payload_len -= 2;
  }

  // padding the last byte if the payload is odd
  if (payload_len) {
    sum += (*pshdr) & htons(0xFF00);
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  
  return static_cast<uint16_t>(~sum);
}

int Session::encapsulateTCP(span<uint8_t> buffer, const string& payload) {
  auto&& hdr = *(tcphdr*)(buffer.data());
  if (!payload.empty()) hdr.psh = 1;  // PSH flag: send data immediately

  // TODO: Fill TCP header
  hdr.ack = 1;                            // there is an ACK sequence number
  hdr.doff = 5;                           // data offset = size of tcp header in 32-bit words
  hdr.dest = htons(state.srcPort);        // send tcp packet back to the source
  hdr.source = htons(state.dstPort);      // so the dst and src are swapped
  hdr.ack_seq = htonl(state.tcpseq);  // ack sequence number: ack the receipt of data up to `tcpseq + 1`
  hdr.seq = htonl(state.tcpackseq);       // sequence number: next sequence number to be sent
  hdr.window = htons(251);                // window size

  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;

  if (!payload.empty()) {
    copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }

  // TODO: Update TCP sequence number
  state.tcpseq += 1; 
  payloadLength += sizeof(tcphdr);

  // TODO: Compute checksum
  hdr.check = tcp_checksum(hdr, payload);

  return payloadLength;
}
