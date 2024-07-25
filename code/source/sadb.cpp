#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>

using namespace std;

optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  vector<uint8_t> message(65536);
  sadb_msg msg{};

  // TODO: Fill sadb_msg
  bzero(&msg, sizeof(msg));
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type = SADB_DUMP;
  msg.sadb_msg_satype = SADB_SATYPE_ESP;
  msg.sadb_msg_len = sizeof(msg) / 8;  // Length in 64-bit words
  msg.sadb_msg_pid = getpid();

  // TODO: Create a PF_KEY_V2 socket and write msg to it
  // Then read from socket to get SADB information
  int sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  if (sock < 0) {
    cerr << "Failed to create PF_KEY_V2 socket." << endl;
    return nullopt;
  }

  // Send message
  if (write(sock, &msg, sizeof(msg)) < 0) {
    cerr << "Failed to send SADB message." << endl;
    close(sock);
    return nullopt;
  }

  // Receive response
  char buf[4096];
  ssize_t msglen = read(sock, &buf, sizeof(buf));
  struct sadb_msg *msgp = (sadb_msg *)(&buf);

  // Close socket
  close(sock);

  // TODO: Set size to number of bytes in response message

  // Has SADB entry
  if (msglen != sizeof(sadb_msg)) {
    ESPConfig config{};

    // TODO: Parse SADB message
    struct sadb_ext *ext = (struct sadb_ext *)(msgp + 1);
    struct sadb_sa *sa;            // security association
    struct sadb_key *key;          // authenticaiton key
    struct sockaddr_in *src_addr;  // source address
    struct sockaddr_in *dst_addr;  // destination address

    msglen -= sizeof(sadb_msg);  // subtract the size of the sadb_msg (header)

    while (msglen > 0) {
      if (ext->sadb_ext_type == SADB_RESERVED) {
        break;
      } else if (ext->sadb_ext_type == SADB_EXT_SA) {
        sa = (struct sadb_sa *)(ext);
      } else if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH) {  // auth key
        key = (struct sadb_key *)(ext);
      } else if (ext->sadb_ext_type == SADB_EXT_ADDRESS_SRC) {
        struct sadb_address *addr = (struct sadb_address *)(ext);
        src_addr = (struct sockaddr_in *)(addr + 1);
      } else if (ext->sadb_ext_type == SADB_EXT_ADDRESS_DST) {
        struct sadb_address *addr = (struct sadb_address *)(ext);
        dst_addr = (struct sockaddr_in *)(addr + 1);
      }
      // Move to the next extension
      ext = (struct sadb_ext *)((char *)(ext) + (ext->sadb_ext_len * 8)); // jump 64 bits
      msglen -= ext->sadb_ext_len * 8;                                    // subtract the size of the extension
    }

    // Security association (spi)
    config.spi = ntohs(sa->sadb_sa_spi);

    // Authentication algorithm (aalg id, key)
    config.aalg = make_unique<ESP_AALG>(sa->sadb_sa_auth, span<uint8_t>((uint8_t *)(key + 1), (uint8_t *)(key + 1) + key->sadb_key_bits / 8));

    // Encryption algorithm (there is none in this project)
    config.ealg = make_unique<ESP_EALG>(SADB_EALG_NONE, span<uint8_t>{});

    // Source and destination addresses
    config.local = ipToString(dst_addr->sin_addr.s_addr);
    config.remote = ipToString(src_addr->sin_addr.s_addr);

    return config;
  }

  cerr << "SADB entry not found." << endl;
  return nullopt;
}

ostream &operator<<(ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << left << setw(30) << setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << endl;
  } else {
    os << "NONE" << endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << left << setw(30) << setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << endl;
  } else {
    os << "NONE" << endl;
  }
  os << "Local : " << config.local << endl;
  os << "Remote: " << config.remote << endl;
  os << "------------------------------------------------------------";
  return os;
}
