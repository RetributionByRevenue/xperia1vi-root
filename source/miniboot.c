/*
 * miniboot.c — standalone on-device bootstrap client for GhostLock re-root.
 *
 * Adapted from ghostlock-oneplus src/core/miniadb.c: connects to the phone's
 * own adbd (loopback TCP, persist.adb.tcp.port), authenticates the legacy
 * AUTH_TOKEN handshake with a pre-authorized RSA key, opens a shell, and runs
 * one command. Runs from any app context (e.g. Termux) — adbd supplies the
 * uid-2000 shell context for the exploit.
 *
 * Android 14+: signs the auth token with SHA-256 first (SHA-1 fallback with
 * re-auth loop).
 *
 * Env:
 *   MINIADB_KEY  path to the PEM RSA private key (default /data/local/tmp/a/adbkey)
 *   MINIADB_PORT adbd TCP port (default 5555)
 * Usage: miniboot "<shell command>"
 * Exit:  0 = command output contained a success marker, 1 otherwise.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define A_CNXN 0x4e584e43
#define A_AUTH 0x48545541
#define A_OPEN 0x4e45504f
#define A_OKAY 0x59414b4f
#define A_WRTE 0x45545257
#define A_CLSE 0x45534c43
#define AUTH_TOKEN     1
#define AUTH_SIGNATURE 2
#define AUTH_RSAPUBKEY 3
#define ADB_VERSION    0x01000001
#define MAX_PAYLOAD    4096
#define NID_SHA1   64
#define NID_SHA256 672

struct adb_msg {
  uint32_t command, arg0, arg1, data_length, data_crc32, magic;
};

static uint32_t payload_sum(const uint8_t *d, size_t n) {
  uint32_t s = 0;
  for (size_t i = 0; i < n; i++) s += d[i];
  return s;
}

static int adb_send(int fd, uint32_t cmd, uint32_t a0, uint32_t a1,
                    const void *data, uint32_t len) {
  struct adb_msg m = {cmd, a0, a1, len,
                      data ? payload_sum(data, len) : 0,
                      cmd ^ 0xffffffff};
  if (write(fd, &m, 24) != 24) return -1;
  if (len && data && write(fd, data, len) != (ssize_t)len) return -1;
  return 0;
}

static int adb_recv(int fd, struct adb_msg *m, uint8_t *buf, size_t cap) {
  if (read(fd, m, 24) != 24) return -1;
  if (m->data_length > 0) {
    if (m->data_length > cap) return -1;
    size_t got = 0;
    while (got < m->data_length) {
      ssize_t n = read(fd, buf + got, m->data_length - got);
      if (n <= 0) return -1;
      got += n;
    }
  }
  return 0;
}

/* dlopen libcrypto (boringssl) and sign the token. nid: SHA-256 or SHA-1. */
static int sign_token(const uint8_t *tok, size_t tok_len,
                      uint8_t *sig, unsigned *sig_len, int nid,
                      const char *keypath) {
  void *lib = dlopen("libcrypto.so", RTLD_NOW);
  if (!lib) lib = dlopen("/system/lib64/libcrypto.so", RTLD_NOW);
  if (!lib) { fprintf(stderr, "miniboot: dlopen libcrypto: %s\n", dlerror()); return -1; }

  void *(*bio_new_file)(const char *, const char *) = dlsym(lib, "BIO_new_file");
  void *(*pem_read)(void *, void **, void *, void *) =
      dlsym(lib, "PEM_read_bio_RSAPrivateKey");
  int (*rsa_sign)(int, const uint8_t *, unsigned, uint8_t *, unsigned *, void *) =
      dlsym(lib, "RSA_sign");
  void (*rsa_free)(void *) = dlsym(lib, "RSA_free");
  void (*bio_free)(void *) = dlsym(lib, "BIO_free_all");

  if (!bio_new_file || !pem_read || !rsa_sign || !rsa_free || !bio_free) {
    fprintf(stderr, "miniboot: libcrypto missing symbols\n");
    dlclose(lib);
    return -1;
  }

  void *bio = bio_new_file(keypath, "r");
  if (!bio) { fprintf(stderr, "miniboot: cannot open key %s\n", keypath); dlclose(lib); return -1; }

  void *rsa = pem_read(bio, NULL, NULL, NULL);
  bio_free(bio);
  if (!rsa) { fprintf(stderr, "miniboot: cannot parse key\n"); dlclose(lib); return -1; }

  int ok = rsa_sign(nid, tok, tok_len, sig, sig_len, rsa);
  rsa_free(rsa);
  dlclose(lib);
  return ok ? 0 : -1;
}

static int connect_adb(int port) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) { perror("miniboot: socket"); return -1; }
  struct sockaddr_in addr = {
    .sin_family = AF_INET, .sin_port = htons(port),
    .sin_addr.s_addr = htonl(0x7f000001)
  };
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "miniboot: connect 127.0.0.1:%d: %s (adbd not in tcp mode?)\n",
            port, strerror(errno));
    close(sock);
    return -1;
  }
  return sock;
}

/* Run a command through the loopback adb shell; return 1 if `needle`
 * appears in the output, 0 otherwise (or -1 on transport failure). */
static int adb_shell_check(const char *cmd, const char *needle, int port,
                           const char *keypath) {
  int sock = connect_adb(port);
  if (sock < 0) return -1;

  adb_send(sock, A_CNXN, ADB_VERSION, MAX_PAYLOAD, "host::", 7);
  struct adb_msg m;
  uint8_t buf[MAX_PAYLOAD + 1];
  if (adb_recv(sock, &m, buf, MAX_PAYLOAD) < 0) { close(sock); return -1; }

  if (m.command == A_AUTH && m.arg0 == AUTH_TOKEN) {
    static const int nids[2] = {NID_SHA1, NID_SHA256};
    int authed = 0;
    for (int attempt = 0; attempt < 2 && !authed; attempt++) {
      uint8_t sig[512];
      unsigned slen = sizeof(sig);
      if (sign_token(buf, m.data_length, sig, &slen, nids[attempt], keypath) < 0)
        continue;
      adb_send(sock, A_AUTH, AUTH_SIGNATURE, 0, sig, slen);
      if (adb_recv(sock, &m, buf, MAX_PAYLOAD) < 0) { close(sock); return -1; }
      if (m.command == A_CNXN) { authed = 1; break; }
      if (!(m.command == A_AUTH && m.arg0 == AUTH_TOKEN)) break;
    }
    if (!authed) { close(sock); return -1; }
  }

  char cmd_buf[1024];
  int cmd_len = snprintf(cmd_buf, sizeof(cmd_buf), "shell:%s", cmd);
  adb_send(sock, A_OPEN, 1, 0, cmd_buf, cmd_len + 1);

  int found = 0;
  uint32_t rid = 0;
  for (;;) {
    if (adb_recv(sock, &m, buf, MAX_PAYLOAD) < 0) break;
    if (m.command == A_OKAY) {
      rid = m.arg0;
    } else if (m.command == A_WRTE) {
      if (m.data_length <= MAX_PAYLOAD) {
        buf[m.data_length] = 0;
        if (needle && strstr((char *)buf, needle)) found = 1;
        if (!needle) fwrite(buf, 1, m.data_length, stdout);
      }
      adb_send(sock, A_OKAY, 1, rid, NULL, 0);
    } else if (m.command == A_CLSE) {
      break;
    }
  }
  close(sock);
  return found;
}

static int autoroot(int port, const char *keypath) {
  fprintf(stderr, "miniboot: autoroot start\n");

  int r = adb_shell_check("su -c id", "uid=0", port, keypath);
  if (r == 1) { fprintf(stderr, "miniboot: already rooted\n"); return 0; }

  adb_shell_check(
    "setsid nohup /data/local/tmp/ghostlock_native --load-prebuilt-profile "
    "/data/local/tmp/xperia_profile_v4.bin --force-attack "
    "> /data/local/tmp/autorun.log 2>&1 < /dev/null &", NULL, port, keypath);
  fprintf(stderr, "miniboot: exploit launched detached\n");

  for (int i = 0; i < 40; i++) {
    sleep(5);
    r = adb_shell_check("su -c id", "uid=0", port, keypath);
    if (r == 1) { fprintf(stderr, "miniboot: ROOT OK\n"); return 0; }
  }
  fprintf(stderr, "miniboot: no root after polling\n");
  return 1;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s \"<shell command>\" | %s --autoroot\n", argv[0], argv[0]);
    return 2;
  }
  const char *keypath = getenv("MINIADB_KEY");
  if (!keypath || !*keypath) keypath = "/data/local/tmp/a/adbkey";
  int port = 5555;
  const char *p = getenv("MINIADB_PORT");
  if (p && *p) port = atoi(p);

  if (!strcmp(argv[1], "--autoroot"))
    return autoroot(port, keypath);

  fprintf(stderr, "step: entry argc=%d port=%d key=%s\n", argc, port, keypath);
  int sock = connect_adb(port);
  if (sock < 0) { fprintf(stderr, "step: connect_adb failed\n"); return 2; }

  const char *banner = "host::";
  adb_send(sock, A_CNXN, ADB_VERSION, MAX_PAYLOAD, banner, 7);

  struct adb_msg m;
  uint8_t buf[MAX_PAYLOAD + 1];

  fprintf(stderr, "step: CNXN sent\n");
  if (adb_recv(sock, &m, buf, MAX_PAYLOAD) < 0) {
    fprintf(stderr, "miniboot: no response from adbd\n");
    close(sock); return 2;
  }
  fprintf(stderr, "step: got msg cmd=%08x arg0=%u len=%u\n", m.command, m.arg0, m.data_length);

  if (m.command == A_AUTH && m.arg0 == AUTH_TOKEN) {
    /* adbd's token is 20 bytes and the legacy handshake signs it as
     * PKCS#1 DigestInfo(SHA-1) — NID_sha256 fails outright (digest size
     * mismatch). Try SHA-1 first; fall back to SHA-256 / re-challenge. */
    static const int nids[2] = {NID_SHA1, NID_SHA256};
    int authed = 0;
    for (int attempt = 0; attempt < 2 && !authed; attempt++) {
      uint8_t sig[512];
      unsigned slen = sizeof(sig);
      if (sign_token(buf, m.data_length, sig, &slen, nids[attempt], keypath) < 0) {
        fprintf(stderr, "miniboot: sign attempt %d failed, trying next\n", attempt);
        continue;
      }
      adb_send(sock, A_AUTH, AUTH_SIGNATURE, 0, sig, slen);
      if (adb_recv(sock, &m, buf, MAX_PAYLOAD) < 0) {
        fprintf(stderr, "miniboot: no response after auth\n");
        close(sock); return 2;
      }
      if (m.command == A_CNXN) { authed = 1; break; }
      if (!(m.command == A_AUTH && m.arg0 == AUTH_TOKEN)) {
        fprintf(stderr, "miniboot: unexpected %08x after auth\n", m.command);
        close(sock); return 2;
      }
      /* adbd rejected the signature and re-challenged — try the other hash. */
    }
    if (!authed) {
      fprintf(stderr, "miniboot: key not authorized (is the pubkey in /data/misc/adb/adb_keys?)\n");
      close(sock); return 2;
    }
  } else if (m.command != A_CNXN) {
    fprintf(stderr, "miniboot: unexpected %08x\n", m.command);
    close(sock); return 2;
  }

  fprintf(stderr, "miniboot: adbd connected\n");

  char cmd_buf[768];
  int cmd_len = snprintf(cmd_buf, sizeof(cmd_buf), "shell:%s", argv[1]);
  uint32_t lid = 1;
  adb_send(sock, A_OPEN, lid, 0, cmd_buf, cmd_len + 1);

  uint32_t rid = 0;
  int ok = 0;
  for (;;) {
    if (adb_recv(sock, &m, buf, MAX_PAYLOAD) < 0) break;
    if (m.command == A_OKAY) {
      rid = m.arg0;
    } else if (m.command == A_WRTE) {
      if (m.data_length <= MAX_PAYLOAD) {
        buf[m.data_length] = 0;
        fwrite(buf, 1, m.data_length, stdout);
        if (strstr((char *)buf, "child is root") ||
            strstr((char *)buf, "KernelSU ready"))
          ok = 1;
      }
      adb_send(sock, A_OKAY, lid, rid, NULL, 0);
    } else if (m.command == A_CLSE) {
      break;
    }
  }

  close(sock);
  fflush(stdout);
  return ok ? 0 : 1;
}
