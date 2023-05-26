#include <criterion/criterion.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <wait.h>

/* Directory in which to create test output files. */
#define TEST_OUTPUT "test_output/"

static void init() {
#ifndef NO_SERVER
    int ret;
    int i = 0;
    do { // Wait for server to start
	ret = system("netstat -an | fgrep '0.0.0.0:9999' > /dev/null");
	sleep(1);
    } while(++i < 30 && WEXITSTATUS(ret));
#endif
}

static void fini() {
}

/*
 * Thread to run a command using system() and collect the exit status.
 */
void *system_thread(void *arg) {
    long ret = system((char *)arg);
    return (void *)ret;
}

// Criterion seems to sort tests by name.  This one can't be delayed
// or others will time out.
Test(student_suite, 00_start_server, .timeout = 30) {
    fprintf(stderr, "server_suite/00_start_server\n");
    int server_pid = 0;
    int ret = system("netstat -an | fgrep '0.0.0.0:9998' > /dev/null");
    cr_assert_neq(WEXITSTATUS(ret), 0, "Server was already running");
    fprintf(stderr, "Starting server...");
    if((server_pid = fork()) == 0) {
	execlp("valgrind", "jeux", "--leak-check=full", "--track-fds=yes",
	       "--error-exitcode=37", "--log-file="TEST_OUTPUT"valgrind.out", "bin/jeux", "-p", "9999", NULL);
	fprintf(stderr, "Failed to exec server\n");
	abort();
    }
    fprintf(stderr, "pid = %d\n", server_pid);
    char *cmd = "sleep 10";
    pthread_t tid;
    pthread_create(&tid, NULL, system_thread, cmd);
    pthread_join(tid, NULL);
    cr_assert_neq(server_pid, 0, "Server was not started by this test");
    fprintf(stderr, "Sending SIGHUP to server pid %d\n", server_pid);
    kill(server_pid, SIGHUP);
    sleep(5);
    kill(server_pid, SIGKILL);
    wait(&ret);
    fprintf(stderr, "Server wait() returned = 0x%x\n", ret);
    if(WIFSIGNALED(ret)) {
	fprintf(stderr, "Server terminated with signal %d\n", WTERMSIG(ret));	
	system("cat "TEST_OUTPUT"valgrind.out");
	if(WTERMSIG(ret) == 9)
	    cr_assert_fail("Server did not terminate after SIGHUP");
    }
    if(WEXITSTATUS(ret) == 37)
	system("cat "TEST_OUTPUT"valgrind.out");
    cr_assert_neq(WEXITSTATUS(ret), 37, "Valgrind reported errors");
    cr_assert_eq(WEXITSTATUS(ret), 0, "Server exit status was not 0");
}

Test(student_suite, 01_connect, .init = init, .fini = fini, .timeout = 5) {
    fprintf(stderr, "server_suite/01_connect\n");
    int ret = system("util/jclient -p 9999 </dev/null | grep 'Connected to server'");
    cr_assert_eq(ret, 0, "expected %d, was %d\n", 0, ret);
}


///////////////////////////////////// CLIENT REGISTRY TESTS /////////////////////////////////////////
* The maximum number of "file descriptors" we will use. */
#define NFD (64)

/* The maximum number of clients we will register. */
#define NCLIENT (64)

/* Number of threads we create in multithreaded tests. */
#define NTHREAD (10)

/* Number of iterations we use in several tests. */
#define NITER (1000000)

/*
 * Shared pool of "file descriptors".  Simulates file descriptors
 * that the system might have assigned to client threads.
 */
static int fdpool[NFD];
static pthread_mutex_t fdpool_lock;

/*
 * Client objects that have been registered.
 * These are needed in order to unregister.
 */
static CLIENT *clients[NFD];

/*
 * Get an unassigned "file descriptor", assign it to a particular
 * client ID, and return the index.
 */
static int getfd(int cid) {
    pthread_mutex_lock(&fdpool_lock);
    // Don't use possibly valid fds, because people try to close them.
    for(int i = 20; i < NFD; i++) {
	if(fdpool[i] == -1) {
	    fdpool[i] = cid;
	    pthread_mutex_unlock(&fdpool_lock);
	    return i;
	}
    }
    pthread_mutex_unlock(&fdpool_lock);
    return -1;
}

/*
 * Release a specified "file descriptor" if assigned to a particular
 * client ID.  If it is not assigned to that client ID, do nothing.
 */
static void relfd(int fd, int cid) {
    pthread_mutex_lock(&fdpool_lock);
    if(fdpool[fd] == cid) {
	fdpool[fd] = -1;
	clients[fd] = NULL;
    }
    pthread_mutex_unlock(&fdpool_lock);
}

static void init() {
    pthread_mutex_init(&fdpool_lock, NULL);
    for(int i = 0; i < NFD; i++)
	fdpool[i] = -1;
}

#define CLIENT_UP(cr, fds, cid) \
   do { \
     int fd = getfd(cid); \
     if(fd != -1) { \
       fds[cid] = fd; \
       clients[fd] = creg_register(cr, fd); \
     } else { \
       fds[cid] = -1; \
     } \
     cid++; \
   } while(0)

#define CLIENT_DOWN(cr, fds, cid) \
   do { \
     cid--; \
     int fd = fds[cid]; \
     if(fd != -1) { \
       creg_unregister(cr, clients[fd]); \
       relfd(fd, cid); \
     } \
   } while(0)

/*
 * Randomly register and unregister clients, then unregister
 * all remaining registered at the end.
 */
void random_reg_unreg(CLIENT_REGISTRY *cr, int n) {
    int cid = 0;
    unsigned int seed = 1; //pthread_self();
    // Array mapping client IDs to file descriptors.
    int fds[NCLIENT];
    for(int i = 0; i < NCLIENT; i++)
	fds[i] = -1;
    for(int i = 0; i < n; i++) {
	if(cid == 0) {
	    // No clients: only way to go is up!
	    CLIENT_UP(cr, fds, cid);
	} else if(cid == NCLIENT) {
	    // Clients maxxed out: only way to go is down!
	    CLIENT_DOWN(cr, fds, cid);
	} else {
	    if(rand_r(&seed) % 2) {
		CLIENT_UP(cr, fds, cid);
	    } else {
		CLIENT_DOWN(cr, fds, cid);
	    }
	}
    }
    // Unregister any remaining file descriptors at the end.
    while(cid > 0)
	CLIENT_DOWN(cr, fds, cid);
}

/*
 * Thread that calls wait_for_empty on a client registry, then checks a set of flags.
 * If all flags are nonzero, the test succeeds, otherwise return from wait_for_empty
 * was premature and the test fails.
 */
struct wait_for_empty_args {
    CLIENT_REGISTRY *cr;
    volatile int *flags;
    int nflags;
    int ret;
};

void *wait_for_empty_thread(void *arg) {
    struct wait_for_empty_args *ap = arg;
    creg_wait_for_empty(ap->cr);
    ap->ret = 1;
    for(int i = 0; i < ap->nflags; i++) {
	if(ap->flags[i] == 0) {
	    ap->ret = 0;
	}
    }
    return NULL;
}

/*
 * Thread that runs random register/unregister, then sets a flag.
 * The thread delays at the start of the test, to make it more likely
 * that other threads started at about the same time are active.
 */
struct random_reg_unreg_args {
    CLIENT_REGISTRY *cr;
    volatile int *done_flag;
    int iters;
    int start_delay;
};

void *random_reg_unreg_thread(void *arg) {
    struct random_reg_unreg_args *ap = arg;
    if(ap->start_delay)
	sleep(ap->start_delay);
    random_reg_unreg(ap->cr, ap->iters);
    if(ap->done_flag != NULL)
	*ap->done_flag = 1;
    return NULL;
}

/*
 * Test one registry, one thread doing random register/unregister,
 * and that thread calling creg_wait_for_empty does not block forever.
 */
Test(client_registry_suite, basic_one_registry, .init = init, .timeout = 5) {
#ifdef NO_CLIENT_REGISTRY
    cr_assert_fail("Client registry was not implemented");
#endif
    // Initialize a thread counter, randomly register and unregister,
    // ending with nothing registered, then call wait_for_zero.
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    // Spawn a thread to run random increment/decrement.
    pthread_t tid;
    struct random_reg_unreg_args *ap = calloc(1, sizeof(struct random_reg_unreg_args));
    ap->cr = cr;
    ap->iters = 100;
    pthread_create(&tid, NULL, random_reg_unreg_thread, ap);

    // Wait for the increment/decrement to complete.
    pthread_join(tid, NULL);

    // Call wait_for_zero -- should not time out.
    creg_wait_for_empty(cr);
    cr_assert(1, "Timed out waiting for zero");
}

/*
 * Test two registries, two threads doing random increment/decrement,
 * and that thread calling creg_wait_for_empty does not block forever.
 */
Test(client_registry_suite, basic_two_registries, .init = init, .timeout = 5) {
#ifdef NO_CLIENT_REGISTRY
    cr_assert_fail("Client registry was not implemented");
#endif
    // Do the same test with two registries and two threads
    CLIENT_REGISTRY *cr1 = creg_init();
    cr_assert_not_null(cr1);
    CLIENT_REGISTRY *cr2 = creg_init();
    cr_assert_not_null(cr2);

    // Spawn a thread to run random register/unregister.
    pthread_t tid1;
    struct random_reg_unreg_args *ap1 = calloc(1, sizeof(struct random_reg_unreg_args));
    ap1->cr = cr1;
    ap1->iters = NITER;
    pthread_create(&tid1, NULL, random_reg_unreg_thread, ap1);

    // Spawn a thread to run random increment/decrement.
    pthread_t tid2;
    struct random_reg_unreg_args *ap2 = calloc(1, sizeof(struct random_reg_unreg_args));
    ap2->cr = cr2;
    ap2->iters = NITER;
    pthread_create(&tid2, NULL, random_reg_unreg_thread, ap2);

    // Wait for both threads to finish.
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);

    // Call wait_for_empty -- should not time out.
    creg_wait_for_empty(cr1);
    creg_wait_for_empty(cr2);
    cr_assert(1);
}

/*
 * Test one registry, one thread doing random register/unregister,
 * check that thread calling creg_wait_for_empty does not return prematurely.
 */
Test(client_registry_suite, basic_one_registry_premature, .init = init, .timeout = 5) {
#ifdef NO_CLIENT_REGISTRY
    cr_assert_fail("Client registry was not implemented");
#endif
    // Initialize a client registry, randomly register and deregister,
    // then call wait_for_empty.
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    // Register a client to temporarily prevent an empty situation.
    int fd = getfd(NCLIENT+1);  // Client ID out-of-range of random register/unregister.
    CLIENT *client = creg_register(cr, fd);

    // Create a flag to be set when random increment/decrement is finished.
    // This probably should be done more properly.
    volatile int flags[1] = { 0 };

    // Spawn a thread to wait for empty and then check the flag.
    pthread_t tid1;
    struct wait_for_empty_args *ap1 = calloc(1, sizeof(struct wait_for_empty_args));
    ap1->cr = cr;
    ap1->flags = flags;
    ap1->nflags = 1;
    pthread_create(&tid1, NULL, wait_for_empty_thread, ap1);

    // Spawn a thread to run a long random register/unregister test and set flag.
    pthread_t tid2;
    struct random_reg_unreg_args *ap2 = calloc(1, sizeof(struct random_reg_unreg_args));
    ap2->cr = cr;
    ap2->iters = NITER;
    ap2->done_flag = &flags[0];
    pthread_create(&tid2, NULL, random_reg_unreg_thread, ap2);

    // Wait for the increment/decrement to complete, then release the thread counter.
    pthread_join(tid2, NULL);
    creg_unregister(cr, client);

    // Get the result from the waiting thread, to see if it returned prematurely.
    pthread_join(tid1, NULL);

    // Assert that the flag was set when the wait was finished.
    cr_assert(ap1->ret, "Premature return from creg_wait_for_empty");
}

Test(client_registry_suite, many_threads_one_registry, .init = init, .timeout = 15) {
#ifdef NO_CLIENT_REGISTRY
    cr_assert_fail("Client registry was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    // Spawn threads to run random increment/decrement.
    pthread_t tid[NTHREAD];
    for(int i = 0; i < NTHREAD; i++) {
	struct random_reg_unreg_args *ap = calloc(1, sizeof(struct random_reg_unreg_args));
	ap->cr = cr;
	ap->iters = NITER;
	pthread_create(&tid[i], NULL, random_reg_unreg_thread, ap);
    }

    // Wait for all threads to finish.
    for(int i = 0; i < NTHREAD; i++)
	pthread_join(tid[i], NULL);

    // Call wait_for_empty -- should not time out.
    creg_wait_for_empty(cr);
    cr_assert(1);
}

Test(client_registry_suite, many_threads_one_registry_premature, .init = init, .timeout = 15) {
#ifdef NO_CLIENT_REGISTRY
    cr_assert_fail("Client registry was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    // Register a client to temporarily prevent an empty situation.
    int fd = getfd(NCLIENT+1);  // Client ID out-of-range of random register/unregister.
    CLIENT *client = creg_register(cr, fd);
 
    // Create flags to be set when random increment/decrement is finished.
    // This probably should be done more properly.
    volatile int flags[NTHREAD] = { 0 };

    // Spawn a thread to wait for empty and then check all the flags.
    pthread_t tid1;
    struct wait_for_empty_args *ap1 = calloc(1, sizeof(struct wait_for_empty_args));
    ap1->cr = cr;
    ap1->flags = flags;
    ap1->nflags = NTHREAD;
    pthread_create(&tid1, NULL, wait_for_empty_thread, ap1);

    // Spawn threads to run random register/unregister.
    pthread_t tid[NTHREAD];
    for(int i = 0; i < NTHREAD; i++) {
	struct random_reg_unreg_args *ap = calloc(1, sizeof(struct random_reg_unreg_args));
	ap->cr = cr;
	ap->iters = NITER;
	ap->done_flag = &flags[i];
	pthread_create(&tid[i], NULL, random_reg_unreg_thread, ap);
    }

    // Wait for all threads to finish, then release the thread counter.
    for(int i = 0; i < NTHREAD; i++)
	pthread_join(tid[i], NULL);
    creg_unregister(cr, client);

    // Get the result from the waiting thread, to see if it returned prematurely.
    pthread_join(tid1, NULL);

    // Assert that the flags were all set when the wait was finished.
    cr_assert(ap1->ret, "Premature return from creg_wait_for_empty");
}

Test(client_registry_suite, lookup_null, .init = init, .timeout = 15) {
#ifdef NO_CLIENT_REGISTRY
    cr_assert_fail("Client registry was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    CLIENT *client = creg_lookup(cr, "Bob");
    cr_assert_eq(client, NULL, "Returned value (%p) was not NULL", client);
}

Test(client_registry_suite, register_login_lookup_null, .init = init, .timeout = 15) {
#ifdef NO_CLIENT_REGISTRY
    cr_assert_fail("Client registry was not implemented");
#endif
    CLIENT_REGISTRY *cr = client_registry = creg_init();
    cr_assert_not_null(cr);
    PLAYER_REGISTRY *pr = player_registry = preg_init();
    cr_assert_not_null(pr);

    CLIENT *alice_client = creg_register(cr, 10);
    PLAYER *alice_player = preg_register(pr, "Alice");
    int err = client_login(alice_client, alice_player);
    cr_assert_eq(err, 0, "Error logging in client");

    CLIENT *client = creg_lookup(cr, "Bob");
    cr_assert_eq(client, NULL, "Returned value (%p) was not NULL", client);
}

Test(client_registry_suite, register_login_lookup_not_null, .init = init, .timeout = 15) {
#ifdef NO_CLIENT_REGISTRY
    cr_assert_fail("Client registry was not implemented");
#endif
    CLIENT_REGISTRY *cr = client_registry = creg_init();
    cr_assert_not_null(cr);
    PLAYER_REGISTRY *pr = player_registry = preg_init();
    cr_assert_not_null(pr);

    CLIENT *alice_client = creg_register(cr, 10);
    PLAYER *alice_player = preg_register(pr, "Alice");
    int err = client_login(alice_client, alice_player);
    cr_assert_eq(err, 0, "Error logging in client");

    CLIENT *client = creg_lookup(cr, "Alice");
    cr_assert_eq(client, alice_client, "Returned value (%p) was not the expected value (%p)",
		  client, alice_client);
}

Test(client_registry_suite, all_players_nonempty, .init = init, .timeout = 15) {
    int err;
#ifdef NO_CLIENT_REGISTRY
    cr_assert_fail("Client registry was not implemented");
#endif
    CLIENT_REGISTRY *cr = client_registry = creg_init();
    cr_assert_not_null(cr);
    PLAYER_REGISTRY *pr = player_registry = preg_init();
    cr_assert_not_null(pr);

    CLIENT *alice_client = creg_register(cr, 10);
    PLAYER *alice_player = preg_register(pr, "Alice");
    err = client_login(alice_client, alice_player);
    cr_assert_eq(err, 0, "Error logging in client");

    CLIENT *bob_client = creg_register(cr, 11);
    PLAYER *bob_player = preg_register(pr, "Bob");
    err = client_login(bob_client, bob_player);
    cr_assert_eq(err, 0, "Error logging in client");

    CLIENT *carol_client = creg_register(cr, 12);
    PLAYER *carol_player = preg_register(pr, "Carol");
    err = client_login(carol_client, carol_player);
    cr_assert_eq(err, 0, "Error logging in client");

    PLAYER **players = creg_all_players(cr);
    PLAYER **player = players;
    while(*player != NULL && player - players <= 3) {
	// Refcount of player should be at least 4:
	//   One for PLAYER variable
	//   One for CLIENT
	//   One for player registry
	//   One for players array
	for(int i = 0; i < 4; i++)
	    player_unref(*player, "to check for increased refcount");
	player++;
    }
    cr_assert_eq(player - players, 3, "Number of players (%ld) was not the expected value (%ld)",
		 player-players, 3);
    cr_assert_eq(*player, NULL, "Too many players or players list not NULL-terminated");
}

Test(client_registry_suite, all_players_empty, .init = init, .timeout = 15) {
#ifdef NO_CLIENT_REGISTRY
    cr_assert_fail("Client registry was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    PLAYER **players = creg_all_players(cr);
    cr_assert_eq(*players, NULL, "Players list not NULL-terminated");
}

/////////////////////////////////////////// CLIENT TEST //////////////////////////////////////////////
/* Number of iterations for which we run the concurrency test. */
#define NITERS (100000)

/* Maximum number of invitations we issue in the concurrency test. */
#define NINVITATION (100)

static char *jeux_packet_type_names[] = {
    [JEUX_NO_PKT]       "NONE",
    [JEUX_LOGIN_PKT]    "LOGIN",
    [JEUX_USERS_PKT]    "USERS",
    [JEUX_INVITE_PKT]   "INVITE",
    [JEUX_REVOKE_PKT]   "REVOKE",
    [JEUX_ACCEPT_PKT]   "ACCEPT",
    [JEUX_DECLINE_PKT]  "DECLINE",
    [JEUX_MOVE_PKT]     "MOVE",
    [JEUX_RESIGN_PKT]   "RESIGN",
    [JEUX_ACK_PKT]      "ACK",
    [JEUX_NACK_PKT]     "NACK",
    [JEUX_INVITED_PKT]  "INVITED",
    [JEUX_REVOKED_PKT]  "REVOKED",
    [JEUX_ACCEPTED_PKT] "ACCEPTED",
    [JEUX_DECLINED_PKT] "DECLINED",
    [JEUX_MOVED_PKT]    "MOVED",
    [JEUX_RESIGNED_PKT] "RESIGNED",
    [JEUX_ENDED_PKT]    "ENDED"
};

static void proto_init_packet(JEUX_PACKET_HEADER *pkt, JEUX_PACKET_TYPE type, size_t size) {
    memset(pkt, 0, sizeof(*pkt));
    pkt->type = type;
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
	perror("clock_gettime");
    }
    pkt->timestamp_sec = htonl(ts.tv_sec);
    pkt->timestamp_nsec = htonl(ts.tv_nsec);
    pkt->size = htons(size);
}

/*
 * These tests involve directly calling functions of the client module.
 * These functions require a CLIENT objects created by client_create
 * on an underlying file descriptor.  The test driver does not send packets
 * on the file descriptor; it is used only for receiving response packets
 * sent as a result of the functions called.  We will use a disk file to
 * store these packets so that they can be read back and checked.
 * This requires two file descriptors: one that is stored in the CLIENT,
 * and the other that is used by the test driver to read back packets.
 */

static void init() {
    client_registry = creg_init();
    player_registry = preg_init();
}

/*
 * Create a CLIENT, together with an associated file to which it can
 * send packets, and another file descriptor that can be used to read back
 * the packets.  The client is logged in under a specified username.
 */
static void setup_client(char *fname, char *uname, CLIENT **clientp, int *readfdp) {
    int writefd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    cr_assert(writefd >= 0, "Failed to open packet file for writing");
    int readfd = open(fname, O_RDONLY);
    cr_assert(readfd >= 0, "Failed to open packet file for reading");
    CLIENT *client = client_create(client_registry, writefd);
    cr_assert_not_null(client, "Error creating client");
    cr_assert_eq(client_get_fd(client), writefd, "Client has wrong file descriptor");
    PLAYER *player = preg_register(player_registry, uname);
    cr_assert_not_null(player, "Error registering player");
    int err = client_login(client, player);
    cr_assert_eq(err, 0, "Error logging in client");
    *clientp = client;
    *readfdp = readfd;
}

/*
 * Assert that there are currently no more packets to be read back.
 */
static void assert_no_packets(int fd) {
    JEUX_PACKET_HEADER pkt;
    void *data;
    int err = proto_recv_packet(fd, &pkt, &data);
    cr_assert_eq(err, -1, "There should be no packets to read");
}

/*
 * Read a packet and check the header fields.
 * The packet and payload are returned.
 */
static void check_packet(int fd, JEUX_PACKET_TYPE type, GAME_ROLE role, int id,
			 JEUX_PACKET_HEADER *pktp, void **payloadp) {
    void *data;
    int err = proto_recv_packet(fd, pktp, &data);
    if(payloadp)
        *payloadp = data;
    cr_assert_eq(err, 0, "Error reading back packet");
    cr_assert_eq(pktp->type, type, "Packet type (%s) was not the expected type (%s)",
		 jeux_packet_type_names[pktp->type], jeux_packet_type_names[type]);
    if(role <= SECOND_PLAYER_ROLE) {
	cr_assert_eq(pktp->role, role, "Role in packet (%d) does not match expected (%d)",
		     pktp->role, role);
    }
    if(id >= 0) {
	cr_assert_eq(pktp->id, id, "ID in packet (%d) does not match expected (%d)",
		     pktp->id, id);
    }
}

/*
 * Test that just sets up and logs in a client, checks that the
 * underlying PLAYER can be retrieved, and then logs the client out.
 * No packets are generated.
 */
Test(client_suite, login_logout, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname = "login_logout.pkts";
    char *uname = "Alice";
    int fd;
    CLIENT *client;
    setup_client(fname, uname, &client, &fd);
    PLAYER *player = client_get_player(client);
    cr_assert_not_null(player, "Error getting player from client");
    cr_assert(!strcmp(player_get_name(player), uname), "Player had wrong username");
    int err = client_logout(client);
    cr_assert_eq(err, 0, "Error logging out client");
}

/*
 * Test sending a single packet using client_send_packet and then
 * and reading it back to verify it.
 */
Test(client_suite, send_packet, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname = "send_packet.pkts";
    char *uname = "Alice";
    int fd;
    CLIENT *client;
    setup_client(fname, uname, &client, &fd);
    void *out_payload = "Hello";
    void *in_payload = NULL;
    JEUX_PACKET_HEADER out_pkt, in_pkt;
    proto_init_packet(&out_pkt, JEUX_ACK_PKT, strlen(out_payload));
    int err = client_send_packet(client, &out_pkt, out_payload);
    cr_assert_eq(err, 0, "Error sending packet");
    proto_recv_packet(fd, &in_pkt, &in_payload);
    cr_assert(!memcmp(&in_pkt, &out_pkt, sizeof(in_pkt)), "Packet header readback was incorrect");
    cr_assert(!memcmp(in_payload, out_payload, ntohs(in_pkt.size)), "Payload readback was incorrect");
}

/*
 * Test sending a single ACK packet using client_send_ack and then
 * and reading it back to verify it.
 */
Test(client_suite, send_ack, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname = "send_ack.pkts";
    char *uname = "Alice";
    int fd;
    CLIENT *client;
    setup_client(fname, uname, &client, &fd);
    void *out_payload = "Hello";
    void *in_payload = NULL;
    JEUX_PACKET_HEADER in_pkt;
    int err = client_send_ack(client, out_payload, strlen(out_payload));
    cr_assert_eq(err, 0, "Error sending ACK");
    check_packet(fd, JEUX_ACK_PKT, 3, -1, &in_pkt, &in_payload);
    cr_assert_eq(ntohs(in_pkt.size), strlen(out_payload), "Payload size readback was incorrect");
    cr_assert(!memcmp(in_payload, out_payload, ntohs(in_pkt.size)), "Payload readback was incorrect");
}

/*
 * Test sending a single NACK packet using client_send_nack and then
 * and reading it back to verify it.
 */
Test(client_suite, send_nack, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname = "send_nack.pkts";
    char *uname = "Alice";
    int fd;
    CLIENT *client;
    setup_client(fname, uname, &client, &fd);
    JEUX_PACKET_HEADER in_pkt;
    int err = client_send_nack(client);
    cr_assert_eq(err, 0, "Error sending ACK");
    check_packet(fd, JEUX_NACK_PKT, 3, -1, &in_pkt, NULL);
    cr_assert_eq(ntohs(in_pkt.size), 0, "Payload size readback was incorrect");
}

/*
 * Set up two clients, then make an invitation from one to the other
 * and check that the required INVITED packet was sent.
 */
Test(client_suite, invite, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname1 = "client_invite1.pkts";
    char *fname2 = "client_invite2.pkts";
    char *uname1 = "Alice";
    char *uname2 = "Bob";
    int fd1, fd2;
    CLIENT *client1, *client2;
    setup_client(fname1, uname1, &client1, &fd1);
    setup_client(fname2, uname2, &client2, &fd2);
    int id1 = client_make_invitation(client1, client2, FIRST_PLAYER_ROLE, SECOND_PLAYER_ROLE);
    cr_assert_eq(id1, 0, "Error making invitation");

    JEUX_PACKET_HEADER in_pkt2;
    assert_no_packets(fd1);
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);
}

/*
 * Set up two clients, make an invitation from one to the other,
 * then have the target decline the invitation.  Verify the packets sent.
 */
Test(client_suite, invite_decline, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname1 = "client_invite_decline1.pkts";
    char *fname2 = "client_invite_decline2.pkts";
    char *uname1 = "Alice";
    char *uname2 = "Bob";
    int fd1, fd2;
    CLIENT *client1, *client2;
    setup_client(fname1, uname1, &client1, &fd1);
    setup_client(fname2, uname2, &client2, &fd2);
    int id1 = client_make_invitation(client1, client2, FIRST_PLAYER_ROLE, SECOND_PLAYER_ROLE);
    cr_assert_neq(id1, -1, "Error making invitation");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);

    int err = client_decline_invitation(client2, in_pkt2.id);
    cr_assert_eq(err, 0, "Error declining invitation");

    check_packet(fd1, JEUX_DECLINED_PKT, 3, id1, &in_pkt1, NULL);
    assert_no_packets(fd2);
}

/*
 * Set up two clients, make an invitation from one to the other,
 * then have the source revoke the invitation.  Verify the packets sent.
 */
Test(client_suite, invite_revoke, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname1 = "client_invite_revoke1.pkts";
    char *fname2 = "client_invite_revoke2.pkts";
    char *uname1 = "Alice";
    char *uname2 = "Bob";
    int fd1, fd2;
    CLIENT *client1, *client2;
    setup_client(fname1, uname1, &client1, &fd1);
    setup_client(fname2, uname2, &client2, &fd2);
    int id1 = client_make_invitation(client1, client2, FIRST_PLAYER_ROLE, SECOND_PLAYER_ROLE);
    cr_assert_neq(id1, -1, "Error making invitation");

    JEUX_PACKET_HEADER in_pkt2;
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);
    int id2 = in_pkt2.id;

    int err = client_revoke_invitation(client1, id1);
    cr_assert_eq(err, 0, "Error revoking invitation");

    assert_no_packets(fd1);
    check_packet(fd2, JEUX_REVOKED_PKT, 3, id2, &in_pkt2, NULL);
}

/*
 * Set up two clients, make an invitation from one to the other,
 * then have the source attempt to decline the invitation.
 * Verify the packets sent.
 */
Test(client_suite, invite_decline_wrong, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname1 = "client_invite_decline_wrong1.pkts";
    char *fname2 = "client_invite_decline_wrong2.pkts";
    char *uname1 = "Alice";
    char *uname2 = "Bob";
    int fd1, fd2;
    CLIENT *client1, *client2;
    setup_client(fname1, uname1, &client1, &fd1);
    setup_client(fname2, uname2, &client2, &fd2);
    int id1 = client_make_invitation(client1, client2, FIRST_PLAYER_ROLE, SECOND_PLAYER_ROLE);
    cr_assert_neq(id1, -1, "Error making invitation");

    JEUX_PACKET_HEADER in_pkt2;
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);

    int err = client_decline_invitation(client1, id1);
    cr_assert_eq(err, -1, "There should have been an error declining the invitation");

    assert_no_packets(fd1);
    assert_no_packets(fd2);
}

/*
 * Set up two clients, make an invitation from one to the other,
 * then have the target attempt to revoke the invitation.
 * Verify the packets sent.
 */
Test(client_suite, invite_revoke_wrong, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname1 = "client_invite_revoke_wrong1.pkts";
    char *fname2 = "client_invite_revoke_wrong2.pkts";
    char *uname1 = "Alice";
    char *uname2 = "Bob";
    int fd1, fd2;
    CLIENT *client1, *client2;
    setup_client(fname1, uname1, &client1, &fd1);
    setup_client(fname2, uname2, &client2, &fd2);
    int id1 = client_make_invitation(client1, client2, FIRST_PLAYER_ROLE, SECOND_PLAYER_ROLE);
    cr_assert_neq(id1, -1, "Error making invitation");

    JEUX_PACKET_HEADER in_pkt2;
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);

    int err = client_revoke_invitation(client2, in_pkt2.id);
    cr_assert_eq(err, -1, "There should have been an error revoking the invitation");

    assert_no_packets(fd1);
    assert_no_packets(fd2);
}

/*
 * Set up two clients, make an invitation from one to the other,
 * then have the target attempt to resign the game.
 * Verify the packets sent.
 */
Test(client_suite, invite_resign_wrong, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname1 = "client_invite_resign_wrong1.pkts";
    char *fname2 = "client_invite_resign_wrong2.pkts";
    char *uname1 = "Alice";
    char *uname2 = "Bob";
    int fd1, fd2;
    CLIENT *client1, *client2;
    setup_client(fname1, uname1, &client1, &fd1);
    setup_client(fname2, uname2, &client2, &fd2);
    int id1 = client_make_invitation(client1, client2, FIRST_PLAYER_ROLE, SECOND_PLAYER_ROLE);
    cr_assert_neq(id1, -1, "Error making invitation");

    JEUX_PACKET_HEADER in_pkt2;
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);

    int err = client_resign_game(client2, in_pkt2.id);
    cr_assert_eq(err, -1, "There should have been an error resigning the game");

    assert_no_packets(fd1);
    assert_no_packets(fd2);
}

/*
 * Set up two clients, make an invitation from one to the other,
 * then have the target accept the invitation.  Verify the packets sent.
 */
Test(client_suite, invite_accept, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname1 = "client_invite_accept1.pkts";
    char *fname2 = "client_invite_accept2.pkts";
    char *uname1 = "Alice";
    char *uname2 = "Bob";
    int fd1, fd2;
    CLIENT *client1, *client2;
    setup_client(fname1, uname1, &client1, &fd1);
    setup_client(fname2, uname2, &client2, &fd2);
    int id1 = client_make_invitation(client1, client2, FIRST_PLAYER_ROLE, SECOND_PLAYER_ROLE);
    cr_assert_neq(id1, -1, "Error making invitation");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);

    char *str;
    int err = client_accept_invitation(client2, in_pkt2.id, &str);
    cr_assert_eq(err, 0, "Error accepting invitation");

    check_packet(fd1, JEUX_ACCEPTED_PKT, 3, id1, &in_pkt1, NULL);
    assert_no_packets(fd2);
}

/*
 * Set up two clients, make an invitation from one to the other,
 * then have the target accept the invitation and the source resign.
 * Verify the packets sent.
 */
Test(client_suite, invite_accept_resign_source, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname1 = "client_invite_accept_resign_source1.pkts";
    char *fname2 = "client_invite_accept_resign_source2.pkts";
    char *uname1 = "Alice";
    char *uname2 = "Bob";
    int fd1, fd2;
    CLIENT *client1, *client2;
    setup_client(fname1, uname1, &client1, &fd1);
    setup_client(fname2, uname2, &client2, &fd2);
    int id1 = client_make_invitation(client1, client2, FIRST_PLAYER_ROLE, SECOND_PLAYER_ROLE);
    cr_assert_neq(id1, -1, "Error making invitation");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);
    int id2 = in_pkt2.id;

    char *str;
    int err = client_accept_invitation(client2, in_pkt2.id, &str);
    cr_assert_eq(err, 0, "Error accepting invitation");

    err = client_resign_game(client1, id1);
    cr_assert_eq(err, 0, "Error resigning game");

    check_packet(fd1, JEUX_ACCEPTED_PKT, 3, id1, &in_pkt1, NULL);
    check_packet(fd1, JEUX_ENDED_PKT, 3, id1, &in_pkt1, NULL);

    check_packet(fd2, JEUX_RESIGNED_PKT, 3, id2, &in_pkt2, NULL);
    check_packet(fd2, JEUX_ENDED_PKT, 3, id2, &in_pkt2, NULL);
}

/*
 * Set up two clients, make an invitation from one to the other,
 * then have the target accept the invitation and then resign.
 * Verify the packets sent.
 */
Test(client_suite, invite_accept_resign_target, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname1 = "client_invite_accept_resign_target1.pkts";
    char *fname2 = "client_invite_accept_resign_target2.pkts";
    char *uname1 = "Alice";
    char *uname2 = "Bob";
    int fd1, fd2;
    CLIENT *client1, *client2;
    setup_client(fname1, uname1, &client1, &fd1);
    setup_client(fname2, uname2, &client2, &fd2);
    int id1 = client_make_invitation(client1, client2, FIRST_PLAYER_ROLE, SECOND_PLAYER_ROLE);
    cr_assert_neq(id1, -1, "Error making invitation");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);
    int id2 = in_pkt2.id;

    char *str;
    int err = client_accept_invitation(client2, in_pkt2.id, &str);
    cr_assert_eq(err, 0, "Error accepting invitation");

    err = client_resign_game(client2, id2);
    cr_assert_eq(err, 0, "Error resigning game");

    check_packet(fd1, JEUX_ACCEPTED_PKT, 3, id1, &in_pkt1, NULL);
    check_packet(fd1, JEUX_RESIGNED_PKT, 3, id1, &in_pkt1, NULL);
    check_packet(fd1, JEUX_ENDED_PKT, 3, id1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_ENDED_PKT, 3, id2, &in_pkt2, NULL);
}

/*
 * Set up two clients, make an invitation from one to the other,
 * then have the target accept the invitation and make a game move.
 * Verify the packets sent.
 */
Test(client_suite, invite_accept_move, .init = init, .timeout = 5) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname1 = "client_invite_accept_move1.pkts";
    char *fname2 = "client_invite_accept_move2.pkts";
    char *uname1 = "Alice";
    char *uname2 = "Bob";
    int fd1, fd2;
    CLIENT *client1, *client2;
    setup_client(fname1, uname1, &client1, &fd1);
    setup_client(fname2, uname2, &client2, &fd2);
    int id1 = client_make_invitation(client1, client2, SECOND_PLAYER_ROLE, FIRST_PLAYER_ROLE);
    cr_assert_neq(id1, -1, "Error making invitation");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd2, JEUX_INVITED_PKT, FIRST_PLAYER_ROLE, -1, &in_pkt2, NULL);
    int id2 = in_pkt2.id;

    char *str;
    int err = client_accept_invitation(client2, in_pkt2.id, &str);
    cr_assert_eq(err, 0, "Error accepting invitation");

    check_packet(fd1, JEUX_ACCEPTED_PKT, 3, id1, &in_pkt1, NULL);
    assert_no_packets(fd2);

    err = client_make_move(client2, id2, "5<-X");
    cr_assert_eq(err, 0, "Error making move");

    check_packet(fd1, JEUX_MOVED_PKT, 3, id1, &in_pkt1, NULL);
    assert_no_packets(fd2);
}

/*
 * Concurrency test:
 * Set up two clients with a thread for each that for many iterations
 * randomly invites the other client and revokes outstanding invitations.
 * Look for error return from invitation and revocation and crashes due
 * to corrupted lists, etc.
 */

struct random_inviter_args {
    CLIENT *source;
    CLIENT *target;
    int iters;
};

void *random_inviter_thread(void *args) {
    struct random_inviter_args *ap = args;
    unsigned int seed = 1;
    // We don't know what values the student code will use for invitations,
    // so we need a separate array to keep track of which ones are outstanding.
    int outstanding[NINVITATION] = { 0 };
    int ids[NINVITATION] = { 0 };
    int err;
    for(int i = 0; i < ap->iters; i++) {
	int n = rand_r(&seed) % NINVITATION;
	if(!outstanding[n]) {
	    ids[n] = client_make_invitation(ap->source, ap->target,
					    FIRST_PLAYER_ROLE, SECOND_PLAYER_ROLE);
	    cr_assert_neq(ids[n], -1, "Error making invitation");
	    outstanding[n] = 1;
	} else {
	    outstanding[n] = 0;
	    err = client_revoke_invitation(ap->source, ids[n]);
	    cr_assert_eq(err, 0, "Error revoking invitation");
	}
    }
    return NULL;
}

Test(client_suite, random_invite_revoke, .init = init, .timeout = 15) {
#ifdef NO_CLIENT
    cr_assert_fail("Client module was not implemented");
#endif
    char *fname1 = "/dev/null";
    char *fname2 = "/dev/null";
    char *uname1 = "Alice";
    char *uname2 = "Bob";
    int fd1, fd2;
    CLIENT *client1, *client2;
    setup_client(fname1, uname1, &client1, &fd1);
    setup_client(fname2, uname2, &client2, &fd2);
    struct random_inviter_args args1 = {
	.source = client1,
	.target = client2,
	.iters = NITERS
    };
    struct random_inviter_args args2 = {
	.source = client2,
	.target = client1,
	.iters = NITERS
    };
    pthread_t tid1, tid2;
    int err = pthread_create(&tid1, NULL, random_inviter_thread, &args1);
    cr_assert(err >= 0, "Failed to create test thread");
    err = pthread_create(&tid2, NULL, random_inviter_thread, &args2);
    cr_assert(err >= 0, "Failed to create test thread");

    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
}


////////////////////////////////////////////////// GAME TEST //////////////////////////////////////////////////
/* Number of games played in the concurrency test. */
#define NGAMES (1000)

/* Maximum number of moves attempted by a thread. */
#define NMOVES (100)

/* Number of threads we create in multithreaded tests. */
#define NTHREAD (10)

/*
 * Create a game and check some things about its initial state.
 */
Test(game_suite, create, .timeout = 5) {
#ifdef NO_GAME
    cr_assert_fail("Game module was not implemented");
#endif
    GAME *game = game_create();
    cr_assert_not_null(game, "Returned value was NULL");
    cr_assert(!game_is_over(game), "Newly created game should not be over yet");
    cr_assert_eq(game_get_winner(game), NULL_ROLE, "Newly created game should not have a winner");
}

/*
 * Create a game and apply a few legal moves to it.
 */
Test(game_suite, legal_moves, .timeout = 5) {
#ifdef NO_GAME
    cr_assert_fail("Game module was not implemented");
#endif
    GAME *game = game_create();
    cr_assert_not_null(game, "Returned value was NULL");

    GAME_MOVE *move = game_parse_move(game, FIRST_PLAYER_ROLE, "5");
    cr_assert_not_null(move, "Returned move was NULL");
    int err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, SECOND_PLAYER_ROLE, "1");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, FIRST_PLAYER_ROLE, "2");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    cr_assert(!game_is_over(game), "Game should not be over yet");
    cr_assert_eq(game_get_winner(game), NULL_ROLE, "Game should not have a winner");
}

/*
 * Create a game and resign it.
 */
Test(game_suite, resign, .timeout = 5) {
#ifdef NO_GAME
    cr_assert_fail("Game module was not implemented");
#endif
    GAME *game = game_create();
    cr_assert_not_null(game, "Returned value was NULL");
    int err = game_resign(game, SECOND_PLAYER_ROLE);
    cr_assert_eq(err, 0, "Returned value was not 0");

    cr_assert(game_is_over(game), "Resigned game should be over");
    int winner = game_get_winner(game);
    cr_assert_eq(winner, FIRST_PLAYER_ROLE,
		 "Game winner (%d) does not match expected (%d)",
		 winner, FIRST_PLAYER_ROLE);
}

/*
 * Create a game and apply an illegal move sequence to it.
 */
Test(game_suite, illegal_move, .timeout = 5) {
#ifdef NO_GAME
    cr_assert_fail("Game module was not implemented");
#endif
    GAME *game = game_create();
    cr_assert_not_null(game, "Returned value was NULL");

    GAME_MOVE *move = game_parse_move(game, FIRST_PLAYER_ROLE, "5");
    cr_assert_not_null(move, "Returned move was NULL");
    int err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, SECOND_PLAYER_ROLE, "1");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, FIRST_PLAYER_ROLE, "1");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, -1, "Returned value was not -1");

    cr_assert(!game_is_over(game), "Game should not be over yet");
    cr_assert_eq(game_get_winner(game), NULL_ROLE, "Game should not have a winner");
}

/*
 * Create a game, apply some moves, and then try to parse a move for
 * the wrong player.
 */
Test(game_suite, parse_move_wrong_player, .timeout = 5) {
#ifdef NO_GAME
    cr_assert_fail("Game module was not implemented");
#endif
    GAME *game = game_create();
    cr_assert_not_null(game, "Returned value was NULL");

    GAME_MOVE *move = game_parse_move(game, FIRST_PLAYER_ROLE, "5");
    cr_assert_not_null(move, "Returned move was NULL");
    int err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, SECOND_PLAYER_ROLE, "1");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, FIRST_PLAYER_ROLE, "2");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, FIRST_PLAYER_ROLE, "3");
    cr_assert_null(move, "Returned move was not NULL");

    cr_assert(!game_is_over(game), "Game should not be over yet");
    cr_assert_eq(game_get_winner(game), NULL_ROLE, "Game should not have a winner");
}

/*
 * Create a game, try parsing and unparsing some moves.
 */
Test(game_suite, parse_unparse_move, .timeout = 5) {
#ifdef NO_GAME
    cr_assert_fail("Game module was not implemented");
#endif
    GAME *game = game_create();
    cr_assert_not_null(game, "Returned value was NULL");

    GAME_MOVE *move = game_parse_move(game, FIRST_PLAYER_ROLE, "5");
    cr_assert_not_null(move, "Returned move was NULL");
    char *str = game_unparse_move(move);
    cr_assert_not_null(str, "Returned string was NULL");
    char *exp = "5<-X";
    cr_assert(!strcmp(str, exp), "Unparsed move (%s) did not match expected (%s)",
	      str, exp);

    move = game_parse_move(game, NULL_ROLE, "5");
    cr_assert_not_null(move, "Returned move was NULL");
    str = game_unparse_move(move);
    cr_assert_not_null(str, "Returned string was NULL");
    exp = "5<-X";
    cr_assert(!strcmp(str, exp), "Unparsed move (%s) did not match expected (%s)",
	      str, exp);

    move = game_parse_move(game, NULL_ROLE, "5<-X");
    cr_assert_not_null(move, "Returned move was NULL");
    str = game_unparse_move(move);
    cr_assert_not_null(str, "Returned string was NULL");
    exp = "5<-X";
    cr_assert(!strcmp(str, exp), "Unparsed move (%s) did not match expected (%s)",
	      str, exp);

    move = game_parse_move(game, NULL_ROLE, "5<-O");
    cr_assert_null(move, "Returned value was not NULL");
}

/*
 * Create a game and apply moves to it to reach a won position.
 */
Test(game_suite, winning_sequence, .timeout = 5) {
#ifdef NO_GAME
    cr_assert_fail("Game module was not implemented");
#endif
    GAME *game = game_create();
    cr_assert_not_null(game, "Returned value was NULL");

    GAME_MOVE *move = game_parse_move(game, FIRST_PLAYER_ROLE, "5");
    cr_assert_not_null(move, "Returned move was NULL");
    int err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, SECOND_PLAYER_ROLE, "1");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, FIRST_PLAYER_ROLE, "3");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, SECOND_PLAYER_ROLE, "2");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, FIRST_PLAYER_ROLE, "7");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    cr_assert(game_is_over(game), "Game should be over");
    cr_assert_neq(game_get_winner(game), NULL_ROLE, "Game should have a winner");

    move = game_parse_move(game, SECOND_PLAYER_ROLE, "4");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, -1, "Returned value was not -1");
}

/*
 * Create a game and apply moves to it to reach a drawn position.
 */
Test(game_suite, drawing_sequence, .timeout = 5) {
#ifdef NO_GAME
    cr_assert_fail("Game module was not implemented");
#endif
    GAME *game = game_create();
    cr_assert_not_null(game, "Returned value was NULL");

    GAME_MOVE *move = game_parse_move(game, FIRST_PLAYER_ROLE, "5");
    cr_assert_not_null(move, "Returned move was NULL");
    int err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, SECOND_PLAYER_ROLE, "1");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, FIRST_PLAYER_ROLE, "2");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, SECOND_PLAYER_ROLE, "3");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, FIRST_PLAYER_ROLE, "6");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, SECOND_PLAYER_ROLE, "4");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, FIRST_PLAYER_ROLE, "7");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, SECOND_PLAYER_ROLE, "8");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    move = game_parse_move(game, FIRST_PLAYER_ROLE, "9");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, 0, "Returned value was not 0");

    cr_assert(game_is_over(game), "Game should be over");
    cr_assert_eq(game_get_winner(game), NULL_ROLE, "Game should have no winner");

    move = game_parse_move(game, SECOND_PLAYER_ROLE, "4");
    cr_assert_not_null(move, "Returned move was NULL");
    err = game_apply_move(game, move);
    cr_assert_eq(err, -1, "Returned value was not -1");
}

/*
 * Tic-tac-toe winner detection.
 */
static int calcSum(GAME_ROLE *board, int startRow, int startCol, int rowInc, int colInc) {
    int sum = 0;
    for(int row = startRow, col = startCol;
	row >= 0 && row < 3 && col >= 0 && col < 3;
	row += rowInc, col += colInc) {
	GAME_ROLE who = board[3*row + col];
	if(who == FIRST_PLAYER_ROLE)
	    sum += 4;
	else if(who == SECOND_PLAYER_ROLE)
	    sum += 1;
    }
    return sum;
}

static GAME_ROLE checkDirection(GAME_ROLE *board, int startRow, int startCol, int rowInc, int colInc) {
    int sum = calcSum(board, startRow, startCol, rowInc, colInc);
    if(sum / 4 >= 3)
	return FIRST_PLAYER_ROLE;
    else if(sum % 4 >= 3)
	return SECOND_PLAYER_ROLE;
    return NULL_ROLE;
}

static GAME_ROLE three_in_a_row(GAME_ROLE *board) {
    GAME_ROLE who = NULL_ROLE;

    // Check rows.
    for(int row = 0; row < 3; row++) {
	who = checkDirection(board, row, 0, 0, 1);
	if(who)
	    return who;
    }
    // Check columns.
    for(int col = 0; col < 3; col++) {
	who = checkDirection(board, 0, col, 1, 0);
	if(who)
	    return who;
    }
    // Check diagonals.
    who = checkDirection(board, 0, 0, 1, 1);
    if(who)
	return who;
    who = checkDirection(board, 2, 0, -1, 1);
    if(who)
	return who;

    return NULL_ROLE;
}

/*
 * Concurrency test: Create a game and give it to a number of threads.
 * The threads will try to make random moves.  Each successful move will
 * also be marked on a reference version of the game board.  About the
 * only thing that we can readily check is that two moves to the same
 * position are never allowed and that the game result is the same.
 */

struct random_moves_args {
    int trial;
    GAME *game;
    GAME_ROLE board[9];
    int moves;
    pthread_mutex_t mutex;
};

void *random_moves_thread(void *arg) {
    struct random_moves_args *ap = arg;
    GAME *game = ap->game;
    unsigned int seed = 1;
    for(int i = 0; i < ap->moves; i++) {
	int pos = (rand_r(&seed) % 9) + 1;
	int role = (rand_r(&seed) %2) + 1;
	char str[3];
	sprintf(str, "%d", pos);
	GAME_MOVE *move = game_parse_move(game, role, str);
	if(move == NULL)
	    continue;
	int err = game_apply_move(game, move);
	if(!err) {
	    pthread_mutex_lock(&ap->mutex);
	    cr_assert_eq(ap->board[pos-1], NULL_ROLE,
			 "Board position (%d) was already taken in game %d", pos, ap->trial);
	    ap->board[pos-1] = role;
	    pthread_mutex_unlock(&ap->mutex);
	}
    }
    return NULL;
}

Test(game_suite, random_moves, .timeout = 15) {
#ifdef NO_GAME
    cr_assert_fail("Game module was not implemented");
#endif
    // Only playing a single random game does not always reveal flaws in
    // the code being tested.  So we will run it several times.
    for(int n = 0; n < NGAMES; n++) {
	struct random_moves_args args;
	args.trial = n;
	args.game = game_create();
	memset(args.board, NULL_ROLE, sizeof(args.board));
	args.moves = NMOVES;
	pthread_mutex_init(&args.mutex, NULL);

	pthread_t tid[NTHREAD];
	for(int i = 0; i < NTHREAD; i++)
	    pthread_create(&tid[i], NULL, random_moves_thread, &args);

	// Wait for all threads to finish.
	for(int i = 0; i < NTHREAD; i++)
	    pthread_join(tid[i], NULL);

	// Check game result.
	int marked = 0;
	for(int i = 0; i < 9; i++) {
	    if(args.board[i] != NULL_ROLE)
		marked++;
	}
	int go = game_is_over(args.game);
	int winner = game_get_winner(args.game);
	int ref_go = (winner != NULL_ROLE || marked == 9);
	cr_assert_eq(go, ref_go, "Game over (%d) does not match expected (%d) in game %d",
		     go, ref_go, n);

	int ref_winner = three_in_a_row(args.board);
	cr_assert_eq(winner, ref_winner,
		     "Game winner (%d) does not match expected (%d) in game %d",
		     winner, ref_winner, n);
    }
}

///////////////////////////////////////////////// INV TEST ////////////////////////////////////////////////
/* Maximum number of iterations performed for some tests. */
#define NITER (1000000)

/* Number of threads we create in multithreaded tests. */
#define NTHREAD (10)

Test(invitation_suite, create_same_client, .timeout = 5) {
#ifdef NO_INVITATION
    cr_assert_fail("Invitation module was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    CLIENT *alice = creg_register(cr, 10);
    cr_assert_not_null(alice);

    INVITATION *inv = inv_create(alice, alice, FIRST_PLAYER_ROLE, SECOND_PLAYER_ROLE);
    cr_assert_null(inv, "Returned value was not NULL");
}

Test(invitation_suite, create_different_clients, .timeout = 5) {
#ifdef NO_INVITATION
    cr_assert_fail("Invitation module was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    CLIENT *alice = creg_register(cr, 10);
    cr_assert_not_null(alice);
    GAME_ROLE alice_role = SECOND_PLAYER_ROLE;
    CLIENT *bob = creg_register(cr, 11);
    cr_assert_not_null(bob);
    GAME_ROLE bob_role = FIRST_PLAYER_ROLE;

    INVITATION *inv = inv_create(alice, bob, alice_role, bob_role);
    cr_assert_not_null(inv, "Returned value was NULL");

    // Check the accessors to see if they return the correct values.
    CLIENT *src = inv_get_source(inv);
    CLIENT *trg = inv_get_target(inv);
    GAME_ROLE src_role = inv_get_source_role(inv);
    GAME_ROLE trg_role = inv_get_target_role(inv);
    cr_assert_eq(src, alice, "Source (%p) did not match expected (%p)", src, alice);
    cr_assert_eq(trg, bob, "Target (%p) did not match expected (%p)", trg, bob);
    cr_assert_eq(src_role, alice_role, "Source role (%d) did not match expected (%d)",
		 src_role, alice_role);
    cr_assert_eq(trg_role, bob_role, "Target role (%d) did not match expected (%d)",
		 trg_role, bob_role);
}

Test(invitation_suite, create_close, .timeout = 5) {
#ifdef NO_INVITATION
    cr_assert_fail("Invitation module was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    CLIENT *alice = creg_register(cr, 10);
    cr_assert_not_null(alice);
    GAME_ROLE alice_role = SECOND_PLAYER_ROLE;
    CLIENT *bob = creg_register(cr, 11);
    cr_assert_not_null(bob);
    GAME_ROLE bob_role = FIRST_PLAYER_ROLE;

    INVITATION *inv = inv_create(alice, bob, alice_role, bob_role);
    cr_assert_not_null(inv, "Returned value was NULL");

    int err = inv_close(inv, NULL_ROLE);
    cr_assert_eq(err, 0, "Returned value (%d) was not 0", err);
}

Test(invitation_suite, create_close_close, .timeout = 5) {
#ifdef NO_INVITATION
    cr_assert_fail("Invitation module was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    CLIENT *alice = creg_register(cr, 10);
    cr_assert_not_null(alice);
    GAME_ROLE alice_role = SECOND_PLAYER_ROLE;
    CLIENT *bob = creg_register(cr, 11);
    cr_assert_not_null(bob);
    GAME_ROLE bob_role = FIRST_PLAYER_ROLE;

    INVITATION *inv = inv_create(alice, bob, alice_role, bob_role);
    cr_assert_not_null(inv, "Returned value was NULL");

    int err = inv_close(inv, NULL_ROLE);
    cr_assert_eq(err, 0, "Returned value (%d) was not 0", err);

    err = inv_close(inv, NULL_ROLE);
    cr_assert_eq(err, -1, "Returned value (%d) was not -1", err);
}

Test(invitation_suite, create_accept, .timeout = 5) {
#ifdef NO_INVITATION
    cr_assert_fail("Invitation module was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    CLIENT *alice = creg_register(cr, 10);
    cr_assert_not_null(alice);
    GAME_ROLE alice_role = SECOND_PLAYER_ROLE;
    CLIENT *bob = creg_register(cr, 11);
    cr_assert_not_null(bob);
    GAME_ROLE bob_role = FIRST_PLAYER_ROLE;

    INVITATION *inv = inv_create(alice, bob, alice_role, bob_role);
    cr_assert_not_null(inv, "Returned value was NULL");

    int err = inv_accept(inv);
    cr_assert_eq(err, 0, "Returned value (%d) was not 0", err);

    // Check to see that a game has been created and is in progress.
    GAME *game = inv_get_game(inv);
    cr_assert_not_null(game, "No game was returned", err);
    cr_assert(!game_is_over(game), "The game should not be over when it has just been started");
}

Test(invitation_suite, create_accept_close, .timeout = 5) {
#ifdef NO_INVITATION
    cr_assert_fail("Invitation module was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    CLIENT *alice = creg_register(cr, 10);
    cr_assert_not_null(alice);
    GAME_ROLE alice_role = SECOND_PLAYER_ROLE;
    CLIENT *bob = creg_register(cr, 11);
    cr_assert_not_null(bob);
    GAME_ROLE bob_role = FIRST_PLAYER_ROLE;

    INVITATION *inv = inv_create(alice, bob, alice_role, bob_role);
    cr_assert_not_null(inv, "Returned value was NULL");

    int err = inv_accept(inv);
    cr_assert_eq(err, 0, "Returned value (%d) was not 0", err);

    err = inv_close(inv, NULL_ROLE);
    cr_assert_eq(err, -1, "Returned value (%d) was not -1", err);
}

Test(invitation_suite, create_accept_resign, .timeout = 5) {
#ifdef NO_INVITATION
    cr_assert_fail("Invitation module was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    CLIENT *alice = creg_register(cr, 10);
    cr_assert_not_null(alice);
    GAME_ROLE alice_role = SECOND_PLAYER_ROLE;
    CLIENT *bob = creg_register(cr, 11);
    cr_assert_not_null(bob);
    GAME_ROLE bob_role = FIRST_PLAYER_ROLE;

    INVITATION *inv = inv_create(alice, bob, alice_role, bob_role);
    cr_assert_not_null(inv, "Returned value was NULL");

    int err = inv_accept(inv);
    cr_assert_eq(err, 0, "Returned value (%d) was not 0", err);

    err = inv_close(inv, SECOND_PLAYER_ROLE);
    cr_assert_eq(err, 0, "Returned value (%d) was not 0", err);

    // Check that the game has been resigned.
    GAME *game = inv_get_game(inv);
    cr_assert_not_null(game, "No game was returned", err);
    cr_assert(game_is_over(game), "The game should be over after a player resigns");
}

/*
 * Concurrency test: An invitation is created and given to a number of threads.
 * The threads enter a loop in which they attempt to resign the invitation
 * (i.e. close it under a role other than NULL_ROLE).  All such attempts should
 * return an error, because the invitation has not yet been accepted.
 * The main thread will accept the invitation after some delay, after which exactly
 * one thread should succeed in resigning the invitation.
 */

static int successful_resignations;
static pthread_mutex_t successful_resignations_lock;

void *resign_thread(void *arg) {
    INVITATION *inv = arg;
    long n = NITER;
    while(n) {
	int err = inv_close(inv, FIRST_PLAYER_ROLE);
	pthread_mutex_lock(&successful_resignations_lock);
	if(successful_resignations)
	    n--;  // Limit iterations after first success.
	if(!err) {
	    successful_resignations++;
	    pthread_mutex_unlock(&successful_resignations_lock);
	    return NULL;
	} 
	pthread_mutex_unlock(&successful_resignations_lock);
    }
    return NULL;
}

Test(invitation_suite, concurrent_resign, .timeout = 15) {
#ifdef NO_INVITATION
    cr_assert_fail("Invitation module was not implemented");
#endif
    CLIENT_REGISTRY *cr = creg_init();
    cr_assert_not_null(cr);

    CLIENT *alice = creg_register(cr, 10);
    cr_assert_not_null(alice);
    GAME_ROLE alice_role = SECOND_PLAYER_ROLE;
    CLIENT *bob = creg_register(cr, 11);
    cr_assert_not_null(bob);
    GAME_ROLE bob_role = FIRST_PLAYER_ROLE;

    INVITATION *inv = inv_create(alice, bob, alice_role, bob_role);
    cr_assert_not_null(inv, "Returned value was NULL");

    // Spawn threads to perform concurrent resignation attempts.
    pthread_mutex_init(&successful_resignations_lock, NULL);
    pthread_t tid[NTHREAD];
    for(int i = 0; i < NTHREAD; i++)
	pthread_create(&tid[i], NULL, resign_thread, inv);

    // Accept the invitation, after a delay to ensure all the threads are running.
    sleep(1);
    inv_accept(inv);

    // Wait for all threads to finish.
    for(int i = 0; i < NTHREAD; i++)
	pthread_join(tid[i], NULL);

    // The number of threads that saw a successful resignation should
    // be exactly one.
    cr_assert_eq(successful_resignations, 1, "The number of successful resignations (%d) was not 1",
		 successful_resignations);
}


////////////////////////////////////////////////// PLAYER REGISTRY //////////////////////////////////////
/* Number of threads we create in multithreaded tests. */
#define NTHREAD (10)

/* Maximum number of players we register in long tests. */
#define NPLAYERS (1000)

/*
 * Register one player, then register again and check that the same PLAYER
 * object is returned.
 */
Test(player_registry_suite, one_registry_one_player, .timeout = 5) {
#ifdef NO_PLAYER_REGISTRY
    cr_assert_fail("Player registry was not implemented");
#endif
    char *user = "Jane";
    PLAYER_REGISTRY *pr = preg_init();
    cr_assert_not_null(pr);

    PLAYER *player = preg_register(pr, user);
    cr_assert_neq(player, NULL, "Returned value was NULL");
    PLAYER *p = preg_register(pr, user);
    cr_assert_eq(p, player, "Returned player (%p) was not the same as expected (%p)",
		 p, player);
}

/*
 * Register three players, then register one again and check that the same PLAYER
 * object is returned.
 */
Test(player_registry_suite, one_registry_three_players, .timeout = 5) {
#ifdef NO_PLAYER_REGISTRY
    cr_assert_fail("Player registry was not implemented");
#endif
    char *user1 = "Alice";
    char *user2 = "Bob";
    char *user3 = "Carol";
    PLAYER_REGISTRY *pr = preg_init();
    cr_assert_not_null(pr);

    PLAYER *player1 = preg_register(pr, user1);
    cr_assert_neq(player1, NULL, "Returned value was NULL");
    PLAYER *player2 = preg_register(pr, user2);
    cr_assert_neq(player2, NULL, "Returned value was NULL");
    PLAYER *player3 = preg_register(pr, user3);
    cr_assert_neq(player3, NULL, "Returned value was NULL");

    PLAYER *p = preg_register(pr, user2);
    cr_assert_eq(p, player2, "Returned player (%p) was not the same as expected (%p)",
		 p, player2);
}

/*
 * Create two registries, register different players in each, and check that
 * each player is found in the appropriate registry and not in the other.
 */
Test(player_registry_suite, two_registries_two_players, .timeout = 5) {
#ifdef NO_PLAYER_REGISTRY
    cr_assert_fail("Player registry was not implemented");
#endif
    char *user1 = "Alice";
    char *user2 = "Bob";
    PLAYER_REGISTRY *pr1 = preg_init();
    cr_assert_not_null(pr1);
    PLAYER_REGISTRY *pr2 = preg_init();
    cr_assert_not_null(pr2);

    PLAYER *player1 = preg_register(pr1, user1);
    cr_assert_neq(player1, NULL, "Returned value was NULL");
    PLAYER *player2 = preg_register(pr2, user2);
    cr_assert_neq(player2, NULL, "Returned value was NULL");

    PLAYER *p1 = preg_register(pr1, user1);
    cr_assert_eq(p1, player1, "Returned player (%p) was not the same as expected (%p)",
		 p1, player1);
    PLAYER *p2 = preg_register(pr2, user2);
    cr_assert_eq(p2, player2, "Returned player (%p) was not the same as expected (%p)",
		 p2, player2);
    p1 = preg_register(pr2, user1);
    cr_assert_neq(p1, player1, "Returned player (%p) should not be (%p)", p1, player1);
    p2 = preg_register(pr1, user2);
    cr_assert_neq(p2, player2, "Returned player (%p) should not be (%p)", p2, player2);
}

/*
 * Set of player objects that have been registered and a lock to protect it.
 */
static PLAYER *players[NPLAYERS];
static pthread_mutex_t players_lock;

/*
 * Randomly choose an index in the players array and register a player under
 * a corresponding name.  If the index was NULL, store the player in the array,
 * otherwise check that the correct existing PLAYER was returned.
 */
struct random_reg_args {
    PLAYER_REGISTRY *pr;
    int iters;
};

void *random_reg_thread(void *arg) {
    struct random_reg_args *ap = arg;
    unsigned int seed = 1;
    char name[32];
    pthread_mutex_init(&players_lock, NULL);
    for(int i = 0; i < ap->iters; i++) {
	int n = rand_r(&seed) % NPLAYERS;
	sprintf(name, "p%d", n);
	PLAYER *player = preg_register(ap->pr, name);
	pthread_mutex_lock(&players_lock);
	if(players[n] == NULL) {
	    players[n] = player;
	} else {
	    cr_assert_eq(player, players[n], "Returned player (%p) did not match expected (%p)",
			 player, players[n]);
	}
	pthread_mutex_unlock(&players_lock);
    }
    return NULL;
}

Test(player_registry_suite, many_threads_one_registry, .timeout = 15) {
#ifdef NO_PLAYER_REGISTRY
    cr_assert_fail("Player registry was not implemented");
#endif
    PLAYER_REGISTRY *pr = preg_init();
    cr_assert_not_null(pr);

    // Spawn threads to perform concurrent registrations.
    pthread_t tid[NTHREAD];
    struct random_reg_args *ap = calloc(1, sizeof(struct random_reg_args));
    ap->pr = pr;
    ap->iters = 10 * NPLAYERS;
    for(int i = 0; i < NTHREAD; i++)
	pthread_create(&tid[i], NULL, random_reg_thread, ap);

    // Wait for all threads to finish.
    for(int i = 0; i < NTHREAD; i++)
	pthread_join(tid[i], NULL);
}


//////////////////////////////////////////////////// PLAYER TESTS /////////////////////////////////////////
/* Maximum number of iterations performed for some tests. */
#define NITER (1000000)

/* Number of threads we create in multithreaded tests. */
#define NTHREAD (10)

/* Number of players we create. */
#define NPLAYER (100)

Test(player_suite, create, .timeout = 5) {
#ifdef NO_PLAYER
    cr_assert_fail("Player module was not implemented");
#endif
    char *name = "Alice";
    PLAYER *player = player_create(name);
    cr_assert_not_null(player, "Returned value was NULL");

    char *pn = player_get_name(player);
    cr_assert(!strcmp(pn, name), "Player name (%s) does not match expected (%s)",
	      pn, name);
    int r = player_get_rating(player);
    cr_assert_eq(r, PLAYER_INITIAL_RATING, "Player rating (%d) does not match expected (%d)",
		 r, PLAYER_INITIAL_RATING);
}

Test(player_suite, post_result_draw, .timeout = 5) {
#ifdef NO_PLAYER
    cr_assert_fail("Player module was not implemented");
#endif
    char *alice = "Alice";
    PLAYER *player_alice = player_create(alice);
    cr_assert_not_null(player_alice, "Returned value was NULL");
    char *bob = "Bob";
    PLAYER *player_bob = player_create(bob);
    cr_assert_not_null(player_bob, "Returned value was NULL");

    player_post_result(player_alice, player_bob, 0);

    // The player's rating should be unchanged.
    int r = player_get_rating(player_alice);
    cr_assert_eq(r, PLAYER_INITIAL_RATING, "Player rating (%d) does not match expected (%d)",
		 r, PLAYER_INITIAL_RATING);
    r = player_get_rating(player_bob);
    cr_assert_eq(r, PLAYER_INITIAL_RATING, "Player rating (%d) does not match expected (%d)",
		 r, PLAYER_INITIAL_RATING);
}

Test(player_suite, post_result_first, .timeout = 5) {
#ifdef NO_PLAYER
    cr_assert_fail("Player module was not implemented");
#endif
    char *alice = "Alice";
    PLAYER *player_alice = player_create(alice);
    cr_assert_not_null(player_alice, "Returned value was NULL");
    char *bob = "Bob";
    PLAYER *player_bob = player_create(bob);
    cr_assert_not_null(player_bob, "Returned value was NULL");

    player_post_result(player_alice, player_bob, 1);

    int r = player_get_rating(player_alice);
    cr_assert_eq(r, 1516, "Player rating (%d) does not match expected (%d)",
		 r, 1516);
    r = player_get_rating(player_bob);
    cr_assert_eq(r, 1484, "Player rating (%d) does not match expected (%d)",
		 r, 1484);
}

Test(player_suite, post_result_series, .timeout = 5) {
#ifdef NO_PLAYER
    cr_assert_fail("Player module was not implemented");
#endif
    char *alice = "Alice";
    PLAYER *player_alice = player_create(alice);
    cr_assert_not_null(player_alice, "Returned value was NULL");
    char *bob = "Bob";
    PLAYER *player_bob = player_create(bob);
    cr_assert_not_null(player_bob, "Returned value was NULL");
    char *carol = "Carol";
    PLAYER *player_carol = player_create(carol);
    cr_assert_not_null(player_carol, "Returned value was NULL");
    char *dan = "Dan";
    PLAYER *player_dan = player_create(dan);
    cr_assert_not_null(player_dan, "Returned value was NULL");

    player_post_result(player_alice, player_carol, 1);
    player_post_result(player_alice, player_bob, 2);
    player_post_result(player_bob, player_dan, 0);
    player_post_result(player_carol, player_dan, 1);
    player_post_result(player_alice, player_dan, 1);

    int r = player_get_rating(player_alice);
    cr_assert_eq(r, 1515, "Player rating (%d) does not match expected (%d)",
		 r, 1515);
    r = player_get_rating(player_bob);
    cr_assert_eq(r, 1516, "Player rating (%d) does not match expected (%d)",
		 r, 1516);
    r = player_get_rating(player_carol);
    cr_assert_eq(r, 1500, "Player rating (%d) does not match expected (%d)",
		 r, 1500);
    r = player_get_rating(player_dan);
    cr_assert_eq(r, 1469, "Player rating (%d) does not match expected (%d)",
		 r, 1469);
}

/*
 * Concurrency test: Create a number of players, then create a number of threads
 * to post random game results.  Once the posting of results has finished, check
 * the sum of the player's ratings to see if rating points have been conserved.
 * This test checks for deadlock (will result in timeout), rating points conservation,
 * and thread-safety of player_post_result.
 */

static PLAYER *players[NPLAYER];

void *post_thread(void *arg) {
    unsigned int seed = 1;
    for(int i = 0; i < NITER; i++) {
	PLAYER *player1 = players[rand_r(&seed) % NPLAYER];
	PLAYER *player2 = players[rand_r(&seed) % NPLAYER];
	if(player1 == player2)
	    continue;
	int result = rand_r(&seed) % 3;
	player_post_result(player1, player2, result);
    }
    return NULL;
}

Test(player_suite, concurrent_post, .timeout = 15) {
#ifdef NO_PLAYER
    cr_assert_fail("Player module was not implemented");
#endif
    char name[32];
    for(int i = 0; i < NPLAYER; i++) {
	sprintf(name, "p%d", i);
	players[i] = player_create(name);
	cr_assert(players[i] != NULL, "Player creation failed");
    }

    pthread_t tid[NTHREAD];
    for(int i = 0; i < NTHREAD; i++)
	pthread_create(&tid[i], NULL, post_thread, NULL);

    // Wait for all threads to finish.
    for(int i = 0; i < NTHREAD; i++)
	pthread_join(tid[i], NULL);

    // Compute the sum of the player ratings and check it.
    int sum = 0;
    for(int i = 0; i < NPLAYER; i++)
	sum += player_get_rating(players[i]);
    cr_assert_eq(sum, NPLAYER * PLAYER_INITIAL_RATING,
		 "The sum of player ratings (%d) did not match the expected value (%d)",
		 sum, NPLAYER * PLAYER_INITIAL_RATING);
}


//////////////////////////////////////////////// PROTOCOL TESTS ///////////////////////////////////////////////
static void init() {
}

Test(protocol_suite, send_no_payload, .init = init, .timeout = 5) {
#ifdef NO_PROTOCOL
    cr_assert_fail("Protocol was not implemented");
#endif
    int fd;
    void *payload = NULL;
    JEUX_PACKET_HEADER pkt = {0};

    pkt.type = JEUX_ACK_PKT;
    pkt.size = htons(0);
    pkt.timestamp_sec = htonl(0x11223344);
    pkt.timestamp_nsec = htonl(0x55667788);

    fd = open("pkt_ack_no_payload", O_CREAT|O_TRUNC|O_RDWR, 0644);
    cr_assert(fd > 0, "Failed to create output file");
    int ret = proto_send_packet(fd, &pkt, payload);
    cr_assert_eq(ret, 0, "Returned value %d was not 0", ret);
    close(fd);

    ret = system("cmp pkt_ack_no_payload tests/rsrc/pkt_ack_no_payload");
    cr_assert_eq(ret, 0, "Packet sent did not match expected");
}

Test(protocol_suite, send_with_payload, .init = init, .timeout = 5) {
#ifdef NO_PROTOCOL
    cr_assert_fail("Protocol was not implemented");
#endif

    int fd;
    char *payloadp = "This is a test payload";
    JEUX_PACKET_HEADER pkt = {0};

    pkt.type = JEUX_ACK_PKT;
    pkt.size = htons(strlen(payloadp));
    pkt.timestamp_sec = htonl(0x11223344);
    pkt.timestamp_nsec = htonl(0x55667788);

    fd = open("pkt_ack_with_payload", O_CREAT|O_TRUNC|O_RDWR, 0644);
    cr_assert(fd > 0, "Failed to create output file");
    int ret = proto_send_packet(fd, &pkt, payloadp);
    cr_assert_eq(ret, 0, "Returned value was %d not 0", ret);
    close(fd);

    ret = system("cmp pkt_ack_with_payload tests/rsrc/pkt_ack_with_payload");
    cr_assert_eq(ret, 0, "Packet sent did not match expected");
}

Test(protocol_suite, send_error, .init = init, .timeout = 5) {
#ifdef NO_PROTOCOL
    cr_assert_fail("Protocol was not implemented");
#endif
    int fd;
    void *payload = NULL;
    JEUX_PACKET_HEADER pkt = {0};

    pkt.type = JEUX_ACK_PKT;
    pkt.size = htons(0);
    pkt.timestamp_sec = htonl(0x11223344);
    pkt.timestamp_nsec = htonl(0x55667788);

    fd = open("pkt_ack_no_payload", O_CREAT|O_TRUNC|O_RDWR, 0644);
    cr_assert(fd > 0, "Failed to create output file");
    // Here is the error.
    close(fd);
    int ret = proto_send_packet(fd, &pkt, payload);
    cr_assert_neq(ret, 0, "Returned value was zero", ret);
}

Test(protocol_suite, recv_no_payload, .init = init, .timeout = 5) {
#ifdef NO_PROTOCOL
    cr_assert_fail("Protocol was not implemented");
#endif
    int fd;
    void *payload = NULL;
    JEUX_PACKET_HEADER pkt = {0};

#ifdef CREATE_REFERENCE_FILES
    fd = open("pkt_revoke_no_payload", O_CREAT|O_TRUNC|O_RDWR, 0644);
    pkt.type = JEUX_REVOKE_PKT;
    pkt.id = 0x99;
    pkt.size = htons(0);
    pkt.timestamp_sec = htonl(0x11223344);
    pkt.timestamp_nsec = htonl(0x55667788);
    proto_send_packet(fd, &pkt, NULL);
    close(fd);
    memset(&pkt, 0, sizeof(pkt));
#endif

    fd = open("tests/rsrc/pkt_revoke_no_payload", O_RDONLY, 0);
    cr_assert(fd > 0, "Failed to open test input file");
    int ret = proto_recv_packet(fd, &pkt, &payload);
    cr_assert_eq(ret, 0, "Returned value was not 0");
    close(fd);

    cr_assert_eq(pkt.type, JEUX_REVOKE_PKT, "Received packet type %d did not match expected %d",
		 pkt.type, JEUX_REVOKE_PKT);
    cr_assert_eq(ntohs(pkt.size), 0, "Received payload size was %u not zero", ntohs(pkt.size));
    cr_assert_eq(ntohl(pkt.timestamp_sec), 0x11223344,
		 "Received message timestamp_sec 0x%x did not match expected 0x%x",
		 ntohl(pkt.timestamp_sec), 0x11223344);
    cr_assert_eq(ntohl(pkt.timestamp_nsec), 0x55667788,
		 "Received message timestamp_nsec 0x%x did not match expected 0x%x",
		 ntohl(pkt.timestamp_nsec), 0x55667788);
}

Test(protocol_suite, recv_with_payload, .init = init, .timeout = 5) {
#ifdef NO_PROTOCOL
    cr_assert_fail("Protocol was not implemented");
#endif
    int fd;
    char *exp_payload = "This_is_a_long_user_name";
    int exp_size = strlen(exp_payload);
    void *payload = NULL;
    JEUX_PACKET_HEADER pkt = {0};

#ifdef CREATE_REFERENCE_FILES
    fd = open("pkt_login", O_CREAT|O_TRUNC|O_RDWR, 0644);
    pkt.type = JEUX_LOGIN_PKT;
    pkt.size = htons(exp_size);
    pkt.timestamp_sec = htonl(0x11223344);
    pkt.timestamp_nsec = htonl(0x55667788);
    proto_send_packet(fd, &pkt, exp_payload);
    close(fd);
    memset(&pkt, 0, sizeof(pkt));
#endif

    fd = open("tests/rsrc/pkt_login", O_RDONLY, 0);
    cr_assert(fd > 0, "Failed to open test input file");
    int ret = proto_recv_packet(fd, &pkt, &payload);
    cr_assert_eq(ret, 0, "Returned value was not 0");
    close(fd);

    cr_assert_eq(pkt.type, JEUX_LOGIN_PKT, "Received packet type %d did not match expected %d",
		 pkt.type, JEUX_LOGIN_PKT);
    cr_assert_eq(ntohs(pkt.size), exp_size, "Received payload size was %u not %u", ntohs(pkt.size),
		 exp_size);
    cr_assert_eq(ntohl(pkt.timestamp_sec), 0x11223344,
		 "Received message timestamp_sec 0x%x did not match expected 0x%x",
		 ntohl(pkt.timestamp_sec), 0x11223344);
    cr_assert_eq(ntohl(pkt.timestamp_nsec), 0x55667788,
		 "Received message timestamp_nsec 0x%x did not match expected 0x%x",
		 ntohl(pkt.timestamp_nsec), 0x55667788);
    int n = strncmp(payload, exp_payload, exp_size);
    cr_assert_eq(n, 0, "Received message payload did not match expected");
}

Test(protocol_suite, recv_empty, .init = init, .timeout = 5) {
#ifdef NO_PROTOCOL
    cr_assert_fail("Protocol was not implemented");
#endif
    int fd;
    void *payload = NULL;
    JEUX_PACKET_HEADER pkt = {0};

    fd = open("tests/rsrc/pkt_empty", O_RDONLY, 0);
    cr_assert(fd > 0, "Failed to open test input file");
    int ret = proto_recv_packet(fd, &pkt, &payload);
    cr_assert_neq(ret, 0, "Returned value was 0");
    close(fd);
}

Test(protocol_suite, recv_short_header, .init = init, .timeout = 5) {
#ifdef NO_PROTOCOL
    cr_assert_fail("Protocol was not implemented");
#endif
    int fd;
    void *payload = NULL;
    JEUX_PACKET_HEADER pkt = {0};

    fd = open("tests/rsrc/pkt_short_header", O_RDONLY, 0);
    cr_assert(fd > 0, "Failed to open test input file");
    int ret = proto_recv_packet(fd, &pkt, &payload);
    cr_assert_neq(ret, 0, "Returned value was 0");
    close(fd);
}

Test(protocol_suite, recv_short_payload, .init = init, .signal = SIGALRM) {
#ifdef NO_PROTOCOL
    cr_assert_fail("Protocol was not implemented");
#endif
    int fd;
    void *payload = NULL;
    JEUX_PACKET_HEADER pkt = {0};
    struct itimerval itv = {{0, 0}, {1, 0}};

    fd = open("tests/rsrc/pkt_short_payload", O_RDONLY, 0);
    cr_assert(fd > 0, "Failed to open test input file");
    // On a network connection, reading will block until the specified
    // amount of payload has been received.  So we have to set an alarm
    // to terminate the test.  Because we are reading from a file here,
    // the underlying read() should return 0, indicating EOF, which
    // proto_recv_packet() should detect and set errno != EINTR.
    // In that case, we have to generate the expected signal manually.
    setitimer(ITIMER_REAL, &itv, NULL);
    int ret = proto_recv_packet(fd, &pkt, &payload);
    cr_assert_neq(ret, 0, "Returned value was 0");
    if(errno != EINTR)
	kill(getpid(), SIGALRM);
    close(fd);
}

Test(protocol_suite, recv_error, .init = init, .timeout = 5) {
#ifdef NO_PROTOCOL
    cr_assert_fail("Protocol was not implemented");
#endif
    int fd;
    void *payload = NULL;
    JEUX_PACKET_HEADER pkt = {0};

    fd = open("tests/rsrc/pkt_empty", O_RDONLY, 0);
    cr_assert(fd > 0, "Failed to open test input file");
    close(fd);
    int ret = proto_recv_packet(fd, &pkt, &payload);
    cr_assert_neq(ret, 0, "Returned value was zero");
}


////////////////////////////////////////////// SERVER TESTS //////////////////////////////////////////
/* Number of threads we create in multithreaded tests. */
#define NTHREAD (15)

static char *jeux_packet_type_names[] = {
    [JEUX_NO_PKT]       "NONE",
    [JEUX_LOGIN_PKT]    "LOGIN",
    [JEUX_USERS_PKT]    "USERS",
    [JEUX_INVITE_PKT]   "INVITE",
    [JEUX_REVOKE_PKT]   "REVOKE",
    [JEUX_ACCEPT_PKT]   "ACCEPT",
    [JEUX_DECLINE_PKT]  "DECLINE",
    [JEUX_MOVE_PKT]     "MOVE",
    [JEUX_RESIGN_PKT]   "RESIGN",
    [JEUX_ACK_PKT]      "ACK",
    [JEUX_NACK_PKT]     "NACK",
    [JEUX_INVITED_PKT]  "INVITED",
    [JEUX_REVOKED_PKT]  "REVOKED",
    [JEUX_ACCEPTED_PKT] "ACCEPTED",
    [JEUX_DECLINED_PKT] "DECLINED",
    [JEUX_MOVED_PKT]    "MOVED",
    [JEUX_RESIGNED_PKT] "RESIGNED",
    [JEUX_ENDED_PKT]    "ENDED"
};

static void init() {
    client_registry = creg_init();
    player_registry = preg_init();

    // Sending packets to disconnected clients will cause termination by SIGPIPE
    // unless we take steps to ignore it.
    struct sigaction sact;
    sact.sa_handler = SIG_IGN;
    sigemptyset(&sact.sa_mask);
    sact.sa_flags = 0;
    sigaction(SIGPIPE, &sact, NULL);
}

static void proto_init_packet(JEUX_PACKET_HEADER *pkt, JEUX_PACKET_TYPE type, size_t size) {
    memset(pkt, 0, sizeof(*pkt));
    pkt->type = type;
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
	perror("clock_gettime");
    }
    pkt->timestamp_sec = htonl(ts.tv_sec);
    pkt->timestamp_nsec = htonl(ts.tv_nsec);
    pkt->size = htons(size);
}

/*
 * Read a packet and check the header fields.
 * The packet and payload are returned.
 */
static void check_packet(int fd, JEUX_PACKET_TYPE type, GAME_ROLE role, int id,
			 JEUX_PACKET_HEADER *pktp, void **payloadp) {
    void *data;
    int err = proto_recv_packet(fd, pktp, &data);
    if(payloadp)
        *payloadp = data;
    cr_assert_eq(err, 0, "Error reading back packet");
    cr_assert_eq(pktp->type, type, "Packet type (%s) was not the expected type (%s)",
		 jeux_packet_type_names[pktp->type], jeux_packet_type_names[type]);
    if(role <= SECOND_PLAYER_ROLE) {
	cr_assert_eq(pktp->role, role, "Role in packet (%d) does not match expected (%d)",
		     pktp->role, role);
    }
    if(id >= 0) {
	cr_assert_eq(pktp->id, id, "ID in packet (%d) does not match expected (%d)",
		     pktp->id, id);
    }
}

/*
 * For these tests, we will set up a connection betwen a test driver thread
 * and a server thread using a socket.  The driver thread will create and
 * bind the socket, then accept a connection.  The server thread will
 * connect and then hand off the file descriptor to the jeux_client_service
 * function, as if the connection had been made over the network.
 * Communication over the connection will be done using whatever protocol
 * functions are linked, so if those don't work then the present tests will
 * likely also fail.
 */

/*
 * Thread function that connects to a socket with a specified name,
 * then hands off the resulting file descriptor to jeux_client_service.
 * Errors cause the invoking test to fail.
 */
static void *server_thread(void *args) {
    char *name = args;  // socket name
    struct sockaddr_un sa;
    sa.sun_family = AF_LOCAL;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", name);
    int sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    cr_assert(sockfd >= 0, "Failed to create socket");
    int err = connect(sockfd, (struct sockaddr *)&sa, sizeof(struct sockaddr_un));
    cr_assert(err == 0, "Failed to connect to socket");
    int *connfdp = malloc(sizeof(int));
    *connfdp = sockfd;
    jeux_client_service(connfdp);
    return NULL;
}

/*
 * Set up a connection to a server thread, via a socket with a specified name.
 * The file descriptor to be used to communicate with the server is returned.
 * Errors cause the invoking test to fail.
 */
static int setup_connection(char *name) {
    // Set up socket to receive connection from server thread.
    int listen_fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    cr_assert(listen_fd >= 0, "Failed to create socket");
    struct sockaddr_un sa;
    sa.sun_family = AF_LOCAL;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", name);
    unlink((char *)sa.sun_path);
    int err = bind(listen_fd, (struct sockaddr *)&sa, sizeof(struct sockaddr_un));
    cr_assert(err >= 0, "Failed to bind socket");
    err = listen(listen_fd, 0);
    cr_assert(err >= 0, "Failed to listen on socket");

    // Create server thread, passing the name of the socket.
    pthread_t tid;
    err = pthread_create(&tid, NULL, server_thread, name);
    cr_assert(err >= 0, "Failed to create server thread");

    // Accept connection from server thread.
    int connfd = accept(listen_fd, NULL, NULL);
    cr_assert(connfd >= 0, "Failed to accept connection");
    return connfd;
}    

/*
 * Perform a login operation on a specified connection, for a specified
 * user name.  Nothing is returned; errors cause the invoking test to fail.
 */
static void login_func(int connfd, char *uname) {
    JEUX_PACKET_HEADER pkt;
    proto_init_packet(&pkt, JEUX_LOGIN_PKT, strlen(uname));
    int err = proto_send_packet(connfd, &pkt, uname);
    cr_assert_eq(err, 0, "Send packet returned an error");
    memset(&pkt, 0, sizeof(pkt));
    check_packet(connfd, JEUX_ACK_PKT, 3, -1, &pkt, NULL);
}

/*
 * Test driver thread that sends a packet other than LOGIN over the connection
 * and checks that NACK is received.
 */
static void *ping_thread(void *arg) {
    return NULL;
}

/*
 * Create a connection and then "ping" it to elicit a NACK.
 */
Test(server_suite, ping, .init = init, .timeout = 5) {
#ifdef NO_SERVER
    cr_assert_fail("Server module was not implemented");
#endif
    char *sockname = "ping.sock";
    int connfd = setup_connection(sockname);

    JEUX_PACKET_HEADER pkt;
    proto_init_packet(&pkt, JEUX_USERS_PKT, 0);
    int err = proto_send_packet(connfd, &pkt, NULL);
    cr_assert_eq(err, 0, "Send packet returned an error");
    check_packet(connfd, JEUX_NACK_PKT, 3, -1, &pkt, NULL);
    close(connfd);
}

/*
 * Create a connection, log in, then close the connection.
 */
Test(server_suite, valid_login, .init = init, .timeout = 5) {
#ifdef NO_SERVER
    cr_assert_fail("Server module was not implemented");
#endif
    char *sockname = "valid_login.sock";
    char *username = "Alice";
    int connfd = setup_connection(sockname);
    login_func(connfd, username);
    close(connfd);
}

/*
 * I would test a LOGIN with no payload, except that my server
 * allocates an empty payload and goes ahead and does a login with
 * an empty username.  So probably not fair.
 */

/*
 * I would also test attempting to LOGIN twice with the same username,
 * except that my server allows that and probably cannot avoid this
 * without some amount of design change.
 */

/*
 * The following tests have some redundancy with the tests for the
 * lower-level client module; however, the present tests verify the
 * proper dispatching of internal functions in response to incoming packets.
 * They also verifies ACK/NACK which is not sent at the lower level.
 */

/*
 * Set up two clients, then make an invitation from one to the other
 * and check that the required INVITED and ACK packets are sent.
 * Finally, close the connections to cause the invitation to be revoked.
 */
Test(server_suite, invite_disconnect, .init = init, .timeout = 5) {
#ifdef NO_SERVER
    cr_assert_fail("Server module was not implemented");
#endif
    char *sockname1 = "server_invite_disconnect1.pkts";
    char *sockname2 = "server_invite_disconnect2.pkts";
    char *username1 = "Alice";
    char *username2 = "Bob";
    int fd1 = setup_connection(sockname1);
    int fd2 = setup_connection(sockname2);
    login_func(fd1, username1);
    login_func(fd2, username2);

    JEUX_PACKET_HEADER pkt;
    proto_init_packet(&pkt, JEUX_INVITE_PKT, strlen(username2));
    pkt.role = SECOND_PLAYER_ROLE;
    int err = proto_send_packet(fd1, &pkt, username2);
    cr_assert_eq(err, 0, "Send packet returned an error");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd1, JEUX_ACK_PKT, 3, -1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);

    close(fd1);
    close(fd2);
}

/*
 * Set up two clients, then make an invitation from one to the other
 * and check that the required INVITED and ACK packets are sent.
 * Then, the target declines the invitation and we check that the
 * required DECLINED and ACK packets are sent.
 */
Test(server_suite, invite_decline, .init = init, .timeout = 5) {
#ifdef NO_SERVER
    cr_assert_fail("Server module was not implemented");
#endif
    char *sockname1 = "server_invite_decline1.pkts";
    char *sockname2 = "server_invite_decline2.pkts";
    char *username1 = "Alice";
    char *username2 = "Bob";
    int fd1 = setup_connection(sockname1);
    int fd2 = setup_connection(sockname2);
    login_func(fd1, username1);
    login_func(fd2, username2);

    JEUX_PACKET_HEADER pkt;
    proto_init_packet(&pkt, JEUX_INVITE_PKT, strlen(username2));
    pkt.role = SECOND_PLAYER_ROLE;
    int err = proto_send_packet(fd1, &pkt, username2);
    cr_assert_eq(err, 0, "Send packet returned an error");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd1, JEUX_ACK_PKT, 3, -1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);
    int id1 = in_pkt1.id;
    int id2 = in_pkt2.id;

    proto_init_packet(&pkt, JEUX_DECLINE_PKT, 0);
    pkt.id = id2;
    err = proto_send_packet(fd2, &pkt, NULL);
    cr_assert_eq(err, 0, "Send packet returned an error");

    check_packet(fd1, JEUX_DECLINED_PKT, 3, id1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_ACK_PKT, 3, -1, &in_pkt2, NULL);

    close(fd1);
    close(fd2);
}

/*
 * Set up two clients, then make an invitation from one to the other
 * and check that the required INVITED and ACK packets are sent.
 * Then, the source revokes the invitation and we check that the
 * required REVOKED and ACK packets are sent.
 */
Test(server_suite, invite_revoke, .init = init, .timeout = 5) {
#ifdef NO_SERVER
    cr_assert_fail("Server module was not implemented");
#endif
    char *sockname1 = "server_invite_revoke1.pkts";
    char *sockname2 = "server_invite_revoke2.pkts";
    char *username1 = "Alice";
    char *username2 = "Bob";
    int fd1 = setup_connection(sockname1);
    int fd2 = setup_connection(sockname2);
    login_func(fd1, username1);
    login_func(fd2, username2);

    JEUX_PACKET_HEADER pkt;
    proto_init_packet(&pkt, JEUX_INVITE_PKT, strlen(username2));
    pkt.role = SECOND_PLAYER_ROLE;
    int err = proto_send_packet(fd1, &pkt, username2);
    cr_assert_eq(err, 0, "Send packet returned an error");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd1, JEUX_ACK_PKT, 3, -1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);
    int id1 = in_pkt1.id;
    int id2 = in_pkt2.id;

    proto_init_packet(&pkt, JEUX_REVOKE_PKT, 0);
    pkt.id = id1;
    err = proto_send_packet(fd1, &pkt, NULL);
    cr_assert_eq(err, 0, "Send packet returned an error");

    check_packet(fd1, JEUX_ACK_PKT, 3, -1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_REVOKED_PKT, 3, id2, &in_pkt2, NULL);

    close(fd1);
    close(fd2);
}

/*
 * Set up two clients, then make an invitation from one to the other
 * and check that the required INVITED and ACK packets are sent.
 * Then, the target accepts the invitation and we check that the
 * required ACCEPTED and ACK packets are sent.
 * In this version, the target has the role of the second player,
 * so the ACCEPTED packet should contain the payload with the initial
 * game state.
 */
Test(server_suite, invite_accept_second, .init = init, .timeout = 5) {
#ifdef NO_SERVER
    cr_assert_fail("Server module was not implemented");
#endif
    char *sockname1 = "server_invite_accept_second1.pkts";
    char *sockname2 = "server_invite_accept_second2.pkts";
    char *username1 = "Alice";
    char *username2 = "Bob";
    int fd1 = setup_connection(sockname1);
    int fd2 = setup_connection(sockname2);
    login_func(fd1, username1);
    login_func(fd2, username2);

    JEUX_PACKET_HEADER pkt;
    proto_init_packet(&pkt, JEUX_INVITE_PKT, strlen(username2));
    pkt.role = SECOND_PLAYER_ROLE;
    int err = proto_send_packet(fd1, &pkt, username2);
    cr_assert_eq(err, 0, "Send packet returned an error");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd1, JEUX_ACK_PKT, 3, -1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);
    int id1 = in_pkt1.id;
    int id2 = in_pkt2.id;

    proto_init_packet(&pkt, JEUX_ACCEPT_PKT, 0);
    pkt.id = id2;
    err = proto_send_packet(fd2, &pkt, NULL);
    cr_assert_eq(err, 0, "Send packet returned an error");

    check_packet(fd1, JEUX_ACCEPTED_PKT, 3, id1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_ACK_PKT, 3, -1, &in_pkt2, NULL);
    cr_assert(ntohs(in_pkt1.size) > 0, "The ACCEPTED packet had no payload");

    close(fd1);
    close(fd2);
}

/*
 * Set up two clients, then make an invitation from one to the other
 * and check that the required INVITED and ACK packets are sent.
 * Then, the target accepts the invitation and we check that the
 * required ACCEPTED and ACK packets are sent.
 * In this version, the target has the role of the first player,
 * so the ACK packet should contain the payload with the initial
 * game state.
 */
Test(server_suite, invite_accept_first, .init = init, .timeout = 5) {
#ifdef NO_SERVER
    cr_assert_fail("Server module was not implemented");
#endif
    char *sockname1 = "server_invite_accept_first1.pkts";
    char *sockname2 = "server_invite_accept_first2.pkts";
    char *username1 = "Alice";
    char *username2 = "Bob";
    int fd1 = setup_connection(sockname1);
    int fd2 = setup_connection(sockname2);
    login_func(fd1, username1);
    login_func(fd2, username2);

    JEUX_PACKET_HEADER pkt;
    proto_init_packet(&pkt, JEUX_INVITE_PKT, strlen(username2));
    pkt.role = FIRST_PLAYER_ROLE;
    int err = proto_send_packet(fd1, &pkt, username2);
    cr_assert_eq(err, 0, "Send packet returned an error");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd1, JEUX_ACK_PKT, 3, -1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_INVITED_PKT, FIRST_PLAYER_ROLE, -1, &in_pkt2, NULL);
    int id1 = in_pkt1.id;
    int id2 = in_pkt2.id;

    proto_init_packet(&pkt, JEUX_ACCEPT_PKT, 0);
    pkt.id = id2;
    err = proto_send_packet(fd2, &pkt, NULL);
    cr_assert_eq(err, 0, "Send packet returned an error");

    check_packet(fd1, JEUX_ACCEPTED_PKT, 3, id1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_ACK_PKT, 3, -1, &in_pkt2, NULL);
    cr_assert(ntohs(in_pkt2.size) > 0, "The ACK packet had no payload");

    close(fd1);
    close(fd2);
}

/*
 * Set up two clients, then make an invitation from one to the other
 * and check that the required INVITED and ACK packets are sent.
 * Then, the target accepts the invitation and we check that the
 * required ACCEPTED and ACK packets are sent.
 * Finally, the source resigns the game and we check that the required
 * RESIGNED, ACK, and ENDED packets are sent.
 */
Test(server_suite, invite_accept_resign, .init = init, .timeout = 5) {
#ifdef NO_SERVER
    cr_assert_fail("Server module was not implemented");
#endif
    char *sockname1 = "server_invite_accept_resign1.pkts";
    char *sockname2 = "server_invite_accept_resign2.pkts";
    char *username1 = "Alice";
    char *username2 = "Bob";
    int fd1 = setup_connection(sockname1);
    int fd2 = setup_connection(sockname2);
    login_func(fd1, username1);
    login_func(fd2, username2);

    JEUX_PACKET_HEADER pkt;
    proto_init_packet(&pkt, JEUX_INVITE_PKT, strlen(username2));
    pkt.role = SECOND_PLAYER_ROLE;
    int err = proto_send_packet(fd1, &pkt, username2);
    cr_assert_eq(err, 0, "Send packet returned an error");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd1, JEUX_ACK_PKT, 3, -1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);
    int id1 = in_pkt1.id;
    int id2 = in_pkt2.id;

    proto_init_packet(&pkt, JEUX_ACCEPT_PKT, 0);
    pkt.id = id2;
    err = proto_send_packet(fd2, &pkt, NULL);
    cr_assert_eq(err, 0, "Send packet returned an error");

    check_packet(fd1, JEUX_ACCEPTED_PKT, 3, id1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_ACK_PKT, 3, -1, &in_pkt2, NULL);
    cr_assert(ntohs(in_pkt1.size) > 0, "The ACCEPTED packet had no payload");

    proto_init_packet(&pkt, JEUX_RESIGN_PKT, 0);
    pkt.id = id1;
    err = proto_send_packet(fd1, &pkt, NULL);
    cr_assert_eq(err, 0, "Send packet returned an error");

    check_packet(fd1, JEUX_ENDED_PKT, 3, id1, &in_pkt1, NULL);
    check_packet(fd1, JEUX_ACK_PKT, 3, -1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_RESIGNED_PKT, 3, id2, &in_pkt2, NULL);
    check_packet(fd2, JEUX_ENDED_PKT, 3, id2, &in_pkt2, NULL);

    close(fd1);
    close(fd2);
}

/*
 * Set up two clients, then make an invitation from one to the other
 * and check that the required INVITED and ACK packets are sent.
 * Then, the target accepts the invitation and we check that the
 * required ACCEPTED and ACK packets are sent.
 * Finally, the first player makes a move we check that the required
 * MOVED and ACK packets are sent.
 */
Test(server_suite, invite_accept_move, .init = init, .timeout = 5) {
#ifdef NO_SERVER
    cr_assert_fail("Server module was not implemented");
#endif
    char *sockname1 = "server_invite_accept_move1.pkts";
    char *sockname2 = "server_invite_accept_move2.pkts";
    char *username1 = "Alice";
    char *username2 = "Bob";
    int fd1 = setup_connection(sockname1);
    int fd2 = setup_connection(sockname2);
    login_func(fd1, username1);
    login_func(fd2, username2);

    JEUX_PACKET_HEADER pkt;
    proto_init_packet(&pkt, JEUX_INVITE_PKT, strlen(username2));
    pkt.role = SECOND_PLAYER_ROLE;
    int err = proto_send_packet(fd1, &pkt, username2);
    cr_assert_eq(err, 0, "Send packet returned an error");

    JEUX_PACKET_HEADER in_pkt1, in_pkt2;
    check_packet(fd1, JEUX_ACK_PKT, 3, -1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_INVITED_PKT, SECOND_PLAYER_ROLE, -1, &in_pkt2, NULL);
    int id1 = in_pkt1.id;
    int id2 = in_pkt2.id;

    proto_init_packet(&pkt, JEUX_ACCEPT_PKT, 0);
    pkt.id = id2;
    err = proto_send_packet(fd2, &pkt, NULL);
    cr_assert_eq(err, 0, "Send packet returned an error");

    check_packet(fd1, JEUX_ACCEPTED_PKT, 3, id1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_ACK_PKT, 3, -1, &in_pkt2, NULL);
    cr_assert(ntohs(in_pkt1.size) > 0, "The ACCEPTED packet had no payload");

    char *move = "5";
    proto_init_packet(&pkt, JEUX_MOVE_PKT, strlen(move));
    pkt.id = id1;
    err = proto_send_packet(fd1, &pkt, move);
    cr_assert_eq(err, 0, "Send packet returned an error");

    check_packet(fd1, JEUX_ACK_PKT, 3, -1, &in_pkt1, NULL);
    check_packet(fd2, JEUX_MOVED_PKT, 3, id2, &in_pkt2, NULL);
    cr_assert(ntohs(in_pkt2.size) > 0, "The MOVED packet had no payload");

    close(fd1);
    close(fd2);
}

/*
 * Create a connection, log in a single user and then send USERS.
 * Check for an ACK with the correct payload.
 * Then close the connection.
 */
Test(server_suite, login_users, .init = init, .timeout = 5) {
#ifdef NO_SERVER
    cr_assert_fail("Server module was not implemented");
#endif
    char *sockname = "login_users.sock";
    char *username = "Alice";
    int connfd = setup_connection(sockname);
    login_func(connfd, username);

    JEUX_PACKET_HEADER pkt;
    proto_init_packet(&pkt, JEUX_USERS_PKT, 0);
    int err = proto_send_packet(connfd, &pkt, NULL);
    cr_assert_eq(err, 0, "Send packet returned an error");
    memset(&pkt, 0, sizeof(pkt));
    void *data = NULL;
    check_packet(connfd, JEUX_ACK_PKT, 3, -1, &pkt, &data);
    char *str = calloc(ntohs(pkt.size)+1, 1);
    strncpy(str, data, ntohs(pkt.size));
    char *exp = "Alice\t1500\n";
    cr_assert(!strcmp(str, exp), "Returned payload (%s) was not the expected (%s)",
	      str, data);

    close(connfd);
}

/*
 * Concurrently create many connections and log in a different
 * user on each one.  Then send USERS and check the payload that
 * is returned.
 */

struct login_thread_args {
    char sockname[32];
    char username[32];
};

void *login_thread(void *args) {
    struct login_thread_args *ap = args;
    int connfd = setup_connection(ap->sockname);
    login_func(connfd, ap->username);
    return (void *)(long)connfd;
}

Test(server_suite, login_many_users, .init = init, .timeout = 5) {
#ifdef NO_SERVER
    cr_assert_fail("Server module was not implemented");
#endif
    char *sockname = "login_many_users.sock";

    pthread_t tids[NTHREAD];
    // The first connection will be used later to issue USERS.
    int connfd = setup_connection(sockname);
    login_func(connfd, "u0");

    // The rest of the connections are made concurrently.
    for(int i = 1; i < NTHREAD; i++) {
	struct login_thread_args *args = malloc(sizeof(struct login_thread_args));
	snprintf(args->sockname, sizeof(args->sockname), "%s.%d", sockname, i);
	snprintf(args->username, sizeof(args->username), "u%d", i);
	int err = pthread_create(&tids[i], NULL, login_thread, args);
	cr_assert(err >= 0, "Failed to create test thread");
    }
    // Wait for all the threads to finish.
    int fds[NTHREAD];
    for(int i = 1; i < NTHREAD; i++)
	fds[i] = (int)pthread_join(tids[i], NULL);

    // Send USERS over the first connection and get the response.
    JEUX_PACKET_HEADER pkt;
    proto_init_packet(&pkt, JEUX_USERS_PKT, 0);
    int err = proto_send_packet(connfd, &pkt, NULL);
    cr_assert_eq(err, 0, "Send packet returned an error");
    void *data = NULL;
    check_packet(connfd, JEUX_ACK_PKT, 3, -1, &pkt, &data);
    char *str = calloc(ntohs(pkt.size)+1, 1);
    strncpy(str, data, ntohs(pkt.size));
    
    // Check the response
    //fprintf(stderr, "\n%s\n", str);
    FILE *f = fmemopen(str, strlen(str), "r");
    int nlines = 0;
    char *ln = NULL;
    size_t sz = 0;
    while(getline(&ln, &sz, f) > 0) {
	nlines++;
	int count = 0;
	for(int i = 0; i < NTHREAD; i++) {
	    char line[64];
	    snprintf(line, sizeof(line), "u%d\t1500\n", i);
	    if(!strcmp(ln, line))
		count++;
	}
	cr_assert_eq(count, 1, "USERS output was incorrect: \n%s\n", str);
	free(ln);
	sz = 0; ln = NULL;
    }
    free(ln);
    fclose(f);
    cr_assert_eq(nlines, NTHREAD, "Number of lines (%d) did not match expected (%d)",
		 nlines, NTHREAD);

    // Close all the connections.
    for(int i = 1; i < NTHREAD; i++)
	close(fds[i]);
    close(connfd);
}
