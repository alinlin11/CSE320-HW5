#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "debug.h"
#include "protocol.h"
#include "server.h"
#include "client_registry.h"
#include "player_registry.h"
#include "jeux_globals.h"
#include "csapp.h"

#ifdef DEBUG
int _debug_packets_ = 1;
#endif

volatile sig_atomic_t sighup_flag = 0;

static void terminate(int status);
void sighup_handler(int sigum, siginfo_t *siginfo, void *context);



void sighup_handler(int signum, siginfo_t *siginfo, void *context) {
    // Terminate server
    sighup_flag = 1;
}
/*
 * "Jeux" game server.
 *
 * Usage: jeux <port>
 */
int main(int argc, char* argv[]){
    // Option processing should be performed here.
    // Option '-p <port>' is required in order to specify the port number
    // on which the server should listen.

    char *port = NULL;
    debug("Arguments: %s %s %s\n", argv[0], argv[1], argv[2]);
    if(argc < 3 || strcmp(argv[1], "-p") != 0) {
        fprintf(stderr, "Incorrect format");
        return EXIT_FAILURE;
    }

    port = argv[2];

    // Perform required initializations of the client_registry and
    // player_registry.
    client_registry = creg_init();
    player_registry = preg_init();

    // TODO: Set up the server socket and enter a loop to accept connections
    // on this socket.  For each connection, a thread should be started to
    // run function jeux_client_service().  In addition, you should install
    // a SIGHUP handler, so that receipt of SIGHUP will perform a clean
    // shutdown of the server.
    struct sigaction sig_hup = {0};
    sig_hup.sa_sigaction = sighup_handler;
    sigemptyset(&sig_hup.sa_mask);
    sig_hup.sa_flags = 0;
    sigaction(SIGHUP, &sig_hup, NULL);


    struct sockaddr_storage clientaddr = {0};
    socklen_t clientlen = 0;


    int listen_fd = Open_listenfd(port);

    debug("Listening at port %s\n", port);
    debug("pid %d", getpid());

    while(1) {
        clientlen = sizeof(struct sockaddr_storage);

        int *client_socket_fd = malloc(sizeof(int));
        *client_socket_fd = Accept(listen_fd, (SA *)&clientaddr, &clientlen);
        if(sighup_flag) {
            terminate(0);
        }

        // create a new thread to handle the client connection
        pthread_t thread;
        pthread_create(&thread, NULL, jeux_client_service, client_socket_fd);

    }
    
    // fprintf(stderr, "You have to finish implementing main() "
	//     "before the Jeux server will function.\n");

    terminate(EXIT_FAILURE);
    // TODO revise signal
}

/*
 * Function called to cleanly shut down the server.
 */
void terminate(int status) {
    // Shutdown all client connections.
    // This will trigger the eventual termination of service threads.
    creg_shutdown_all(client_registry);
    
    debug("%ld: Waiting for service threads to terminate...", pthread_self());
    creg_wait_for_empty(client_registry);
    debug("%ld: All service threads terminated.", pthread_self());

    // Finalize modules.
    creg_fini(client_registry);
    preg_fini(player_registry);

    debug("%ld: Jeux server terminating", pthread_self());
    exit(status);
}
