#include <stdlib.h>
#include <semaphore.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

#include "debug.h"
#include "client_registry.h"


// Define the CLIENT_REGISTRY TYPE
struct client_registry {
    int client_count;
    sem_t mutex;
    pthread_mutex_t count_mutex;
    CLIENT *clients[MAX_CLIENTS];
};

// Mutex<T>
// Mutex<client_registry>
// Mutex<client_list>
// Mutex<client_count>


CLIENT_REGISTRY *creg_init() {
    CLIENT_REGISTRY *registry = malloc(sizeof(CLIENT_REGISTRY));
    registry->client_count = 0;
    sem_init(&registry->mutex, 0, 1);
    pthread_mutex_init(&registry->count_mutex, NULL);

    for(int i = 0; i < MAX_CLIENTS; i++) {
        registry->clients[i] = NULL;
    }

    return registry;
}

void creg_fini(CLIENT_REGISTRY *cr) {
    if(cr->client_count < 0) {
        return;
    }

    // sem_wait(&cr->sem);

    // Free the clients fd array
    // for(int i = 0; i < cr->client_count; i++) {
    //     // close(cr->clients[i]->fd);
    //     if(cr->clients[i] != NULL) {
    //         // creg_unregister(cr, cr->clients[i]);
    //         cr->clients[i] = NULL;
    //     }   
        
    // }
    
    sem_destroy(&cr->mutex);
    pthread_mutex_destroy(&cr->count_mutex);
    free(cr);

}

CLIENT *creg_register(CLIENT_REGISTRY *cr, int fd) {
    // Mutex
    sem_wait(&cr->mutex);

    if (cr->client_count == MAX_CLIENTS) {
        sem_post(&cr->mutex);
        return NULL;
    }

    CLIENT *client = client_create(cr, fd);
    if(client == NULL) {
        sem_post(&cr->mutex);
        return NULL;
    }

    pthread_mutex_lock(&cr->count_mutex);

    // Add client to registry
    for(int i = 0; i < MAX_CLIENTS; i++) {
        if(cr->clients[i] == NULL) {
            cr->clients[i] = client;
            cr->client_count += 1;
            break;
        }
    }

    pthread_mutex_unlock(&cr->count_mutex);
    sem_post(&cr->mutex);

    return client;
}

int creg_unregister(CLIENT_REGISTRY *cr, CLIENT *client) {
    sem_wait(&cr->mutex);
    pthread_mutex_lock(&cr->count_mutex);

    for(int i = 0; i < MAX_CLIENTS; i++) {
        if(cr->clients[i] == client) {
            cr->client_count -= 1;
            cr->clients[i] = NULL;
            client_unref(client, "Reference count decreased to unregister client");
            
            pthread_mutex_unlock(&cr->count_mutex);
            sem_post(&cr->mutex);
            // client_logout(client);
            return 0;
        }
    }

    pthread_mutex_unlock(&cr->count_mutex);
    sem_post(&cr->mutex);
    return -1;
}

CLIENT *creg_lookup(CLIENT_REGISTRY *cr, char *user) {
    for(int i = 0; i < MAX_CLIENTS; i++) {
        if(cr->clients[i] != NULL) {
            PLAYER *player = client_get_player(cr->clients[i]);
            if(player == NULL) {
                continue;
            }
            char *name = player_get_name(player);
            debug("comparing user: %s and the name inside reg: %s", user, name);

            if(strcmp(name, user) == 0) {
                client_ref(cr->clients[i], "Ref count incremented because of creg_lookup");
                return cr->clients[i];
            }
        }
        
    }
    return NULL;
}

PLAYER **creg_all_players(CLIENT_REGISTRY *cr) {
    //t is the caller's responsibility to decrement the reference count of each of the entries and to free the array when it is no longer needed

    PLAYER **players = calloc((cr->client_count + 1), sizeof(PLAYER *));

    int idx = 0;
    for(int i = 0; i < MAX_CLIENTS; i++) {
        if (cr->clients[i] != NULL) {
            PLAYER *player = client_get_player(cr->clients[i]);
            
            if(player != NULL) {
                players[idx] = client_get_player(cr->clients[i]);
                player_ref(players[idx], "Someone called creg_all_players");
                idx++;
            }
        }    
    }

    return players;
}

void creg_wait_for_empty(CLIENT_REGISTRY *cr) {
     while (1) {
        sem_wait(&cr->mutex);
        if (cr->client_count == 0) {
            sem_post(&cr->mutex);
            return;
        }
        sem_post(&cr->mutex);
    }
}

void creg_shutdown_all(CLIENT_REGISTRY *cr) {
    sem_wait(&cr->mutex);

    for(int i = 0; i < cr->client_count; i++) {
        if(cr->clients[i] != NULL) {
            shutdown(client_get_fd(cr->clients[i]), SHUT_RD);
        }
    }

    sem_post(&cr->mutex);
}