#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "player_registry.h"

typedef struct player_node {
    PLAYER *player;
    struct player_node* next;
} PLAYER_NODE;

struct player_registry {
    PLAYER_NODE *head;
    int num_players;
    pthread_mutex_t mutex;
};


PLAYER_REGISTRY *preg_init(void) {
    PLAYER_REGISTRY *players = malloc(sizeof(PLAYER_REGISTRY));
    if(players == NULL) {
        return NULL;
    }
    players->head = NULL;
    players->num_players = 0;
    
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&players->mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    return players;
}

void preg_fini(PLAYER_REGISTRY *preg) {
    pthread_mutex_lock(&preg->mutex);

    PLAYER_NODE *current = preg->head;
    while (current != NULL) {
        PLAYER_NODE *temp = current;
        current = current->next;
        free(temp);
        temp = NULL;
    }

    pthread_mutex_unlock(&preg->mutex);
    pthread_mutex_destroy(&preg->mutex);
    free(preg);
}

PLAYER *preg_register(PLAYER_REGISTRY *preg, char *name) {
    pthread_mutex_lock(&preg->mutex);

    PLAYER_NODE *current = preg->head;
    while(current != NULL) {
        PLAYER *player = current->player;
        char *username = player_get_name(player);

        if(strcmp(username, name) == 0) {
            player_ref(player, "Player was found in the registry");
            return player;
        }
        current = current->next;
    }

    PLAYER_NODE *new_node = malloc(sizeof(PLAYER_NODE));
    PLAYER *new_player = player_create(name);
    if(new_player == NULL) {
        free(new_node);
        return NULL;
    }

    new_node->player = new_player;
    current = new_node;
    new_node->next = NULL;
    preg->num_players++;

    pthread_mutex_unlock(&preg->mutex);
    player_ref(new_player, "Player retained by player registry");
    return new_player;
}