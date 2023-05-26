#include <stdlib.h>
#include <pthread.h>

#include "client_registry.h"
#include "debug.h"


struct invitation {
    CLIENT *source;
    GAME_ROLE source_role;

    CLIENT *target;
    GAME_ROLE target_role;

    INVITATION_STATE state;
    GAME *game;
    int ref_count;
    pthread_mutex_t mutex;
};

INVITATION *inv_create(CLIENT *source, CLIENT *target, GAME_ROLE source_role, GAME_ROLE target_role) {
    if(source == NULL || target == NULL || source_role == 0 || target_role == 0 || source == target) {
        return NULL;
    }

    INVITATION *inv = malloc(sizeof(INVITATION));
    inv->source = source;
    inv->source_role = source_role;
    inv->target = target;
    inv->target_role = target_role;
    inv->state = INV_OPEN_STATE;
    inv->game = NULL;
    inv->ref_count = 0;
    inv_ref(inv, "New invitation was created");
    
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&inv->mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    client_ref(source, "Created an reference in inv_create");
    client_ref(target, "Created an reference in inv_create");

    return inv;
}

INVITATION *inv_ref(INVITATION *inv, char *why) {
    pthread_mutex_lock(&inv->mutex);

    int prev = inv->ref_count;
    inv->ref_count++;
    debug("Invination %p reference count added from %d to %d: %s\n", inv, prev, inv->ref_count, why);

    pthread_mutex_unlock(&inv->mutex);

    return inv;
}

void inv_unref(INVITATION *inv, char *why) {
    pthread_mutex_lock(&inv->mutex);

    int prev = inv->ref_count;
    inv->ref_count--;
    debug("Invination %p reference count subtracted from %d to %d: %s\n", inv, prev, inv->ref_count, why);

    if((inv->ref_count) == 0) {
        pthread_mutex_unlock(&inv->mutex);
        pthread_mutex_destroy(&inv->mutex);
        free(inv);
    }

    else {
        pthread_mutex_unlock(&inv->mutex);
    }
    
}

CLIENT *inv_get_source(INVITATION *inv) {
    return inv->source;
}

CLIENT *inv_get_target(INVITATION *inv) {
    return inv->target;
}

GAME_ROLE inv_get_source_role(INVITATION *inv) {
    return inv->source_role;
}

GAME_ROLE inv_get_target_role(INVITATION *inv) {
    return inv->target_role;
}

GAME *inv_get_game(INVITATION *inv) {
    if(inv->game == NULL)
        return NULL;
    
    return inv->game;
}

int inv_accept(INVITATION *inv) {
    if(inv->state != INV_OPEN_STATE) {
        return -1;
    }

    inv->state = INV_ACCEPTED_STATE;
    GAME *game = game_create();
    if(game == NULL) {
        return -1;
    }

    pthread_mutex_lock(&inv->mutex);
    inv->game = game;
    pthread_mutex_unlock(&inv->mutex);
    return 0;
}

int inv_close(INVITATION *inv, GAME_ROLE role) {
    if((inv->state) == INV_CLOSED_STATE) {
        // pthread_mutex_unlock(&inv->mutex);
        return -1;
    }

    if(role == NULL_ROLE) {
        if(inv_get_game(inv) == NULL) {
            pthread_mutex_lock(&inv->mutex);
            inv->state = INV_CLOSED_STATE;
            pthread_mutex_unlock(&inv->mutex);
            return 0;
        }
        
        // Game in progress
        else if(game_is_over(inv->game) == 0) {
            return -1;
        }
        
    }

    if(inv->state == INV_ACCEPTED_STATE && game_is_over(inv->game) == 0) {
        // Resign chosen player
        game_resign(inv->game, role);
    }
    
    pthread_mutex_lock(&inv->mutex);
    inv->state = INV_CLOSED_STATE;
    pthread_mutex_unlock(&inv->mutex);
    return 0;
}