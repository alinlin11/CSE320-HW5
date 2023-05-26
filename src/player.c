#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <math.h>

#include "player.h"
#include "debug.h"
#include "player_registry.h"


struct player {
    char *username;
    int rating;
    int ref_count;
    pthread_mutex_t mutex;
};


PLAYER *player_create(char *name) {
    if(name == NULL) {
        return NULL;
    }

    char *name_copy = calloc(1, strlen(name) + 1);
    strcpy(name_copy, name);

    PLAYER *player = malloc(sizeof(PLAYER));
    player->username = name_copy;
    player->rating = PLAYER_INITIAL_RATING;
    player->ref_count = 0;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&player->mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    player_ref(player, "New player created"); 

    return player;
}

PLAYER *player_ref(PLAYER *player, char *why) {
    pthread_mutex_lock(&player->mutex);
    int prev = player->ref_count;
    player->ref_count++;
    debug("Player reference count from %d -> %d: %s", prev, player->ref_count, why);
    pthread_mutex_unlock(&player->mutex);

    return player;
}

void player_unref(PLAYER *player, char *why) {
    pthread_mutex_lock(&player->mutex);
    int prev = player->ref_count;
    player->ref_count--;
    debug("Player reference count from %d -> %d: %s", prev, player->ref_count, why);

    if(player->ref_count == 0) {
        pthread_mutex_unlock(&player->mutex);
        pthread_mutex_destroy(&player->mutex);
        free(player->username);
        free(player);

        return;
    }
    pthread_mutex_unlock(&player->mutex);
}

char *player_get_name(PLAYER *player) {
    return player->username;
}

int player_get_rating(PLAYER *player) {
    return player->rating;
}

void player_post_result(PLAYER *player1, PLAYER *player2, int result) {
    // result: 0 if draw, 1 if player1 won, 2 if player2 won

    if(player1 < player2) {
        pthread_mutex_lock(&player1->mutex);
        pthread_mutex_lock(&player2->mutex);
    }
    else {
        pthread_mutex_lock(&player2->mutex);
        pthread_mutex_lock(&player1->mutex);
    }

    float player1_score = 0;
    float player2_score = 0;

    if(result == 0) {
        player1_score = 0.5;
        player2_score = 0.5;
    }

    else if(result == 1) {
        player1_score = 1;
    }

    else {
        player2_score = 1;
    }

    double exp1 = ((double)player2->rating - (double)player1->rating) / 400;
    double exp2 = ((double)player1->rating - (double)player2->rating) / 400;

    debug("EXP1: %lf  EXP2: %lf", exp1, exp2);

    double e1 = 1/(1 + pow(10, (double) exp1));
    double e2 = 1/(1 + pow(10, (double) exp2));

    debug("E1: %lf  E2: %lf", e1, e2);

    int r1 = player1->rating + (int)(32 * (player1_score - e1));
    int r2 = player2->rating + (int)(32 * (player2_score - e2));

    player1->rating = r1;
    player2->rating = r2;

    if(player1 < player2) {
        pthread_mutex_unlock(&player2->mutex);
        pthread_mutex_unlock(&player1->mutex);
    }
    else {
        pthread_mutex_unlock(&player1->mutex);
        pthread_mutex_unlock(&player2->mutex);
    }
}