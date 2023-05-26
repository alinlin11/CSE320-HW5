#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "game.h"
#include "player.h"
#include "debug.h"

struct game {
    int is_over;
    GAME_ROLE winner;
    char **board;
    int ref_count;
    int current_role;
    pthread_mutex_t mutex;
};

struct game_move {
    int row;
    int column;
    GAME_ROLE role;
    int move;
};

GAME *game_create(void) {
    GAME *game = malloc(sizeof(GAME));
    game->is_over = -1;
    game->winner = NULL_ROLE;
    game->board = malloc(3 * sizeof(char *));
    for (int i = 0; i < 3; i++) {
        game->board[i] = malloc(3 * sizeof(char));
        
        for (int j = 0; j < 3; j++) {
            game->board[i][j] = ' ';
        }
    }
    game->ref_count = 0;
    game->current_role = FIRST_PLAYER_ROLE;

    pthread_mutex_init(&game->mutex, NULL);
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&game->mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    game_ref(game, "New game created");

    return game;
}   

GAME *game_ref(GAME *game, char *why) {
    pthread_mutex_lock(&game->mutex);

    int prev_count = game->ref_count;
    game->ref_count++;

    debug("Game reference count from %d -> %d: %s", prev_count, game->ref_count, why);
    pthread_mutex_unlock(&game->mutex);
    return game;
}

void game_unref(GAME *game, char *why) {
     pthread_mutex_lock(&game->mutex);

    int prev_count = game->ref_count;
    game->ref_count--;

    debug("Game reference count from %d -> %d: %s", prev_count, game->ref_count, why);

    if(game->ref_count == 0) {
        // Freeing the memory
        for (int i = 0; i < 3; i++) {
            free(game->board[i]);
        }
        free(game->board);
        pthread_mutex_unlock(&game->mutex);
        pthread_mutex_destroy(&game->mutex);
        free(game);
    }

    pthread_mutex_unlock(&game->mutex); 
}

int game_apply_move(GAME *game, GAME_MOVE *move) {
    debug("In game apply move");
    if(move->column < 0 || move->column > 2) {
        return -1;
    }

    if(move->row < 0 || move->row > 2) {
        return -1;
    }

    if(move->role != FIRST_PLAYER_ROLE && move->role != SECOND_PLAYER_ROLE) {
        return -1;
    }

    // Apply the move to the board
    if(game->board[move->row][move->column] != ' ') {
        return -1;
    }

    pthread_mutex_lock(&game->mutex);
    char m = 'X';
    if(game->current_role == FIRST_PLAYER_ROLE) {
        game->board[move->row][move->column] = 'X';
        game->current_role = SECOND_PLAYER_ROLE;
    }
    
    else {
        game->board[move->row][move->column] = 'O';
        game->current_role = FIRST_PLAYER_ROLE;
        m = 'O';
    }

    // Check board for win and if full
    // Check rows
    for (int i = 0; i < 3; i++) {
        if (game->board[i][0] == game->board[i][1] && game->board[i][1] == game->board[i][2] && game->board[i][2]== m) {
            game->is_over = 1;
            game->winner = move->role;
        }
    }

    // Check columns
    for (int i = 0; i < 3; i++) {
        if (game->board[0][i] == game->board[1][i] && game->board[1][i] == game->board[2][i] && game->board[2][i] == m) {
            game->is_over = 1;
            game->winner = move->role;
        }
    }

    // Check diagonals
    if (game->board[0][0] == game->board[1][1] && game->board[1][1] == game->board[2][2] && game->board[2][2] == m) {
        game->is_over = 1;
        game->winner = move->role;
    }

    if (game->board[0][2] == game->board[1][1] && game->board[1][1] == game->board[2][0] && game->board[2][0] == m) {
        game->is_over = 1;
        game->winner = move->role;
    }

    pthread_mutex_unlock(&game->mutex);

    int is_full = 1;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            if (game->board[i][j] == ' ') {
                is_full = -1;
            }
        }
    }

    if(is_full == 1) {
        pthread_mutex_lock(&game->mutex);
        game->is_over = 1;
        game->winner = NULL_ROLE;
        pthread_mutex_unlock(&game->mutex);
    }

    return 0;
}

int game_resign(GAME *game, GAME_ROLE role) {
    if(game_is_over(game) == 1) {
        return -1;
    }

    pthread_mutex_lock(&game->mutex);
    game->is_over = 1;
    game->winner = role;
    pthread_mutex_unlock(&game->mutex);

    return 0;
}

char *game_unparse_state(GAME *game) {
    char *string = calloc(40, sizeof(char *));

    char c = 'X';
    if(game->current_role == SECOND_PLAYER_ROLE) {
        c = 'O';
    }

    snprintf(string, 40, "%c|%c|%c\n-----\n%c|%c|%c\n-----\n%c|%c|%c\n%c to move", 
        game->board[0][0], game->board[0][1], game->board[0][2],
        game->board[1][0], game->board[1][1], game->board[1][2],
        game->board[2][0], game->board[2][1], game->board[2][2], c);

    debug("CURRENT BOARD STATE: %s", string);
    return string;
}

int game_is_over(GAME *game) {
    if(game->is_over == 1) {
        return 1;
    }

    return 0;
}

GAME_ROLE game_get_winner(GAME *game) {
    if(game_is_over(game) == 0 || (game_is_over(game) == 1 && game->winner == NULL_ROLE)) {
        return NULL_ROLE;
    }

    return game->winner;
}

GAME_MOVE *game_parse_move(GAME *game, GAME_ROLE role, char *str) {
    int move = atoi(str);

    debug("GAME_PARSE_MOVE move: %d", move);
    if(move < 1 || move > 9) {
        return NULL;
    }
    debug("GAME_PARSE_MOVE role: %d and game curretn role %d", role, game->current_role);
    if(game->current_role != role) {
        return NULL;
    }

    int count = 0;
    int row = 0;
    int column = 0;
    for(int i = 0; i < 3; i++) {
        for(int j = 0; j < 3; j++) {
            count++;
            if(count == move) {
                row = i;
                column = j;
                break;
            }

        }
    }

    GAME_MOVE *game_move = malloc(sizeof(GAME_MOVE));
    game_move->row = row;
    game_move->column = column;
    game_move->role = role;
    game_move->move = move;
    return game_move;
}


char *game_unparse_move(GAME_MOVE *move) {
    char *string = malloc(6 * sizeof(char)); // Allocate memory for the string

    char c = 'X';
    if (move->role == SECOND_PLAYER_ROLE) {
        c = 'O';
    }

    snprintf(string, 6, "%d <-%c", move->move, c);
    debug("Unparse move: %s", string);

    return string;
}