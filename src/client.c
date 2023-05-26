#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "server.h"
#include "client.h"
#include "debug.h"
#include "invitation.h"


struct client {
    int fd;
    int loggedIn;
    PLAYER *player;
    INVITATION *inv_list[1024];
    int ref_count;
    pthread_mutex_t mutex;
};


CLIENT *client_create(CLIENT_REGISTRY *creg, int fd) {
    CLIENT *client = malloc(sizeof(CLIENT));
    if(client == NULL) {
        return NULL;
    }

    client->fd = fd;
    client->loggedIn = -1;
    client->player = NULL;
    for(int i = 0; i < 256; i++) {
        client->inv_list[i] = NULL;
    }
    client->ref_count = 0;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&client->mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    client_ref(client, "Client created");

    // creg_register(client_registry, fd);
    return client;
}

CLIENT *client_ref(CLIENT *client, char *why) {
    pthread_mutex_lock(&client->mutex);

    int prev = client->ref_count;
    client->ref_count++;

    debug("Client %p reference count from %d -> %d: %s", client, prev, client->ref_count, why);

    pthread_mutex_unlock(&client->mutex);
    return client;
}

void client_unref(CLIENT *client, char *why) {
    pthread_mutex_lock(&client->mutex);

    int prev = client->ref_count;
    client->ref_count--;

    debug("Client %p reference count from %d -> %d: %s", client, prev, client->ref_count, why);

    if(client->ref_count == 0) {
        debug("Client being freed");
        for(int i = 0; i < 256; i++) {
            client->inv_list[i] = NULL;
        }
        close(client->fd);
        pthread_mutex_unlock(&client->mutex);
        pthread_mutex_destroy(&client->mutex);
        free(client);
        return;
    }


    pthread_mutex_unlock(&client->mutex);
}

int client_login(CLIENT *client, PLAYER *player) {
    if(client->loggedIn == 1 || player == NULL) {
        return -1;
    }

    // Check if there is already some other CLIENT that is logged in as the specified PLAYER.
    char *username = player_get_name(player);
    CLIENT *other = creg_lookup(client_registry, username);
    // Player is already logged in
    if(other != NULL) {
        client_unref(other, "Decrement after creg_lookup() was claled");
        return -1;
    }

    pthread_mutex_lock(&client->mutex);

    // Else login
    client->loggedIn = 1;
    client->player = player;
    player_ref(player, "Client logged in with player");

    pthread_mutex_unlock(&client->mutex);
    return 0;
}

int client_logout(CLIENT *client) {
    debug("Client loggin out");
    if(client == NULL || client->loggedIn == -1) {
        return -1;
    }

    // Discard reference to player
    player_unref(client->player, "Client logged out with player");

    pthread_mutex_lock(&client->mutex);
    client->loggedIn = -1;
    client->player = NULL;

    // Decline and revoke all invitations and resign any games in progres
    for(int i = 0; i < 256; i++) {
        // Invintation is either in accepted state
        if(client->inv_list[i] != NULL) {
            GAME *game = inv_get_game(client->inv_list[i]);
            if(game != NULL) {
                client_resign_game(client, i);
            }

            // Invintation is currently in open/closed state
            else {
                if(inv_get_source(client->inv_list[i]) == client) {
                    client_revoke_invitation(client, i);
                }

                else {
                    client_decline_invitation(client, i);
                }
            }
                client->inv_list[i] = NULL;
        }
    }
    
    client_unref(client, "Client logged out");
    pthread_mutex_unlock(&client->mutex);

    return 0;
}

PLAYER *client_get_player(CLIENT *client) {
    if(client == NULL || client->player == NULL) {
        return NULL;
    }

    return client->player;
}

int client_get_fd(CLIENT *client) {
    return client->fd;
}

int client_send_packet(CLIENT *player, JEUX_PACKET_HEADER *pkt, void *data) {
    pthread_mutex_lock(&player->mutex);

    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    uint32_t seconds = current_time.tv_sec;
    uint32_t nanoseconds = current_time.tv_nsec;

    pkt->timestamp_sec = htonl(seconds);
    pkt->timestamp_nsec = htonl(nanoseconds);


    if(proto_send_packet(player->fd, pkt, data) == -1) {
        pthread_mutex_unlock(&player->mutex);
        return -1;
    }

    pthread_mutex_unlock(&player->mutex);
    return 0;
}

int client_send_ack(CLIENT *client, void *data, size_t datalen) {
    pthread_mutex_lock(&client->mutex);

    JEUX_PACKET_HEADER *header = malloc(sizeof(JEUX_PACKET_HEADER));
    header->type = JEUX_ACK_PKT;
    header->id = 0;
    header->role = 0;
    header->size = htons(datalen);

    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    uint32_t seconds = current_time.tv_sec;
    uint32_t nanoseconds = current_time.tv_nsec;

    header->timestamp_sec = htonl(seconds);
    header->timestamp_nsec = htonl(nanoseconds);

    if(proto_send_packet(client->fd, header, data) == -1) {
        free(header);
        pthread_mutex_unlock(&client->mutex);
        return -1;
    }

    free(header);
    pthread_mutex_unlock(&client->mutex);
    return 0;
}

int client_send_nack(CLIENT *client) {
    pthread_mutex_lock(&client->mutex);

    JEUX_PACKET_HEADER *header = malloc(sizeof(JEUX_PACKET_HEADER));
    header->type = JEUX_NACK_PKT;
    header->id = 0;
    header->role = 0;
    header->size = 0;

    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    uint32_t seconds = current_time.tv_sec;
    uint32_t nanoseconds = current_time.tv_nsec;

    header->timestamp_sec = htonl(seconds);
    header->timestamp_nsec = htonl(nanoseconds);

    if(proto_send_packet(client->fd, header, NULL) == -1) {
        free(header);
        pthread_mutex_unlock(&client->mutex);
        return -1;
    }

    free(header);
    pthread_mutex_unlock(&client->mutex);
    return 0;
}


int client_add_invitation(CLIENT *client, INVITATION *inv) {
    if(inv == NULL) {
        return -1;
    }

    pthread_mutex_lock(&client->mutex);
    int id = 0;

    for(int i = 0; i < 256; i++) {
        if(client->inv_list == NULL) {
            client->inv_list[i] = inv;
            id = i;
            break;
        }
    }

    pthread_mutex_unlock(&client->mutex);
    inv_ref(inv, "Invitation was added to client");
    return id;
}   

int client_remove_invitation(CLIENT *client, INVITATION *inv) {
        if(inv == NULL) {
            return -1;
        }

        pthread_mutex_lock(&client->mutex);
        int id = 0;
        int removed = -1;

        for(int i = 0; i < 256; i++) {
            if(client->inv_list[i] == inv) {
                client->inv_list[i] = NULL;
                id = i;
                removed = 1;
                break;
            }
        }

        pthread_mutex_unlock(&client->mutex);

        if(removed == -1) {
            return -1;
        }

        inv_unref(inv, "Invitation removed from client");
        return id;
}

int client_make_invitation(CLIENT *source, CLIENT *target, GAME_ROLE source_role, GAME_ROLE target_role) {
    INVITATION *inv = inv_create(source, target, source_role, target_role);

    if(inv == NULL) {
        return -1;
    }

    // Add to source client
    int source_id = 0;
    pthread_mutex_lock(&source->mutex);
    for(int i = 0; i < 256; i++) {
        if(source->inv_list[i] == NULL) {
            source->inv_list[i] = inv;
            source_id = i;
            break;
        }
    }
    pthread_mutex_unlock(&source->mutex);
    inv_ref(inv, "Invitation added to source client");


    // Add to target client
    pthread_mutex_lock(&target->mutex);
    int target_id = 0;

    for(int i = 0; i < 256; i++) {
        if(target->inv_list[i] == NULL) {
            target->inv_list[i] = inv;
            target_id = i;
            break;
        }
    }
    pthread_mutex_unlock(&target->mutex);
    inv_ref(inv, "Invitation added to target client");


    // Send invite packet to invitation
    pthread_mutex_lock(&target->mutex);

    JEUX_PACKET_HEADER *packet = malloc(sizeof(JEUX_PACKET_HEADER));
    packet->type = JEUX_INVITED_PKT;
    packet->id = target_id;
    packet->role = 0;
    packet->size = 0;

    client_send_packet(target, packet, NULL);
    free(packet);

    pthread_mutex_unlock(&target->mutex);
    return source_id;
}

int client_revoke_invitation(CLIENT *client, int id) {
    INVITATION *source_inv = client->inv_list[id];

    if(source_inv == NULL || inv_get_source(source_inv) != client) {
        return -1;
    } 

    int in_target_list = -1;
    int target_id = 0;
    CLIENT *target = inv_get_target(source_inv);
    for(int i = 0; i < 256; i++) {
        if(target->inv_list[i] == source_inv) {
            target_id = i;
            in_target_list = 1;
            break;
        }
    }

    if(in_target_list == -1) {
        return -1;
    }

    // Check if the inv is in OPEN STATE
    GAME *game = inv_get_game(source_inv);
    if(game != NULL) {
        return -1;
    }

    // Remove from source and target invitation lists
    // Unreference invitations
    pthread_mutex_lock(&client->mutex);
    client->inv_list[id] = NULL;
    pthread_mutex_unlock(&client->mutex);

    pthread_mutex_lock(&target->mutex);
    target->inv_list[target_id] = NULL;
    pthread_mutex_unlock(&target->mutex);

    inv_unref(source_inv, "Remoned from source client inv list");
    inv_unref(source_inv, "removed from target client inv list");
    
    // Send a revoke packet to the target
    pthread_mutex_lock(&target->mutex);
    JEUX_PACKET_HEADER *packet = malloc(sizeof(JEUX_PACKET_HEADER));
    packet->type = JEUX_REVOKED_PKT;
    packet->id = target_id;
    packet->role = 0;
    packet->size = 0;
    client_send_packet(target, packet, NULL);
    free(packet);

    pthread_mutex_unlock(&target->mutex);

    inv_close(source_inv, inv_get_source_role(source_inv));
    return 0;
}

int client_decline_invitation(CLIENT *client, int id) {
    INVITATION *inv = client->inv_list[id];
    if(inv == NULL || inv_get_target(inv) != client) {
        return -1;
    }

    CLIENT *source = inv_get_source(inv);
    int source_id = 0;
    int found_source_inv = -1;

    for(int i = 0; i < 256; i++) {
        if(source->inv_list[i] == inv) {
            source_id = i;
            found_source_inv = 1;
            break;
        }
    }

    if(found_source_inv == -1) {
        return -1;
    }

    // Check is client is in open state
    GAME *game = inv_get_game(inv);
    if(game != NULL) {
        return -1;
    }

    pthread_mutex_lock(&source->mutex);
    source->inv_list[source_id] = NULL;
    pthread_mutex_unlock(&source->mutex);

    pthread_mutex_lock(&client->mutex);
    client->inv_list[id] = NULL;
    pthread_mutex_unlock(&client->mutex);

    inv_unref(inv, "Invitation removed from source client");
    inv_unref(inv, "Invitation removed from target client");

    pthread_mutex_lock(&source->mutex);
    // Send decline packet to source
    JEUX_PACKET_HEADER *packet = malloc(sizeof(JEUX_PACKET_HEADER));
    packet->type = JEUX_DECLINED_PKT;
    packet->id = source_id;
    packet->role = 0;
    packet->size = 0;
    client_send_packet(source, packet, NULL);
    free(packet);

    pthread_mutex_unlock(&source->mutex);
    inv_close(inv, inv_get_source_role(inv));
    return 0;
}

int client_accept_invitation(CLIENT *client, int id, char **strp) {
    // Client is the target of the invitation
    INVITATION *inv = client->inv_list[id];

    if(inv == NULL || inv_get_target(inv) != client) {
        return -1;
    }

    CLIENT *source = inv_get_source(inv);
    int source_id = 0;
    for(int i = 0; i < 256; i++) {
        if(source->inv_list[i] == inv) {
            source_id = i;
            break;
        }
    }

    if(inv_accept(inv) == -1) {
        return -1;
    }

    GAME *game = inv_get_game(inv);

    pthread_mutex_lock(&source->mutex);
    // Get target's role
    if(inv_get_target_role(inv) == SECOND_PLAYER_ROLE) {
        strp = NULL;
    }
    else {
        *strp = game_unparse_state(game);
    }
    
    // Send accepted packet to source with source inv id
    JEUX_PACKET_HEADER *packet = malloc(sizeof(JEUX_PACKET_HEADER));
    packet->type = JEUX_ACCEPTED_PKT;
    packet->id = source_id;
    packet->role = SECOND_PLAYER_ROLE;
    packet->size = 0;

    if(inv_get_source_role(inv) == FIRST_PLAYER_ROLE) {
        packet->role = FIRST_PLAYER_ROLE;
        char *payload = game_unparse_state(game);
        packet->size = htons(strlen(payload));

        pthread_mutex_unlock(&source->mutex);
        client_send_packet(source, packet, payload);
        // debug("Sending game payload: %s", payload);
        free(payload);
        return 0;
    }

    pthread_mutex_unlock(&source->mutex);
    client_send_packet(source, packet, NULL);

    // Increment game ref?
    return 0;
}

int client_resign_game(CLIENT *client, int id) {
    INVITATION *inv = client->inv_list[id];
    if(inv == NULL) {
        return -1;
    }

    CLIENT *other = inv_get_source(inv);
    GAME_ROLE other_role = inv_get_source_role(inv);
    if(other == client) {
        other = inv_get_target(inv);
        other_role = inv_get_target_role(inv);
    }

    GAME *game = inv_get_game(inv);
    if(game == NULL) {
        return -1;
    }

    if(other_role == FIRST_PLAYER_ROLE) {
        inv_close(inv, SECOND_PLAYER_ROLE);
    }
    
    else {
        inv_close(inv, FIRST_PLAYER_ROLE);
    }

    // Remove from source and target lists
    pthread_mutex_lock(&client->mutex);
    client->inv_list[id] = NULL;
    pthread_mutex_unlock(&client->mutex);


    pthread_mutex_lock(&other->mutex);
    int other_id = 0;
    for(int i = 0; i < 256; i++) {
        if(inv == other->inv_list[i]) {
            other->inv_list[i] = NULL;
            other_id = i;
            break;
        }
    }

    // Send resign packet to opponenet(other)
    JEUX_PACKET_HEADER *packet = malloc(sizeof(JEUX_PACKET_HEADER));
    packet->type = JEUX_RESIGNED_PKT;
    packet->id = other_id;
    packet->role = other_role;
    packet->size = 0;

    client_send_packet(other, packet, NULL);
    free(packet);

    pthread_mutex_unlock(&other->mutex);

    player_post_result(client_get_player(client), client_get_player(other), 2);

    return 0;
}

int client_make_move(CLIENT *client, int id, char *move) {
    INVITATION *inv = client->inv_list[id];
    if(inv == NULL) {
        return -1;
    }

    GAME *game = inv_get_game(inv);
    if(game == NULL) {
        return -1;
    } 

    // Get the opponenet's role
    GAME_ROLE role = FIRST_PLAYER_ROLE;
    CLIENT *opp = inv_get_source(inv);
    
    if(inv_get_source(inv) == client) {
        role = inv_get_source_role(inv);
        opp = inv_get_target(inv);
    }
    else {
        role = inv_get_target_role(inv);
    }

    debug("Passing role: %d into game_parse_move", role);
    GAME_MOVE *game_move = game_parse_move(game, role, move);
    if(game_move == NULL) {
        debug("GAME_PARSE_MOVE IS NULL");
        return -1;
    }

    if(game_apply_move(game, game_move) == -1) {
        return -1;
    }

    free(game_move);
    pthread_mutex_lock(&opp->mutex);

    // SEND MOVE PACKET to the opponent
    JEUX_PACKET_HEADER *move_packet = malloc(sizeof(JEUX_PACKET_HEADER));
    move_packet->type = JEUX_MOVED_PKT;
    move_packet->id = 0;
    move_packet->role = 0;
    char *state = game_unparse_state(game);
    move_packet->size = htons(strlen(state));

    client_send_packet(opp, move_packet, state);
    free(state);
    free(move_packet);
    pthread_mutex_unlock(&opp->mutex);

    if(game_is_over(game) == 0) {
        return 0;
    }

    pthread_mutex_lock(&opp->mutex);

    // Send ENDED packet
    JEUX_PACKET_HEADER *end_packet = malloc(sizeof(JEUX_PACKET_HEADER));
    end_packet->type = JEUX_ENDED_PKT;
    end_packet->id = id;
    end_packet->role = game_get_winner(game);
    end_packet->size = 0;

    client_send_packet(client, end_packet, NULL);

    // Get opponenet inv id
    for(int i = 0; i < 256; i++) {
        if(inv == opp->inv_list[i]) {
            end_packet->id = i;
            break;
        }
    }

    client_send_packet(opp, end_packet, NULL);
    free(end_packet);
    
    pthread_mutex_unlock(&opp->mutex);


    // Remove from source and target
    pthread_mutex_lock(&client->mutex);
    client->inv_list[id] = NULL;
    pthread_mutex_unlock(&client->mutex);

    pthread_mutex_lock(&opp->mutex);
    for(int i = 0; i < 256; i++) {
        if(inv == opp->inv_list[i]) {
            opp->inv_list[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&opp->mutex);


    int result = 0;
    if(game_get_winner(game) == role) {
        result = 1;
    }
    else if(game_get_winner(game) == NULL_ROLE) {
        result = 0;
    }
    else {
        result = 2;
    }

    PLAYER *c1 = client_get_player(client);
    PLAYER *c2 = client_get_player(opp);
    player_post_result(c1, c2, result);

    return 0;

}


