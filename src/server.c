#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "server.h"
#include "jeux_globals.h"
#include "debug.h"

void login(CLIENT *client, char *username);
void users(CLIENT *client);
void invite(CLIENT *client, char *p2_username, GAME_ROLE p2_role);
void revoke_inv(CLIENT *client, int inv_id);
void decline_inv(CLIENT *client, int inv_id);
void accept_inv(CLIENT *client, int inv_id, int role);
void make_move(CLIENT *client, int inv_id, char *move);
void resign(CLIENT *client, int inv_id);

// Also, since the read side of the pipe is closed when they disconnect, any write would be writing through a broken pipe and send SIGPIPE which you need to handle
// For example, try having a player accept 2 invites from another, then disconnecting them
// your program shouldn't crash, but it likely will since you will be trying to write end packets to the already disconnected client.
// Set up a SIGPIPE handler to ignore the signal and the check errno after write
// if errno == EPIPE, you can just return 0

void *jeux_client_service(void *arg) {
    // debug("JEUX_CLIENT_SERVICE CALLED");

    int client_fd = *((int *)arg);
    free(arg);
    pthread_detach(pthread_self());
    
    CLIENT *client = creg_register(client_registry, client_fd);
    int login_flag = -1;

    while(1) {
        JEUX_PACKET_HEADER *header = malloc(sizeof(JEUX_PACKET_HEADER));
        void *payload = NULL;


        int ret = proto_recv_packet(client_fd, header, &payload);

        if (header->type == JEUX_NO_PKT) {
            // debug("detect eof");
            free(header);
            client_logout(client);
            creg_unregister(client_registry, client);
            break;
        }

        if(ret == 0) {
            // debug("JEUX_CLIENT_SERVICE: Recieveing packets loop");
            
            // Login Packet
            if(header->type == JEUX_LOGIN_PKT && login_flag == -1) {
                // debug("Not logged in loop");
                char *username = calloc(1, ntohs(header->size) + 1);
                strncpy(username, payload, ntohs(header->size));

                 PLAYER *player = preg_register(player_registry, username);
    
                if(client_login(client, player) == 0) {
                    client_send_ack(client, NULL, 0);
                    login_flag = 1;
                }

                else {
                    client_send_nack(client);
                }   

                free(username);
            }
            
            else if(login_flag == 1) {
                // debug("Logged in");

                if(header->type == JEUX_USERS_PKT ) {
                    users(client);
                }

                else if(header->type == JEUX_INVITE_PKT) {
                    char *username = calloc(1, ntohs(header->size) + 1);
                    strncpy(username, payload, ntohs(header->size));

                    // debug("Payload %s with length of %ld", (char *)payload, strlen(payload));
                    // debug("Username %s with length of %ld", username, strlen(username));
                    debug("Username %s from invite packet", username);
                    

                    invite(client, username, header->role);
                    free(username);
                }

                else if(header->type == JEUX_REVOKE_PKT) {
                    revoke_inv(client, header->id);
                }

                else if(header->type == JEUX_DECLINE_PKT) {
                    decline_inv(client, header->id);
                }

                else if(header->type == JEUX_ACCEPT_PKT) {
                    accept_inv(client, header->id, header->role);
                }

                else if(header->type == JEUX_MOVE_PKT) {
                    make_move(client, header->id, payload);
                }

                else if(header->type == JEUX_RESIGN_PKT) {
                    resign(client, header->id);
                }
                
                else {
                    client_send_nack(client);
                }
            }

            else {
                client_send_nack(client);
            }
            
            if(payload != NULL)
                free(payload);
        }


    }

    return NULL;
}


void login(CLIENT *client, char *username) {
    debug("Calling login for username: %s", username);

   
}

void users(CLIENT *client) {
    debug("Calling get all users");

    PLAYER **players_list = creg_all_players(client_registry);
    char *payload;
    size_t payload_size = 0;
    FILE *memstream = open_memstream(&payload, &payload_size);


    for(int i = 0; players_list[i] != NULL; i++) {
        // debug("Player %p", players_list[i]);
        char *username = player_get_name(players_list[i]);
        int rating = player_get_rating(players_list[i]);

        // debug("USERNAME: %s, RATING: %d\n", username, rating);

        fprintf(memstream, "%s\t%d\n", username, rating);
        player_unref(players_list[i], "Decrement reference count when players_list not needed");
        players_list[i] = NULL;
    }
    
    free(players_list);
    fclose(memstream);
    client_send_ack(client, (void *)payload, payload_size);
    // debug("Users payload: %s\n", payload);
    free(payload);
}

void invite(CLIENT *client, char *p2_username, GAME_ROLE p2_role) {
    // client is the source
    // p2 is the target

    debug("Calling invite to %s with role %d\n", p2_username, p2_role);

    CLIENT *p2 = creg_lookup(client_registry, p2_username);
    if(p2 == NULL || (p2_role != FIRST_PLAYER_ROLE && p2_role != SECOND_PLAYER_ROLE)) {
        // client_unref(p2, "Decrement reference count because creg_lookup() was called");
        client_send_nack(client);
        return;
    }

    GAME_ROLE p1_role = NULL_ROLE;
    if(p2_role == FIRST_PLAYER_ROLE)  {
        p1_role = SECOND_PLAYER_ROLE;
    }
    else {
        p1_role = FIRST_PLAYER_ROLE;
    }
        
    int inv_id = client_make_invitation(client, p2, p1_role, p2_role);
    if(inv_id != -1) {
        // client_send_ack(client, NULL, 0);
        JEUX_PACKET_HEADER *packet = malloc(sizeof(JEUX_PACKET_HEADER));
        packet->type = JEUX_ACK_PKT;
        packet->id = inv_id;
        packet->role = p1_role;
        packet->size = 0;

        client_send_packet(client, packet, NULL);
        free(packet);
    }

    else {
        client_send_nack(client);
    }

    client_unref(p2, "Decrement reference count because creg_lookup() was called");
}

void revoke_inv(CLIENT *client, int inv_id) {    
    if(client_revoke_invitation(client, inv_id) == 0) {
        client_send_ack(client, NULL, 0);
    }
    else {
        client_send_nack(client);
    }
}

void decline_inv(CLIENT *client, int inv_id) {
    debug("Calling decline on id %d", inv_id);

    if(client_decline_invitation(client, inv_id) == 0) {
        client_send_ack(client, NULL, 0);
    }
    else {
        client_send_nack(client);
    }
}

void accept_inv(CLIENT *client, int inv_id, int role) {
    debug("Calling accept inv for id %d and role %d", inv_id, role);

    char *strp = NULL;
    // if(role == FIRST_PLAYER_ROLE) {
    //     str = strdup("Invitation Accepted");
    //     strp = &str;

    //     debug("ACCEPT PAYLOAD: %s\n", str);
    // }

    if(client_accept_invitation(client, inv_id, &strp) == 0) {
        debug("Returning ACK");
        if(strp) {
            client_send_ack(client, strp, strlen(strp));
        }
        else {
            client_send_ack(client, NULL, 0);
        }
    }
    else {
        debug("Returning NAK");
        client_send_nack(client);
    }

    if(role == FIRST_PLAYER_ROLE) {
        free(strp);
    }
}

void make_move(CLIENT *client, int inv_id, char *move) {
    if(client_make_move(client, inv_id, move) == 0) {
        client_send_ack(client, NULL, 0);
    }
    else {
        client_send_nack(client);
    }
}

void resign(CLIENT *client, int inv_id) {
    if(client_resign_game(client, inv_id) == 0) {
        client_send_ack(client, NULL, 0);
    }
    else {
        client_send_nack(client);
    }
}

