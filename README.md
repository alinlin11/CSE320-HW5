# CSE320-HW5
Homework 5 - CSE 320 - Spring 2023

Professor Eugene Stark

Due Date: Friday 5/5/2023 @ 11:59pm


Introduction
The goal of this assignment is to become familiar with low-level POSIX
threads, multi-threading safety, concurrency guarantees, and networking.
The overall objective is to implement a simple game server that allows
users to play each other in a two-player game and assigns them numerical
"ratings" that reflect their performance relative to other players.
As you will probably find this somewhat difficult, to grease the way
I have provided you with a design for the server, as well as binary object
files for almost all the modules.  This means that you can build a
functioning server without initially facing too much complexity.
In each step of the assignment, you will replace one of my
binary modules with one built from your own source code.  If you succeed
in replacing all of my modules, you will have completed your own
version of the server.
It is probably best if you work on the modules in roughly the order
indicated below.  Turn in as many modules as you have been able to finish
and have confidence in.  Don't submit incomplete modules or modules
that don't function at some level, as these will negatively impact
the ability of the code to be compiled or to pass tests.

Takeaways
After completing this homework, you should:

Have a basic understanding of socket programming
Understand thread execution, mutexes, and semaphores
Have an advanced understanding of POSIX threads
Have some insight into the design of concurrent data structures
Have enhanced your C programming abilities


Hints and Tips


We strongly recommend you check the return codes of all system
calls. This will help you catch errors.


BEAT UP YOUR OWN CODE! Throw lots of concurrent calls at your
data structures to ensure safety.


Your code should NEVER crash. We will be deducting points for
each time your program crashes during grading. Make sure your code
handles invalid usage gracefully.


You should make use of the macros in debug.h. You would never
expect a library to print arbitrary statements as it could interfere
with the program using the library. FOLLOW THIS CONVENTION!
make debug is your friend.



😱 DO NOT modify any of the header files provided to you in the base code.
These have to remain unmodified so that the modules can interoperate correctly.
We will replace these header files with the original versions during grading.
You are of course welcome to create your own header files that contain anything
you wish.


🤓 When writing your program, try to comment as much as possible
and stay consistent with your formatting.


Helpful Resources

Textbook Readings
You should make sure that you understand the material covered in
chapters 11.4 and 12 of Computer Systems: A Programmer's
Perspective 3rd Edition before starting this assignment.  These
chapters cover networking and concurrency in great detail and will be
an invaluable resource for this assignment.

pthread Man Pages
The pthread man pages can be easily accessed through your terminal.
However, this opengroup.org site
provides a list of all the available functions.  The same list is also
available for semaphores.

Getting Started
Fetch and merge the base code for hw5 as described in hw0. You can
find it at this link: https://gitlab02.cs.stonybrook.edu/cse320/hw5.
Remember to use the --strategy-option=theirs flag for the git merge
command to avoid merge conflicts in the Gitlab CI file.

The Jeux Game Server: Overview
"Jeux" is a simple implementation of a game server, which allows users
to play each other in a two-player game.  Since implementing the game
itself is not our primary interest in this assignment, we have chosen
to support a very simple game: tic-tac-toe.  However, the design of the
server is such that it would be very easy to substitute a more interesting
game, such as checkers or chess, and with a little bit of extension to
the design it could support multiple types of games at once.
Perhaps the easiest way to understand what the server does is to try it out.
For this purpose, I have provided an executable (demo/jeux) for
a completely implemented demonstration version of the server.
Launch it using the following command:

$ demo/jeux -p 3333


The -p 3333 option is required, and it specifies the port number on which
the server will listen.  It will be convenient to start the server in a
separate terminal window, because it has not been written to detach from the
terminal and run as a daemon like a normal server would do.  This is because
you will be starting and stopping it frequently and you will want to be able
to see the voluminous debugging messages it issues.
The server does not ignore SIGINT as a normal daemon would,
so you can ungracefully shut down the server at any time by typing CTRL-C.
Note that the only thing that the server prints are debugging messages;
in a non-debugging setting there should be no output from the server
while it is running.
Once the server is started, you can use a test client program to access it.
The test client is called util/jclient and it has been provided only as
a binary executable.  The client is invoked as follows:

util/jclient -p <port> [-h <host>] [-d]


The -p option is required, and it is used to specify the port
number of the server.  If the -h option is given, then it specifies
the name of the network host on which the server is running.
If it is not given, then localhost is used.
The optional -d argument turns on some additional debugging printout
that shows the network packets being sent and received by the client.
Once the client is invoked, it will attempt to connect to the server.
If this succeeds, you will be presented with a command prompt and a
help message that lists the available commands:

$ util/jclient -p 3333
Jeux test client.
Commands are:
	help
	login <username>
	users
	invite <username> <role>
	revoke <id>
	accept <id>
	decline id>
	move <id> <move>
	resign <id>
Connected to server localhost:3333
> 


Once connected to the server, it is necessary to log in before any commands
other than help or login can be used.  Logging in is accomplished
using the login command, which requires that a username be specified
as an argument.  Any username can be used, as long as it is not currently
in use by some other logged-in user.
Multiple clients can connect to the server at one time.  You should try
opening several terminal windows and starting a client in each of them to see
how this works.  If your computer and/or LAN does not firewall the connections,
you will also be able to connect to a server running on one computer from a
server elsewhere in the Internet.  This will be most likely to work between two
computers on the same LAN (e.g. connected to the same WiFi router, if the
router is configured to allow connected computers to talk to each other).
If it doesn't, there isn't much I can do about it.  In that case you'll just have
to use it on your own computer.
The Jeux server architecture is that of a multi-threaded network server.
When the server is started, a master thread sets up a socket on which to
listen for connections from clients.  When a connection is accepted,
a client service thread is started to handle requests sent by the client
over that connection.  The client service thread executes a service loop in which
it repeatedly receives a request packet sent by the client, performs the request,
and possibly sends one or more packets in response.  The server will also
send packets to the client asynchronously as the result of actions performed by
other users.  For example, whenever a player makes a move, a packet is sent
to the player's opponent announcing that a move has been made and giving the
current game state.

🤓 One of the basic tenets of network programming is that a
network connection can be broken at any time and the parties using
such a connection must be able to handle this situation.  In the
present context, the client's connection to the Jeux server may
be broken at any time, either as a result of explicit action by the
client or for other reasons.  When disconnection of the client is
noticed by the client service thread, the corresponding player is logged
out of the server and the client service thread terminates.
Any outstanding invitations to games held by the now-logged-out player
are revoked or declined, and games in progress involving that player
are resigned.  Information about the player remains in the system;
in the present implementation this consists of the player's name and rating.


The Base Code
Here is the structure of the base code:

.
├── .gitignore
├── .gitlab-ci.yml
└── hw5
    ├── demo
    │   └── jeux
    ├── include
    │   ├── client.h
    │   ├── client_registry.h
    │   ├── debug.h
    │   ├── game.h
    │   ├── invitation.h
    │   ├── jeux_globals.h
    │   ├── player.h
    │   ├── player_registry.h
    │   ├── protocol.h
    │   └── server.h
    ├── lib
    │   ├── jeux.a
    │   └── jeux_debug.a
    ├── Makefile
    ├── src
    │   └── main.c
    ├── test_output
    │   ├── .git-keep
    │   └── valgrind.out
    ├── tests
    │   └── jeux_tests.c
    └── util
        └── jclient


The base code consists of header files that define module interfaces,
a library jeux.a containing binary object code for my
implementations of the modules, and a source code file main.c that
contains containing a stub for function main().  The Makefile is
designed to compile any existing source code files and then link them
against the provided library.  The result is that any modules for
which you provide source code will be included in the final
executable, but modules for which no source code is provided will be
pulled in from the library.

😱  Note that if you define any functions in a particular
source code module, then you must define all of them
(at least you must provide stubs), otherwise the linker will pull in
the library module as well as linking your module and the result will
be a "multiply defined" error for the functions that you did define.

The jeux.a library was compiled without -DDEBUG, so it does not
produce any debugging printout.  Also provided is jeux_debug.a,
which was compiled with -DDEBUG, and which will produce a lot of
debugging output.  The Makefile is set up to use jeux_debug.a when
you say make debug and jeux.a when you just say make.
The util directory contains the executable for the text-based client
program, jclient.
Besides the -h, -p, and -d options discussed above, the jclient program
also supports the -q option, which takes no arguments.  If -q is given,
then jclient suppresses its normal prompt.  This may be useful for using
jclient to feed in pre-programmed commands written in a file.
The list of commands that jclient understands is printed out when it starts
and can also be viewed by typing help at the command prompt.
Most of the detailed specifications for the various modules and functions
that you are to implement are provided in the comments in the header
files in the include directory.  In the interests of brevity and avoiding
redundancy, those specifications are not reproduced in this document.
Nevertheless, the information they contain is very important, and constitutes
the authoritative specification of what you are to implement.

😱 The various functions and variables defined in the header files
constitute the entirety of the interfaces between the modules in this program.
Use these functions and variables as described and do not introduce any
additional functions or global variables as "back door" communication paths
between the modules.  If you do, the modules you implement will not interoperate
properly with my implementations, and it will also likely negatively impact
our ability to test your code.

The test file I have provided contains some code to start a server and
attempt to connect to it.  It will probably be useful while you are
working on main.c.

Additional Background Information

Reference Counting
Many of the modules in the Jeux server use the technique of reference counting.
A reference count is a field maintained in an object to keep track of the number
of extant pointers to that object.  Each time a new pointer to the object is created,
the reference count is incremented.  Each time a pointer is released, the reference
count is decremented.  A reference-counted object is freed when, and only when,
the reference count reaches zero.  Using this scheme, once a thread has obtained
a pointer to an object, with the associated incremented reference count,
it can be sure that until it explicitly releases that object and decrements the
reference count, that the object will not be freed.
In the Jeux server, several types of objects are reference counted;
namely, CLIENT, GAME, INVITATION, and PLAYER.
The specifications of the functions provided by the various modules include
information on when reference counts are incremented and whose responsibility
it is to decrement these reference counts.  It is important to pay attention to this
information -- if you do not, your implementation will end up with storage leaks,
or worse, segmentation faults due to "dangling pointers".
A number of "get" functions do not increment the reference count of the object
they return.  This is to make them more convenient to use in a setting in which
one is already holding a reference to the containing object.
As long as the containing object is not freed, neither will the objects returned
by the "get" function.  However, if you obtain an object by a "get" function,
and then decrement the reference count on the containing object, it is possible
that the containing object will be freed as a result.  This will result in the
contained objects having their reference counts decremented, and those objects
might then be freed.  You could then end up with a "dangling pointer" to a free object.
To avoid this, if you intend to use a pointer returned by a "get" function after
the containing object has had its reference count decreased, then you should first
explicitly increase the reference count of the object returned by "get" so that
the pointer is guaranteed to be valid until you are finished with it.
Finally, note that, in a multi-threaded setting, the reference count in an object
is shared between threads and therefore needs to be protected by a mutex if
it is to work reliably.

Thread Safety
Nearly all of the modules in the Jeux server implement data that is shared
by multiple threads, so synchronization has to be used to make these modules
thread-safe.  The basic approach to this is for each object to contain
a mutex which is locked while the object is being manipulated and unlocked
when the manipulation is finished.  The mutexes will be private fields of the
objects, which are not exposed by the interfaces of the modules.
It will be your responsibility to include the necessary mutexes in your
implementation and to determine when the mutexes should be locked or
unlocked in each function.  Some modules may need some additional synchronization
features; for example, for the client registry it is suggested that you use
a semaphore in order to implement the creg_wait_for_empty functionality.
Functions that operate on more than one object at a time require special
care in order to avoid the possibility of deadlock.  An example of this
is the player_post_result function of the player module.  This function
needs to update the ratings of two players based on the result of a
just-completed game between those players and the current ratings of those
players.  A correct rating update involves the transfer of some number of
rating points from one player to the other, so that the total number of
rating points in the system is conserved.
If the PLAYER objects are locked one at a time, then rating updates going
on concurrently could violate this conservation property.
On the other hand, unless some care is taken, attempting to lock two
PLAYER objects at once could result in deadlock.
More generally, whenever one mutex is already held while an attempt is
made to lock another, care needs to be taken to avoid deadlock.
Refer to information given in the lecture notes for some ideas on strategies
to prevent this.

Debugging Multi-threaded Programs
GDB has support for debugging multi-threaded programs.
At any given time, there is one thread on which the debugger is currently
focused.  The usual commands such as bt (backtrace, to get a stack trace)
pertain to the current thread.  If you want to find out about a different
thread, you need to change the focus to that thread.
The info threads command will show you a list of the existing threads.
Each thread has a corresponding "Id" which you can use to specify that
thread to gdb.  The command thread N (replace N by the ID of a thread)
will switch the focus to that particular thread.

Task I: Server Initialization
When the base code is compiled and run, it will print out a message
saying that the server will not function until main() is
implemented.  This is your first task.  The main() function will
need to do the following things:


Obtain the port number to be used by the server from the command-line
arguments.  The port number is to be supplied by the required option
-p <port>.


Install a SIGHUP handler so that clean termination of the server can
be achieved by sending it a SIGHUP.  Note that you need to use
sigaction() rather than signal(), as the behavior of the latter is
not well-defined in a multithreaded context.


Set up the server socket and enter a loop to accept connections
on this socket.  For each connection, a thread should be started to
run function jeux_client_service().


These things should be relatively straightforward to accomplish, given the
information presented in class and in the textbook.  If you do them properly,
the server should function and accept connections on the specified port,
and you should be able to connect to the server using the test client.
Note that if you build the server using make debug, then the binaries
I have supplied will produce a fairly extensive debugging trace of what
they are doing.  This, together with the specifications in this document
and in the header files, will likely be invaluable to you in understanding
the desired behavior of the various modules.

Task II: Send and Receive Functions
The header file include/protocol.h defines the format of the packets
used in the Jeux network protocol.  The concept of a protocol is an
important one to understand.  A protocol creates a standard for
communication so that any program implementing the protocol will be able
to connect and operate with any other program implementing the same
protocol.  Any client should work with any server if they both
implement the same protocol correctly.  In the Jeux protocol,
clients and servers exchange packets with each other.  Each packet
has two parts: a fixed-size header that describes the packet, and an
optional payload that can carry arbitrary data.  The fixed-size
header always has the same size and format, which is given by the
JEUX_PACKET_HEADER structure; however the payload can be of arbitrary size.
One of the fields in the header tells how long the payload is.

The function proto_send_packet is used to send a packet over a
network connection.  The fd argument is the file descriptor of a
socket over which the packet is to be sent.  The hdr argument is a
pointer to the fixed-size packet header.  The data argument is a
pointer to the data payload, if there is one, otherwise it is NULL.
The proto_send_packet function uses the write() system call
write the packet header to the "wire" (i.e. the network connection).
If the length field of the header specifies a nonzero payload length,
then an additional write() call is used to write the payload data
to the wire immediately following the header.


🤓  The proto_send_packet assumes that multi-byte fields in
the packet passed to it are stored in network byte order,
which is a standardized byte order for sending multi-byte values
over the network.  Note that, as it happens, network byte order
is different than the host byte order used on the x86-64 platforms
we are using, so you must convert multi-byte quantities from host
to network byte order when storing them in a packet, and you must
convert from network to host byte order when reading multi-byte
quantities out of a packet.  These conversions can be accomplished
using the library functions htons(), htonl(), ntohs(), ntohl(),
etc.  See the man page for ntohl() for details and a full list
of the available functions.


The function proto_recv_packet() reverses the procedure in order to
receive a packet.  It first uses the read() system call to read a
fixed-size packet header from the wire.  If the length field of the header
is nonzero then an additional read() is used to read the payload from the
wire (note that the length field arrives in network byte order!).
The proto_recv_packet() uses malloc() to allocate memory for the
payload (if any), whose length is not known until the packet header is read.
A pointer to the payload is stored in a variable supplied by the caller.
It is the caller's responsibility to free() the payload once it is
no longer needed.

NOTE: Remember that it is always possible for read() and write()
to read or write fewer bytes than requested.  You must check for and
handle these "short count" situations.
Implement these functions in a file protocol.c.  If you do it
correctly, the server should function as before.

Task III: Client Registry
You probably noticed the initialization of the client_registry
variable in main() and the use of the creg_wait_for_empty()
function in terminate().  The client registry provides a way of
keeping track of the number of client connections that currently exist,
and to allow a "master" thread to forcibly shut down all of the
connections and to await the termination of all server threads
before finally terminating itself.  It is much more organized and
modular to simply present to each of the server threads a condition
that they can't fail to notice (i.e. EOF on the client connection)
and to allow themselves to perform any necessary finalizations and shut
themselves down, than it is for the main thread to try to reach in
and understand what the server threads are doing at any given time
in order to shut them down cleanly.
The functions provided by a client registry are specified in the
client_registry.h header file.  Provide implementations for these
functions in a file src/client_registry.c.  Note that these functions
need to be thread-safe (as will most of the functions you implement
for this assignment), so synchronization will be required.  Use a
mutex to protect access to the thread counter data.  Use a semaphore
to perform the required blocking in the creg_wait_for_empty()
function.  To shut down a client connection, use the shutdown()
function described in Section 2 of the Linux manual pages.
It is sufficient to use SHUT_RD to shut down just the read-side
of the connection, as this will cause the client service thread to
see an EOF indication and terminate.
Implementing the client registry should be a fairly easy warm-up
exercise in concurrent programming.  If you do it correctly, the
Bourse server should still shut down cleanly in response to SIGHUP
using your version.
Note: You should test your client registry separately from the
server.  Create test threads that rapidly call creg_register() and
creg_unregister() methods concurrently and then check that a call to the
creg_wait_for_empty() function blocks until the number of registered
clients reaches zero, and then returns.

Task IV: Client Service Thread
Next, you should implement the thread function that performs service
for a client.  This function is called jeux_client_service, and
you should implement it in the src/server.c file.
The jeux_client_service function is invoked as the thread function
for a thread that is created (using pthread_create()) to service a
client connection.
The argument is a pointer to the integer file descriptor to be used
to communicate with the client.  Once this file descriptor has been
retrieved, the storage it occupied needs to be freed.
The thread must then become detached, so that it does not have to be
explicitly reaped, and it must register the client file descriptor with
the client registry.
Finally, the thread should enter a service loop in which it repeatedly
receives a request packet sent by the client, carries out the request,
and sends any response packets.
The possible types of packets that can be received are listed below,
together with a discussion of how the server responds to these packets.
Note that much of the functionality described is not performed directly
by the server module, but by functions in other modules which it calls.


LOGIN:  The payload portion of the packet contains the player username
(not null-terminated) given by the user.
Upon receipt of a LOGIN packet, the client_login() function should be called.
In case of a successful LOGIN an ACK packet with no payload should be
sent back to the client.  In case of an unsuccessful LOGIN, a NACK packet
(also with no payload) should be sent back to the client.

Until a LOGIN has been successfully processed, other packets sent by the
client should elicit a NACK response from the server.
Once a LOGIN has been successfully processed, other packets should be
processed normally, and LOGIN packets should result in a NACK.


USERS:  This type of packet has no payload.  The server responds by
sending an ACK packet whose payload consists of a text string in which
each line gives the username of a currently logged in player, followed by
a single TAB character, followed by the player's current rating.


INVITE:  The payload of this type of packet is the username of another
player, who is invited to play a game.  The sender of the INVITE is the
"source" of the invitation; the invited player is the "target".
The role field of the header contains an integer value that specifies the
role in the game to which the player is invited (1 for first player to move,
2 for second player to move).
The server responds either by sending an ACK with no payload in case of
success or a NACK with no payload in case of error.  In case of an ACK,
the id field of the ACK packet will contain the integer ID that the
source client can use to identify that invitation in the future.
An INVITED packet will be sent to the target as a notification that the
invitation has been made.  This id field of this packet gives an ID that
the target can use to identify the invitation.  Note that, in general,
the IDs used by the source and target to refer to an invitation will be
different from each other.


REVOKE:  This type of packet has no payload.  The id field of the header
contains the ID of the invitation to be revoked.  The revoking player must
be the source of that invitation.  The server responds by
attempting to revoke the invitation.  If successful, an ACK with no payload
sent, otherwise a NACK with no payload is sent.  A successful revocation causes
a REVOKED packet to be sent to notify the invitation target.


DECLINE:  This type of packet is similar to REVOKE, except that it is
sent by the target of an invitation in order to decline it.  The server's
response is either an ACK or NACK as for REVOKE.  If the invitation is
successfully declined, a DECLINED packet is sent to notify the source.


ACCEPT:  This type of packet is sent by the target of an invitation in
order to accept it.  The id field of the header contains the ID of the invitation
to be accepted.  If the invitation has been revoked or previously accepted,
a NACK is sent by the server.  Otherwise a new game is created and an ACK
is sent by the server.  If the target's role in the game is that of first player
to move, then the payload of the ACK will contain a string describing the
initial game state.  In addition, the source of the invitation will be sent an
ACCEPTED packet, the id field of which contains the source's ID for the
invitation.  If the source's role is that of the first player to move, then
the payload of the ACCEPTED packet will contain a string describing the
initial game state.


MOVE:  This type of packet is sent by a client to make a move in a game
in progress.  The id field of the header contains the client's ID for the
invitation that resulted in the game.  The payload of the packet contains a
string describing the move.  For the tic-tac-toe game, a move string may
consist either of a single digit in the range ['1' - '9'], or a string consisting
of such a digit, followed either by "<-X" or "<-O".  The latter forms specify
the role of the player making the move as well as the square to be occupied
by the player's mark.  The server will respond with ACK with no payload if
the move is legal and is successfully applied to the game state, otherwise
with NACK with no payload.  In addition, the opponent of the player making
the move will be sent a MOVED packet, the id field of which contains the
opponent's ID for the game and the payload of which contains a string that
describes the new game state after the move.


RESIGN:  This type of packet is sent by a client to resign a game in
progress.  The id field of the header contains the client's ID for the
invitation that resulted in the game.  There is no payload.
If the resignation is successful, then the server responds with ACK,
otherwise with NACK.  In addition, the opponent of the player who is
resigning is sent a RESIGNED packet, the id field of which contains the
opponent's ID for the game.


There is one other packet type not mentioned in the above discussion.
This is the ENDED packet type.  This type of packet is sent by the server
when a game terminates to notify the clients participating in a game that
the game is over.  The id field of the packet header contains an ID that
identifies the game to the client.  The role field of the packet header
contains an integer value 0, 1, 2, according to whether the game was drawn,
the first player won, or the second player won.

Task V: Invitation Module
An INVITATION records the status of an offer, made by one CLIENT
to another, to participate in a GAME.  The CLIENT that initiates
the offer is called the "source" of the invitation, and the client that
is the recipient of the offer is called the "target" of the invitation.
An INVITATION can be in one of three states: "open", "accepted",
or "closed.  An INVITATION in the "accepted" state will contain a
reference to a GAME that is in progress.
The invitation module provides the functions listed below.
For more detailed specifications, see the comments in the header file
invitation.h.


inv_create: Create a new INVITATION.

inv_ref: Increase the reference count on an INVITATION.

inv_unref: Decrease the reference count on an INVITATION, freeing the
INVITATION and its contents if the reference count has reached zero.

inv_get_source: Get the CLIENT that is the source of an INVITATION.

inv_get_target: Get the CLIENT that is the target of an INVITATION.

inv_get_source_role: Get the GAME_ROLE to be played by the source
of an INVITATION.

inv_get_target_role: Get the GAME_ROLE to be played by the target
of an INVITATION.

inv_get_game: Get the game (if any game is in progress) associated with
an INVITATION.

inv_accept: Accept an INVITATION, changing it from the "open" state
to the "accepted" state, and creating a new GAME.

inv_close: Close an invitation, changing it from either the "open" state
or the "accepted" state to the "closed" state.  Closing an INVITATION
with a game in progress will result in the resignation of the player
doing the closing.


Task VI: Client Module
This is the most complex module, so you should work on it only when you
get to the point that you feel you have developed some understanding of
how the Jeux server works.  A CLIENT represents the state of a network
client connected to the system.  It contains the file descriptor of the
connection to the client and it provides functions for sending packets
to the client.  If the client is logged in, it contains a reference to
a PLAYER object and it contains a list of invitations for which the client
is either the source or the target.  CLIENT objects are managed by a
client registry.  The client module provides the functions listed below.
For more detailed specifications, see the comments in the header file
client.h.


client_create: Create a new CLIENT object.

client_ref: Increase the reference count on a CLIENT object.

client_unref: Decrease the reference count on a CLIENT, freeing the
CLIENT and its contents if the reference count has reached zero.

client_login: Log in a CLIENT as a specified PLAYER.

client_logout: Log out a CLIENT.

client_get_player: Get the PLAYER for a logged-in client.

client_get_fd: Get the file descriptor for the network connection
associated with a CLIENT.

client_send_packet: Send a packet over the network to a connected
client.

client_send_ack: Send an ACK packet to a client.

client_send_nack: Send a NACK packet to a client.

client_make_invitation: Make a new invitation from a specified
"source" CLIENT to a specified "target" CLIENT.

client_revoke_invitation: Called by the source of an INVITATION
to revoke it.  The target of the invitation is sent a REVOKED packet.

client_decline_invitation: Called by the target of an INVITATION
to decline it. The source of the invitation is sent a DECLINED packet.

client_accept_invitation: Called by the target of an INVITATION
to accept it.  A new GAME is created and the source of the
invitation is sent an ACCEPTED packet.

client_resign_game: Called by either the source or target of an
INVITATION to resign a game in progress.  The invitation is removed
from the source's and target's lists and the opponent of the caller
is sent a RESIGNED packet.

client_make_move: Called by a participant in a GAME to make a move.
A MOVED packet is sent to the caller's opponent.  If the move results
in the game being over, then the invitation containing the terminated
game is removed from both player's lists, an ENDED packet is sent
to both players, and the result of the game is posted in order to
update the players' ratings.


Task VII: Player Module
A PLAYER object represents a user of the system.  A PLAYER has a
username, which does not change once the PLAYER is created, and it also
has a "rating" which is an integer value that reflects the player's
skill level among all players known to the system.  A player's rating
changes as a result of each game in which the player participates.
The player module provides the functions listed below.
For more detailed specifications, see the comments in the header file
player.h.


player_create: Create a new PLAYER.

player_ref: Increase the reference count on a PLAYER.

player_unref: Decrease the reference count on a PLAYER, freeing the
PLAYER and its contents if the reference count has reached zero.

player_get_name: Get the username of a PLAYER.

player_get_rating: Get the rating of a PLAYER.

player_post_result: Post the result of a game between two players,
updating their ratings accordingly (see the specs for more information).


Task VIII: Player Registry Module
A player registry keeps track of information about known users of the system,
in the form of a mapping from user names to PLAYER objects.
This information persists from the time a player is first registered until
the server is shut down.  It provides the functions listed below.
For more detailed specifications, see the comments in the header file
player_registry.h.


preg_init: Initialize a new player registry.

preg_fini: Finalize a player registry, freeing all associated resources.

preg_register: Register a player with a specified user name or look up
an existing player with that name.


Task IX: Game Module
A GAME represents the current state of a game between participating players.
I have listed this module last because most of what is involved in coding it
has to do with the game (tic-tac-toe) that is implemented, rather than
additional features involving threads and concurrency.  It is certainly not
the main point of the assignment to program the game of tic-tac-toe,
so you should not get bogged down here.
In addition to the GAME type,
this module also defines the auxiliary types GAME_MOVE, which represents a
move in a game, and GAME_ROLE, which represents the role of a player in the
game.  The GAME_ROLE type is an enumerated type which is defined in the
game.h header file, but the details of the GAME_MOVE structure are
up to you.
The functions provided by the game module are listed below.
For more detailed specifications, see the comments in the header file game.h.


game_create: Create a new game.

game_ref: Increase the reference count on a GAME.

game_unref: Decrease the reference count on a GAME, freeing the
GAME and its contents if the reference count has reached zero.

game_apply_move: Apply a GAME_MOVE to a GAME.

game_resign: Called by one of the players to resign the game.

game_unparse_state:  Get a string that describes the current GAME state,
in a format appropriate for human users.

game_is_over: Determine if a specified GAME has terminated.

game_get_winner: Get the GAME_ROLE of the player who has won the game.

game_parse_move: Attempt to interpret a string as a move in the specified
GAME, for the player in the specified GAME_ROLE.

game_unparse_move: Get a string that describes a specified GAME_MOVE,
in a format appropriate to be shown to human users.


Submission Instructions
Make sure your hw5 directory looks similarly to the way it did
initially and that your homework compiles (be sure to try compiling
both with and without "debug").
Note that you should omit any source files for modules that you did not
complete, and that you might have some source and header files in addition
to those shown.  You are also, of course, encouraged to create Criterion
tests for your code.  Because the interfaces of the various modules have
been specified in full detail, this program would be very conducive to
unit testing.  Although there is significant value in unit tests that just
put each module through its paces in a single-threaded context, to fully
test the thread-safety of a module it is necessary to call its functions
rapidly and concurrently by multiple threads, in order to try to exercise
race conditions and deadlocks.
It would definitely be a good idea to use valgrind to check your program
for memory and file descriptor leaks, as well as more serious errors.
Keeping track of allocated objects and making sure to free them is one of
the more challenging aspects of this assignment.
To submit, run git submit hw5.
