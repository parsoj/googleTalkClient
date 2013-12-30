/*
** client.c -- a  socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>



#include <termios.h>
#include <recv_xml.h>
#include <gsasl.h>
//#include <gsasl-compat.h>
//#include <gsasl-mech.h>
//#include <gsasl-compat.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
//#include <gnutls/gnutlsxx.h>

#include <arpa/inet.h>

#define MAXDATASIZE 2048// max number of bytes we can get at once 
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"

typedef struct {
	roster_entry * next;
	roster_entry * prev;
	Available_Data rdata;
} roster_entry


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}



void sendstr(int sockfd,char* buf){
	int sent = 0;
	int bufsize = strlen(buf);
	while( sent < bufsize){
		sent += send(sockfd, &buf[sent], bufsize-sent, 0);

	}



}	

void sendchat(gnutls_session_t ses,char * tojid, char * fromjid, char * message){
	char chatxml[MAXDATASIZE];
	sprintf(chatxml, "<message to='%s' from='%s' type='chat' xml:lang='en'><body>%s</body></message>",tojid, fromjid, message);
	sendstr_tls(ses, chatxml); 


}

void print_roster(roster_entry *roster){
	while(curr != NULL){
		char username[MAXDATASIZE];
		int u=0;
		while(curr->rdata.jid[u] != '/'){
			username[u] = curr->rdata.jid[u];
			u++;
		}
		username[u] = '\0';
		printf("%s\t%s\n\t%s\n", curr->rdata.show, username,curr->rdata.status);
		curr = curr->next;
	}	

}



void print_message(Xml_Stanza stanza){
	char username[MAXDATASIZE];
	int u=0;
	while(stanza.data.message_data.from[u] != '/'){
		username[u] = stanza.data.message_data.from[u];
		u++;
	
	}
	printf("%s: %s\n", username, stanza.data.message_data.message);



}


void sendstr_tls(gnutls_session_t session,char* buf){w	int sent = 0;
	int bufsize = strlen(buf);
	while( sent < bufsize){
		sent += gnutls_record_send(session, &buf[sent], bufsize-sent);

	}



}
Xml_Stanza recv_and_print(sockfd){
	Xml_Stanza *tempStanza;
	tempStanza=NULL;
	while(tempStanza == NULL){
		tempStanza = recv_xml_stream(sockfd);
	}

//	printf("client: received '%s'\n",tempStanza->stream);
	return *tempStanza;
}

gnutls_session_t tlsInit(int sd)
{
	int ret;//,sd, ii;
	gnutls_session_t session;
//	char buffer[MAXDATASIZE];
	const char *err;
	gnutls_certificate_credentials_t xcred;

	gnutls_global_init ();

	/* X509 stuff */
	gnutls_certificate_allocate_credentials (&xcred);

	/* sets the trusted cas file
	*/
	gnutls_certificate_set_x509_trust_file (xcred, CAFILE, GNUTLS_X509_FMT_PEM);
//	gnutls_certificate_set_verify_function (xcred, _verify_certificate_callback);

	/* If client holds a certificate it can be set using the following:
	 *
	 gnutls_certificate_set_x509_key_file (xcred, 
	 "cert.pem", "key.pem", 
	 GNUTLS_X509_FMT_PEM); 
	 */

	/* Initialize TLS session 
	*/
	gnutls_init (&session, GNUTLS_CLIENT);

	gnutls_session_set_ptr (session, (void *) "my_host_name");

	gnutls_server_name_set (session, GNUTLS_NAME_DNS, "my_host_name", 
			strlen("my_host_name"));

	/* Use default priorities */
	ret = gnutls_priority_set_direct (session, "NORMAL", &err);
	if (ret < 0)
	{
		if (ret == GNUTLS_E_INVALID_REQUEST)
		{
			fprintf (stderr, "Syntax error at: %s\n", err);
		}
		exit (1);
	}

	/* put the x509 credentials to the current session
	*/
	gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

	/* connect to the peer
	*/
	//sd = tcp_connect ();

	gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);
//	gnutls_handshake_set_timeout (session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	/* Perform the TLS handshake
	*/
	do
	{
		ret = gnutls_handshake (session);
	}
	while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

	if (ret < 0)
	{
		fprintf (stderr, "*** Handshake failed\n");
		gnutls_perror (ret);
		goto end;
	}
/*	else
	{
		printf ("- Handshake was completed\n");
	}

//	gnutls_record_send (session, MSG, strlen (MSG));

	ret = gnutls_record_recv (session, buffer, MAXDATASIZE);
	if (ret == 0)
	{
		printf ("- Peer has closed the TLS connection\n");
		goto end;
	}
	else if (ret < 0)
	{
		fprintf (stderr, "*** Error: %s\n", gnutls_strerror (ret));
		goto end;
	}

	printf ("- Received %d bytes: ", ret);
	for (ii = 0; ii < ret; ii++)
	{
		fputc (buffer[ii], stdout);
	}
	fputs ("\n", stdout);
*/
//	gnutls_bye (session, GNUTLS_SHUT_RDWR);

end:
/*
	tcp_close (sd);

	gnutls_deinit (session);

	gnutls_certificate_free_credentials (xcred);

	gnutls_global_deinit ();
*/


  return session;
}


static char*
client_authenticate (Gsasl_session * session)
{
	char buf[BUFSIZ] = "";
	char *p;
	int rc;

	/* This loop mimics a protocol where the client send data first. */

	do
	{
		/* Generate client output. */
		rc = gsasl_step64 (session, buf, &p);

		if (rc == GSASL_NEEDS_MORE || rc == GSASL_OK)
		{
			/* If sucessful, print it. */
//			printf ("Output:\n%s\n", p);
	//		gsasl_free (p);
		}

		if (rc == GSASL_NEEDS_MORE)
		{
			/* If the client need more data from server, get it here. */
			printf ("Input base64 encoded data from server:\n");
			p = fgets (buf, sizeof (buf) - 1, stdin);
			if (p == NULL)
			{
				perror ("fgets");
				return NULL;
			}
			if (buf[strlen (buf) - 1] == '\n')
				buf[strlen (buf) - 1] = '\0';
		}
	}
	while (rc == GSASL_NEEDS_MORE);

	printf ("\n");

	if (rc != GSASL_OK)
	{
		printf ("Authentication error (%d): %s\n", rc, gsasl_strerror (rc));
		return NULL;
	}

	return p;
}

	static char*
client (Gsasl * ctx)
{
	Gsasl_session *session;
	const char *mech = "PLAIN";
	int rc;

	
	struct termios oflags, nflags;

	/* disabling echo */
	tcgetattr(fileno(stdin), &oflags);
	nflags = oflags;
	nflags.c_lflag &= ~ECHO;
	nflags.c_lflag |= ECHONL;

//prompt for username/password
//	char  usrname[MAXDATASIZE];
//	char  passwd[MAXDATASIZE];
	//printf("Username: ");
	//scanf("%s", usrname);


	if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
		perror("tcsetattr");
		return "EXIT_FAILURE";

	}

//	printf("Password: ");
//	scanf("%s", passwd);
//
	/* restore terminal */
	if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
		perror("tcsetattr");
		return "EXIT_FAILURE";
	}



	/* Create new authentication session. */
	if ((rc = gsasl_client_start (ctx, mech, &session)) != GSASL_OK)
	{
		printf ("Cannot initialize client (%d): %s\n", rc, gsasl_strerror (rc));
		return NULL;
	}

	/* Set username and password in session handle.  This info will be
	   lost when this session is deallocated below.  */
	//TODO put this back!!!
	//gsasl_property_set (session, GSASL_AUTHID, usrname);
	//gsasl_property_set (session, GSASL_PASSWORD, passwd);
	gsasl_property_set (session, GSASL_AUTHID, "parsoj");
	gsasl_property_set (session, GSASL_PASSWORD, "jeff88831");


	/* Do it. */
	char * p = client_authenticate (session);


	/* Cleanup. */
//	gsasl_finish (session);
	return p;
}



void update_roster(roster_entry * roster, Xml_Stanza stanza){

	roster_entry * curr = roster;
	bool found = 0;
	roster_entry * prev = NULL;
	if(stanza.type == ST_AVAILABLE){
		while( curr != NULL){
			if(stanza.data.available_data.jid == curri->rdata.jid){		
				curr->rdata = stanza.data.available_data;
				found = 1;
			}
			prev = curr;
			curr = curr->next;
		}
		if(found = 0){
			curr->next = (roster_entry*)malloc(sizeof(roster_entry));
			if(prev != NULL) prev->next = curr;
			curr->rdata = stanza.data.available_data;
			curr->next = NULL;
		}
	}	
	else{
		while(curr != NULL){
			if(stanza.data.available_data.jid == curri->rdata.jid){		
				prev->next = curr->next;
				free(curr);	
			}
			prev = curr;
			curr = curr->next;
		}


	}
	
	
	
	return;
}




int main(int argc, char *argv[])
{
	int sockfd;   
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];


	if (argc != 3) {
	    fprintf(stderr,"usage: client hostname\n");
	    exit(1);
	}
	//strcpy(buf,"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='gmail.com' version='1.0'>");
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((rv = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s:port %s\n", s,argv[2]);

	freeaddrinfo(servinfo); // all done with this structure



	sendstr(sockfd, "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='gmail.com' version='1.0'>"); 

//	recv_and_print(sockfd);
//	recv_and_print(sockfd);
	Xml_Stanza *tempStanza;
	tempStanza=NULL;
	while(tempStanza == NULL){
		tempStanza = recv_xml_stream(sockfd);
	}
	
//	printf("client: received '%s'\n",tempStanza->stream);

	tempStanza=NULL;
	while(tempStanza == NULL){
		tempStanza = recv_xml_stream(sockfd);
	}

//	printf("client: received '%s'\n",tempStanza->stream);


//p4--PART4


	
	sendstr(sockfd,"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");

	tempStanza=NULL;
	while(tempStanza == NULL){
		tempStanza = recv_xml_stream(sockfd);
	}
	//printf("client: received '%s'\n",tempStanza->stream);



	gnutls_session_t tlsSession = tlsInit(sockfd);


//p5--PART5	
	Gsasl *ctx = NULL;
	int rc;
	
	//init GSASL
	if ((rc = gsasl_init (&ctx)) != GSASL_OK)
	{
		printf ("Cannot initialize libgsasl (%d): %s",
				rc, gsasl_strerror (rc));
		return 1;
	}
	char * step64out = client(ctx);

	sendstr_tls(tlsSession, "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='gmail.com' version='1.0'>");
	tempStanza = NULL;
	while(tempStanza == NULL){
		tempStanza = recv_tls_xml_stream(tlsSession);

	}

//	printf("client: received '%s'\n",tempStanza->stream);
	tempStanza = NULL;
	while(tempStanza == NULL){
		tempStanza = recv_tls_xml_stream(tlsSession);

	}
//	printf("client: received '%s'\n",tempStanza->stream);

	char saslAuthXml[MAXDATASIZE];
	sprintf(saslAuthXml,"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN' xmlns:ga='http://www.google.com/talk/protocol/auth' ga:client-uses-full-bind-result='true'>%s</auth>",step64out );
//	printf("%s\n",saslAuthXml);
 
	sendstr_tls(tlsSession,  saslAuthXml);

	tempStanza = NULL;
	while(tempStanza == NULL){
		tempStanza = recv_tls_xml_stream(tlsSession);

	}
	printf("client: received '%s'\n",tempStanza->stream);


//p6--PART6



	sendstr_tls(tlsSession, "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='gmail.com' version='1.0'>");

	tempStanza = NULL;
	while(tempStanza == NULL){
		tempStanza = recv_tls_xml_stream(tlsSession);

	}
//	printf("client: received '%s'\n",tempStanza->stream);

	tempStanza = NULL;
	while(tempStanza == NULL){
		tempStanza = recv_tls_xml_stream(tlsSession);

	}
//	printf("client: received '%s'\n",tempStanza->stream);

	sendstr_tls(tlsSession, "<iq type='set' id='bind 1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource> gmail.</resource></bind></iq>");


//get JID here
	tempStanza = NULL;
	while(tempStanza == NULL){
		tempStanza = recv_tls_xml_stream(tlsSession);
	}

	//printf("client: received '%s'\n",tempStanza->stream);
	char jid[MAXDATASIZE];
	strcpy(jid,tempStanza->data.bind_data.jid);
	printf("JID is: %s\n",jid); 

	sendstr_tls(tlsSession, "<iq to='gmail.com' type='set' id='sess 1'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>");
	tempStanza = NULL;
	while(tempStanza == NULL){
		tempStanza = recv_tls_xml_stream(tlsSession);
	}
	printf("client: received '%s'\n",tempStanza->stream);

	
	sendstr_tls(tlsSession, "<presence/>");
	tempStanza = NULL;
	while(tempStanza == NULL){
		tempStanza = recv_tls_xml_stream(tlsSession);
	}
	printf("client: received '%s'\n",tempStanza->stream);

//p7--PART7

fd_set rd, wr, ex;

char buf[MAXDATASIZE];
char curr_recip[MAXDATASIZE];
	
roster_entry * roster ;
char* tojid;
for(;;){



	FD_ZERO(&rd);
	FD_ZERO(&wr);
	FD_ZERO(&ex);

	FD_SET(sockfd, &rd);
	FD_SET(fileno(stdin), &rd);
	FD_SET(sockfd,&wr);

	if (select(sockfd+1,&rd,&wr,&ex,NULL) == -1){
		perror("select:");
		exit(1);
	}
	//if there are any data ready to read from the socket
	if (FD_ISSET(sockfd, &rd)){
		//printf it
		tempStanza = NULL;
		while(tempStanza == NULL){
			tempStanza = recv_tls_xml_stream(tlsSession);
		}
		if(tempStanza->type == ST_AVAILABLE){
			update_roster(roster, tempStanza);	 
		}
		if(tempStanza->type == ST_UNAVAILABLE){
			update_roster(roster, tempStanza);	 

		}
		if(tempStanza->type == ST_MESSAGE){
			print_message(tempStanza);
		}
	//	printf("client: received '%s'\n",tempStanza->stream);



	}
	// if there is something in stdin
	if (FD_ISSET(fileno(stdin), &rd)){
		if(FD_ISSET(sockfd, &wr)){
			int numbytes;
			//read from keyboard
			numbytes = read(fileno(stdin), buf, MAXDATASIZE);
			buf[numbytes] = '\0';i
			
			//check for :
			if(buf[0] ==':'){

				//check for :q
				if((numbytes == 2) && (buf[1] == "q")){

				}
				//check for :roster
				if((numbytes == 7) && ( 0 ==strcmp(buf, ":roster"))){

				}	
				//check for :to
				if((numbytes > 4) && (buf[1] == 't') && (buf[2] == '0')){
					char * tempbufa[MAXDATASIZE];
					strcpy(tempbufa, &buf[4]);
					roster_entry* curr = roster;
					boolean found = 0;
					while(curr != NULL){
						if( 0 == strncmp(tempbufa,curr->rdata.jid, strlen(tempbufa))){
							found = 1;
							tojid= curr->rdata.jid;
							break;
						}
						curr = curr->next;	
					}
					if(found == 0){
						printf("user not available");
					}

				}

			}
			//printf it
			printf("You: %s\n",buf);
			//send() it through socket
			sendstr_tls(tlsSession, buf);
		}


	}

}





gnutls_deinit (tlsSession);

//	gnutls_certificate_free_credentials (xcred);

gnutls_global_deinit ();

gsasl_done(ctx);
close(sockfd);

return 0;
}

