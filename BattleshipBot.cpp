
#include "stdafx.h"
#include <winsock2.h>

#define HAVE_REMOTE

// My Additions
#include <math.h>  
#include <thread>
#include <fstream> // for file reading
#include <iostream>
#include <string>
#include <algorithm>

// ARP Spoofing links
//#include "pcap.h"
#include "ether.h"
#include "arp.h"
#include "arp_helper.h"
#include "utils.h"
#include <stdio.h>
#include <conio.h> // For _kbhit/_getch
#include <windows.h> // For Sleep

#pragma comment(lib, "wsock32.lib")

#define STUDENT_NUMBER		"S"
#define STUDENT_FIRSTNAME	"Anthony"
#define STUDENT_FAMILYNAME	"Scully"

//#define IP_ADDRESS_SERVER	"127.0.0.1"
//#define IP_ADDRESS_SERVER "164.11.80.70"
//
#define IP_ADDRESS_SERVER "164.11.174.44"
#define LEADER_IP "164.11.157.141"

#define PORT_SEND	 1924 // We define a port that we are going to use.
#define PORT_RECEIVE 1925 // We define a port that we are going to use.
#define MAX_BUFFER_SIZE	99999
#define MAX_SHIPS		200

#define MOVE_LEFT		-1
#define MOVE_RIGHT		 1
#define MOVE_UP			 1
#define MOVE_DOWN		-1
#define MOVE_FAST		 2
#define MOVE_SLOW		 1

// My #defines
#define FIRING_RANGE	10000
#define MIN_ALLY_DIST	100
#define MAX_ALLY_DIST	400
#define MAX_LOCATIONS	8
#define MAX_ALLIES		3
//#define JOSH_IP			"164.11.80.99"
//#define BRYAN_IP		"164.11.166.51"
//#define DOM_IP			"164.11.80.79"

#define FLAG_HIDE		21
#define HUNTER_DISTANCE	22500
#define COMBAT_DISTANCE	14400

// ARP Spoofing Defines
#define CAP_SNAPLEN 65536
#define CAP_TIMEOUT_MS 1000
#define POISON_INTERVAL_MS 100
#define UNPOISON_RETRIES 10
#define VICTIM1_IP (164 + (11 << 8) + (80 << 16) + (20 << 24))
#define VICTIM2_IP (164 + (11 << 8) + (80 << 16) + (70 << 24))
#define ARP_ATTACK_STOP_MESSAGE	"1"

// For moving to locations.
const int outerDifference = 200, innerDifference = 300; // Defines how far away from the edge of the map. Increase the value to stay closer to the centre.
const int outerLower = outerDifference, outerUpper = 1000 - outerDifference; 
const int innerLower = innerDifference, innerHigher = 1000 - innerDifference;
const int centreOfMap = 500;
const char JOSH_IP[50]="";
const char BRYAN_IP[50]="";
const char DOM_IP[50]="";


SOCKADDR_IN sendto_addr;
SOCKADDR_IN receive_addr;

SOCKET sock_send;  // This is our socket, it is the handle to the IO address to read/write packets
SOCKET sock_recv;  // This is our socket, it is the handle to the IO address to read/write packets

WSADATA data;

char InputBuffer [MAX_BUFFER_SIZE];
char botID;

int myX;
int myY;
int myHealth;
int myFlag;

int number_of_ships;
int shipX[MAX_SHIPS];
int shipY[MAX_SHIPS];
int shipHealth[MAX_SHIPS];
int shipFlag[MAX_SHIPS];

bool fire = false;
int fireX;
int fireY;

bool moveShip = false;
int moveX;
int moveY;

bool setFlag = true;
bool isLeader = false;
int new_flag = 0;

void fire_at_ship(int X, int Y);
void move_in_direction(int left_right, int up_down);
void set_new_flag(int newFlag);


/*
* Author: Anthony Scully (13021034)
* Created: 21/01/2014
* Revised: 25/03/2014
* Revisions:
*	Communnications are fully working.
*	Removed arp spoofing from code. Was causing issues with other team mates
* User advice:
*	Read over the custom method listed below.
*	Descriptions of the methods are available when hovering over them throughout the method name.
*/


/*************************************************************/
/********* Your tactics code starts here *********************/
/*************************************************************/

int up_down = MOVE_LEFT*MOVE_SLOW;
int left_right = MOVE_UP*MOVE_FAST;

//#define PORT 1925

//Structure with the properties of a ship. Used when receiving data from friends.
struct ShipDetails
{
	int ID;
	int x;
	int y;
	int health;
	int flag;
	int numberOfShips;
	long distance;
	bool isAlly;
	char recvDataStruct[30];
	int recvBufSize;
};

// General use variables for solo use.
int previousHealth = myHealth-1, closestFriend = 0;
//int movementLocations[MAX_LOCATIONS][3], lineCount = 0;
int nextLocation = 3, enemyCount = 0;
ShipDetails shipStructArray[MAX_SHIPS];
ShipDetails movementLocations[MAX_LOCATIONS]; // Re-uses ship details for setting up movement. Primarily the ID, x and y.
static const struct ShipDetails emptyStruct; // Used to wipe the ship data in the ShipStructArray

// Ally variables.
static int const josh = 0,bryan = 1,dom = 2;
int allianceX = 0,allianceY = 0, allyDistance = MIN_ALLY_DIST;
char sendBuffer[MAX_BUFFER_SIZE] = "T 1,2,3,4";
std::string allyIPArray[MAX_ALLIES];
ShipDetails allyShipArray[MAX_ALLIES];
sockaddr_in allyAddrArray[MAX_ALLIES];

// Booleans methods used in the sorting alogrithm srd::sort
bool sortLowestHealth(ShipDetails lhs, ShipDetails rhs){ return lhs.health < rhs.health; }
bool sortClosestShip(ShipDetails lhs, ShipDetails rhs) { return lhs.distance < rhs.distance; }
bool sortIsAlly(ShipDetails lhs, ShipDetails rhs) { return lhs.isAlly < rhs.isAlly; }

void leaderSetup(){
	char recvBuffer[MAX_BUFFER_SIZE];
	int  len = sizeof(SOCKADDR);
	char chr, *p;
	int ally1 = 0,ally2 = 0,ally3 = 0;
	char replyBuffer[4] = "0 1";
	char temp[30];

	while (true)
	{
		p = ::inet_ntoa(receive_addr.sin_addr);
		if (recvfrom(sock_recv, recvBuffer, sizeof(recvBuffer)-1, 0, (SOCKADDR *)&receive_addr, &len) != SOCKET_ERROR)
		{
			printf("buffer is %s",recvBuffer);
			//if (sscanf_s(recvBuffer,"%s", &temp) == 1){
			if (sprintf_s(recvBuffer,"%s", &temp) == 2){
				printf("Temp is %s",temp);
				if (strcmp(temp, "1") == 0){
					ally1 = 1;
					allyAddrArray[0].sin_addr.s_addr = receive_addr.sin_addr.s_addr;
					printf("Recieved 1\n");
				}
				else if(strcmp(temp, "2") ==0){
					ally2 = 1;
					allyAddrArray[1].sin_addr.s_addr = receive_addr.sin_addr.s_addr;
					printf("Recieved 2\n");
				}
				else if (strcmp(temp, "3")==0){
					ally3 = 1;
					allyAddrArray[2].sin_addr.s_addr = receive_addr.sin_addr.s_addr;
					printf("Recieved 3\n");
				}

			}
		}

		// If all allies send info, then time to exit and begin combat. One last message is sent to tell them to begin combat.
		if (ally1 !=0 && ally2 !=0 && ally3 !=0)
		{
			char ipAddresses[200];
			for (int i = 0; i < MAX_ALLIES; i++)
			{
				if (i == 0){
					sprintf_s(ipAddresses,"IPInfo %s, %s",&allyAddrArray[1].sin_addr.s_addr,&allyAddrArray[2].sin_addr.s_addr);
					
				}
				if (i == 1){
					sprintf_s(ipAddresses,"IPInfo %s, %s",&allyAddrArray[0].sin_addr.s_addr,&allyAddrArray[2].sin_addr.s_addr);
				}
				if (i == 2){
					sprintf_s(ipAddresses,"IPInfo %s, %s",allyAddrArray[0].sin_addr.s_addr,allyAddrArray[1].sin_addr.s_addr);
				}

				if(sendto(sock_send, ipAddresses, strlen(sendBuffer), 0, (SOCKADDR *)&allyAddrArray[i], sizeof(SOCKADDR)) < 0)
					printf("Send Error to id %d\n", 3);
			}
			char tempThing[30];

			for (int i = 0; i < MAX_ALLIES; i++)
			{
				strcpy(tempThing,inet_ntoa(allyAddrArray[i].sin_addr));
				strcat(allyShipArray[0].recvDataStruct, tempThing);
			}
		}


	}
}

void soldierSetup(){
	char recvBuffer[MAX_BUFFER_SIZE];
	int  len = sizeof(SOCKADDR);
	char chr, *p;
	int ally1 = 0,ally2 = 0,ally3 = 0;
	char replyBuffer[4];
	replyBuffer[0] = botID;
	strcpy(sendBuffer,replyBuffer);
	printf("Sending data to leader. \n");
	//std::cin >>allyIPArray[0];

	//allyAddrArray[0].sin_addr.s_addr = inet_addr(allyIPArray[0].c_str());
	allyAddrArray[0].sin_addr.s_addr = inet_addr(LEADER_IP);

	while (true)
	{
		p = ::inet_ntoa(receive_addr.sin_addr);
		if(sendto(sock_send, sendBuffer, strlen(replyBuffer), 0, (SOCKADDR *)&allyAddrArray[0], sizeof(SOCKADDR)) < 0)
			printf("Send Error to id %d\n", 3);

		if (recvfrom(sock_recv, recvBuffer, sizeof(recvBuffer)-1, 0, (SOCKADDR *)&receive_addr, &len) != SOCKET_ERROR)
		{
			if(sprintf_s(recvBuffer,"IPInfo %s, %s",allyAddrArray[1].sin_addr.s_addr,allyAddrArray[2].sin_addr.s_addr)== 3){
				printf("Recieved data from leader. \n");
				break;
			}
		}
	}

	char tempThing[30];

	for (int i = 0; i < MAX_ALLIES; i++)
	{
		strcpy(tempThing,inet_ntoa(allyAddrArray[i].sin_addr));
		strcat(allyShipArray[0].recvDataStruct, tempThing);
	}
}


// Creates all the address data for communicating with allies.
void setupAllyAddressData()
{
	for (int i = 0; i < MAX_ALLIES; i++)
	{
		memset(&allyAddrArray[i], 0, sizeof(SOCKADDR_IN));
		allyAddrArray[i].sin_family = AF_INET;
		//allyAddrArray[i].sin_addr.s_addr = inet_addr(allyIPArray[i].c_str());
		allyAddrArray[i].sin_port = htons(PORT_RECEIVE);
	}

	if (isLeader)
		leaderSetup();
	else
		soldierSetup();
}

//  Encrypts my flag based on my x and y location.
void encryptFlag()
{
	int flagVal;
	flagVal = myX;
	flagVal = (flagVal << 16 ) + myY;
	flagVal = flagVal ^ FLAG_HIDE;
	set_new_flag(flagVal);
}

// Checks if the ship is an ally or not
bool isAlly(int shipFlag, int shipX, int shipY)
{
	int leftSide, rightSide, allowance = 3;
	shipFlag = shipFlag ^ FLAG_HIDE;
	rightSide  = shipFlag & 0xFFFF;
	leftSide  = (shipFlag >> 16) & 0xFFFF;

	int differenceX = abs(leftSide-shipX);
	int differenceY = abs(rightSide-shipY);
	if (differenceX < allowance && differenceY < allowance)
		return true;
	else
		return false;
}

// Bombard enemy with fake data so they do not fire at me.
void spamData()
{
	struct hostent *hp;
	int mySocket;
	char fakeData[4096] = "1,2,3,4 | 1,1,1,1";
	struct sockaddr_in servAddr; // Server address
	struct sockaddr_in myAddr;

	if (WSAStartup(MAKEWORD(2, 2), &data) != 0);

	if ((mySocket = socket(AF_INET,SOCK_DGRAM,0)) == SOCKET_ERROR) perror("cannot create socket");

	memset((char *) &myAddr, 0, sizeof(myAddr));
	myAddr.sin_family = AF_INET;
	myAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myAddr.sin_port = htons(0);

	//bind(socket, address details)
	if (bind(mySocket, (struct sockaddr *)&myAddr, sizeof(myAddr)) < 0) perror("Error binding socket.");

	memset((char*)&servAddr,0,sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(1925);//htons(port); port can be any number
	//servAddr.sin_port = htons(0);

	while (true)
	{

		int quit = 0;

		while (_kbhit())
			if (tolower(_getch()) == 'q')
				quit = 1;
		if (quit)
		{
			printf("Ending spam\n");
			break;
		}


		for (int i = 0; i < 255; i++)
		{
			if (i !=41 || i !=99 || i !=51 || i !=47)
			{
				std::string val = "164.11.80." + std::to_string(i);

				hp = gethostbyname(val.c_str());
				if (!hp) fprintf(stderr, "could not obtain address of %d\n",i);

				printf("Spamming Data on 80\n");

				memcpy((void*)&servAddr.sin_addr,hp->h_addr_list[0],hp->h_length);
				if (sendto(sock_send,fakeData,strlen(fakeData),0,(struct sockaddr *)&servAddr,sizeof(servAddr)) < 0) perror("sendto failed");
				if (val != allyIPArray[0] && val != allyIPArray[1] && val != allyIPArray[2])
				{
					hp = gethostbyname(val.c_str());
					if (!hp) fprintf(stderr, "could not obtain address of %s\n",val.c_str());
					memcpy((void*)&servAddr.sin_addr,hp->h_addr_list[0],hp->h_length);
					if (sendto(mySocket,fakeData,strlen(fakeData),0,(struct sockaddr *)&servAddr,sizeof(servAddr)) < 0) perror("sendto failed");
				}

			}
		}

		for (int i = 0; i < 255; i++)
		{
			//if (i !=46)
			//{
			std::string val = "164.11.166." + std::to_string(i);

			hp = gethostbyname(val.c_str());
			if (!hp) fprintf(stderr, "could not obtain address of %d\n",i);

			printf("Spamming Data on 166\n");
			memcpy((void*)&servAddr.sin_addr,hp->h_addr_list[0],hp->h_length);
			if (sendto(sock_send,fakeData,strlen(fakeData),0,(struct sockaddr *)&servAddr,sizeof(servAddr)) < 0) perror("sendto failed");
			if (val != allyIPArray[0] && val != allyIPArray[1] && val != allyIPArray[2])
			{
				hp = gethostbyname(val.c_str());
				if (!hp) fprintf(stderr, "could not obtain address of %s\n",val.c_str());
				memcpy((void*)&servAddr.sin_addr,hp->h_addr_list[0],hp->h_length);
				if (sendto(mySocket,fakeData,strlen(fakeData),0,(struct sockaddr *)&servAddr,sizeof(servAddr)) < 0) perror("sendto failed");
			}

			//}
		}


		Sleep(100); // 1000 = 1 second
	}

	closesocket(mySocket);
	WSACleanup();
}

//Returns the distance between two locations.
long getDistance(int sourceX, int sourceY,int destinationX, int destinationY)
{
	int x = sourceX-destinationX, y = sourceY-destinationY;
	long distance = (pow(x,2)) + (pow(y,2));
	return distance;
}

// Adds data from the default arrays into a struct array. My ship is not included in the new array
void addDataToStructArray()
{
	for (int x = 1; x <= number_of_ships; x++)
	{
		shipStructArray[x-1].ID = x;
		shipStructArray[x-1].x = shipX[x];
		shipStructArray[x-1].y = shipY[x];
		shipStructArray[x-1].health = shipHealth[x];
		shipStructArray[x-1].flag = shipFlag[x];
		shipStructArray[x-1].distance = getDistance(myX,myY,shipX[x],shipY[x]);
		shipStructArray[x-1].isAlly = isAlly(shipFlag[x],shipX[x],shipY[x]);
	}
	number_of_ships--; // Minus 1 because my ship will no be included in the shipStructArray
}

// Clears all the ship data in the struct array. Called when there are no ships around
void clearShipStructArray()
{
	for (int x = 0; x < number_of_ships; x++)
		shipStructArray[x] = emptyStruct;
}

//Original movement algorithm that Martin created.
void orignalMovement()
{
	if ( myY > 800) up_down = MOVE_DOWN*MOVE_FAST;
	if (myX < 150) left_right = MOVE_RIGHT*MOVE_FAST;
	if ( myY < 150) up_down = MOVE_UP*MOVE_FAST;
	if (myX > 800) left_right = MOVE_LEFT*MOVE_FAST;
	move_in_direction(left_right, up_down);
}

// Moves my ship to the specified co-ordinates.
void moveToLocation(int x, int y)
{
	int moveSpeedX = MOVE_FAST,moveSpeedY = MOVE_FAST;
	int differenceX = myX - x;
	int differenceY = myY - y;

	// Allows me to move in a straight line without staggering.
	if (abs(differenceY) == 1) moveSpeedY = MOVE_SLOW;
	if (abs(differenceX) == 1) moveSpeedX = MOVE_SLOW;

	if (differenceY > 0) up_down = MOVE_DOWN*moveSpeedY;
	else if (differenceY < 0) up_down = MOVE_UP*moveSpeedY;
	else up_down = 0;

	if (differenceX > 0) left_right = MOVE_LEFT*moveSpeedX;
	else if(differenceX < 0) left_right = MOVE_RIGHT*moveSpeedX;
	else left_right = 0;

	move_in_direction(left_right, up_down);
}

// Reports the ID number of the location that my ship is near (within 10 metres). Reports the value 4 when not at any of the locations.
int getCurrentLocation()
{
	long distance = LONG_MAX;
	for (int i = 0; i < MAX_LOCATIONS; i++)
	{
		distance = getDistance(myX,myY,movementLocations[i].x,movementLocations[i].y);
		if (distance < 10) return i;
	}
	return MAX_LOCATIONS;
}

// Finds the closest location ID from my ships current location and move tot that location.
void setNextLocation(bool respawn)
{
	if (isLeader)
	{
		int currentLocation = getCurrentLocation();
		long lowestDistance = LONG_MAX,distance;
		if ((currentLocation == nextLocation && currentLocation != MAX_LOCATIONS) || respawn) // Only looks for the next location if the bot has arrived at one of the designated locations already.
		{
			for (int i = 0; i < MAX_LOCATIONS; i++)
			{
				distance = getDistance(myX,myY,movementLocations[i].x,movementLocations[i].y); // Replace with your own get distance method

				if (respawn)
				{
					if (distance < lowestDistance)
					{
						nextLocation = i;
						lowestDistance = distance;
					}
				}
				else
				{
					int locationReferenceDifference = i - currentLocation;
					// Checks if the location is closer than the previously noted location.
					if (distance < lowestDistance && (locationReferenceDifference == 1 || locationReferenceDifference == -(MAX_LOCATIONS-1)))
					{
						nextLocation = i;
						lowestDistance = distance;
					}
				}
			}
		}
	}

	allianceX = movementLocations[nextLocation].x;
	allianceY = movementLocations[nextLocation].y;
	moveToLocation(allianceX,allianceY); // Takes the x and y of an area and moves to that location. Replace with your own move to location method
}

//Creates the array for navigating the map. 4 key locations are created that have to be navigated to. Can increase the number to make any pattern.
void movementLocationsetup()
{
	for (int x = 0; x < MAX_LOCATIONS; x++)
	{
		movementLocations[x].ID = x;
		switch (x)
		{
		case 0:
			movementLocations[x].x = outerLower;
			movementLocations[x].y = outerLower;
			break;
		case 1:
			movementLocations[x].x = centreOfMap;
			movementLocations[x].y = innerDifference;
			break;
		case 2:
			movementLocations[x].x = outerUpper;
			movementLocations[x].y = outerLower;
			break;
		case 3:
			movementLocations[x].x = innerHigher;
			movementLocations[x].y = centreOfMap;
			break;
		case 4:
			movementLocations[x].x = outerUpper;
			movementLocations[x].y = outerUpper;
			break;
		case 5:
			movementLocations[x].x = centreOfMap;
			movementLocations[x].y = innerHigher;
			break;
		case 6:
			movementLocations[x].x = outerLower;
			movementLocations[x].y = outerUpper;
			break;
		case 7:
			movementLocations[x].x = innerDifference;
			movementLocations[x].y = centreOfMap;
			break;
		default:
			break;
		}
	}
}

// Returns the ID of the friend who is the closest
int friendCount = 0;
int getClosestFriend()
{
	long closestDistance = LONG_MAX;
	int closestFriendID = MAX_ALLIES;	
	for (int i = 0; i < MAX_ALLIES; i++)
	{
		if (allyShipArray[i].distance != 0)
		{
			if (allyShipArray[i].distance < allyDistance)
				friendCount++;

			if (allyShipArray[i].distance < closestDistance && allyShipArray[i].distance >= allyDistance)
			{
				closestFriendID = i;
				closestDistance = allyShipArray[i].distance;
			}
		}
	}

	if (closestFriendID == MAX_ALLIES) allyDistance = MAX_ALLY_DIST;
	else allyDistance = MIN_ALLY_DIST;

	return closestFriendID;
}

// Counts the number of ships in a surrounding area that isn't an ally
int getEnemyCount()
{
	int counter = 0;
	for (int i = 0; i < number_of_ships; i++)
		if (shipStructArray[i].isAlly == false && (shipStructArray[i].distance < COMBAT_DISTANCE || friendCount != 0))
			counter++;

	return counter;
}

// Main tactics are put in here.
void tactics()
{
	friendCount = 0;
	addDataToStructArray();
	enemyCount = getEnemyCount();
	closestFriend = getClosestFriend();
	// Handles combat
	if (enemyCount == 0) // Handles friends
	{
		std::sort(shipStructArray,shipStructArray+number_of_ships, sortLowestHealth);
		if (shipStructArray[0].health < 6)
			fire_at_ship(shipStructArray[0].x,shipStructArray[0].y); // Shoots ally if their health is too low
	}
	else // Handles enemies
	{
		std::sort(shipStructArray,shipStructArray+number_of_ships, sortClosestShip);
		std::sort(shipStructArray,shipStructArray+number_of_ships, sortIsAlly);
		if(!shipStructArray[0].isAlly)
		{
			fire_at_ship(shipStructArray[0].x,shipStructArray[0].y);
			allianceX = shipStructArray[0].x;
			allianceY = shipStructArray[0].y;
		}
	}

	// Handles movement

	if (closestFriend == MAX_ALLIES) // Movement when grouped with allies
	{
		if (enemyCount == 0)
		{
			if (previousHealth < myHealth) setNextLocation(true);
			else setNextLocation(false);
		}
		else moveToLocation(allianceX,allianceY);
	}// Movement when no completely grouped
	else
	{
		//Attack an enemy alone if certain criteria is met
		if (shipStructArray[0].health < myHealth && shipStructArray[0].distance < HUNTER_DISTANCE && enemyCount != 0 && friendCount == 0)
			moveToLocation(allianceX,allianceY);
		else
			moveToLocation(allyShipArray[closestFriend].x,allyShipArray[closestFriend].y);
	}

	//printf("Health, fire, ally : %d, %d, %d\n",shipStructArray[0].health, fire, shipStructArray[0].isAlly);
	//printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");

	previousHealth = myHealth;
	encryptFlag();
}

/*************************************************************/
/********* Your tactics code ends here ***********************/
/*************************************************************/

void getUserInput()
{
	std::string userCommand;
	while (true) 
	{
		std::cin >> userCommand;
		if (userCommand.compare(ARP_ATTACK_STOP_MESSAGE) == 0)
		{			
			int successCheck = 1; //arpSpoof();
			if (successCheck == 0) printf("Attack completed succuesfully.\n");
			else printf("Attack failed. Error code: %d\n", successCheck);
		}
		else if (userCommand.compare("2") == 0)
		{
			printf("Spamming Data\n");
			spamData();
		}
	}
}

// Contains infite loop that sends and receives data to and from the server and allies
void communicate_with_server()
{
	char buffer[MAX_BUFFER_SIZE];
	int  len = sizeof(SOCKADDR);
	char chr, *p;
	bool finished;
	int  i;
	int  j;
	int  rc;


	char recvStructure[MAX_BUFFER_SIZE];
	char sendStructure[MAX_BUFFER_SIZE];

	WSADATA wsaData;
	char name[255];
	char ip[30];
	PHOSTENT hostinfo;

	// Gets the bots ip address
	if( gethostname ( name, sizeof(name)) == 0)
	{
		if((hostinfo = gethostbyname(name)) != NULL)
		{
			strcpy(ip,inet_ntoa (*(struct in_addr *)*hostinfo->h_addr_list));
		}
	}

	strcat(sendStructure, ip);

	if (isLeader)
	{
		strcat(recvStructure," %d, %d, %d, %d");
		strcat(sendStructure," %d, %d, %d, %d, %d, %d");

		for (int i = 0; i < MAX_ALLIES; i++)
		{
			strcat(allyShipArray[i].recvDataStruct, recvStructure);
			allyShipArray[i].recvBufSize = 4;
		}
	}else
	{
		for (int i = 0; i < MAX_ALLIES; i++)
		{
			if (i == 0)
			{
				strcat(allyShipArray[i].recvDataStruct, " %d, %d, %d, %d, %d, %d");
				allyShipArray[i].recvBufSize = 6;
			}
			else
			{
				strcat(allyShipArray[i].recvDataStruct, " %d, %d, %d, %d");
				allyShipArray[i].recvBufSize = 4;
			}

		}
		strcat(sendStructure," %d, %d, %d, %d");
	}






	sprintf_s(buffer, "Register  %s,%s,%s", STUDENT_NUMBER, STUDENT_FIRSTNAME, STUDENT_FAMILYNAME);
	sendto(sock_send, buffer, strlen(buffer), 0, (SOCKADDR *)&sendto_addr, sizeof(SOCKADDR));

	//std::thread t1(getUserInput);
	//t1.detach();

	while (true)
	{
		p = ::inet_ntoa(receive_addr.sin_addr);
		if (recvfrom(sock_recv, buffer, sizeof(buffer)-1, 0, (SOCKADDR *)&receive_addr, &len) != SOCKET_ERROR)
		{
			if ((strcmp(IP_ADDRESS_SERVER, "127.0.0.1") == 0) || strcmp(IP_ADDRESS_SERVER, p) == 0 || strcmp(JOSH_IP, p) == 0 || strcmp(BRYAN_IP, p) == 0 || strcmp(DOM_IP, p) == 0)
			{
				//Friend Format example: "S, x, y, health, number_of_ships"
				if (sscanf_s(buffer,allyShipArray[josh].recvDataStruct, &allyShipArray[josh].x, &allyShipArray[josh].y, &allyShipArray[josh].health, &allyShipArray[josh].numberOfShips,allianceX,allianceY) == allyShipArray[josh].recvBufSize)
					allyShipArray[josh].distance = getDistance(myX,myY,allyShipArray[josh].x,allyShipArray[josh].y);
				else if (sscanf_s(buffer,allyShipArray[bryan].recvDataStruct, &allyShipArray[bryan].x, &allyShipArray[bryan].y, &allyShipArray[bryan].health, &allyShipArray[bryan].numberOfShips,allianceX,allianceY) == allyShipArray[bryan].recvBufSize)
					allyShipArray[bryan].distance = getDistance(myX,myY,allyShipArray[bryan].x,allyShipArray[bryan].y);
				else if (sscanf_s(buffer,allyShipArray[dom].recvDataStruct, &allyShipArray[dom].x, &allyShipArray[dom].y, &allyShipArray[dom].health, &allyShipArray[dom].numberOfShips,allianceX,allianceY) == allyShipArray[dom].recvBufSize)
					allyShipArray[dom].distance = getDistance(myX,myY,allyShipArray[dom].x,allyShipArray[dom].y);
				else
				{
					i = 0;
					j = 0;
					finished = false;
					number_of_ships = 0;
					while (!finished)
					{
						chr = buffer[i];

						switch (chr)
						{
						case '|':
							InputBuffer[j] = '\0';
							j = 0;
							sscanf_s(InputBuffer,"%d,%d,%d,%d", &shipX[number_of_ships], &shipY[number_of_ships], &shipHealth[number_of_ships], &shipFlag[number_of_ships]);
							number_of_ships++;
							break;

						case '\0':
							InputBuffer[j] = '\0';
							sscanf_s(InputBuffer,"%d,%d,%d,%d", &shipX[number_of_ships], &shipY[number_of_ships], &shipHealth[number_of_ships], &shipFlag[number_of_ships]);
							number_of_ships++;
							finished = true;
							break;

						default:
							InputBuffer[j] = chr;
							j++;
							break;
						}
						i++;
					}

					myX = shipX[0];
					myY = shipY[0];
					myHealth = shipHealth[0];
					myFlag = shipFlag[0];

					tactics();

					if (fire)
					{
						sprintf_s(buffer, "Fire %s,%d,%d", STUDENT_NUMBER, fireX, fireY);
						sendto(sock_send, buffer, strlen(buffer), 0, (SOCKADDR *)&sendto_addr, sizeof(SOCKADDR));
						fire = false;
					}

					if (moveShip)
					{
						sprintf_s(buffer, "Move %s,%d,%d", STUDENT_NUMBER, moveX, moveY);
						rc = sendto(sock_send, buffer, strlen(buffer), 0, (SOCKADDR *)&sendto_addr, sizeof(SOCKADDR));
						moveShip = false;
					}

					if (setFlag)
					{
						sprintf_s(buffer, "Flag %s,%d", STUDENT_NUMBER, new_flag);
						sendto(sock_send, buffer, strlen(buffer), 0, (SOCKADDR *)&sendto_addr, sizeof(SOCKADDR));
						setFlag = false;
					}


					if (isLeader)
					{
						sprintf_s(sendBuffer, sendStructure,myX,myY,myHealth,number_of_ships,allianceX,allianceY);
					}
					else
						sprintf_s(sendBuffer, sendStructure,myX,myY,myHealth,number_of_ships);


					// Send data to team mates
					for (int i = 0; i < MAX_ALLIES; i++)
						if(sendto(sock_send, sendBuffer, strlen(sendBuffer), 0, (SOCKADDR *)&allyAddrArray[i], sizeof(SOCKADDR)) < 0)
							printf("Send Error to id %d\n", i);

					clearShipStructArray();

				}
			}else printf("%s \n", p);
		}
		else printf_s("recvfrom error = %d\n", WSAGetLastError());
	}
	printf_s("Student %s\n", STUDENT_NUMBER);
}

void fire_at_ship(int X, int Y)
{		
	fire = true;
	fireX = X;
	fireY = Y;
}

void move_in_direction(int X, int Y)
{
	if (X < -2) X = -2;
	if (X >  2) X =  2;
	if (Y < -2) Y = -2;
	if (Y >  2) Y =  2;

	moveShip = true;
	moveX = X;
	moveY = Y;
}

void set_new_flag(int newFlag)
{
	setFlag = true;
	new_flag = newFlag;
}



int _tmain(int argc, _TCHAR* argv[])
{
	char chr = '\0';

	printf("\n");
	printf("Battleship Bots\n");
	printf("UWE Computer and Network Systems Assignment 2 (2013-14)\n");
	printf("\n");

	if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return(0);

	sock_send = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  // Here we create our socket, which will be a UDP socket (SOCK_DGRAM).
	if (!sock_send) printf("Socket creation failed!\n"); 

	sock_recv = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  // Here we create our socket, which will be a UDP socket (SOCK_DGRAM).
	if (!sock_recv) printf("Socket creation failed!\n"); 

	memset(&sendto_addr, 0, sizeof(SOCKADDR_IN));
	sendto_addr.sin_family = AF_INET;
	sendto_addr.sin_addr.s_addr = inet_addr(IP_ADDRESS_SERVER);
	sendto_addr.sin_port = htons(PORT_SEND);

	// Custom setup data
	allyIPArray[josh] = JOSH_IP; // Josh
	allyIPArray[bryan] = BRYAN_IP; // Bryan
	allyIPArray[dom] = DOM_IP; // Dom

	// Setup port to recieve
	memset(&receive_addr, 0, sizeof(SOCKADDR_IN));
	receive_addr.sin_family = AF_INET;
	receive_addr.sin_addr.s_addr = INADDR_ANY;
	receive_addr.sin_port = htons(PORT_RECEIVE);

	int ret = bind(sock_recv, (SOCKADDR *)&receive_addr, sizeof(SOCKADDR));
	if (ret) printf("Bind failed! %d\n", WSAGetLastError());  

	// Sets wether the bot is a leader or a soldier
	printf("Input your bot ID: ");
	
	botID = getchar();

	if (botID == '0')
		isLeader = true;
	else
		isLeader=false;

	movementLocationsetup();
	setupAllyAddressData();

	communicate_with_server();

	closesocket(sock_send);
	closesocket(sock_recv);
	WSACleanup();

	while (chr != '\n')
	{
		chr = getchar();
	}

	return 0;
}