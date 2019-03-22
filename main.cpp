/**********************************Libraries*********************************************/

#include "mbed.h"    //Mbed support library
#include "Crypto.h" //Cryptocurrency library
#include "rtos.h"  //Real-time operating system library for threading

/*********************************Definitions********************************************/

//Photointerrupter input pins
#define I1pin D3
#define I2pin D6
#define I3pin D5

//Incremental encoder input pins
#define CHApin   D12
#define CHBpin   D11

//Motor Drive output pins   //Mask in output byte
#define L1Lpin D1           //0x01
#define L1Hpin A3           //0x02
#define L2Lpin D0           //0x04
#define L2Hpin A6          //0x08
#define L3Lpin D10           //0x10
#define L3Hpin D2          //0x20

#define PWMpin D9

//Motor current sense
#define MCSPpin   A1
#define MCSNpin   A0

//Message ID codes that can be converted to messages using threads
enum msgCode {
    msgMotorState,          //Current motor state code
    msgHashRate,            //Hash rate code
    msgNonceMatch,          //Nonce match code
    msgKeyAdded,            //Key added code
    msgVelocityOut,         //Current velocity code
    msgVelocityIn,          //Target velocity code
    msgPositionIn,          //Target position code
    msgPositionOut,         //Current position code
    msgRotations,           
    msgTorque,              //Torque value code
    msgError                //Error message code
};

//More restrictions
#define MAXCOMMANDLENGTH 18 //Maximum acceptable command length

//Motor Torque
#define PWMPERIOD 2000
//Structure defining new data type for storing messages
typedef struct {
    msgCode code;           //Message code
    int32_t message;       //Message data
} message_t;   

/********************************Global Variables*****************************************/

//Mapping from sequential drive states to motor phase outputs
/*
 State   L1  L2  L3
 0       H   -   L
 1       -   H   L
 2       L   H   -
 3       L   -   H
 4       -   L   H
 5       H   L   -
 6       -   -   -
 7       -   -   -
 */

//Drive state to output table
const int8_t driveTable[] = {0x12,0x18,0x09,0x21,0x24,0x06,0x00,0x00};

//Mapping from interrupter inputs to sequential rotor states. 0x00 and 0x07 are not valid
const int8_t stateMap[] = {0x07,0x05,0x03,0x04,0x01,0x00,0x02,0x07};

//Phase lead to make motor spin
int8_t lead = 2;  //2 for forwards, -2 for backwards

// Represents 6 times the number of revolutions
volatile int32_t motorPosition; 

//Starting state of the rotor
int8_t orState = 0;

//Status LED
DigitalOut led1(LED1);

//Photointerrupter inputs
InterruptIn I1(I1pin);
InterruptIn I2(I2pin);
InterruptIn I3(I3pin);

//Motor Drive outputs
PwmOut L1L(L1Lpin);
DigitalOut L1H(L1Hpin);
PwmOut L2L(L2Lpin);
DigitalOut L2H(L2Hpin);
PwmOut L3L(L3Lpin);
DigitalOut L3H(L3Hpin);

//PwmOut PWM(PWMpin);

//*****Initial Values*****
volatile uint32_t motorTorque = 1500; //initialise PWM to 75%
volatile float endVelocity = 30.0;
volatile float endRotation = 100.0;
//Key required for mining
volatile uint64_t newKey;   // Key
Mutex newKey_mutex;         // Mutex prevents deadlock.

//
Mail<message_t,16> mail_box;

//Mail queue 
Queue<void, 8> inCharQ;

//Serial command buffer
char newCommand[MAXCOMMANDLENGTH];
volatile uint8_t index = 0;

//Serial port connection
RawSerial pc(SERIAL_TX, SERIAL_RX);

/****************************************Threads*****************************************/

Thread outThread(osPriorityAboveNormal,1024);  // Output to serial port
Thread inThread(osPriorityAboveNormal,1024);  // Input from serial port
Thread motorCtrlT(osPriorityNormal,1024);    // Motor control thread

/*********************************Function prototypes************************************/

void putMessage(msgCode code, float message); 
void motorOut(int8_t driveState);
inline int8_t readRotorState();
int8_t motorHome();
void commOut();
void commIn();
void parseCommand();
void serialISR();
void motorISR();
void motorCtrlFn();
void motorCtrlTick();

/*****************************************Main*******************************************/

int main() {
    
    //Start threads
    outThread.start(commOut);
    inThread.start(commIn);
    motorCtrlT.start(motorCtrlFn);
    
    //Initialise the serial port
    pc.printf("Hello\n\r");
    
    //PWM Pin period set to 2ms
    //PWM.period_us(2000);
    L1L.period_us(PWMPERIOD);
    L2L.period_us(PWMPERIOD);
    L3L.period_us(PWMPERIOD);
    //PWM.pulsewidth(motorTorque);
    
    //Run the motor synchronisation
    orState = motorHome();
    pc.printf("Rotor origin: %x\n\r",orState);
    //orState is subtracted from future rotor state inputs to align rotor and motor states
    
    //Attach ISR to serial port events
    pc.attach(&serialISR);
    
    //Attach photointerrupters to motor ISR
    I1.rise(&motorISR);     //Detects rising edge of interrupt
    I1.fall(&motorISR);     //Detects falling edge
    I2.rise(&motorISR);
    I2.fall(&motorISR);
    I3.rise(&motorISR);
    I3.fall(&motorISR);
    
    motorISR();
    
    //Declaring Bitcoin variables
    SHA256 SHA256Instance;
    uint8_t sequence[] = {0x45,0x6D,0x62,0x65,0x64,0x64,0x65,0x64,
        0x20,0x53,0x79,0x73,0x74,0x65,0x6D,0x73,
        0x20,0x61,0x72,0x65,0x20,0x66,0x75,0x6E,
        0x20,0x61,0x6E,0x64,0x20,0x64,0x6F,0x20,
        0x61,0x77,0x65,0x73,0x6F,0x6D,0x65,0x20,
        0x74,0x68,0x69,0x6E,0x67,0x73,0x21,0x20,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    
    uint64_t* key = (uint64_t*)((int)sequence + 48);
    uint64_t* nonce = (uint64_t*)((int)sequence + 56);
    uint8_t hash[32];
    uint32_t hashCtr = 0;
    Timer btcTimer;
    
    //Bitcoin mining loop
    btcTimer.start();
    while (1) {
        newKey_mutex.lock();    //Prevents value being changed
        (*key) = newKey;        //Changed key
        newKey_mutex.unlock();  //Unlocks the value
        
        SHA256Instance.computeHash(hash, sequence, 64); //Computes the hash
    hashCtr++;
        if ((hash[0]==0)&&(hash[1]==0)){
            putMessage(msgNonceMatch, *nonce);  //Print the nonce when matched
           
        }
        (*nonce)++;     //Increment nonce
        if (btcTimer.read()>=1){
            putMessage(msgHashRate, (float)(hashCtr));
            hashCtr = 0;
            btcTimer.reset();
        }
    }
}

/********************************Set motor control ticker********************************/

void motorCtrlTick(){
    motorCtrlT.signal_set(0x1);
}

/*************************************Motor control**************************************/

void motorCtrlFn(){
    
    //Declare variables
    Ticker motorCtrlTicker;
    int32_t locMotorPosition;
    int32_t velocity;
    static int32_t oldMotorPosition = 0;
    uint8_t motorCtrlCounter = 0;
    float speedError;
    float rotationError;
    int32_t Ts;  
    int32_t Tr;
    int32_t torque;
    static float rotationErrorOld;
    
    //Delcare control Variables
    int32_t kps = 36;
    int32_t kpr = 35;
    float kdr = 16.0;
    
    //Attach motor ticker to the callback function, running every 100 ms
    motorCtrlTicker.attach_us(&motorCtrlTick,100000);
    while(1){
        motorISR();
        motorCtrlT.signal_wait(0x1);
        
        core_util_critical_section_enter();
        locMotorPosition = motorPosition;   //Access shared variables here
        core_util_critical_section_exit();
        
        velocity = (locMotorPosition - oldMotorPosition) * 10;
        oldMotorPosition = locMotorPosition;
        motorCtrlCounter++;
        if (motorCtrlCounter >= 10) {   //Reset the counter every 10th iteration
            motorCtrlCounter = 0; 
            putMessage(msgVelocityOut, float(velocity));    //Reports the current velocity
            putMessage(msgPositionOut, float(locMotorPosition));    //Reports the current position
        }
        
        //Speed controller
        speedError = (endVelocity * 6) * 1.1 - abs(velocity);   //Read endVelocity and calculate the velocity error
        
        //Initialise controller output Ts  
        if (speedError == -abs(velocity)) {
            Ts = PWMPERIOD;   
        }
        else {
            Ts = (int)(kps * speedError);
        }
        
        //Rotation controller
        rotationError = endRotation * 0.98 - (locMotorPosition/6);  //Read endRotation and calculate the rotation error. 
        
        //Initialise controller output Tr
        Tr = kpr*rotationError + kdr*(rotationError - rotationErrorOld);    //Implement controller transfer function Ts= Kp*Er + Kd* (dEr/dt)        
        rotationErrorOld = rotationError;   //Update rotation error                         
        if(rotationError < 0){  //Use error's sign to set the controller, relative to the direction of rotation
            Ts = -Ts;                               
        }
        
        //Choose Ts or Tr based on distance from target value
        if((velocity>=0 && Ts<Tr) || (velocity<0 && Ts>Tr) || (endRotation == 0)){   so that it takes 
            torque = Ts; 
        }
        else{
            torque = Tr;
        }
        if(torque < 0){ //Variable torque can't be negative as it sets the PWM so make it positive
            torque = -torque;  
            lead = -2;  //Reverse the direction
        }
        else{
            lead = 2;
        }
        if(torque > PWMPERIOD){ //Set PWM to the 75% max if it's greater
            torque = PWMPERIOD; 
        }
        
        motorTorque = torque;
        
    }
}

/***********************************Decoding commands***********************************/

void parseCommand(){
    switch(newCommand[0]) {
        case 'K':
            newKey_mutex.lock();                        //Prevent deadlock
            sscanf(newCommand, "K%x", &newKey);         //Scan the desired the Key code
            putMessage(msgKeyAdded, newKey);           //Print it out
            newKey_mutex.unlock();
            break;
            
        case 'V':
            sscanf(newCommand, "V%f", &endVelocity);          //Find desired the end velocity
            putMessage(msgVelocityIn, endVelocity);
            break;
             
        case 'R':
            sscanf(newCommand, "R%f", &endRotation);          //Find desired end rotation
            putMessage(msgPositionIn, endRotation);
            break;
            
        case 'T':
            sscanf(newCommand, "T%d", &motorTorque);         //Find desired target torque
            putMessage(msgTorque, motorTorque);         //Print it out
            break;
        default: break;
    }
}

/*********************Queue and proccess incoming serial characters*********************/

void commIn() {
    while (1) {
        osEvent newEvent = inCharQ.get();   //Get next character
        uint8_t newChar = *((uint8_t*)(&newEvent.value.p));
        pc.putc(newChar);
        if(index >= MAXCOMMANDLENGTH){  //Cancel and restart if overflow
            index = 0;
            putMessage(msgError, 1);
        }
        else{
            if(newChar != '\r'){                //Isn't the end of the command
                newCommand[index] = newChar;    //Save input character
                index++;                        //Increment index
            }
            else{
                newCommand[index] = '\0';     //End of the command
                index = 0;                    //Reset index
                parseCommand();               //Parse the command for decoding.
            }
        }
    }
}

/***********************************Serial motor ISR************************************/

void serialISR() {
    uint8_t newChar = pc.getc();    //Obtains value from serial port
    inCharQ.put((void*)newChar);    //Places into newChar
}

/********************************Put message in mail queue******************************/

void putMessage(msgCode code, float message){
    message_t *pMessage = mail_box.alloc();     //Received messages are allocated to mail box
    pMessage->code = code;
    pMessage->message = message;
    mail_box.put(pMessage);
}

/*********************Output communication code to message conversion*******************/

void commOut() {
    while(1) {
        osEvent newEvent = mail_box.get();      //Pulls the message from the mail box
        message_t *pMessage = (message_t*)newEvent.value.p;     //Assigns the values to pMessage
        
        //Case switch to choose serial output based on incoming message code
        switch(pMessage->code) {
            case msgMotorState:
                pc.printf("Current Motor State: %x\n\r", pMessage->message);    //Outputs current motor state
                break;
            case msgHashRate:
                pc.printf("The system is mining at a rate of %d Hash/second\n\r", (int32_t)pMessage->message);    //Outputs current hash rate
                break;
            case msgNonceMatch:
                pc.printf("Nonce Matched! Nonce Code: %x\n\r", pMessage->message);      //Outputs the nonce when correct
                break;
            case msgKeyAdded:
                pc.printf("New key added:\t0x%016x\n\r", pMessage->message);        //Outputs new key input
                break;
            case msgTorque:
                pc.printf("The current motor torque is:\t%d\n\r", pMessage->message);       //Outputs current motor torque
                break;
                
            case msgVelocityIn:
                 pc.printf("The input velocity is:\t%d\n\r", (int32_t)pMessage->message);
                 break;
                 
            case msgVelocityOut:
                pc.printf("The current motor velocity is:\t%.2f\n\r", 
                          (pMessage->message) / 6.0);         //Outputs current velocity
                break;
                
            case msgPositionIn:
                pc.printf("Target rotation set to:\t%.2f\n\r", (pMessage->message));         //Outputs target rotation
                break;
            case msgPositionOut:
                pc.printf("Current position:\t%.2f\n\r", (pMessage->message)/6.0);         //Outputs current position
                break;
            case msgError:
                pc.printf("Debugging position:%x\n\r", pMessage->message);
                break;
            default:
                pc.printf("Unknown Error. Data: %x\n\r", pMessage->message);    //
                break;
        }
        mail_box.free(pMessage);    //Removes the message
    }
}

/****************************Motor interrupt service routine****************************/

void motorISR(){
    static int8_t oldRotorState;
    int8_t rotorState = readRotorState();
    motorOut((rotorState-orState+lead+6)%6); //+6 to make sure the remainder is positive
    if (rotorState - oldRotorState == 5) motorPosition--;
    else if (rotorState - oldRotorState == -5) motorPosition++;
    else motorPosition += (rotorState - oldRotorState);
    oldRotorState = rotorState;
}

/********************************Set a given drive state********************************/

void motorOut(int8_t driveState){
    
    //Lookup the output byte from the drive state.
    int8_t driveOut = driveTable[driveState & 0x07];
    
    //Turn off first
    if (~driveOut & 0x01) L1L.pulsewidth_us(0);
    if (~driveOut & 0x02) L1H = 1;
    if (~driveOut & 0x04) L2L.pulsewidth_us(0);
    if (~driveOut & 0x08) L2H = 1;
    if (~driveOut & 0x10) L3L.pulsewidth_us(0);
    if (~driveOut & 0x20) L3H = 1;
    
    //Then turn on
    if (driveOut & 0x01) L1L.pulsewidth_us(motorTorque);
    if (driveOut & 0x02) L1H = 0;
    if (driveOut & 0x04) L2L.pulsewidth_us(motorTorque);
    if (driveOut & 0x08) L2H = 0;
    if (driveOut & 0x10) L3L.pulsewidth_us(motorTorque);
    if (driveOut & 0x20) L3H = 0;
}

/******************Convert photointerrupter inputs to a rotor state*********************/

inline int8_t readRotorState(){
    return stateMap[I1 + 2*I2 + 4*I3];
}

/*****************************Basic synchronisation routine*****************************/

int8_t motorHome() {
    //Put the motor in drive state 0 and wait for it to stabilise
    motorOut(0);
    wait(2.0);
    
    //Get the rotor state
    return readRotorState();
}
