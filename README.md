# SecureChatApplication

SecureChatApplication is a Java-based application that simulates a secure chat between two clients. It provides a graphical user interface for each client and an activity monitor to log the interactions.

## Functionality

### SecureChatApplication

- Initializes two chat clients and an activity monitor
- Connects the two chat clients to simulate a chat
- Logs the start of the application and any messages sent between clients

### ChatClient

- Represents a chat client in the application
- Connects to another chat client to simulate a chat

### ActivityMonitor

- Provides a graphical user interface to display logged messages
- Logs formatted messages with timestamps and client names

## Running the Application

To run the application, execute the `main` method in the `SecureChatApplication` class. This will initialize the application and open the graphical user interfaces for the chat clients and the activity monitor.
```bash
cd src
javac SecureChatApplication.java && java SecureChatApplication
```
